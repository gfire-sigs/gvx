// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gvx

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/sandboxrpc"
	"z.gfire.dev/gvx/pkg/netbackend"
)

func networkProxyForTest(t *testing.T, cfg Config) *processNetworkProxy {
	t.Helper()
	broker, err := newNetworkBroker(t.Context(), &cfg)
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	server, err := sandboxrpc.NewServer(left, "Network", broker)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { server.Serve(); close(done) }()
	client := sandboxrpc.NewClient(right)
	proxy := &processNetworkProxy{client: client}
	t.Cleanup(func() { broker.Close(); client.Close(); server.Close(); <-done; proxy.pending.Wait() })
	return proxy
}

func TestNetworkBrokerRefusesUnconfiguredEgress(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for _, cfg := range []Config{{NetworkMode: NetModeNone}, {NetworkMode: NetModeNAT, IsolateLAN: true}} {
		t.Run(string(cfg.NetworkMode), func(t *testing.T) {
			proxy := networkProxyForTest(t, cfg)
			if connection, err := proxy.dial(t.Context(), "tcp", listener.Addr().String()); err == nil {
				connection.Close()
				t.Fatal("broker opened a forbidden connection")
			}
			if listener, err := proxy.listen("tcp", "127.0.0.1:0"); err == nil {
				listener.Close()
				t.Fatal("broker bound an unconfigured listener")
			}
		})
	}
}

func TestNetworkBrokerPreservesTCPStream(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	proxy := networkProxyForTest(t, Config{NetworkMode: NetModeNAT})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	connection, err := proxy.dial(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := connection.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(server)
	if err != nil || string(data) != "request" {
		t.Fatalf("request after half-close: %q, %v", data, err)
	}
	if _, err := server.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := server.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err = io.ReadAll(connection)
	if err != nil || string(data) != "response" {
		t.Fatalf("response after half-close: %q, %v", data, err)
	}
}

func TestWireGuardBrokerPinsPeer(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	alternate, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer alternate.Close()
	config := netbackend.WireGuardConfig{PrivateKey: [32]byte{1}, PeerPublicKey: [32]byte{2}, PeerEndpoint: peer.LocalAddr().String()}
	proxy := networkProxyForTest(t, Config{NetworkMode: NetModeWireGuard, WireGuardConfig: &config})
	packet, err := proxy.listenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	if _, err := packet.WriteTo([]byte("wrong"), alternate.LocalAddr()); err == nil {
		t.Fatal("broker accepted another WireGuard peer")
	}
	if _, err := packet.WriteTo([]byte("pinned"), peer.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var data [64]byte
	n, from, err := peer.ReadFromUDPAddrPort(data[:])
	if err != nil || string(data[:n]) != "pinned" {
		t.Fatalf("peer read: %q, %v", data[:n], err)
	}
	if _, err := peer.WriteToUDPAddrPort([]byte("reply"), from); err != nil {
		t.Fatal(err)
	}
	if err := packet.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, source, err := packet.ReadFrom(data[:])
	if err != nil || string(data[:n]) != "reply" || source.String() != peer.LocalAddr().String() {
		t.Fatalf("peer reply: %q from %v, %v", data[:n], source, err)
	}
	if connection, err := proxy.dial(t.Context(), "udp", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 1).String()); err == nil {
		connection.Close()
		t.Fatal("WireGuard broker opened another socket")
	}
}

func TestPublishedUDPRepliesRequireObservedClient(t *testing.T) {
	proxy := networkProxyForTest(t, Config{NetworkMode: NetModeNAT, IsolateLAN: true, PortForwards: []PortForward{{HostPort: 0, GuestPort: 8080, Protocol: "udp"}}})
	packet, err := proxy.listenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	alternate, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer alternate.Close()
	if _, err := packet.WriteTo([]byte("unsolicited"), client.LocalAddr()); err == nil {
		t.Fatal("published socket sent to an unobserved client")
	}
	if _, err := client.WriteTo([]byte("request"), packet.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if err := packet.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var data [64]byte
	n, from, err := packet.ReadFrom(data[:])
	if err != nil || string(data[:n]) != "request" {
		t.Fatalf("published request: %q, %v", data[:n], err)
	}
	if _, err := packet.WriteTo([]byte("response"), from); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err = client.ReadFrom(data[:])
	if err != nil || string(data[:n]) != "response" {
		t.Fatalf("published response: %q, %v", data[:n], err)
	}
	if _, err := packet.WriteTo([]byte("other peer"), alternate.LocalAddr()); err == nil {
		t.Fatal("published socket reused another client's authority")
	}
}
