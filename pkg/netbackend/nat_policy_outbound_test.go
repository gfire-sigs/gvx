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

package netbackend

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"testing/synctest"
	"time"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
)

func compileOutboundPolicy(t *testing.T, egress, ingress NATPolicyDirectionConfig) *CompiledNATPolicy {
	t.Helper()
	compiled, err := CompileNATPolicy(&NATPolicyConfig{Egress: egress, Ingress: ingress})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return compiled
}

func TestNATPolicyRequiresBothGatewayAddressesBeforeHostDial(t *testing.T) {
	for _, tc := range []struct {
		name       string
		blocked    string
		control    netip.AddrPort
		standalone bool
		wantDialed []string
	}{
		{name: "guest gateway", blocked: "10.0.2.2/32", wantDialed: []string{"127.0.0.1:8081"}},
		{name: "mapped host loopback", blocked: "127.0.0.1/32", wantDialed: []string{"127.0.0.1:8081"}},
		{name: "TCP control address permits UDP", control: netip.MustParseAddrPort("127.0.0.1:8080"), wantDialed: []string{"127.0.0.1:8080", "127.0.0.1:8081"}},
		{name: "standalone TCP control address permits UDP", control: netip.MustParseAddrPort("127.0.0.1:8080"), standalone: true, wantDialed: []string{"127.0.0.1:8080", "127.0.0.1:8081"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var compiled *CompiledNATPolicy
			if tc.blocked != "" {
				compiled = compileOutboundPolicy(t, NATPolicyDirectionConfig{Default: "allow", Rules: []NATPolicyRule{
					{Action: "deny", CIDR: tc.blocked, Protocol: "udp", Ports: "8080"},
				}}, NATPolicyDirectionConfig{Default: "allow"})
			}
			var dialed []string
			f := natPacketFamilies()[0]
			cfg := NATConfig{
				DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
					dialed = append(dialed, address)
					return nil, net.ErrClosed
				},
			}
			if tc.standalone {
				cfg.ControlTCPAddr = tc.control
			} else {
				cfg.Policy = NewNATPolicy(compiled, tc.control)
				defer cfg.Policy.Close()
			}
			s, nf := newNATPacketTestStack(t, f, cfg)
			for _, port := range []uint16{8080, 8081} {
				udp := natTestUDP(f.guest, hostGatewayAddr, 40001, port, "datagram")
				f.send(t, s, Eth0NICID, f.packet(f.guest, hostGatewayAddr, header.UDPProtocolNumber, udp, 0, false))
			}
			if !slices.Equal(dialed, tc.wantDialed) {
				t.Fatalf("native UDP dial targets = %v, want %v", dialed, tc.wantDialed)
			}
			if tc.control.IsValid() {
				if _, err := nf.ResolveOutboundTarget(netip.MustParseAddr("::ffff:10.0.2.2"), 8080); err == nil {
					t.Error("mapped gateway reached the control endpoint")
				}
			}
		})
	}
}

func TestNATPolicyRevokesEstablishedOutboundRelay(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			allow := NATPolicyDirectionConfig{Default: "allow"}
			deny := NATPolicyDirectionConfig{Default: "deny"}
			policy := NewNATPolicy(compileOutboundPolicy(t, allow, deny), netip.AddrPort{})
			defer policy.Close()
			host, relay := net.Pipe()
			defer host.Close()
			defer relay.Close()
			s, nf, err := NewNATStack(NATConfig{
				Policy:     policy,
				DNSServers: []string{"192.0.2.53:53"},
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return relay, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			defer nf.Close()
			ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
			defer cancel()
			addr := tcpip.FullAddress{NIC: Eth0NICID, Addr: hostGatewayAddr, Port: 8443}
			var guest net.Conn
			if network == "tcp" {
				guest, err = gonet.DialContextTCP(ctx, s, addr, ipv4.ProtocolNumber)
			} else {
				guest, err = gonet.DialUDP(s, nil, &addr, ipv4.ProtocolNumber)
			}
			if err != nil {
				t.Fatalf("open guest %s connection: %v", network, err)
			}
			defer guest.Close()
			deadline := time.Now().Add(testTimeout)
			if err := host.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := guest.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			request, response := []byte("ping"), []byte("pong")
			if network == "udp" {
				request = bytes.Repeat(request, 2048)
				response = bytes.Repeat(response, 2048)
			}
			data := make([]byte, len(request))
			if _, err := guest.Write(request); err != nil {
				t.Fatal(err)
			}
			if n, err := io.ReadFull(host, data); err != nil || !bytes.Equal(data, request) {
				t.Fatalf("host read = (%d bytes, %v), want intact %d-byte request", n, err, len(request))
			}
			if _, err := host.Write(response); err != nil {
				t.Fatal(err)
			}
			if n, err := io.ReadFull(guest, data); err != nil || !bytes.Equal(data, response) {
				t.Fatalf("guest read = (%d bytes, %v), want intact %d-byte reply despite deny ingress", n, err, len(response))
			}
			if err := policy.Replace(compileOutboundPolicy(t, deny, deny)); err != nil {
				t.Fatalf("replace policy: %v", err)
			}
			if _, err := host.Read(data[:]); !errors.Is(err, io.EOF) {
				t.Fatalf("host read after denying established relay = %v, want EOF", err)
			}
		})
	}
}

func TestNATPolicyAuthorizesEveryDNSFallback(t *testing.T) {
	denied := startFakeDNSServer(t, answerWith("192.0.2.1"))
	truncated := startFakeDNSServer(t, func(q []byte, tcp bool) []byte {
		resp := answerWith("192.0.2.2")(q, tcp)
		if !tcp {
			resp[2] |= 2 // TC flag.
		}
		return resp
	})
	allowed := startFakeDNSServer(t, answerWith("192.0.2.3"))
	upstreamRule := func(server string) NATPolicyRule {
		ap := netip.MustParseAddrPort(server)
		return NATPolicyRule{Action: "allow", CIDR: netip.PrefixFrom(ap.Addr(), 32).String(), Protocol: "udp", Ports: strconv.Itoa(int(ap.Port()))}
	}
	virtualRule := NATPolicyRule{Action: "allow", CIDR: "10.0.2.3/32", Protocol: "udp", Ports: "53"}
	deny := NATPolicyDirectionConfig{Default: "deny"}
	policy := NewNATPolicy(compileOutboundPolicy(t, NATPolicyDirectionConfig{Default: "deny", Rules: []NATPolicyRule{
		virtualRule, upstreamRule(truncated.addr), upstreamRule(allowed.addr),
	}}, deny), netip.AddrPort{})
	defer policy.Close()
	nf := newTestForwarder(t, NATConfig{Policy: policy}, denied.addr, truncated.addr, allowed.addr)
	req := buildDNSQuery(42, "fallback.example.test", dnsTypeA)
	if got := answerIPs(t, nf.handleDNSQuery(t.Context(), req)); !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.0.2.3")}) {
		t.Fatalf("DNS answers = %v, want answer from the permitted UDP fallback", got)
	}
	if got := denied.queries.Load(); got != 0 {
		t.Errorf("denied upstream received %d queries, want none", got)
	}
	if got := truncated.queries.Load(); got != 1 {
		t.Errorf("truncating upstream received %d queries, want UDP only", got)
	}
	if err := policy.Replace(compileOutboundPolicy(t, deny, deny)); err != nil {
		t.Fatalf("replace policy: %v", err)
	}
	if resp := nf.handleDNSQuery(t.Context(), buildDNSQuery(43, "localhost", dnsTypeA)); len(resp) != 0 {
		t.Fatalf("blocked virtual DNS relayed a local answer: %x", resp)
	}
}

func TestNATPolicyRevokesInFlightDNSAttempt(t *testing.T) {
	const server = "192.0.2.53:5353"
	policy := NewNATPolicy(nil, netip.AddrPort{})
	defer policy.Close()
	host, relay := net.Pipe()
	defer host.Close()
	defer relay.Close()
	nf := newTestForwarder(t, NATConfig{
		Policy: policy,
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return relay, nil
		},
	}, server)
	req := buildDNSQuery(42, "pending.example.test", dnsTypeA)
	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()
	done := make(chan []byte, 1)
	go func() { done <- nf.handleDNSQuery(ctx, req) }()
	if err := host.SetDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(host, make([]byte, len(req))); err != nil {
		t.Fatalf("read original DNS attempt: %v", err)
	}
	deny := NATPolicyDirectionConfig{Default: "deny"}
	if err := policy.Replace(compileOutboundPolicy(t, NATPolicyDirectionConfig{Default: "deny", Rules: []NATPolicyRule{
		{Action: "allow", CIDR: "10.0.2.3/32", Protocol: "udp", Ports: "53"},
	}}, deny)); err != nil {
		t.Fatalf("replace policy: %v", err)
	}
	var data [1]byte
	if _, err := host.Read(data[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("read after denying upstream = %v, want EOF", err)
	}
	select {
	case resp := <-done:
		if dnsRCode(resp) != dnsRCodeSrv {
			t.Fatalf("DNS reply = %x, want SERVFAIL after revoking the upstream", resp)
		}
	case <-ctx.Done():
		t.Fatalf("DNS query did not finish after closing upstream: %v", ctx.Err())
	}
}

func TestNATPolicyRevokesPartiallyWrittenTCPDNSReply(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		policy := NewNATPolicy(nil, netip.AddrPort{})
		defer policy.Close()
		guest, relay := net.Pipe()
		done := make(chan struct{})
		virtual := NATPolicyFlow{
			Direction: NATPolicyEgress, Protocol: uint8(header.TCPProtocolNumber),
			Guest: dnsGuestAddr, Remote: natVirtualDNSIP, Port: DefaultDNSPort, PortKnown: true,
		}
		upstream := virtual
		upstream.Remote = netip.MustParseAddr("192.0.2.53")
		go func() {
			defer close(done)
			serveTCPDNSConn(t.Context(), relay, time.Hour, nil, func(ctx context.Context, _ []byte) dnsReply {
				replyCtx, release, allowed := policy.Track(ctx, virtual, upstream)
				if !allowed {
					t.Error("initial policy denied the reply")
					return dnsReply{}
				}
				return dnsReply{wire: []byte("answer"), upstreamCtx: replyCtx, finish: release}
			})
		}()
		defer func() {
			_ = guest.Close()
			<-done
		}()
		if _, err := guest.Write([]byte{0, 1, 1}); err != nil {
			t.Fatalf("send framed DNS request: %v", err)
		}
		var prefix [2]byte
		if _, err := io.ReadFull(guest, prefix[:]); err != nil || binary.BigEndian.Uint16(prefix[:]) != 6 {
			t.Fatalf("read reply length = (%v, %v), want (6, nil)", prefix, err)
		}
		synctest.Wait()
		deny := NATPolicyDirectionConfig{Default: "deny"}
		if err := policy.Replace(compileOutboundPolicy(t, NATPolicyDirectionConfig{Default: "deny", Rules: []NATPolicyRule{
			{Action: "allow", CIDR: "10.0.2.3/32", Protocol: "tcp", Ports: "53"},
		}}, deny)); err != nil {
			t.Fatalf("revoke upstream only: %v", err)
		}
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("revoking upstream did not interrupt the blocked guest write")
		}
		var payload [6]byte
		if n, err := guest.Read(payload[:]); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("read after upstream revocation = (%d bytes, %v), want EOF without frame payload", n, err)
		}
	})
}

func TestNATPolicyRevalidatesQueuedPackets(t *testing.T) {
	for _, f := range natPacketFamilies() {
		t.Run(f.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				policy := NewNATPolicy(nil, netip.AddrPort{})
				defer policy.Close()
				shaper := NewBandwidthShaper(BandwidthRates{TXBPS: 8, RXBPS: 8})
				defer shaper.Close()
				s, nf := newNATPacketTestStack(t, f, NATConfig{Policy: policy, Bandwidth: shaper})
				const peerPort, guestPort = 8000, 9000
				guest, err := gonet.DialUDP(s, &tcpip.FullAddress{Addr: f.guest, Port: guestPort}, nil, f.protocol)
				if err != nil {
					t.Fatal(err)
				}
				defer guest.Close()
				send := func(data string) {
					udp := natTestUDP(f.peer, f.guest, peerPort, guestPort, data)
					f.send(t, nf.stack, hostNICID, f.packet(f.peer, f.guest, header.UDPProtocolNumber, udp, 0, false))
				}
				first, last := f.echoFragments()
				f.send(t, s, Eth0NICID, first)
				f.send(t, s, Eth0NICID, last)
				send("queued before replacement")
				deny := NATPolicyDirectionConfig{Default: "deny"}
				if err := policy.Replace(compileOutboundPolicy(t, deny, deny)); err != nil {
					t.Fatalf("replace policy: %v", err)
				}
				shaper.SetRates(BandwidthRates{})
				synctest.Wait()
				echoes, _ := f.echoCounters(s, nf.stack)
				if got := echoes.Value(); got != 0 {
					t.Errorf("private peer received %d queued echo requests after deny, want none", got)
				}
				// Verify the denied raw UDP did not survive the queue. A new
				// packet still reaches the same socket once ingress allows it.
				allow := NATPolicyDirectionConfig{Default: "allow"}
				if err := policy.Replace(compileOutboundPolicy(t, deny, allow)); err != nil {
					t.Fatalf("replace ingress policy: %v", err)
				}
				send("allowed after replacement")
				if err := guest.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				var data [64]byte
				n, err := guest.Read(data[:])
				if err != nil || string(data[:n]) != "allowed after replacement" {
					t.Fatalf("guest read = (%q, %v), want only the newly admitted packet", data[:n], err)
				}
			})
		})
	}
}
