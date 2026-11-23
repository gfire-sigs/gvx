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
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
)

func compilePublicationPolicy(t *testing.T, fallback string, rules ...NATPolicyRule) *CompiledNATPolicy {
	t.Helper()
	policy, err := CompileNATPolicy(&NATPolicyConfig{
		Ingress: NATPolicyDirectionConfig{Default: fallback, Rules: rules},
		Egress:  NATPolicyDirectionConfig{Default: "deny"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func dialPublication(t *testing.T, network, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout(network, addr, testTimeout)
	if err != nil {
		t.Fatalf("connect to publication %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatal(err)
	}
	return conn
}

func assertPublicationClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if n, err := conn.Read(b[:]); n != 0 || err == nil || isTimeout(err) {
		t.Fatalf("read from denied publication: %d bytes, %v; want closed connection", n, err)
	}
}

func TestPortForwarderPolicyGatesTCPPublications(t *testing.T) {
	for _, source := range []string{PortSourceStatic, PortSourceDynamic, PortSourceAuto} {
		t.Run(source, func(t *testing.T) {
			s := newForwardStack(t)
			port := uint16(8080)
			var autoListener net.Listener
			if source == PortSourceAuto {
				ln, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = ln.Close() })
				autoListener = ln
				port = uint16(ln.Addr().(*net.TCPAddr).Port)
			}
			guest := guestLoopbackAddr(port)
			guestCIDR := "127.0.0.1/32"
			if source == PortSourceDynamic {
				guest = guestFullAddr(port)
				guestCIDR = DefaultGuestIPv4 + "/32"
			}
			guestLn, err := gonet.ListenTCP(s, guest, ipv4.ProtocolNumber)
			if err != nil {
				t.Fatal(err)
			}
			tcpEchoServer(t, guestLn)

			allow := compilePublicationPolicy(t, "deny", NATPolicyRule{
				Action: "allow", CIDR: "127.0.0.1/32", GuestCIDR: guestCIDR,
				Protocol: "tcp", Ports: strconv.Itoa(int(port)),
			})
			policy := NewNATPolicy(allow, netip.AddrPort{})
			t.Cleanup(policy.Close)
			pf := NewPortForwarder(tuning.Values{})
			t.Cleanup(func() { _ = pf.Close() })
			pf.SetNATPolicy(policy)
			rule := PortForwardRule{Proto: "tcp", GuestPort: port}
			var addr string
			switch source {
			case PortSourceStatic:
				if err := pf.PreBind([]PortForwardRule{rule}); err != nil {
					t.Fatal(err)
				}
				pf.Start(s)
				addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(int(pf.BoundRules()[0].HostPort)))
			case PortSourceDynamic:
				pf.Start(s)
				bound, err := pf.AddDynamicRule(rule, false, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(int(bound.HostPort)))
			case PortSourceAuto:
				addr = autoListener.Addr().String()
				ready := make(chan struct{}, 1)
				pf.EnableDynamicLoopback(DynamicForwardOptions{
					PollInterval: time.Hour,
					ListenTCP: func(_, address string) (net.Listener, error) {
						if address != addr {
							return nil, fmt.Errorf("unexpected auto publication address %s", address)
						}
						return autoListener, nil
					},
					OnPublish: func(r PortForwardRule, added bool) {
						if added && r.GuestPort == port {
							ready <- struct{}{}
						}
					},
				})
				pf.Start(s)
				select {
				case <-ready:
				case <-time.After(testTimeout):
					t.Fatal("auto publication did not start")
				}
			}

			conn := dialPublication(t, "tcp4", addr)
			roundTripTCP(t, conn, []byte("admitted"))
			if err := policy.Replace(compilePublicationPolicy(t, "deny")); err != nil {
				t.Fatal(err)
			}
			assertPublicationClosed(t, conn)
			assertPublicationClosed(t, dialPublication(t, "tcp4", addr))
		})
	}
}

func TestPortForwarderPolicyActivationClosesUnixPublication(t *testing.T) {
	s := newForwardStack(t)
	const port = 2375
	guestLn, err := gonet.ListenTCP(s, guestFullAddr(port), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	tcpEchoServer(t, guestLn)
	sock := filepath.Join(shortTempDir(t), "forward.sock")
	shaper := NewBandwidthShaper(BandwidthRates{TXBPS: 8_000_000, RXBPS: 8_000_000})
	t.Cleanup(shaper.Close)
	policy := NewNATPolicy(nil, netip.AddrPort{})
	t.Cleanup(policy.Close)
	pf := NewPortForwarder(tuning.Values{})
	t.Cleanup(func() { _ = pf.Close() })
	pf.SetBandwidthShaper(shaper)
	pf.SetNATPolicy(policy)
	if err := pf.PreBind([]PortForwardRule{{Proto: "tcp", HostSocket: sock, GuestPort: port}}); err != nil {
		t.Fatal(err)
	}
	pf.Start(s)

	conn := dialPublication(t, "unix", sock)
	roundTripTCP(t, conn, []byte("only-bandwidth-limited"))
	if err := policy.Replace(compilePublicationPolicy(t, "allow")); err != nil {
		t.Fatal(err)
	}
	assertPublicationClosed(t, conn)
	assertPublicationClosed(t, dialPublication(t, "unix", sock))
}

func TestPortForwarderPolicyRevokesQueuedUDP(t *testing.T) {
	s := newForwardStack(t)
	const port = 5300
	guestAddr := guestLoopbackAddr(port)
	guest, err := gonet.DialUDP(s, &guestAddr, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	udpEchoServer(t, guest)
	shaper := NewBandwidthShaper(BandwidthRates{})
	t.Cleanup(shaper.Close)
	allow := compilePublicationPolicy(t, "deny", NATPolicyRule{
		Action: "allow", CIDR: "127.0.0.1/32", GuestCIDR: "127.0.0.1/32", Protocol: "udp", Ports: "5300",
	})
	policy := NewNATPolicy(allow, netip.AddrPort{})
	t.Cleanup(policy.Close)
	pf, hostAddr := preBoundUDPForward(t, port)
	pf.SetNATPolicy(policy)
	pf.SetBandwidthShaper(shaper)
	pf.Start(s)
	client := newClientSocket(t)
	write := func(payload string) {
		t.Helper()
		if _, err := client.WriteToUDP([]byte(payload), hostAddr); err != nil {
			t.Fatal(err)
		}
	}
	write("admitted")
	if got := recvFrom(t, client); got != "admitted" {
		t.Fatalf("initial echo = %q, want admitted", got)
	}

	shaper.SetRates(BandwidthRates{RXBPS: 1})
	write(strings.Repeat("queued", 32))
	var queued *BandwidthFlow
	waitUntil(t, testTimeout, "published UDP datagram to enter the bandwidth queue", func() bool {
		pf.mu.Lock()
		defer pf.mu.Unlock()
		for _, sess := range pf.udpList[0].sessions {
			if sess.rx.Pending() {
				queued = &sess.rx
				return true
			}
		}
		return false
	})
	if err := policy.Replace(compilePublicationPolicy(t, "deny")); err != nil {
		t.Fatal(err)
	}
	if err := policy.Replace(allow); err != nil {
		t.Fatal(err)
	}
	shaper.SetRates(BandwidthRates{})
	waitUntil(t, testTimeout, "revoked datagram to leave the bandwidth queue", func() bool { return !queued.Pending() })
	write("new-admission")
	if got := recvFrom(t, client); got != "new-admission" {
		t.Fatalf("echo after restoring policy = %q, want only the newly admitted datagram", got)
	}
}
