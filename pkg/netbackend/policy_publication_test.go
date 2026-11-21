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
	"errors"
	"fmt"
	"io"
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

func publicationRules(lines ...string) string {
	return "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\n" + strings.Join(lines, "") + "COMMIT\n"
}

func publicationLeg(proto, ip string, port uint16) string {
	return fmt.Sprintf("-A OUTPUT -d %s -p %s -m %s --dport %d -j ACCEPT\n", ip, proto, proto, port) +
		fmt.Sprintf("-A INPUT -s %s -p %s -m %s --sport %d -j ACCEPT\n", ip, proto, proto, port)
}

func compilePublicationPolicy(t *testing.T, v4, v6 string) *CompiledPolicy {
	t.Helper()
	compiled, err := CompilePolicy(PolicyConfig{RulesV4: v4, RulesV6: v6})
	if err != nil {
		t.Fatalf("compile publication policy: %v", err)
	}
	return compiled
}

func newPolicyPublication(t *testing.T, v4, v6 string) (*NATPolicy, *PortForwarder) {
	t.Helper()
	policy := NewNATPolicy(compilePublicationPolicy(t, v4, v6), netip.AddrPort{})
	t.Cleanup(policy.Close)
	pf := NewPortForwarderWithOptions(tuning.Values{}, PortForwardOptions{Policy: policy})
	t.Cleanup(func() {
		if err := pf.Close(); err != nil {
			t.Errorf("close publication: %v", err)
		}
	})
	return policy, pf
}

func commitPublicationPolicy(t *testing.T, policy *NATPolicy, v4, v6 string) {
	t.Helper()
	if err := policy.Commit(compilePublicationPolicy(t, v4, v6), func() error { return nil }); err != nil {
		t.Fatalf("commit publication policy: %v", err)
	}
}

func dialPolicyPublication(t *testing.T, network, ip string, port uint16) net.Conn {
	t.Helper()
	addr := net.JoinHostPort(ip, strconv.Itoa(int(port)))
	c, err := net.DialTimeout(network, addr, testTimeout)
	if err != nil {
		t.Fatalf("dial published socket %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.SetDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatalf("set deadline on published socket %s: %v", addr, err)
	}
	return c
}

func requirePublishedTCPClosed(t *testing.T, c net.Conn) {
	t.Helper()
	var one [1]byte
	n, err := c.Read(one[:])
	if n != 0 || err == nil || isTimeout(err) {
		t.Fatalf("read denied publication: got %d bytes, %v; want the connection closed", n, err)
	}
}

func TestPolicyPublicationRejectsUnobservableBindings(t *testing.T) {
	tests := []struct {
		name string
		rule PortForwardRule
		want error
	}{
		{"IPv4 UDP wildcard", PortForwardRule{Proto: "udp", HostIP: "0.0.0.0", GuestPort: 80}, errPolicyPublicationUDPBind},
		{"IPv6 UDP wildcard", PortForwardRule{Proto: "udp", HostIP: "::", GuestPort: 80}, errPolicyPublicationUDPBind},
		{"mapped UDP wildcard", PortForwardRule{Proto: "udp", HostIP: "::ffff:0.0.0.0", GuestPort: 80}, errPolicyPublicationUDPBind},
		{"Unix socket", PortForwardRule{HostSocket: filepath.Join(t.TempDir(), "published.sock"), GuestPort: 80}, errPolicyPublicationUnix},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, pf := newPolicyPublication(t, publicationRules(), publicationRules())
			err := pf.PreBind([]PortForwardRule{{GuestPort: 80}, tc.rule})
			if !errors.Is(err, tc.want) {
				t.Fatalf("PreBind(%+v) = %v, want %v", tc.rule, err, tc.want)
			}
			if got := pf.BoundRules(); len(got) != 0 {
				t.Fatalf("PreBind opened sockets before rejecting %+v: %+v", tc.rule, got)
			}
		})
	}
}

func TestPolicyPublicationTCPWildcardUsesActualHostEndpoints(t *testing.T) {
	for _, tc := range []struct {
		network, bind, loopback string
	}{
		{"tcp4", "0.0.0.0", "127.0.0.1"},
		{"tcp6", "::", "::1"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			if tc.network == "tcp6" {
				probe, err := net.Listen("tcp6", "[::1]:0")
				if err != nil {
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				_ = probe.Close()
			}
			s := newForwardStack(t)
			guest, err := gonet.ListenTCP(s, guestFullAddr(0), ipv4.ProtocolNumber)
			if err != nil {
				t.Fatal(err)
			}
			tcpEchoServer(t, guest)
			guestPort := uint16(guest.Addr().(*net.TCPAddr).Port)
			policy, pf := newPolicyPublication(t, publicationRules(), publicationRules())
			pf.SetAccept(net.Listener.Accept)
			if err := pf.PreBind([]PortForwardRule{{HostIP: tc.bind, GuestPort: guestPort}}); err != nil {
				t.Fatalf("bind TCP wildcard %s: %v", tc.bind, err)
			}
			hostPort := pf.BoundRules()[0].HostPort
			hostLeg := fmt.Sprintf("-A OUTPUT -s %s -d %s -p tcp -m tcp --dport %d -j ACCEPT\n", tc.loopback, tc.loopback, hostPort) +
				fmt.Sprintf("-A INPUT -s %s -d %s -p tcp -m tcp --sport %d -j ACCEPT\n", tc.loopback, tc.loopback, hostPort)
			guestLeg := publicationLeg("tcp", DefaultGuestIPv4, guestPort)
			v4, v6 := publicationRules(guestLeg), publicationRules(hostLeg)
			if tc.network == "tcp4" {
				v4, v6 = publicationRules(hostLeg, guestLeg), publicationRules()
			}
			commitPublicationPolicy(t, policy, v4, v6)
			pf.Start(s)
			client := dialPolicyPublication(t, tc.network, tc.loopback, hostPort)
			roundTripTCP(t, client, []byte("authorized wildcard TCP"))

			commitPublicationPolicy(t, policy, publicationRules(guestLeg), publicationRules())
			requirePublishedTCPClosed(t, client)
			requirePublishedTCPClosed(t, dialPolicyPublication(t, tc.network, tc.loopback, hostPort))
		})
	}
}

func TestPolicyPublicationEstablishedTCPResumesAfterCheckpointPause(t *testing.T) {
	s := newForwardStack(t)
	guest, err := gonet.ListenTCP(s, guestFullAddr(0), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	tcpEchoServer(t, guest)
	guestPort := uint16(guest.Addr().(*net.TCPAddr).Port)
	policy, pf := newPolicyPublication(t, publicationRules(), publicationRules())
	if err := pf.PreBind([]PortForwardRule{{GuestPort: guestPort}}); err != nil {
		t.Fatal(err)
	}
	hostPort := pf.BoundRules()[0].HostPort
	commitPublicationPolicy(t, policy, publicationRules(
		publicationLeg("tcp", "127.0.0.1", hostPort),
		publicationLeg("tcp", DefaultGuestIPv4, guestPort),
	), publicationRules())
	pf.Start(s)
	client := dialPolicyPublication(t, "tcp4", "127.0.0.1", hostPort)
	roundTripTCP(t, client, []byte("before checkpoint"))

	pf.QuiesceForSave()
	const want = "during checkpoint"
	if _, err := io.WriteString(client, want); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(quietPeriod)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if n, err := client.Read(got); n != 0 || !isTimeout(err) {
		t.Fatalf("read during checkpoint pause: got %d bytes, %v; want timeout", n, err)
	}
	if err := pf.ResumeAfterSave(); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, got); err != nil || string(got) != want {
		t.Fatalf("read after checkpoint: got %q, %v; want %q", got, err, want)
	}
}

func TestPolicyPublicationTCPAuthorizesLoopbackFallbackBeforeDial(t *testing.T) {
	s := newForwardStack(t)
	const guestPort = 8315
	guest, err := gonet.ListenTCP(s, guestLoopbackAddr(guestPort), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	policy, pf := newPolicyPublication(t, publicationRules(), publicationRules())
	if err := pf.PreBind([]PortForwardRule{{GuestPort: guestPort}}); err != nil {
		t.Fatal(err)
	}
	hostPort := pf.BoundRules()[0].HostPort
	hostLeg := publicationLeg("tcp", "127.0.0.1", hostPort)
	commitPublicationPolicy(t, policy, publicationRules(hostLeg, publicationLeg("tcp", DefaultGuestIPv4, guestPort)), publicationRules())
	pf.Start(s)

	accepted := make(chan net.Conn)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if c, err := guest.Accept(); err == nil {
			select {
			case accepted <- c:
			case <-t.Context().Done():
				_ = c.Close()
			}
		}
	}()
	t.Cleanup(func() {
		_ = guest.Close()
		<-done
	})
	requirePublishedTCPClosed(t, dialPolicyPublication(t, "tcp4", "127.0.0.1", hostPort))
	commitPublicationPolicy(t, policy, publicationRules(hostLeg, publicationLeg("tcp", "127.0.0.1", guestPort)), publicationRules())
	client := dialPolicyPublication(t, "tcp4", "127.0.0.1", hostPort)
	const want = "authorized loopback TCP"
	if _, err := io.WriteString(client, want); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-accepted:
		defer c.Close()
		if err := c.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(want))
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != want {
			t.Fatalf("first guest connection got %q, %v; want %q from authorized client", buf, err, want)
		}

		relayPort := c.RemoteAddr().(*net.TCPAddr).Port
		guestRequest := fmt.Sprintf("-A OUTPUT -d 127.0.0.1 -p tcp -m tcp --sport %d --dport %d -j ACCEPT\n", relayPort, guestPort)
		guestReply := fmt.Sprintf("-A INPUT -s 127.0.0.1 -p tcp -m tcp --sport %d --dport %d -j ACCEPT\n", guestPort, relayPort)
		commitPublicationPolicy(t, policy, publicationRules(hostLeg, guestRequest, guestReply), publicationRules())
		if _, err := io.WriteString(client, want); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != want {
			t.Fatalf("guest relay port %d lost permission after replacement: got %q, %v", relayPort, buf, err)
		}
	case <-time.After(testTimeout):
		t.Fatal("authorized client did not reach guest loopback service")
	}
}

func TestPolicyPublicationDynamicTCPRequiresGuestLeg(t *testing.T) {
	s := newForwardStack(t)
	port := reserveFreeLoopbackPort(t, "tcp")
	guest, err := gonet.ListenTCP(s, guestFullAddr(port), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	tcpEchoServer(t, guest)
	hostLeg := fmt.Sprintf("-A OUTPUT -s 127.0.0.1 -d 127.0.0.1 -p tcp -m tcp --dport %d -j ACCEPT\n", port) +
		fmt.Sprintf("-A INPUT -s 127.0.0.1 -p tcp -m tcp --sport %d -j ACCEPT\n", port)
	policy, pf := newPolicyPublication(t, publicationRules(hostLeg), publicationRules())
	published := make(chan PortForwardRule, 1)
	bindErr := make(chan error, 1)
	pf.EnableDynamicLoopback(DynamicForwardOptions{
		ListenTCP: net.Listen,
		OnPublish: func(rule PortForwardRule, added bool) {
			if added && rule.Proto == "tcp" && rule.GuestPort == port {
				select {
				case published <- rule:
				default:
				}
			}
		},
		OnBindError: func(_ string, p uint16, err error) {
			if p == port {
				select {
				case bindErr <- err:
				default:
				}
			}
		},
	})
	pf.Start(s)
	select {
	case <-published:
	case err := <-bindErr:
		t.Fatalf("dynamic TCP bind: %v", err)
	case <-time.After(testTimeout):
		t.Fatal("did not publish guest TCP listener")
	}
	requirePublishedTCPClosed(t, dialPolicyPublication(t, "tcp4", "127.0.0.1", port))
	commitPublicationPolicy(t, policy, publicationRules(hostLeg, publicationLeg("tcp", DefaultGuestIPv4, port)), publicationRules())
	client := dialPolicyPublication(t, "tcp4", "127.0.0.1", port)
	roundTripTCP(t, client, []byte("authorized dynamic TCP"))
}

func TestPolicyPublicationUDPEvaluatesEveryDatagram(t *testing.T) {
	s := newForwardStack(t)
	addr := guestFullAddr(0)
	guest, err := gonet.DialUDP(s, &addr, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = guest.Close() })
	guestPort := uint16(guest.LocalAddr().(*net.UDPAddr).Port)
	policy, pf := newPolicyPublication(t, publicationRules(), publicationRules())
	if err := pf.PreBind([]PortForwardRule{{Proto: "udp", GuestPort: guestPort}}); err != nil {
		t.Fatal(err)
	}
	hostPort := pf.BoundRules()[0].HostPort
	hostAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(hostPort)}
	hostLeg := publicationLeg("udp", "127.0.0.1", hostPort)
	guestLeg := publicationLeg("udp", DefaultGuestIPv4, guestPort)
	commitPublicationPolicy(t, policy, publicationRules(hostLeg, guestLeg), publicationRules())
	pf.Start(s)
	client := newClientSocket(t)
	write := func(c net.PacketConn, payload string, to net.Addr) {
		t.Helper()
		if _, err := c.WriteTo([]byte(payload), to); err != nil {
			t.Fatalf("write published UDP %q: %v", payload, err)
		}
	}
	read := func(c net.PacketConn, want string) net.Addr {
		t.Helper()
		if err := c.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
			t.Fatal(err)
		}
		var buf [64]byte
		n, from, err := c.ReadFrom(buf[:])
		if err != nil || string(buf[:n]) != want {
			t.Fatalf("read published UDP got %q, %v; want %q", buf[:n], err, want)
		}
		return from
	}

	write(client, "request", hostAddr)
	relayAddr := read(guest, "request")
	for _, reply := range []string{"first reply", "second reply"} {
		write(guest, reply, relayAddr)
		read(client, reply)
	}
	for _, tc := range []struct {
		ip   string
		port uint16
	}{
		{DefaultGuestIPv4, guestPort}, {"127.0.0.1", hostPort},
	} {
		deny := fmt.Sprintf("-A INPUT -s %s -p udp -m udp --sport %d -j DROP\n", tc.ip, tc.port)
		commitPublicationPolicy(t, policy, publicationRules(deny, hostLeg, guestLeg), publicationRules())
		write(client, "additional request", hostAddr)
		if got := read(guest, "additional request"); got.String() != relayAddr.String() {
			t.Fatalf("guest relay address changed after reply denial: %s, want %s", got, relayAddr)
		}
		write(guest, "denied reply", relayAddr)
		requireNoPublishedDatagram(t, client)
	}
	commitPublicationPolicy(t, policy, publicationRules(hostLeg), publicationRules())
	write(client, "denied request on existing session", hostAddr)
	requireNoPublishedDatagram(t, guest)
}

func TestPolicyPublicationUDPAuthorizesLoopbackTarget(t *testing.T) {
	s := newForwardStack(t)
	const guestPort = 8316
	addr := guestLoopbackAddr(guestPort)
	guest, err := gonet.DialUDP(s, &addr, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = guest.Close() })
	policy, pf := newPolicyPublication(t, publicationRules(), publicationRules())
	if err := pf.PreBind([]PortForwardRule{{Proto: "udp", GuestPort: guestPort}}); err != nil {
		t.Fatal(err)
	}
	hostPort := pf.BoundRules()[0].HostPort
	hostLeg := publicationLeg("udp", "127.0.0.1", hostPort)
	commitPublicationPolicy(t, policy, publicationRules(hostLeg, publicationLeg("udp", DefaultGuestIPv4, guestPort)), publicationRules())
	pf.Start(s)
	host := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(hostPort)}
	client := newClientSocket(t)
	if _, err := client.WriteToUDP([]byte("denied loopback"), host); err != nil {
		t.Fatal(err)
	}
	requireNoPublishedDatagram(t, guest)

	commitPublicationPolicy(t, policy, publicationRules(hostLeg, publicationLeg("udp", "127.0.0.1", guestPort)), publicationRules())
	if _, err := client.WriteToUDP([]byte("allowed loopback"), host); err != nil {
		t.Fatal(err)
	}
	if err := guest.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatal(err)
	}
	var buf [64]byte
	n, from, err := guest.ReadFrom(buf[:])
	if err != nil || string(buf[:n]) != "allowed loopback" {
		t.Fatalf("published UDP loopback got %q, %v; want allowed loopback", buf[:n], err)
	}
	if _, err := guest.WriteTo([]byte("loopback reply"), from); err != nil {
		t.Fatal(err)
	}
	if got := recvFrom(t, client); got != "loopback reply" {
		t.Fatalf("client got %q, want loopback reply", got)
	}
}

func requireNoPublishedDatagram(t *testing.T, c net.PacketConn) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var buf [64]byte
	n, _, err := c.ReadFrom(buf[:])
	if !isTimeout(err) {
		t.Fatalf("read denied UDP: got %q, %v; want timeout", buf[:n], err)
	}
}
