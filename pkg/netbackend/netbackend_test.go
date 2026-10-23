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
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
)

func TestNATForwarderHostGatewayAndInboundPortForward(t *testing.T) {
	// 1. Start a host TCP echo server on 127.0.0.1:0.
	hostLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	defer func() {
		_ = hostLn.Close()
	}()
	hostPort := uint16(hostLn.Addr().(*net.TCPAddr).Port)

	go func() {
		conn, acceptErr := hostLn.Accept()
		if acceptErr != nil {
			return
		}
		defer func() {
			_ = conn.Close()
		}()
		_, _ = io.Copy(conn, conn)
	}()

	// 2. Create Netstack with Track A NAT forwarder.
	s, natFwd, err := NewNATStack(NATConfig{IsolateLAN: false})
	if err != nil {
		t.Fatalf("NewNATStack failed: %v", err)
	}
	defer func() {
		_ = natFwd.Close()
		s.Close()
	}()

	// 3. Dial outbound from Netstack to 10.0.2.2:hostPort (host.docker.internal).
	gwAddr := tcpip.FullAddress{
		NIC:  Eth0NICID,
		Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 2}),
		Port: hostPort,
	}
	guestOutConn, err := gonet.DialTCP(s, gwAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet.DialTCP to 10.0.2.2:%d failed: %v", hostPort, err)
	}
	wantMsg := []byte("hello-host-gateway")
	if _, err := guestOutConn.Write(wantMsg); err != nil {
		t.Fatalf("guestOutConn.Write failed: %v", err)
	}
	gotMsg := make([]byte, len(wantMsg))
	if _, err := io.ReadFull(guestOutConn, gotMsg); err != nil {
		t.Fatalf("io.ReadFull from host echo failed: %v", err)
	}
	_ = guestOutConn.Close()
	if !bytes.Equal(gotMsg, wantMsg) {
		t.Fatalf("echoed payload = %q, want %q", gotMsg, wantMsg)
	}

	// 4. Listen inside Netstack on 10.0.2.15:8080 and forward inbound -p 0:8080.
	guestListenAddr := tcpip.FullAddress{
		NIC:  Eth0NICID,
		Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 15}),
		Port: 8080,
	}
	guestLn, err := gonet.ListenTCP(s, guestListenAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet.ListenTCP failed: %v", err)
	}
	defer func() {
		_ = guestLn.Close()
	}()

	go func() {
		gc, acceptErr := guestLn.Accept()
		if acceptErr != nil {
			return
		}
		defer func() {
			_ = gc.Close()
		}()
		_, _ = gc.Write([]byte("guest-http-200-ok"))
	}()

	rule, err := ParsePortForwardRule("127.0.0.1:0:8080/tcp")
	if err != nil {
		t.Fatalf("ParsePortForwardRule failed: %v", err)
	}
	pf := NewPortForwarder()
	defer func() {
		_ = pf.Close()
	}()
	if err := pf.PreBind([]PortForwardRule{rule}); err != nil {
		t.Fatalf("PreBind failed: %v", err)
	}
	pf.Start(s)

	bound := pf.BoundRules()
	if len(bound) != 1 || bound[0].HostPort == 0 {
		t.Fatalf("BoundRules() = %+v, want 1 bound port", bound)
	}

	hostClient, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", bound[0].HostPort), 3*time.Second)
	if err != nil {
		t.Fatalf("net.DialTimeout to forwarded host port failed: %v", err)
	}
	defer func() {
		_ = hostClient.Close()
	}()
	resp, err := io.ReadAll(hostClient)
	if err != nil {
		t.Fatalf("io.ReadAll from forwarded port failed: %v", err)
	}
	if string(resp) != "guest-http-200-ok" {
		t.Fatalf("forwarded response = %q, want %q", string(resp), "guest-http-200-ok")
	}
}

func TestNATIsolateLANPolicy(t *testing.T) {
	nf := &NATForwarder{cfg: NATConfig{IsolateLAN: true}}
	blocked := []string{"10.0.2.2", "10.0.2.15", "127.0.0.1", "192.168.1.1", "172.16.0.5", "169.254.169.254"}
	for _, ipStr := range blocked {
		if _, err := nf.ResolveOutboundTarget(netip.MustParseAddr(ipStr), 443); err == nil {
			t.Fatalf("ResolveOutboundTarget(%s) succeeded under IsolateLAN, want error", ipStr)
		}
	}
	target, err := nf.ResolveOutboundTarget(netip.MustParseAddr("1.1.1.1"), 443)
	if err != nil || target != "1.1.1.1:443" {
		t.Fatalf("ResolveOutboundTarget(1.1.1.1) = (%q, %v), want (\"1.1.1.1:443\", nil)", target, err)
	}
}

// TestNATGuestLocalAddressesNeverReachHostServices proves that a guest dial to
// its own loopback or its own address fails while a host service listens on
// the same port. Netstack hands such a SYN to the forwarder when no guest
// socket listens, so a plain dial would reach the host service.
func TestNATGuestLocalAddressesNeverReachHostServices(t *testing.T) {
	hostLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	defer func() {
		_ = hostLn.Close()
	}()
	hostPort := uint16(hostLn.Addr().(*net.TCPAddr).Port)
	accepted := make(chan struct{}, 4)
	go func() {
		for {
			conn, acceptErr := hostLn.Accept()
			if acceptErr != nil {
				return
			}
			accepted <- struct{}{}
			_ = conn.Close()
		}
	}()

	s, natFwd, err := NewNATStack(NATConfig{IsolateLAN: false})
	if err != nil {
		t.Fatalf("NewNATStack failed: %v", err)
	}
	defer func() {
		_ = natFwd.Close()
		s.Close()
	}()

	for _, guestLocal := range [][4]byte{{127, 0, 0, 1}, {10, 0, 2, 15}} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		conn, err := gonet.DialContextTCP(ctx, s, tcpip.FullAddress{Addr: tcpip.AddrFrom4(guestLocal), Port: hostPort}, ipv4.ProtocolNumber)
		cancel()
		if err == nil {
			_ = conn.Close()
			t.Errorf("guest dial to %v:%d succeeded, want a refused connection", net.IP(guestLocal[:]), hostPort)
		}
	}
	select {
	case <-accepted:
		t.Error("the host service accepted a connection from a guest dial to a guest-local address")
	case <-time.After(200 * time.Millisecond):
	}

	nf := &NATForwarder{}
	for _, ipStr := range []string{"::1", "0.0.0.0", "::"} {
		if _, err := nf.ResolveOutboundTarget(netip.MustParseAddr(ipStr), hostPort); err == nil {
			t.Errorf("ResolveOutboundTarget(%s) succeeded, want an error", ipStr)
		}
	}
	if target, err := nf.ResolveOutboundTarget(netip.MustParseAddr(HostGatewayIPv4), hostPort); err != nil || target != fmt.Sprintf("127.0.0.1:%d", hostPort) {
		t.Errorf("ResolveOutboundTarget(gateway) = (%q, %v), want the host loopback", target, err)
	}
}

func TestNATVirtualDNSRelayUDPAndTCP(t *testing.T) {
	s, natFwd, err := NewNATStack(NATConfig{
		IsolateLAN: true,
		LookupHost: func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "registry.internal.corp" {
				return []netip.Addr{netip.MustParseAddr("198.51.100.42")}, nil
			}
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		},
	})
	if err != nil {
		t.Fatalf("NewNATStack failed: %v", err)
	}
	defer func() {
		_ = natFwd.Close()
		s.Close()
	}()

	// Build an RFC 1035 A-record query for registry.internal.corp.
	var q []byte
	q = append(q,
		0x12, 0x34, // ID
		0x01, 0x00, // Standard query, RD=1
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	)
	for _, label := range []string{"registry", "internal", "corp"} {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0x00, 0x00, 0x01, 0x00, 0x01) // QTYPE=A, QCLASS=IN

	dnsAddr := tcpip.FullAddress{
		NIC:  Eth0NICID,
		Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 3}),
		Port: 53,
	}

	// 1. Verify UDP DNS query to 10.0.2.3:53 succeeds even under IsolateLAN=true.
	uConn, err := gonet.DialUDP(s, nil, &dnsAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet.DialUDP to 10.0.2.3:53 failed: %v", err)
	}
	defer func() {
		_ = uConn.Close()
	}()
	if _, err := uConn.Write(q); err != nil {
		t.Fatalf("uConn.Write DNS query failed: %v", err)
	}
	_ = uConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp := make([]byte, 512)
	n, err := uConn.Read(resp)
	if err != nil {
		t.Fatalf("uConn.Read DNS response failed: %v", err)
	}
	if n < 16 || binary.BigEndian.Uint16(resp[0:2]) != 0x1234 || binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Fatalf("unexpected UDP DNS response header: len=%d id=0x%x ancount=%d", n, binary.BigEndian.Uint16(resp[0:2]), binary.BigEndian.Uint16(resp[6:8]))
	}
	gotIP := netip.AddrFrom4([4]byte{resp[n-4], resp[n-3], resp[n-2], resp[n-1]})
	if gotIP != netip.MustParseAddr("198.51.100.42") {
		t.Fatalf("resolved UDP DNS IP = %s, want 198.51.100.42", gotIP)
	}

	// 2. Verify TCP DNS query to 10.0.2.3:53.
	tConn, err := gonet.DialTCP(s, dnsAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet.DialTCP to 10.0.2.3:53 failed: %v", err)
	}
	defer func() {
		_ = tConn.Close()
	}()
	tcpFrame := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(tcpFrame[0:2], uint16(len(q)))
	copy(tcpFrame[2:], q)
	if _, err := tConn.Write(tcpFrame); err != nil {
		t.Fatalf("tConn.Write DNS query failed: %v", err)
	}
	var lenHdr [2]byte
	if _, err := io.ReadFull(tConn, lenHdr[:]); err != nil {
		t.Fatalf("io.ReadFull TCP DNS length failed: %v", err)
	}
	tcpResp := make([]byte, binary.BigEndian.Uint16(lenHdr[:]))
	if _, err := io.ReadFull(tConn, tcpResp); err != nil {
		t.Fatalf("io.ReadFull TCP DNS body failed: %v", err)
	}
	gotTCPIP := netip.AddrFrom4([4]byte{tcpResp[len(tcpResp)-4], tcpResp[len(tcpResp)-3], tcpResp[len(tcpResp)-2], tcpResp[len(tcpResp)-1]})
	if gotTCPIP != netip.MustParseAddr("198.51.100.42") {
		t.Fatalf("resolved TCP DNS IP = %s, want 198.51.100.42", gotTCPIP)
	}
}
