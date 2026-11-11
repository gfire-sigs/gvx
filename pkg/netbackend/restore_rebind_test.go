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
	"strconv"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/tcp"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
	"z.gfire.dev/gvx/pkg/waiter"
)

type savedStackEndpoints struct {
	Stack       *stack.Stack
	TCPWQ       *waiter.Queue
	TCPListenEP tcpip.Endpoint
	UDPWQ       *waiter.Queue
	UDPEP       tcpip.Endpoint
}

func (*savedStackEndpoints) StateTypeName() string {
	return "pkg/netbackend.savedStackEndpoints"
}

func (*savedStackEndpoints) StateFields() []string {
	return []string{"Stack", "TCPWQ", "TCPListenEP", "UDPWQ", "UDPEP"}
}

func (s *savedStackEndpoints) StateSave(sink state.Sink) {
	sink.Save(0, &s.Stack)
	sink.Save(1, &s.TCPWQ)
	sink.Save(2, &s.TCPListenEP)
	sink.Save(3, &s.UDPWQ)
	sink.Save(4, &s.UDPEP)
}

func (s *savedStackEndpoints) StateLoad(_ context.Context, src state.Source) {
	src.Load(0, &s.Stack)
	src.Load(1, &s.TCPWQ)
	src.Load(2, &s.TCPListenEP)
	src.Load(3, &s.UDPWQ)
	src.Load(4, &s.UDPEP)
}

func init() {
	state.RegisterNoHooks((*savedStackEndpoints)(nil))
}

func buildDNSQueryPacket(id uint16, labels ...string) []byte {
	var q []byte
	q = append(q,
		byte(id>>8), byte(id),
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	)
	for _, label := range labels {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0x00, 0x00, 0x01, 0x00, 0x01)
	return q
}

func TestNATForwarderAndPortForwarderAttachRestoredStack(t *testing.T) {
	hostLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	defer func() {
		_ = hostLn.Close()
	}()
	hostPort := uint16(hostLn.Addr().(*net.TCPAddr).Port)

	go func() {
		for {
			conn, acceptErr := hostLn.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() {
					_ = c.Close()
				}()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	origStack, natFwd, err := NewNATStack(NATConfig{
		IsolateLAN: false,
		LookupHost: func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "restored.nat.internal" {
				return []netip.Addr{netip.MustParseAddr("198.51.100.88")}, nil
			}
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		},
	})
	if err != nil {
		t.Fatalf("NewNATStack failed: %v", err)
	}
	defer func() {
		_ = natFwd.Close()
		origStack.Destroy()
	}()

	const (
		guestTCPPort = 8080
		guestUDPPort = 8081
	)
	var tcpWQ waiter.Queue
	tcpListenEP, tcpErr := origStack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &tcpWQ)
	if tcpErr != nil {
		t.Fatalf("origStack.NewEndpoint(TCP): %s", tcpErr)
	}
	defer tcpListenEP.Close()
	if err := tcpListenEP.Bind(tcpip.FullAddress{
		NIC:  Eth0NICID,
		Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 15}),
		Port: guestTCPPort,
	}); err != nil {
		t.Fatalf("tcpListenEP.Bind: %s", err)
	}
	if err := tcpListenEP.Listen(16); err != nil {
		t.Fatalf("tcpListenEP.Listen: %s", err)
	}

	var udpWQ waiter.Queue
	udpEP, udpErr := origStack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &udpWQ)
	if udpErr != nil {
		t.Fatalf("origStack.NewEndpoint(UDP): %s", udpErr)
	}
	defer udpEP.Close()
	if err := udpEP.Bind(tcpip.FullAddress{
		NIC:  Eth0NICID,
		Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 15}),
		Port: guestUDPPort,
	}); err != nil {
		t.Fatalf("udpEP.Bind: %s", err)
	}

	tcpRule, err := ParsePortForwardRule(fmt.Sprintf("127.0.0.1:0:%d/tcp", guestTCPPort))
	if err != nil {
		t.Fatalf("ParsePortForwardRule(tcp): %v", err)
	}
	udpRule, err := ParsePortForwardRule(fmt.Sprintf("127.0.0.1:0:%d/udp", guestUDPPort))
	if err != nil {
		t.Fatalf("ParsePortForwardRule(udp): %v", err)
	}
	pf := NewPortForwarder(tuning.Values{})
	defer func() {
		_ = pf.Close()
	}()
	if err := pf.PreBind([]PortForwardRule{tcpRule, udpRule}); err != nil {
		t.Fatalf("pf.PreBind: %v", err)
	}
	pf.Start(origStack)
	boundBefore := pf.BoundRules()
	if len(boundBefore) != 2 {
		t.Fatalf("pf.BoundRules() before save = %+v, want 2 rules", boundBefore)
	}

	orig := savedStackEndpoints{
		Stack:       origStack,
		TCPWQ:       &tcpWQ,
		TCPListenEP: tcpListenEP,
		UDPWQ:       &udpWQ,
		UDPEP:       udpEP,
	}

	origStack.Pause()
	var buf bytes.Buffer
	ctx := context.Background()
	_, saveErr := state.Save(ctx, &buf, &orig)
	origStack.Resume()
	if saveErr != nil {
		t.Fatalf("state.Save: %v", saveErr)
	}

	var restored savedStackEndpoints
	if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	defer func() {
		if restored.TCPListenEP != nil {
			restored.TCPListenEP.Close()
		}
		if restored.UDPEP != nil {
			restored.UDPEP.Close()
		}
		if restored.Stack != nil {
			restored.Stack.Destroy()
		}
	}()

	if err := natFwd.AttachRestoredStack(restored.Stack); err != nil {
		t.Fatalf("natFwd.AttachRestoredStack: %v", err)
	}
	if err := pf.AttachRestoredStack(restored.Stack); err != nil {
		t.Fatalf("pf.AttachRestoredStack: %v", err)
	}

	boundAfter := pf.BoundRules()
	if len(boundAfter) != 2 || boundAfter[0].HostPort != boundBefore[0].HostPort || boundAfter[1].HostPort != boundBefore[1].HostPort {
		t.Fatalf("pf.BoundRules() after restore = %+v, want %+v", boundAfter, boundBefore)
	}

	// 1. Outbound TCP from the restored guest stack to host.docker.internal (10.0.2.2).
	gwAddr := tcpip.FullAddress{
		NIC:  Eth0NICID,
		Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 2}),
		Port: hostPort,
	}
	guestOutConn, err := gonet.DialTCP(restored.Stack, gwAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet.DialTCP from restored stack to 10.0.2.2:%d failed: %v", hostPort, err)
	}
	wantOut := []byte("restored-outbound-nat")
	if _, err := guestOutConn.Write(wantOut); err != nil {
		t.Fatalf("guestOutConn.Write: %v", err)
	}
	gotOut := make([]byte, len(wantOut))
	if _, err := io.ReadFull(guestOutConn, gotOut); err != nil {
		t.Fatalf("io.ReadFull from host echo: %v", err)
	}
	_ = guestOutConn.Close()
	if !bytes.Equal(gotOut, wantOut) {
		t.Fatalf("outbound echoed payload = %q, want %q", gotOut, wantOut)
	}

	// 2. Inbound TCP port forward to the restored guest listening socket.
	acceptedDone := make(chan error, 1)
	go func() {
		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
		restored.TCPWQ.EventRegister(&waitEntry)
		defer restored.TCPWQ.EventUnregister(&waitEntry)
		for {
			ep, wq, acceptErr := restored.TCPListenEP.Accept(nil)
			if _, ok := acceptErr.(*tcpip.ErrWouldBlock); ok {
				<-notifyCh
				continue
			}
			if acceptErr != nil {
				acceptedDone <- fmt.Errorf("restored.TCPListenEP.Accept: %s", acceptErr)
				return
			}
			conn := gonet.NewTCPConn(wq, ep)
			_, writeErr := conn.Write([]byte("restored-guest-tcp-ok"))
			_ = conn.Close()
			acceptedDone <- writeErr
			return
		}
	}()

	hostClient, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", boundAfter[0].HostPort), 3*time.Second)
	if err != nil {
		t.Fatalf("net.DialTimeout to forwarded TCP port after restore: %v", err)
	}
	defer func() {
		_ = hostClient.Close()
	}()
	tcpResp, err := io.ReadAll(hostClient)
	if err != nil {
		t.Fatalf("io.ReadAll from forwarded TCP port: %v", err)
	}
	if string(tcpResp) != "restored-guest-tcp-ok" {
		t.Fatalf("forwarded TCP response = %q, want %q", string(tcpResp), "restored-guest-tcp-ok")
	}
	if acceptErr := <-acceptedDone; acceptErr != nil {
		t.Fatal(acceptErr)
	}

	// 3. Inbound UDP port forward to the restored guest UDP socket.
	udpEchoDone := make(chan error, 1)
	go func() {
		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
		restored.UDPWQ.EventRegister(&waitEntry)
		defer restored.UDPWQ.EventUnregister(&waitEntry)
		var buf bytes.Buffer
		for {
			res, readErr := restored.UDPEP.Read(&buf, tcpip.ReadOptions{NeedRemoteAddr: true})
			if _, ok := readErr.(*tcpip.ErrWouldBlock); ok {
				<-notifyCh
				continue
			}
			if readErr != nil {
				udpEchoDone <- fmt.Errorf("restored.UDPEP.Read: %s", readErr)
				return
			}
			var r bytes.Reader
			r.Reset(append([]byte("echo:"), buf.Bytes()...))
			_, writeErr := restored.UDPEP.Write(&r, tcpip.WriteOptions{To: &res.RemoteAddr})
			if writeErr != nil {
				udpEchoDone <- fmt.Errorf("restored.UDPEP.Write: %s", writeErr)
				return
			}
			udpEchoDone <- nil
			return
		}
	}()

	udpClient, err := net.DialTimeout("udp", fmt.Sprintf("127.0.0.1:%d", boundAfter[1].HostPort), 3*time.Second)
	if err != nil {
		t.Fatalf("net.DialTimeout to forwarded UDP port: %v", err)
	}
	defer func() {
		_ = udpClient.Close()
	}()
	if _, err := udpClient.Write([]byte("udp-ping")); err != nil {
		t.Fatalf("udpClient.Write: %v", err)
	}
	_ = udpClient.SetReadDeadline(time.Now().Add(3 * time.Second))
	udpBuf := make([]byte, 64)
	n, err := udpClient.Read(udpBuf)
	if err != nil {
		t.Fatalf("udpClient.Read: %v", err)
	}
	if got := string(udpBuf[:n]); got != "echo:udp-ping" {
		t.Fatalf("forwarded UDP response = %q, want %q", got, "echo:udp-ping")
	}
	if err := <-udpEchoDone; err != nil {
		t.Fatal(err)
	}

	// 4. Virtual DNS relay on the restored stack.
	dnsAddr := tcpip.FullAddress{
		NIC:  Eth0NICID,
		Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 3}),
		Port: 53,
	}
	dnsConn, err := gonet.DialUDP(restored.Stack, nil, &dnsAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet.DialUDP to 10.0.2.3:53 on restored stack: %v", err)
	}
	defer func() {
		_ = dnsConn.Close()
	}()
	q := buildDNSQueryPacket(0x55aa, "restored", "nat", "internal")
	if _, err := dnsConn.Write(q); err != nil {
		t.Fatalf("dnsConn.Write: %v", err)
	}
	_ = dnsConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	dnsResp := make([]byte, 512)
	dnsN, err := dnsConn.Read(dnsResp)
	if err != nil {
		t.Fatalf("dnsConn.Read: %v", err)
	}
	if dnsN < 16 || binary.BigEndian.Uint16(dnsResp[0:2]) != 0x55aa || binary.BigEndian.Uint16(dnsResp[6:8]) != 1 {
		t.Fatalf("unexpected DNS response after NAT restore: len=%d", dnsN)
	}
	gotDNSIP := netip.AddrFrom4([4]byte{dnsResp[dnsN-4], dnsResp[dnsN-3], dnsResp[dnsN-2], dnsResp[dnsN-1]})
	if gotDNSIP != netip.MustParseAddr("198.51.100.88") {
		t.Fatalf("resolved DNS IP after NAT restore = %s, want 198.51.100.88", gotDNSIP)
	}
}

func TestWireGuardEndpointAttachRestoredStack(t *testing.T) {
	ctx := testContext(t)
	guestKey, peerKey := newWGKeyPair(t), newWGKeyPair(t)
	peer := newWGPeer(t, wgPeerOptions{
		key:       peerKey,
		remotePub: guestKey.public,
		addrs:     []netip.Prefix{peerPrefixV4},
		remoteIPs: []netip.Prefix{netip.PrefixFrom(guestPrefixV4.Addr(), 32)},
	})

	guestLogs := newLogRecorder()
	guest, err := NewWireGuardEndpoint(WireGuardConfig{
		PrivateKey:    guestKey.private,
		PeerPublicKey: peerKey.public,
		PeerEndpoint:  net.JoinHostPort("127.0.0.1", strconv.Itoa(int(peer.port))),
		GuestIPv4:     guestPrefixV4,
		Logger:        guestLogs.logger(),
		LookupHost: func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "restored.wg.internal" {
				return []netip.Addr{netip.MustParseAddr("198.51.100.99")}, nil
			}
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		},
	})
	if err != nil {
		t.Fatalf("NewWireGuardEndpoint: %v", err)
	}
	t.Cleanup(func() { _ = guest.Close() })
	if err := guest.PreBindUDP(); err != nil {
		t.Fatalf("PreBindUDP: %v", err)
	}
	origUDPAddr := guest.LocalUDPAddr().String()
	origStack, err := guest.Start()
	if err != nil {
		t.Fatalf("guest.Start: %v", err)
	}
	t.Cleanup(func() { origStack.Destroy() })

	const preservedPort = 7100
	var tcpWQ waiter.Queue
	tcpListenEP, tcpErr := origStack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &tcpWQ)
	if tcpErr != nil {
		t.Fatalf("origStack.NewEndpoint(TCP): %s", tcpErr)
	}
	defer tcpListenEP.Close()
	if err := tcpListenEP.Bind(tcpip.FullAddress{
		NIC:  Eth0NICID,
		Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 15}),
		Port: preservedPort,
	}); err != nil {
		t.Fatalf("tcpListenEP.Bind: %s", err)
	}
	if err := tcpListenEP.Listen(16); err != nil {
		t.Fatalf("tcpListenEP.Listen: %s", err)
	}

	orig := savedStackEndpoints{
		Stack:       origStack,
		TCPWQ:       &tcpWQ,
		TCPListenEP: tcpListenEP,
	}

	origStack.Pause()
	var buf bytes.Buffer
	_, saveErr := state.Save(context.Background(), &buf, &orig)
	origStack.Resume()
	if saveErr != nil {
		t.Fatalf("state.Save: %v", saveErr)
	}

	var restored savedStackEndpoints
	if _, err := state.Load(context.Background(), bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	defer func() {
		if restored.TCPListenEP != nil {
			restored.TCPListenEP.Close()
		}
		if restored.Stack != nil {
			restored.Stack.Destroy()
		}
	}()

	if err := guest.AttachRestoredStack(restored.Stack); err != nil {
		t.Fatalf("guest.AttachRestoredStack: %v", err)
	}
	if gotAddr := guest.LocalUDPAddr().String(); gotAddr != origUDPAddr {
		t.Fatalf("guest.LocalUDPAddr() after AttachRestoredStack = %q, want %q", gotAddr, origUDPAddr)
	}

	p := &wgPair{
		guest:      guest,
		guestStack: restored.Stack,
		guestKey:   guestKey,
		guestLogs:  guestLogs,
		peer:       peer,
		peerKey:    peerKey,
	}
	checkTraffic(ctx, t, p, guestPrefixV4.Addr(), peerPrefixV4.Addr())

	// Verify the pre-save listening TCP socket on the restored stack accepts a connection over WireGuard.
	acceptedDone := make(chan error, 1)
	go func() {
		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
		restored.TCPWQ.EventRegister(&waitEntry)
		defer restored.TCPWQ.EventUnregister(&waitEntry)
		for {
			ep, wq, acceptErr := restored.TCPListenEP.Accept(nil)
			if _, ok := acceptErr.(*tcpip.ErrWouldBlock); ok {
				<-notifyCh
				continue
			}
			if acceptErr != nil {
				acceptedDone <- fmt.Errorf("restored.TCPListenEP.Accept: %s", acceptErr)
				return
			}
			conn := gonet.NewTCPConn(wq, ep)
			_, writeErr := conn.Write([]byte("wg-restored-listener-ok"))
			_ = conn.Close()
			acceptedDone <- writeErr
			return
		}
	}()

	peerConn, err := dialTCP(ctx, t, peer.stack, guestPrefixV4.Addr(), preservedPort)
	if err != nil {
		t.Fatalf("peer dialTCP to restored listener on %s:%d: %v", guestPrefixV4.Addr(), preservedPort, err)
	}
	gotBanner, err := io.ReadAll(peerConn)
	if err != nil {
		t.Fatalf("io.ReadAll(peerConn): %v", err)
	}
	if string(gotBanner) != "wg-restored-listener-ok" {
		t.Fatalf("peer received %q from restored listener, want %q", string(gotBanner), "wg-restored-listener-ok")
	}
	if err := <-acceptedDone; err != nil {
		t.Fatal(err)
	}

	// Verify virtual DNS relay (10.0.2.3:53) on the restored WireGuard stack.
	dnsAddr := tcpip.FullAddress{
		NIC:  Eth0NICID,
		Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 3}),
		Port: 53,
	}
	dnsConn, err := gonet.DialUDP(restored.Stack, nil, &dnsAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet.DialUDP to 10.0.2.3:53 on restored WireGuard stack: %v", err)
	}
	defer func() {
		_ = dnsConn.Close()
	}()
	q := buildDNSQueryPacket(0x66bb, "restored", "wg", "internal")
	if _, err := dnsConn.Write(q); err != nil {
		t.Fatalf("dnsConn.Write: %v", err)
	}
	_ = dnsConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	dnsResp := make([]byte, 512)
	dnsN, err := dnsConn.Read(dnsResp)
	if err != nil {
		t.Fatalf("dnsConn.Read: %v", err)
	}
	if dnsN < 16 || binary.BigEndian.Uint16(dnsResp[0:2]) != 0x66bb || binary.BigEndian.Uint16(dnsResp[6:8]) != 1 {
		t.Fatalf("unexpected DNS response after WireGuard restore: len=%d", dnsN)
	}
	gotDNSIP := netip.AddrFrom4([4]byte{dnsResp[dnsN-4], dnsResp[dnsN-3], dnsResp[dnsN-2], dnsResp[dnsN-1]})
	if gotDNSIP != netip.MustParseAddr("198.51.100.99") {
		t.Fatalf("resolved DNS IP after WireGuard restore = %s, want 198.51.100.99", gotDNSIP)
	}
}
