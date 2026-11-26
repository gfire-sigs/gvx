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
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/link/wgtun"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
	"z.gfire.dev/gvx/pkg/waiter"
)

type wrappedUDPConn struct {
	*net.UDPConn
}

type notifyCloseConn struct {
	net.Conn
	once     sync.Once
	closedCh chan struct{}
}

func (c *notifyCloseConn) Close() error {
	c.once.Do(func() { close(c.closedCh) })
	return c.Conn.Close()
}

// newTCPStreamPair returns a real connected loopback TCP socket pair.
func newTCPStreamPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()
	type acceptRes struct {
		c   net.Conn
		err error
	}
	ch := make(chan acceptRes, 1)
	go func() {
		c, err := ln.Accept()
		ch <- acceptRes{c, err}
	}()
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	res := <-ch
	if res.err != nil {
		_ = c1.Close()
		t.Fatalf("Accept: %v", res.err)
	}
	return c1, res.c
}

// framedPeerStack attaches a standards-compliant gVisor Netstack (with
// stack.CapabilityNone so all L4 checksums are computed and verified on the
// wire) to the peer end of a PacketLink stream.
type framedPeerStack struct {
	st     *stack.Stack
	chEP   *channel.Endpoint
	conn   net.Conn
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newFramedPeerStack(t *testing.T, peerConn net.Conn, mtu uint32, peerIPs ...string) *framedPeerStack {
	t.Helper()
	s, err := newStack(StackOptions{})
	if err != nil {
		t.Fatalf("newStack: %v", err)
	}
	chEP := channel.New(256, mtu, "")
	if err := s.CreateNIC(1, chEP); err != nil {
		s.Close()
		t.Fatalf("CreateNIC: %s", err)
	}
	for _, ip := range peerIPs {
		addr := netip.MustParseAddr(ip)
		pa := tcpip.ProtocolAddress{
			Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFrom4(addr.As4()),
				PrefixLen: 24,
			},
		}
		if err := s.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
			s.Close()
			t.Fatalf("AddProtocolAddress(%s): %s", ip, err)
		}
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
	})

	ctx, cancel := context.WithCancel(context.Background())
	p := &framedPeerStack{
		st:     s,
		chEP:   chEP,
		conn:   peerConn,
		cancel: cancel,
	}
	p.wg.Add(2)
	go func() {
		defer p.wg.Done()
		var hdr [4]byte
		var buf [PacketLinkMaxMTU]byte
		for {
			if _, err := io.ReadFull(peerConn, hdr[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(hdr[:])
			if n == 0 || n > PacketLinkMaxMTU {
				return
			}
			if _, err := io.ReadFull(peerConn, buf[:n]); err != nil {
				return
			}
			proto, err := wgtun.IPPacketProtocol(buf[:n])
			if err != nil {
				continue
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(buf[:n]),
			})
			chEP.InjectInbound(proto, pkt)
			pkt.DecRef()
		}
	}()
	go func() {
		defer p.wg.Done()
		var scratch [PacketLinkMaxMTU]byte
		var frame [4 + PacketLinkMaxMTU]byte
		for {
			pkt := chEP.ReadContext(ctx)
			if pkt == nil {
				return
			}
			n, ok := wgtun.CopyPacket(pkt, scratch[:])
			pkt.DecRef()
			if !ok || n == 0 {
				continue
			}
			binary.BigEndian.PutUint32(frame[:4], uint32(n))
			copy(frame[4:4+n], scratch[:n])
			if err := writeFull(peerConn, frame[:4+n]); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		p.Close()
	})
	return p
}

func (p *framedPeerStack) Close() {
	p.cancel()
	_ = p.conn.SetDeadline(time.Now())
	_ = p.conn.Close()
	p.chEP.Close()
	p.wg.Wait()
	p.st.Close()
}

func startPeerTCPEcho(t *testing.T, st *stack.Stack, ip string, port uint16) {
	t.Helper()
	addr := tcpip.FullAddress{
		Addr: tcpip.AddrFrom4(netip.MustParseAddr(ip).As4()),
		Port: port,
	}
	ln, err := gonet.ListenTCP(st, addr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP(%s:%d): %v", ip, port, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
}

func startPeerUDPEcho(t *testing.T, st *stack.Stack, ip string, port uint16) {
	t.Helper()
	var wq waiter.Queue
	ep, err := st.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint UDP: %s", err)
	}
	addr := tcpip.FullAddress{
		Addr: tcpip.AddrFrom4(netip.MustParseAddr(ip).As4()),
		Port: port,
	}
	if err := ep.Bind(addr); err != nil {
		ep.Close()
		t.Fatalf("Bind UDP(%s:%d): %s", ip, port, err)
	}
	c := gonet.NewUDPConn(&wq, ep)
	t.Cleanup(func() { _ = c.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, raddr, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := c.WriteTo(buf[:n], raddr); err != nil {
				return
			}
		}
	}()
}

func TestPacketLinkTCPUDPAndNICStatsWithStrictChecksums(t *testing.T) {
	guestConn, peerConn := newTCPStreamPair(t)
	st, pl, err := NewPacketLinkStack(PacketLinkConfig{Conn: guestConn})
	if err != nil {
		_ = peerConn.Close()
		t.Fatalf("NewPacketLinkStack: %v", err)
	}
	defer func() {
		if err := pl.Close(); err != nil {
			t.Errorf("PacketLink.Close: %v", err)
		}
	}()

	peer := newFramedPeerStack(t, peerConn, DefaultPacketLinkMTU, "203.0.113.10", HostDNSIPv4)
	startPeerTCPEcho(t, peer.st, "203.0.113.10", 8080)
	startPeerUDPEcho(t, peer.st, HostDNSIPv4, 53)

	// TCP echo proves outbound and inbound L4 checksums are valid without offload.
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()
	tcpConn, err := gonet.DialContextTCP(dialCtx, st, tcpip.FullAddress{
		Addr: tcpip.AddrFrom4([4]byte{203, 0, 113, 10}),
		Port: 8080,
	}, ipv4.ProtocolNumber)
	if err != nil {
		gInfo := st.NICInfo()[Eth0NICID]
		pInfo := peer.st.NICInfo()[1]
		t.Fatalf("DialTCP over PacketLink: %v\nguest eth0 rx=%d tx=%d ip=%+v tcp=%+v\npeer nic1 rx=%d tx=%d ip=%+v tcp=%+v",
			err,
			gInfo.Stats.Rx.Packets.Value(), gInfo.Stats.Tx.Packets.Value(), st.Stats().IP, st.Stats().TCP,
			pInfo.Stats.Rx.Packets.Value(), pInfo.Stats.Tx.Packets.Value(), peer.st.Stats().IP, peer.st.Stats().TCP)
	}
	wantTCP := bytes.Repeat([]byte("packet-link-tcp!"), 200)
	if _, err := tcpConn.Write(wantTCP); err != nil {
		_ = tcpConn.Close()
		t.Fatalf("tcp Write: %v", err)
	}
	gotTCP := make([]byte, len(wantTCP))
	if _, err := io.ReadFull(tcpConn, gotTCP); err != nil {
		_ = tcpConn.Close()
		t.Fatalf("tcp ReadFull: %v", err)
	}
	_ = tcpConn.Close()
	if !bytes.Equal(gotTCP, wantTCP) {
		t.Fatalf("TCP echo mismatch")
	}

	// UDP echo to 10.0.2.3:53 (peer DNS address).
	udpConn, err := gonet.DialUDP(st, nil, &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 3}),
		Port: 53,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialUDP over PacketLink: %v", err)
	}
	defer udpConn.Close()
	wantUDP := []byte("dns-query-payload")
	if _, err := udpConn.Write(wantUDP); err != nil {
		t.Fatalf("udp Write: %v", err)
	}
	gotUDP := make([]byte, 128)
	n, err := udpConn.Read(gotUDP)
	if err != nil {
		t.Fatalf("udp Read: %v", err)
	}
	if !bytes.Equal(gotUDP[:n], wantUDP) {
		t.Fatalf("UDP echo = %q, want %q", gotUDP[:n], wantUDP)
	}

	// Verify /proc/net/dev NICStats reflect RX and TX traffic on eth0.
	info, ok := st.NICInfo()[Eth0NICID]
	if !ok {
		t.Fatal("eth0 missing from NICInfo")
	}
	if info.Stats.Rx.Packets.Value() == 0 || info.Stats.Tx.Packets.Value() == 0 ||
		info.Stats.Rx.Bytes.Value() == 0 || info.Stats.Tx.Bytes.Value() == 0 {
		t.Errorf("eth0 stats = rx(%d pkts, %d B) tx(%d pkts, %d B), want all > 0",
			info.Stats.Rx.Packets.Value(), info.Stats.Rx.Bytes.Value(),
			info.Stats.Tx.Packets.Value(), info.Stats.Tx.Bytes.Value())
	}
	if got := pl.GuestResolvConf(); got != "nameserver "+HostDNSIPv4+"\n" {
		t.Errorf("GuestResolvConf() = %q, want nameserver %s", got, HostDNSIPv4)
	}
}

func TestPacketLinkValidationAndConnCleanup(t *testing.T) {
	t.Run("nil conn", func(t *testing.T) {
		_, _, err := NewPacketLinkStack(PacketLinkConfig{})
		if !errors.Is(err, ErrInvalidPacketLinkConfig) {
			t.Fatalf("err = %v, want ErrInvalidPacketLinkConfig", err)
		}
	})

	t.Run("UDPConn rejected and closed", func(t *testing.T) {
		u1, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer u1.Close()
		u2, err := net.DialUDP("udp4", nil, u1.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = NewPacketLinkStack(PacketLinkConfig{Conn: u2})
		if !errors.Is(err, ErrInvalidPacketLinkConfig) {
			t.Fatalf("err = %v, want ErrInvalidPacketLinkConfig", err)
		}
		// Verify u2 was closed by NewPacketLinkStack.
		if _, werr := u2.Write([]byte("x")); !errors.Is(werr, net.ErrClosed) {
			t.Errorf("u2.Write after rejected NewPacketLinkStack = %v, want net.ErrClosed", werr)
		}
	})

	t.Run("wrapped UDPConn rejected via SO_TYPE syscall.Conn and closed", func(t *testing.T) {
		u1, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer u1.Close()
		u2, err := net.DialUDP("udp4", nil, u1.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = NewPacketLinkStack(PacketLinkConfig{Conn: &wrappedUDPConn{UDPConn: u2}})
		if !errors.Is(err, ErrInvalidPacketLinkConfig) {
			t.Fatalf("err = %v, want ErrInvalidPacketLinkConfig", err)
		}
		if _, werr := u2.Write([]byte("x")); !errors.Is(werr, net.ErrClosed) {
			t.Errorf("wrapped u2.Write after rejected NewPacketLinkStack = %v, want net.ErrClosed", werr)
		}
	})

	t.Run("invalid MTU and IP configs close Conn", func(t *testing.T) {
		badConfigs := []struct {
			name string
			cfg  PacketLinkConfig
		}{
			{"MTU too small", PacketLinkConfig{MTU: PacketLinkMinMTU - 1}},
			{"MTU too large", PacketLinkConfig{MTU: PacketLinkMaxMTU + 1}},
			{"IPv6 GuestIPv4", PacketLinkConfig{GuestIPv4: netip.MustParsePrefix("fd00::1/64")}},
			{"Gateway equals guest", PacketLinkConfig{
				GuestIPv4:   netip.MustParsePrefix("10.0.2.1/24"),
				GatewayIPv4: netip.MustParseAddr("10.0.2.1"),
			}},
			{"Invalid DNS server", PacketLinkConfig{DNSServers: []netip.Addr{{}}}},
		}
		for _, tc := range badConfigs {
			t.Run(tc.name, func(t *testing.T) {
				c1, c2 := net.Pipe()
				defer c2.Close()
				cfg := tc.cfg
				cfg.Conn = c1
				_, _, err := NewPacketLinkStack(cfg)
				if !errors.Is(err, ErrInvalidPacketLinkConfig) {
					t.Fatalf("err = %v, want ErrInvalidPacketLinkConfig", err)
				}
				if _, werr := c1.Write([]byte("x")); !errors.Is(werr, io.ErrClosedPipe) {
					t.Errorf("Conn not closed on error: write err = %v", werr)
				}
			})
		}
	})

	t.Run("point-to-point /32 and /31 install on-link default route", func(t *testing.T) {
		for _, pfx := range []string{"10.99.0.1/32", "10.99.0.0/31"} {
			c1, c2 := net.Pipe()
			defer c2.Close()
			st, pl, err := NewPacketLinkStack(PacketLinkConfig{
				Conn:       c1,
				GuestIPv4:  netip.MustParsePrefix(pfx),
				DNSServers: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")},
			})
			if err != nil {
				t.Fatalf("prefix %s: %v", pfx, err)
			}
			if got := pl.GuestResolvConf(); got != "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" {
				t.Errorf("GuestResolvConf = %q", got)
			}
			foundDefault := false
			for _, r := range st.GetRouteTable() {
				if r.NIC == Eth0NICID && r.Destination == header.IPv4EmptySubnet {
					foundDefault = true
					if r.Gateway.Len() != 0 {
						t.Errorf("prefix %s: default route gateway = %s, want on-link", pfx, r.Gateway)
					}
				}
			}
			if !foundDefault {
				t.Errorf("prefix %s: missing default route on eth0", pfx)
			}
			_ = pl.Close()
		}
	})
}

func TestPacketLinkFramingSafetyAndLoopbackSurvivesPeerDeath(t *testing.T) {
	verifyLoopbackAlive := func(t *testing.T, st *stack.Stack) {
		t.Helper()
		ln, err := gonet.ListenTCP(st, tcpip.FullAddress{
			Addr: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
			Port: 19999,
		}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("loopback ListenTCP after peer death: %v", err)
		}
		defer ln.Close()
		done := make(chan error, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				done <- err
				return
			}
			defer c.Close()
			_, err = c.Write([]byte("lo-ok"))
			done <- err
		}()
		c, err := gonet.DialTCP(st, tcpip.FullAddress{
			Addr: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
			Port: 19999,
		}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("loopback DialTCP after peer death: %v", err)
		}
		defer c.Close()
		buf := make([]byte, 5)
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "lo-ok" {
			t.Fatalf("loopback read = %q, %v; want lo-ok", buf, err)
		}
		if err := <-done; err != nil {
			t.Fatalf("loopback server: %v", err)
		}
	}

	for name, badHeader := range map[string][]byte{
		"zero-length frame": {0, 0, 0, 0},
		"oversized frame":   {0x00, 0x01, 0x00, 0x00}, // 65536 > 65535
		"max uint32 frame":  {0xff, 0xff, 0xff, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			guestConn, peerConn := net.Pipe()
			defer peerConn.Close()
			st, pl, err := NewPacketLinkStack(PacketLinkConfig{Conn: guestConn})
			if err != nil {
				t.Fatalf("NewPacketLinkStack: %v", err)
			}
			defer pl.Close()

			// Keep peerConn open so the close must come from PacketLink rejecting
			// the invalid length prefix, not from peer EOF.
			if err := peerConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatalf("SetDeadline: %v", err)
			}
			if _, err := peerConn.Write(badHeader); err != nil {
				t.Fatalf("Write badHeader: %v", err)
			}
			var one [1]byte
			if _, err := peerConn.Read(one[:]); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("peerConn.Read after %s = %v, want EOF or ErrClosedPipe", name, err)
			}
			verifyLoopbackAlive(t, st)
		})
	}

	for name, partial := range map[string][]byte{
		"truncated header":  {0x00, 0x00},
		"truncated payload": {0x00, 0x00, 0x00, 0x20, 0x45, 0x00},
	} {
		t.Run(name, func(t *testing.T) {
			rawGuest, peerConn := net.Pipe()
			closedCh := make(chan struct{})
			guestConn := &notifyCloseConn{Conn: rawGuest, closedCh: closedCh}
			st, pl, err := NewPacketLinkStack(PacketLinkConfig{Conn: guestConn})
			if err != nil {
				_ = peerConn.Close()
				t.Fatalf("NewPacketLinkStack: %v", err)
			}
			defer pl.Close()

			if err := peerConn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatalf("SetWriteDeadline: %v", err)
			}
			if _, err := peerConn.Write(partial); err != nil {
				t.Fatalf("Write partial: %v", err)
			}
			_ = peerConn.Close()

			select {
			case <-closedCh:
			case <-time.After(2 * time.Second):
				t.Fatalf("PacketLink did not close guestConn after %s", name)
			}
			verifyLoopbackAlive(t, st)
		})
	}

	t.Run("unknown IP version and runt frames dropped without closing link", func(t *testing.T) {
		guestConn, peerConn := newTCPStreamPair(t)
		st, pl, err := NewPacketLinkStack(PacketLinkConfig{Conn: guestConn})
		if err != nil {
			_ = peerConn.Close()
			t.Fatalf("NewPacketLinkStack: %v", err)
		}
		defer pl.Close()

		// Send an unknown IP version (version 3) and a runt IPv4 packet before
		// attaching the real framed peer stack.
		writeFrame := func(payload []byte) {
			var hdr [4]byte
			binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
			if err := writeFull(peerConn, append(hdr[:], payload...)); err != nil {
				t.Fatalf("writeFrame: %v", err)
			}
		}
		writeFrame([]byte{0x35, 0x00, 0x00, 0x04})
		writeFrame([]byte{0x45, 0x00, 0x00, 0x04})

		peer := newFramedPeerStack(t, peerConn, DefaultPacketLinkMTU, HostDNSIPv4)
		startPeerUDPEcho(t, peer.st, HostDNSIPv4, 53)
		udpConn, err := gonet.DialUDP(st, nil, &tcpip.FullAddress{
			Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 3}),
			Port: 53,
		}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("DialUDP: %v", err)
		}
		defer udpConn.Close()
		if _, err := udpConn.Write([]byte("still-alive")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		buf := make([]byte, 32)
		n, err := udpConn.Read(buf)
		if err != nil || string(buf[:n]) != "still-alive" {
			t.Fatalf("UDP after dropped bad frames = %q, %v; want still-alive", buf[:n], err)
		}
	})
}

func TestPacketLinkQuiesceForSaveStalledPeerAndCheckpointRestore(t *testing.T) {
	t.Run("QuiesceForSave does not deadlock when peer stops reading", func(t *testing.T) {
		guestConn, peerConn := net.Pipe()
		defer peerConn.Close()
		tuned, err := tuning.Values{}.WithInt(tuning.LinkQueueLength, 16)
		if err != nil {
			t.Fatal(err)
		}
		st, pl, err := NewPacketLinkStack(PacketLinkConfig{
			Conn:   guestConn,
			Tuning: tuned,
		})
		if err != nil {
			t.Fatalf("NewPacketLinkStack: %v", err)
		}
		defer pl.Close()

		// Flood UDP packets while nobody reads peerConn so writeLoop blocks in
		// conn.Write and txCh fills completely.
		udpConn, err := gonet.DialUDP(st, nil, &tcpip.FullAddress{
			Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 3}),
			Port: 53,
		}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("DialUDP: %v", err)
		}
		defer udpConn.Close()
		for range 40 {
			_, _ = udpConn.Write([]byte("flood"))
		}

		// QuiesceForSave must return promptly and be idempotent.
		done := make(chan struct{})
		go func() {
			pl.QuiesceForSave()
			pl.QuiesceForSave()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("QuiesceForSave deadlocked with stalled peer")
		}
		if err := pl.ResumeAfterSave(); err != nil {
			t.Fatalf("ResumeAfterSave: %v", err)
		}
		if err := pl.ResumeAfterSave(); err != nil {
			t.Fatalf("second ResumeAfterSave: %v", err)
		}
	})

	t.Run("Quiesce stops traffic, state.Save succeeds, and Restore preserves Eth0Config", func(t *testing.T) {
		guestConn1, peerConn1 := newTCPStreamPair(t)
		st1, pl1, err := NewPacketLinkStack(PacketLinkConfig{
			Conn: guestConn1,
			MTU:  4000,
		})
		if err != nil {
			_ = peerConn1.Close()
			t.Fatalf("NewPacketLinkStack: %v", err)
		}
		peer1 := newFramedPeerStack(t, peerConn1, 4000, HostDNSIPv4)
		startPeerUDPEcho(t, peer1.st, HostDNSIPv4, 53)

		// Verify traffic works before quiesce.
		u1, err := gonet.DialUDP(st1, nil, &tcpip.FullAddress{
			Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 3}),
			Port: 53,
		}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("DialUDP: %v", err)
		}
		if _, err := u1.Write([]byte("before")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 32)
		if n, err := u1.Read(buf); err != nil || string(buf[:n]) != "before" {
			t.Fatalf("pre-quiesce UDP = %q, %v", buf[:n], err)
		}

		// Mutate eth0 MTU at runtime to verify SnapshotEth0Config + Restore preserve it.
		if err := st1.SetNICMTU(Eth0NICID, 9000); err != nil {
			t.Fatalf("SetNICMTU(9000): %s", err)
		}

		// Quiesce, snapshot eth0, and serialize stack with real state.Save (tests
		// channel.queue.saveC() under quiesce with zero deadlock or refcount race).
		pl1.QuiesceForSave()
		eth0Cfg, ok := SnapshotEth0Config(st1)
		if !ok || eth0Cfg.MTU != 9000 {
			t.Fatalf("SnapshotEth0Config = %+v (ok=%v), want MTU 9000", eth0Cfg, ok)
		}

		var saved bytes.Buffer
		if _, err := state.Save(context.Background(), &saved, st1); err != nil {
			t.Fatalf("state.Save: %v", err)
		}
		_ = u1.Close()
		_ = pl1.Close()
		peer1.Close()

		// Restore onto a brand-new PacketLink + LinkConn (with default LinkMTU=0
		// to verify saved MTU=9000 is restored from Eth0Config!).
		var restored stack.Stack
		if _, err := state.Load(context.Background(), bytes.NewReader(saved.Bytes()), &restored); err != nil {
			t.Fatalf("state.Load: %v", err)
		}
		guestConn2, peerConn2 := newTCPStreamPair(t)
		pl2, err := NewPacketLinkForRestore(PacketLinkConfig{Conn: guestConn2})
		if err != nil {
			_ = peerConn2.Close()
			t.Fatalf("NewPacketLinkForRestore: %v", err)
		}
		defer pl2.Close()

		if err := pl2.AttachRestoredStackWithConfig(&restored, &eth0Cfg); err != nil {
			t.Fatalf("AttachRestoredStackWithConfig: %v", err)
		}
		if got := restored.NICInfo()[Eth0NICID].MTU; got != 9000 {
			t.Errorf("restored eth0 MTU = %d, want 9000", got)
		}

		peer2 := newFramedPeerStack(t, peerConn2, 9000, HostDNSIPv4)
		startPeerUDPEcho(t, peer2.st, HostDNSIPv4, 53)
		u2, err := gonet.DialUDP(&restored, nil, &tcpip.FullAddress{
			Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 3}),
			Port: 53,
		}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("restored DialUDP: %v", err)
		}
		defer u2.Close()
		if _, err := u2.Write([]byte("after-restore")); err != nil {
			t.Fatalf("restored Write: %v", err)
		}
		if n, err := u2.Read(buf); err != nil || string(buf[:n]) != "after-restore" {
			t.Fatalf("post-restore UDP = %q, %v; want after-restore", buf[:n], err)
		}
	})

	t.Run("peer disconnect racing with QuiesceForSave and state.Save is race-free", func(t *testing.T) {
		for iter := range 16 {
			guestConn, peerConn := newTCPStreamPair(t)
			st, pl, err := NewPacketLinkStack(PacketLinkConfig{Conn: guestConn})
			if err != nil {
				_ = peerConn.Close()
				t.Fatalf("iter %d NewPacketLinkStack: %v", iter, err)
			}
			u, err := gonet.DialUDP(st, nil, &tcpip.FullAddress{
				Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 3}),
				Port: 53,
			}, ipv4.ProtocolNumber)
			if err != nil {
				_ = peerConn.Close()
				_ = pl.Close()
				t.Fatalf("iter %d DialUDP: %v", iter, err)
			}
			for range 4 {
				_, _ = u.Write([]byte("queued-pkt"))
			}

			var closeWG sync.WaitGroup
			closeWG.Add(1)
			go func(yields int) {
				defer closeWG.Done()
				for range yields {
					runtime.Gosched()
				}
				_ = peerConn.Close()
			}(iter % 4)

			pl.QuiesceForSave()
			var saved bytes.Buffer
			if _, err := state.Save(context.Background(), &saved, st); err != nil {
				closeWG.Wait()
				_ = u.Close()
				_ = pl.Close()
				t.Fatalf("iter %d state.Save: %v", iter, err)
			}
			if iter%2 == 0 {
				if err := pl.ResumeAfterSave(); err != nil {
					closeWG.Wait()
					_ = u.Close()
					_ = pl.Close()
					t.Fatalf("iter %d ResumeAfterSave: %v", iter, err)
				}
			}
			closeWG.Wait()
			_ = u.Close()
			if err := pl.Close(); err != nil {
				t.Fatalf("iter %d Close: %v", iter, err)
			}
		}
	})
}

func TestPacketLinkEnforcesNetlinkMTURange(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	st, pl, err := NewPacketLinkStack(PacketLinkConfig{Conn: c1})
	if err != nil {
		t.Fatalf("NewPacketLinkStack: %v", err)
	}
	defer pl.Close()

	if err := st.SetNICMTU(Eth0NICID, PacketLinkMinMTU-1); err == nil {
		t.Error("SetNICMTU below PacketLinkMinMTU succeeded, want error")
	}
	if err := st.SetNICMTU(Eth0NICID, PacketLinkMaxMTU+1); err == nil {
		t.Error("SetNICMTU above PacketLinkMaxMTU succeeded, want error")
	}
	if err := st.SetNICMTU(Eth0NICID, 9000); err != nil {
		t.Errorf("SetNICMTU(9000) failed: %s", err)
	}
	if got := st.NICInfo()[Eth0NICID].MTU; got != 9000 {
		t.Errorf("MTU = %d, want 9000", got)
	}

	var closedCount atomic.Int32
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := pl.Close(); err != nil {
				t.Errorf("concurrent Close: %v", err)
			}
			closedCount.Add(1)
		}()
	}
	wg.Wait()
	if closedCount.Load() != 4 {
		t.Errorf("closedCount = %d, want 4", closedCount.Load())
	}
}
