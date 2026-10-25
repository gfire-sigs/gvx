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
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

var (
	guestPrefixV4 = netip.MustParsePrefix("10.0.2.15/24")
	guestPrefixV6 = netip.MustParsePrefix("fd00:2::15/64")
	peerPrefixV4  = netip.MustParsePrefix("10.0.2.1/24")
	peerPrefixV6  = netip.MustParsePrefix("fd00:2::1/64")
)

// wgPair is a guest endpoint connected to an independent wireguard-go peer.
type wgPair struct {
	guest      *WireGuardEndpoint
	guestStack *stack.Stack
	guestKey   wgKeyPair
	guestLogs  *logRecorder
	peer       *wgPeer
	peerKey    wgKeyPair
}

type wgPairOptions struct {
	// withIPv6 adds IPv6 addresses to both sides.
	withIPv6 bool
	// guestPSK and peerPSK set the preshared key of each side.
	guestPSK, peerPSK [32]byte
	// guestWrongPeerKey makes the guest trust a key that the peer does not own.
	guestWrongPeerKey bool
	// peerWrongGuestKey makes the peer trust a key that the guest does not own.
	peerWrongGuestKey bool
	// keepalive is the guest PersistentKeepalive in seconds.
	keepalive int
	// noStart leaves the guest unstarted.
	noStart bool
}

func newWGPair(t *testing.T, o wgPairOptions) *wgPair {
	t.Helper()
	guestKey, peerKey := newWGKeyPair(t), newWGKeyPair(t)
	guestTrusts, peerTrusts := peerKey.public, guestKey.public
	if o.guestWrongPeerKey {
		guestTrusts = newWGKeyPair(t).public
	}
	if o.peerWrongGuestKey {
		peerTrusts = newWGKeyPair(t).public
	}

	peerAddrs := []netip.Prefix{peerPrefixV4}
	guestHosts := []netip.Prefix{netip.PrefixFrom(guestPrefixV4.Addr(), 32)}
	var guestV6 netip.Prefix
	if o.withIPv6 {
		peerAddrs = append(peerAddrs, peerPrefixV6)
		guestHosts = append(guestHosts, netip.PrefixFrom(guestPrefixV6.Addr(), 128))
		guestV6 = guestPrefixV6
	}
	peer := newWGPeer(t, wgPeerOptions{
		key:       peerKey,
		remotePub: peerTrusts,
		psk:       o.peerPSK,
		addrs:     peerAddrs,
		remoteIPs: guestHosts,
	})

	guestLogs := newLogRecorder()
	guest, err := NewWireGuardEndpoint(WireGuardConfig{
		PrivateKey:          guestKey.private,
		PeerPublicKey:       guestTrusts,
		PresharedKey:        o.guestPSK,
		PeerEndpoint:        net.JoinHostPort("127.0.0.1", strconv.Itoa(int(peer.port))),
		GuestIPv4:           guestPrefixV4,
		GuestIPv6:           guestV6,
		PersistentKeepalive: time.Duration(o.keepalive) * time.Second,
		Logger:              guestLogs.logger(),
	})
	if err != nil {
		t.Fatalf("NewWireGuardEndpoint: %v", err)
	}
	t.Cleanup(func() { _ = guest.Close() })
	if err := guest.PreBindUDP(); err != nil {
		t.Fatalf("PreBindUDP: %v", err)
	}
	p := &wgPair{guest: guest, guestKey: guestKey, guestLogs: guestLogs, peer: peer, peerKey: peerKey}
	if !o.noStart {
		p.guestStack, err = guest.Start()
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
	}
	return p
}

// dialTCP opens a TCP connection from s to addr:port and closes it with the test.
func dialTCP(ctx context.Context, t *testing.T, s *stack.Stack, addr netip.Addr, port uint16) (*gonet.TCPConn, error) {
	t.Helper()
	c, err := gonet.DialContextTCP(ctx, s, fullAddr(addr, port), netProto(addr))
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, nil
}

func listenTCP(t *testing.T, s *stack.Stack, addr netip.Addr, port uint16) *gonet.TCPListener {
	t.Helper()
	l, err := gonet.ListenTCP(s, fullAddr(addr, port), netProto(addr))
	if err != nil {
		t.Fatalf("ListenTCP(%s:%d): %v", addr, port, err)
	}
	return l
}

func listenUDP(t *testing.T, s *stack.Stack, addr netip.Addr, port uint16) *gonet.UDPConn {
	t.Helper()
	c, err := gonet.DialUDP(s, &tcpip.FullAddress{Addr: fullAddr(addr, 0).Addr, Port: port}, nil, netProto(addr))
	if err != nil {
		t.Fatalf("listen UDP(%s:%d): %v", addr, port, err)
	}
	return c
}

func dialUDP(t *testing.T, s *stack.Stack, addr netip.Addr, port uint16) *gonet.UDPConn {
	t.Helper()
	fa := fullAddr(addr, port)
	c, err := gonet.DialUDP(s, nil, &fa, netProto(addr))
	if err != nil {
		t.Fatalf("dial UDP(%s:%d): %v", addr, port, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

// checkTraffic proves TCP, UDP, and ICMP echo work in both directions between
// the guest and the peer at the given addresses.
func checkTraffic(ctx context.Context, t *testing.T, p *wgPair, guestAddr, peerAddr netip.Addr) {
	t.Helper()

	// TCP, guest to peer. The first dial also runs the handshake.
	tcpL := listenTCP(t, p.peer.stack, peerAddr, 7000)
	tcpEchoServer(t, tcpL)
	c, err := dialTCP(ctx, t, p.guestStack, peerAddr, 7000)
	if err != nil {
		t.Fatalf("guest TCP dial to peer: %v", err)
	}
	roundTripTCP(t, c, []byte("guest-to-peer-tcp"))
	// A transfer larger than the MTU checks segmentation and ordering through the tunnel.
	big := randomBytes(t, 256*1024)
	roundTripTCP(t, c, big)

	// TCP, peer to guest.
	guestL := listenTCP(t, p.guestStack, guestAddr, 7001)
	tcpEchoServer(t, guestL)
	c2, err := dialTCP(ctx, t, p.peer.stack, guestAddr, 7001)
	if err != nil {
		t.Fatalf("peer TCP dial to guest: %v", err)
	}
	roundTripTCP(t, c2, []byte("peer-to-guest-tcp"))
	sum := sha256.Sum256(big)
	roundTripTCP(t, c2, big)
	if sha256.Sum256(big) != sum {
		t.Fatal("test payload changed during the transfer")
	}

	// UDP, both directions.
	udpPeer := listenUDP(t, p.peer.stack, peerAddr, 7002)
	udpEchoServer(t, udpPeer)
	roundTripUDP(t, dialUDP(t, p.guestStack, peerAddr, 7002), []byte("guest-to-peer-udp"))
	udpGuest := listenUDP(t, p.guestStack, guestAddr, 7003)
	udpEchoServer(t, udpGuest)
	roundTripUDP(t, dialUDP(t, p.peer.stack, guestAddr, 7003), []byte("peer-to-guest-udp"))

	// ICMP echo, both directions. Netstack answers the request on the far side.
	if err := pingEcho(ctx, t, p.guestStack, peerAddr); err != nil {
		t.Fatalf("guest ping to peer: %v", err)
	}
	if err := pingEcho(ctx, t, p.peer.stack, guestAddr); err != nil {
		t.Fatalf("peer ping to guest: %v", err)
	}
}

func TestWireGuardGuestInitiatesHandshakeAndCarriesTraffic(t *testing.T) {
	ctx := testContext(t)
	p := newWGPair(t, wgPairOptions{})

	// The peer has no endpoint for the guest, so only a handshake that the
	// guest starts can connect the two devices.
	if ep := ipcGet(t, p.peer.dev)["endpoint"]; len(ep) != 0 {
		t.Fatalf("peer knows the guest endpoint %v before any packet", ep)
	}
	if got := handshakeTime(t, p.guest.dev); got != "0" {
		t.Fatalf("guest handshake time = %s before traffic, want 0", got)
	}

	checkTraffic(ctx, t, p, guestPrefixV4.Addr(), peerPrefixV4.Addr())

	if got := handshakeTime(t, p.guest.dev); got == "0" {
		t.Fatal("guest reports no completed handshake after traffic")
	}
	// The peer sees the guest at the port of the pre-bound socket. This proves
	// that the pre-bound socket carries the encrypted packets.
	guestPort := p.guest.LocalUDPAddr().(*net.UDPAddr).Port
	want := net.JoinHostPort("127.0.0.1", strconv.Itoa(guestPort))
	if ep := ipcGet(t, p.peer.dev)["endpoint"]; len(ep) != 1 || ep[0] != want {
		t.Fatalf("peer endpoint for the guest = %v, want [%s]", ep, want)
	}
	if got := ipcGet(t, p.guest.dev)["listen_port"]; len(got) != 1 || got[0] != strconv.Itoa(guestPort) {
		t.Fatalf("guest device listen_port = %v, want [%d]", got, guestPort)
	}
}

func TestWireGuardCarriesIPv6Traffic(t *testing.T) {
	ctx := testContext(t)
	p := newWGPair(t, wgPairOptions{withIPv6: true})
	checkTraffic(ctx, t, p, guestPrefixV6.Addr(), peerPrefixV6.Addr())
}

func TestWireGuardPresharedKey(t *testing.T) {
	t.Run("match", func(t *testing.T) {
		ctx := testContext(t)
		psk := newWGPSK(t)
		p := newWGPair(t, wgPairOptions{guestPSK: psk, peerPSK: psk})
		checkTraffic(ctx, t, p, guestPrefixV4.Addr(), peerPrefixV4.Addr())
	})

	for _, tc := range []struct {
		name              string
		guestPSK, peerPSK [32]byte
	}{
		{name: "mismatch", guestPSK: newWGPSKStatic(1), peerPSK: newWGPSKStatic(2)},
		{name: "guest_only", guestPSK: newWGPSKStatic(1)},
		{name: "peer_only", peerPSK: newWGPSKStatic(2)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testContext(t)
			p := newWGPair(t, wgPairOptions{guestPSK: tc.guestPSK, peerPSK: tc.peerPSK})
			l := listenTCP(t, p.peer.stack, peerPrefixV4.Addr(), 7000)
			accepted := make(chan struct{}, 1)
			go func() {
				if c, err := l.Accept(); err == nil {
					accepted <- struct{}{}
					_ = c.Close()
				}
			}()
			t.Cleanup(func() { _ = l.Close() })

			dialCtx, cancel := context.WithCancel(ctx)
			dialErr := make(chan error, 1)
			go func() {
				c, err := gonet.DialContextTCP(dialCtx, p.guestStack, fullAddr(peerPrefixV4.Addr(), 7000), ipv4.ProtocolNumber)
				if err == nil {
					_ = c.Close()
				}
				dialErr <- err
			}()
			// The responder derives a key from the initiation, but the
			// initiator cannot verify the response when the keys differ.
			if err := p.guestLogs.waitFor(ctx, "invalid response message"); err != nil {
				cancel()
				t.Fatal(err)
			}
			cancel()
			if err := <-dialErr; err == nil {
				t.Fatal("guest dial succeeded although the preshared keys differ")
			}
			if got := handshakeTime(t, p.guest.dev); got != "0" {
				t.Fatalf("guest completed a handshake with mismatched preshared keys (time %s)", got)
			}
			select {
			case <-accepted:
				t.Fatal("peer accepted a connection with mismatched preshared keys")
			default:
			}
		})
	}
}

// newWGPSKStatic returns a deterministic non-zero key for table tests.
func newWGPSKStatic(seed byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

func TestWireGuardRejectsWrongPeerKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts wgPairOptions
		// peerLog is the message that the peer logs for the rejected initiation.
		peerLog string
	}{
		{
			name:    "guest_trusts_wrong_key",
			opts:    wgPairOptions{guestWrongPeerKey: true},
			peerLog: "invalid mac1",
		},
		{
			name:    "peer_trusts_wrong_key",
			opts:    wgPairOptions{peerWrongGuestKey: true},
			peerLog: "invalid initiation message",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testContext(t)
			p := newWGPair(t, tc.opts)
			l := listenTCP(t, p.peer.stack, peerPrefixV4.Addr(), 7000)
			accepted := make(chan struct{}, 1)
			go func() {
				if c, err := l.Accept(); err == nil {
					accepted <- struct{}{}
					_ = c.Close()
				}
			}()
			t.Cleanup(func() { _ = l.Close() })

			dialCtx, cancel := context.WithCancel(ctx)
			dialErr := make(chan error, 1)
			go func() {
				c, err := gonet.DialContextTCP(dialCtx, p.guestStack, fullAddr(peerPrefixV4.Addr(), 7000), ipv4.ProtocolNumber)
				if err == nil {
					_ = c.Close()
				}
				dialErr <- err
			}()
			if err := p.peer.logs.waitFor(ctx, tc.peerLog); err != nil {
				cancel()
				t.Fatal(err)
			}
			cancel()
			if err := <-dialErr; err == nil {
				t.Fatal("guest dial succeeded through a tunnel with a wrong key")
			}
			if got := handshakeTime(t, p.guest.dev); got != "0" {
				t.Fatalf("guest completed a handshake with a wrong key (time %s)", got)
			}
			if rx := ipcGet(t, p.guest.dev)["rx_bytes"]; len(rx) != 1 || rx[0] != "0" {
				t.Fatalf("guest received data %v from a peer with a wrong key, want none", rx)
			}
			select {
			case <-accepted:
				t.Fatal("peer accepted a connection with a wrong key")
			default:
			}
		})
	}
}

func TestWireGuardEndpointRoaming(t *testing.T) {
	ctx := testContext(t)
	p := newWGPair(t, wgPairOptions{})
	guestAddr, peerAddr := guestPrefixV4.Addr(), peerPrefixV4.Addr()

	// The peer has no endpoint for the guest, so the guest starts the handshake.
	peerEcho := listenUDP(t, p.peer.stack, peerAddr, 7002)
	udpEchoServer(t, peerEcho)
	roundTripUDP(t, dialUDP(t, p.guestStack, peerAddr, 7002), []byte("handshake"))

	echo := listenUDP(t, p.guestStack, guestAddr, 7003)
	echoSeen := make(chan string, 16)
	udpEchoServerNotify(t, echo, echoSeen)
	roundTripUDP(t, dialUDP(t, p.peer.stack, guestAddr, 7003), []byte("before-roaming"))
	if got := <-echoSeen; got != "before-roaming" {
		t.Fatalf("guest received %q, want before-roaming", got)
	}

	// The peer moves to a new UDP port, as a peer behind a NAT does after a
	// rebind. The guest still points at the old port until it hears from the
	// peer at the new one.
	oldPort := p.peer.port
	if err := p.peer.dev.IpcSet("listen_port=0\n"); err != nil {
		t.Fatalf("peer rebind: %v", err)
	}
	newPort := p.peer.listenPort(t)
	if newPort == oldPort {
		t.Fatalf("peer kept UDP port %d after rebind", oldPort)
	}
	if got := ipcGet(t, p.guest.dev)["endpoint"]; len(got) != 1 || got[0] != net.JoinHostPort("127.0.0.1", strconv.Itoa(int(oldPort))) {
		t.Fatalf("guest endpoint before roaming = %v, want the old peer port %d", got, oldPort)
	}

	// The peer sends first from the new port. wireguard-go moves the endpoint
	// after it delivers a packet, so the guest may answer this first datagram
	// at the old port. The guest receives the second datagram only after the
	// receiver routine updated the endpoint for the first one.
	client := dialUDP(t, p.peer.stack, guestAddr, 7003)
	if err := client.SetDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("roam-1")); err != nil {
		t.Fatal(err)
	}
	if got := <-echoSeen; got != "roam-1" {
		t.Fatalf("guest received %q, want roam-1", got)
	}
	if _, err := client.Write([]byte("roam-2")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	for {
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("no reply from the guest after roaming: %v", err)
		}
		if string(buf[:n]) == "roam-2" {
			break
		}
	}
	want := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(newPort)))
	if got := ipcGet(t, p.guest.dev)["endpoint"]; len(got) != 1 || got[0] != want {
		t.Fatalf("guest endpoint after roaming = %v, want [%s]", got, want)
	}

	// Traffic that the guest starts now follows the new endpoint.
	l := listenTCP(t, p.peer.stack, peerAddr, 7000)
	tcpEchoServer(t, l)
	c, err := dialTCP(ctx, t, p.guestStack, peerAddr, 7000)
	if err != nil {
		t.Fatalf("guest dial after roaming: %v", err)
	}
	roundTripTCP(t, c, []byte("guest-after-roaming"))
}

func TestWireGuardPersistentKeepaliveStartsHandshake(t *testing.T) {
	ctx := testContext(t)
	p := newWGPair(t, wgPairOptions{keepalive: 25})
	// No application packet exists, so only the keepalive can start the handshake.
	if err := p.peer.logs.waitFor(ctx, "Received handshake initiation"); err != nil {
		t.Fatal(err)
	}
	if got := ipcGet(t, p.guest.dev)["persistent_keepalive_interval"]; len(got) != 1 || got[0] != "25" {
		t.Fatalf("guest persistent_keepalive_interval = %v, want [25]", got)
	}
}

func TestWireGuardAllowedIPsLimitOutboundTraffic(t *testing.T) {
	outside := netip.MustParseAddr("192.0.2.1")
	for _, tc := range []struct {
		name      string
		allowed   []netip.Prefix
		wantReach bool
	}{
		{"destination inside AllowedIPs", []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24"), netip.MustParsePrefix("192.0.2.0/24")}, true},
		{"destination outside AllowedIPs", []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testContext(t)
			guestKey, peerKey := newWGKeyPair(t), newWGKeyPair(t)
			peer := newWGPeer(t, wgPeerOptions{
				key:       peerKey,
				remotePub: guestKey.public,
				addrs:     []netip.Prefix{peerPrefixV4, netip.PrefixFrom(outside, 24)},
				remoteIPs: []netip.Prefix{netip.PrefixFrom(guestPrefixV4.Addr(), 32)},
			})
			guest, err := NewWireGuardEndpoint(WireGuardConfig{
				PrivateKey:    guestKey.private,
				PeerPublicKey: peerKey.public,
				PeerEndpoint:  net.JoinHostPort("127.0.0.1", strconv.Itoa(int(peer.port))),
				GuestIPv4:     guestPrefixV4,
				AllowedIPs:    tc.allowed,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = guest.Close() })
			st, err := guest.Start()
			if err != nil {
				t.Fatal(err)
			}

			l := listenTCP(t, peer.stack, outside, 7000)
			tcpEchoServer(t, l)
			dialTimeout := testTimeout
			if !tc.wantReach {
				dialTimeout = time.Second
			}
			dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
			defer cancel()
			c, err := gonet.DialContextTCP(dialCtx, st, fullAddr(outside, 7000), ipv4.ProtocolNumber)
			if tc.wantReach {
				if err != nil {
					t.Fatalf("dial %s inside AllowedIPs: %v", outside, err)
				}
				defer c.Close()
				roundTripTCP(t, c, []byte("allowed"))
				return
			}
			if err == nil {
				_ = c.Close()
				t.Fatalf("dial %s outside AllowedIPs succeeded, want it blocked", outside)
			}
			if tx := ipcGet(t, guest.dev)["tx_bytes"]; len(tx) != 1 || tx[0] != "0" {
				t.Fatalf("guest sent %v bytes to the peer for a destination outside AllowedIPs, want 0", tx)
			}
		})
	}
}

func TestWireGuardSendsNothingBeforeHandshakeCompletes(t *testing.T) {
	ctx := testContext(t)
	// The fake peer is a plain UDP socket. It never answers, so no handshake can finish.
	fake, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()

	guestKey, peerKey := newWGKeyPair(t), newWGKeyPair(t)
	guest, err := NewWireGuardEndpoint(WireGuardConfig{
		PrivateKey:    guestKey.private,
		PeerPublicKey: peerKey.public,
		PeerEndpoint:  fake.LocalAddr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = guest.Close() })
	st, err := guest.Start()
	if err != nil {
		t.Fatal(err)
	}

	// Queue application data. The tunnel must hold it until a handshake completes.
	go func() {
		c, err := gonet.DialContextTCP(ctx, st, fullAddr(netip.MustParseAddr("10.0.2.1"), 80), ipv4.ProtocolNumber)
		if err == nil {
			_ = c.Close()
		}
	}()
	udpc := dialUDP(t, st, netip.MustParseAddr("10.0.2.1"), 9)
	if _, err := udpc.Write([]byte("must-not-leave-in-plaintext")); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2048)
	if err := fake.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatal(err)
	}
	n, from, err := fake.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no first datagram: %v", err)
	}
	wantPort := guest.LocalUDPAddr().(*net.UDPAddr).Port
	if got := from.(*net.UDPAddr).Port; got != wantPort {
		t.Fatalf("first datagram came from port %d, want the pre-bound port %d", got, wantPort)
	}
	const initiationSize = 148
	if n != initiationSize || binary.LittleEndian.Uint32(buf[:4]) != 1 {
		t.Fatalf("first datagram is %d bytes of type %d, want a %d-byte handshake initiation (type 1)", n, binary.LittleEndian.Uint32(buf[:4]), initiationSize)
	}

	// Closing waits for every sender, so the socket now holds all datagrams
	// that the guest ever sent. None may be transport data (type 4).
	if err := guest.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := fake.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	for {
		n, _, err := fake.ReadFrom(buf)
		if err != nil {
			if !isTimeout(err) {
				t.Fatalf("drain: %v", err)
			}
			break
		}
		if typ := binary.LittleEndian.Uint32(buf[:4]); typ == 4 {
			t.Fatalf("guest sent a %d-byte transport datagram before any handshake completed", n)
		}
		if bytes.Contains(buf[:n], []byte("must-not-leave-in-plaintext")) {
			t.Fatal("plaintext payload left the guest")
		}
	}
}

func TestWireGuardEndpointCloseReleasesSocketAndGoroutines(t *testing.T) {
	ctx := testContext(t)
	p := newWGPair(t, wgPairOptions{})
	checkTraffic(ctx, t, p, guestPrefixV4.Addr(), peerPrefixV4.Addr())

	port := p.guest.LocalUDPAddr().(*net.UDPAddr).Port
	// While the endpoint is open, the port is taken.
	if busy, err := net.ListenPacket("udp", ":"+strconv.Itoa(port)); err == nil {
		busy.Close()
		t.Fatalf("port %d is free while the endpoint is open", port)
	}

	p.peer.close()
	if err := p.guest.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := p.guest.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	reuse, err := net.ListenPacket("udp", ":"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("UDP port %d is still bound after Close: %v", port, err)
	}
	reuse.Close()

	if err := waitNoGoroutines(ctx, "golang.zx2c4.com/wireguard/", "(*channelTUN)", "(*preboundBind)"); err != nil {
		t.Fatalf("goroutines remain after Close: %v", err)
	}
}

func TestWireGuardEndpointLifecycle(t *testing.T) {
	guestKey, peerKey := newWGKeyPair(t), newWGKeyPair(t)
	cfg := WireGuardConfig{PrivateKey: guestKey.private, PeerPublicKey: peerKey.public}
	w, err := NewWireGuardEndpoint(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if w.LocalUDPAddr() != nil || w.ChannelEndpoint() != nil {
		t.Fatal("endpoint has a socket or a channel before PreBindUDP and Start")
	}

	// Start without PreBindUDP must open the socket itself.
	s1, err := w.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	s2, err := w.Start()
	if err != nil || s1 != s2 {
		t.Fatalf("second Start = (%p, %v), want the same stack %p", s2, err, s1)
	}
	if err := w.PreBindUDP(); err != nil {
		t.Fatalf("PreBindUDP after Start: %v", err)
	}
	if w.ChannelEndpoint() == nil || w.ChannelEndpoint().MTU() != DefaultWireGuardMTU {
		t.Fatalf("channel endpoint = %v, want MTU %d", w.ChannelEndpoint(), DefaultWireGuardMTU)
	}
	local := w.LocalUDPAddr().(*net.UDPAddr)
	if !local.IP.IsUnspecified() || local.Port == 0 {
		t.Fatalf("pre-bound socket address = %s, want the wildcard address with a port", local)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := w.Start(); err == nil {
		t.Fatal("Start after Close succeeded, want an error")
	}
	if err := w.PreBindUDP(); err == nil {
		t.Fatal("PreBindUDP after Close succeeded, want an error")
	}

	// Close before Start releases an open socket.
	w2, err := NewWireGuardEndpoint(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := w2.PreBindUDP(); err != nil {
		t.Fatal(err)
	}
	port := w2.LocalUDPAddr().(*net.UDPAddr).Port
	if err := w2.Close(); err != nil {
		t.Fatalf("Close before Start: %v", err)
	}
	reuse, err := net.ListenPacket("udp", ":"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("socket still bound after Close before Start: %v", err)
	}
	reuse.Close()
}

func TestWireGuardEndpointUsesRequestedListenAddress(t *testing.T) {
	guestKey, peerKey := newWGKeyPair(t), newWGKeyPair(t)
	w, err := NewWireGuardEndpoint(WireGuardConfig{
		PrivateKey:    guestKey.private,
		PeerPublicKey: peerKey.public,
		ListenUDPAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.PreBindUDP(); err != nil {
		t.Fatal(err)
	}
	if ip := w.LocalUDPAddr().(*net.UDPAddr).IP; !ip.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("socket address = %s, want 127.0.0.1", ip)
	}

	bad, err := NewWireGuardEndpoint(WireGuardConfig{
		PrivateKey:    guestKey.private,
		PeerPublicKey: peerKey.public,
		ListenUDPAddr: "256.0.0.1:0",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	if err := bad.PreBindUDP(); err == nil {
		t.Fatal("PreBindUDP with an invalid listen address succeeded")
	}
}

func TestNewWireGuardEndpointValidatesConfig(t *testing.T) {
	good := newWGKeyPair(t)
	peer := newWGKeyPair(t)
	base := WireGuardConfig{PrivateKey: good.private, PeerPublicKey: peer.public}
	// 1 followed by zeros is a point of small order. X25519 maps it to the zero secret.
	var lowOrder [32]byte
	lowOrder[0] = 1

	tests := []struct {
		name   string
		mutate func(*WireGuardConfig)
	}{
		{"zero private key", func(c *WireGuardConfig) { c.PrivateKey = [32]byte{} }},
		{"zero peer key", func(c *WireGuardConfig) { c.PeerPublicKey = [32]byte{} }},
		{"low order peer key", func(c *WireGuardConfig) { c.PeerPublicKey = lowOrder }},
		{"peer key equals own key", func(c *WireGuardConfig) { c.PeerPublicKey = good.public }},
		{"IPv6 as GuestIPv4", func(c *WireGuardConfig) { c.GuestIPv4 = netip.MustParsePrefix("fd00::1/64") }},
		{"IPv4 as GuestIPv6", func(c *WireGuardConfig) { c.GuestIPv6 = netip.MustParsePrefix("10.0.0.1/24") }},
		{"MTU below minimum", func(c *WireGuardConfig) { c.MTU = 100 }},
		{"MTU below IPv6 minimum", func(c *WireGuardConfig) {
			c.GuestIPv6 = netip.MustParsePrefix("fd00::1/64")
			c.MTU = 1000
		}},
		{"MTU above maximum", func(c *WireGuardConfig) { c.MTU = 1 << 20 }},
		{"invalid allowed prefix", func(c *WireGuardConfig) { c.AllowedIPs = []netip.Prefix{{}} }},
		{"negative keepalive", func(c *WireGuardConfig) { c.PersistentKeepalive = -time.Second }},
		{"fractional keepalive", func(c *WireGuardConfig) { c.PersistentKeepalive = 1500 * time.Millisecond }},
		{"huge keepalive", func(c *WireGuardConfig) { c.PersistentKeepalive = 70000 * time.Second }},
		{"endpoint without port", func(c *WireGuardConfig) { c.PeerEndpoint = "192.0.2.1" }},
		{"endpoint with bad port", func(c *WireGuardConfig) { c.PeerEndpoint = "192.0.2.1:70000" }},
		{"endpoint port zero", func(c *WireGuardConfig) { c.PeerEndpoint = "192.0.2.1:0" }},
		{"endpoint unspecified address", func(c *WireGuardConfig) { c.PeerEndpoint = "0.0.0.0:51820" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mutate(&cfg)
			w, err := NewWireGuardEndpoint(cfg)
			if err == nil {
				_ = w.Close()
				t.Fatal("NewWireGuardEndpoint succeeded, want an error")
			}
			if w != nil {
				t.Fatalf("NewWireGuardEndpoint returned %v with an error", w)
			}
		})
	}

	t.Run("defaults", func(t *testing.T) {
		w, err := NewWireGuardEndpoint(base)
		if err != nil {
			t.Fatal(err)
		}
		if w.cfg.MTU != DefaultWireGuardMTU || w.cfg.GuestIPv4 != netip.MustParsePrefix("10.0.2.15/24") ||
			w.cfg.ListenUDPAddr != ":0" || len(w.cfg.AllowedIPs) != 2 {
			t.Fatalf("defaults = %+v", w.cfg)
		}
	})
	t.Run("does not alias caller allowed prefixes", func(t *testing.T) {
		cfg := base
		cfg.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.1.2.3/8")}
		w, err := NewWireGuardEndpoint(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.AllowedIPs[0] != netip.MustParsePrefix("10.1.2.3/8") {
			t.Fatalf("NewWireGuardEndpoint modified the caller slice: %v", cfg.AllowedIPs)
		}
		if w.cfg.AllowedIPs[0] != netip.MustParsePrefix("10.0.0.0/8") {
			t.Fatalf("allowed prefix = %v, want the masked form 10.0.0.0/8", w.cfg.AllowedIPs[0])
		}
	})
}

func TestResolveWireGuardPeerEndpoint(t *testing.T) {
	var asked []string
	lookup := func(_ context.Context, network, host string) ([]netip.Addr, error) {
		asked = append(asked, network+" "+host)
		switch host {
		case "v4.example":
			return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
		case "mapped.example":
			return []netip.Addr{netip.MustParseAddr("::ffff:192.0.2.11")}, nil
		case "multi.example":
			return []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.12")}, nil
		case "empty.example":
			return nil, nil
		case "unspecified.example":
			return []netip.Addr{netip.IPv4Unspecified()}, nil
		}
		return nil, errors.New("lookup failed")
	}
	good := map[string]string{
		"":                     "invalid AddrPort",
		"192.0.2.1:51820":      "192.0.2.1:51820",
		"[2001:db8::2]:51820":  "[2001:db8::2]:51820",
		"[::ffff:192.0.2.3]:9": "192.0.2.3:9",
		"v4.example:51820":     "192.0.2.10:51820",
		"mapped.example:7":     "192.0.2.11:7",
		"multi.example:51820":  "[2001:db8::1]:51820",
	}
	for in, want := range good {
		got, err := resolveWireGuardPeerEndpoint(t.Context(), in, lookup)
		if err != nil || got.String() != want {
			t.Fatalf("resolve(%q) = (%s, %v), want %s", in, got, err, want)
		}
	}
	for _, in := range []string{"192.0.2.1", "v4.example", "v4.example:0", "v4.example:70000", "v4.example:x", "empty.example:1", "unspecified.example:1", "unknown.example:1", "[::]:1"} {
		if got, err := resolveWireGuardPeerEndpoint(t.Context(), in, lookup); err == nil {
			t.Fatalf("resolve(%q) = %s, want an error", in, got)
		}
	}
	// Literal addresses need no lookup.
	asked = nil
	if _, err := resolveWireGuardPeerEndpoint(t.Context(), "192.0.2.1:1", lookup); err != nil || len(asked) != 0 {
		t.Fatalf("literal endpoint triggered lookups %v (err %v)", asked, err)
	}
}

func TestWireGuardIPCConfig(t *testing.T) {
	cfg := WireGuardConfig{
		PrivateKey:          newWGPSKStatic(1),
		PeerPublicKey:       newWGPSKStatic(2),
		PresharedKey:        newWGPSKStatic(3),
		AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd00::/8")},
		PersistentKeepalive: 25 * time.Second,
	}
	got := wireGuardIPCConfig(cfg, netip.MustParseAddrPort("192.0.2.9:51820"))
	want := fmt.Sprintf("private_key=%x\npublic_key=%x\npreshared_key=%x\nendpoint=192.0.2.9:51820\n"+
		"persistent_keepalive_interval=25\nreplace_allowed_ips=true\nallowed_ip=10.0.0.0/8\nallowed_ip=fd00::/8\n",
		cfg.PrivateKey, cfg.PeerPublicKey, cfg.PresharedKey)
	if got != want {
		t.Fatalf("IPC config:\n%s\nwant:\n%s", got, want)
	}
	cfg.PresharedKey = [32]byte{}
	got = wireGuardIPCConfig(cfg, netip.AddrPort{})
	if bytes.Contains([]byte(got), []byte("preshared_key")) || bytes.Contains([]byte(got), []byte("endpoint")) {
		t.Fatalf("IPC config includes an unset preshared key or endpoint:\n%s", got)
	}
}

func TestParseWireGuardINIDNS(t *testing.T) {
	guestKey, peerKey := newWGKeyPair(t), newWGKeyPair(t)
	ini := fmt.Sprintf(`[Interface]
PrivateKey = %x
Address = 10.0.2.15/24
DNS = 10.0.2.1, [fd00:2::1]:5353, corp.internal

[Peer]
PublicKey = %x
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
`, guestKey.private, peerKey.public)

	cfg, err := ParseWireGuardINI(ini)
	if err != nil {
		t.Fatalf("ParseWireGuardINI: %v", err)
	}
	wantDNS := []string{
		"10.0.2.1:53",
		"[fd00:2::1]:5353",
	}
	if len(cfg.DNSServers) != len(wantDNS) || cfg.DNSServers[0] != wantDNS[0] || cfg.DNSServers[1] != wantDNS[1] {
		t.Fatalf("DNSServers = %v, want %v", cfg.DNSServers, wantDNS)
	}
}

func TestWireGuardVirtualDNSRelayUDPAndTCP(t *testing.T) {
	guestKey, peerKey := newWGKeyPair(t), newWGKeyPair(t)
	w, err := NewWireGuardEndpoint(WireGuardConfig{
		PrivateKey:    guestKey.private,
		PeerPublicKey: peerKey.public,
		LookupHost: func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "wg.internal.corp" {
				return []netip.Addr{netip.MustParseAddr("198.51.100.77")}, nil
			}
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		},
	})
	if err != nil {
		t.Fatalf("NewWireGuardEndpoint: %v", err)
	}
	defer func() {
		_ = w.Close()
	}()
	s, err := w.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	var q []byte
	q = append(q,
		0x43, 0x21,
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	)
	for _, label := range []string{"wg", "internal", "corp"} {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0x00, 0x00, 0x01, 0x00, 0x01)

	dnsAddr := tcpip.FullAddress{
		NIC:  Eth0NICID,
		Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 3}),
		Port: 53,
	}

	uConn, err := gonet.DialUDP(s, nil, &dnsAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet.DialUDP to 10.0.2.3:53: %v", err)
	}
	defer func() {
		_ = uConn.Close()
	}()
	if _, err := uConn.Write(q); err != nil {
		t.Fatalf("uConn.Write: %v", err)
	}
	_ = uConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp := make([]byte, 512)
	n, err := uConn.Read(resp)
	if err != nil {
		t.Fatalf("uConn.Read: %v", err)
	}
	if n < 16 || binary.BigEndian.Uint16(resp[0:2]) != 0x4321 || binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Fatalf("unexpected UDP DNS response: len=%d id=0x%x ancount=%d", n, binary.BigEndian.Uint16(resp[0:2]), binary.BigEndian.Uint16(resp[6:8]))
	}
	gotIP := netip.AddrFrom4([4]byte{resp[n-4], resp[n-3], resp[n-2], resp[n-1]})
	if gotIP != netip.MustParseAddr("198.51.100.77") {
		t.Fatalf("resolved UDP DNS IP = %s, want 198.51.100.77", gotIP)
	}

	tConn, err := gonet.DialTCP(s, dnsAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet.DialTCP to 10.0.2.3:53: %v", err)
	}
	defer func() {
		_ = tConn.Close()
	}()
	tcpFrame := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(tcpFrame[0:2], uint16(len(q)))
	copy(tcpFrame[2:], q)
	if _, err := tConn.Write(tcpFrame); err != nil {
		t.Fatalf("tConn.Write: %v", err)
	}
	_ = tConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var lenHdr [2]byte
	if _, err := tConn.Read(lenHdr[:]); err != nil {
		t.Fatalf("tConn.Read length: %v", err)
	}
	tcpResp := make([]byte, binary.BigEndian.Uint16(lenHdr[:]))
	if _, err := tConn.Read(tcpResp); err != nil {
		t.Fatalf("tConn.Read body: %v", err)
	}
	gotTCPIP := netip.AddrFrom4([4]byte{tcpResp[len(tcpResp)-4], tcpResp[len(tcpResp)-3], tcpResp[len(tcpResp)-2], tcpResp[len(tcpResp)-1]})
	if gotTCPIP != netip.MustParseAddr("198.51.100.77") {
		t.Fatalf("resolved TCP DNS IP = %s, want 198.51.100.77", gotTCPIP)
	}
}
