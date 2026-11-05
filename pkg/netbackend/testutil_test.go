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
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/checksum"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/icmp"
	"z.gfire.dev/gvx/pkg/tcpip/transport/tcp"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
	"z.gfire.dev/gvx/pkg/waiter"
)

// testTimeout bounds every blocking wait in the tests. A passing test never waits this long.
const testTimeout = 20 * time.Second

// testContext returns a context that ends after testTimeout or when the test ends.
func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}

// wgKeyPair is an X25519 key pair in the byte form that WireGuardConfig uses.
type wgKeyPair struct {
	private [32]byte
	public  [32]byte
}

func newWGKeyPair(t *testing.T) wgKeyPair {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519 key: %v", err)
	}
	var kp wgKeyPair
	copy(kp.private[:], priv.Bytes())
	copy(kp.public[:], priv.PublicKey().Bytes())
	return kp
}

func newWGPSK(t *testing.T) [32]byte {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatalf("generate preshared key: %v", err)
	}
	return k
}

// logRecorder is a slog.Handler that stores every message and lets a test
// wait for a message without polling.
type logRecorder struct {
	mu       sync.Mutex
	messages []string
	changed  chan struct{}
}

func newLogRecorder() *logRecorder {
	return &logRecorder{changed: make(chan struct{})}
}

func (r *logRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *logRecorder) WithAttrs([]slog.Attr) slog.Handler       { return r }
func (r *logRecorder) WithGroup(string) slog.Handler            { return r }

func (r *logRecorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.messages = append(r.messages, rec.Message)
	close(r.changed)
	r.changed = make(chan struct{})
	return nil
}

func (r *logRecorder) logger() *slog.Logger { return slog.New(r) }

// waitFor blocks until a recorded message contains substr or ctx ends.
func (r *logRecorder) waitFor(ctx context.Context, substr string) error {
	for {
		r.mu.Lock()
		for _, m := range r.messages {
			if strings.Contains(m, substr) {
				r.mu.Unlock()
				return nil
			}
		}
		changed := r.changed
		r.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return fmt.Errorf("no log message contains %q: %w", substr, ctx.Err())
		}
	}
}

// has reports whether a recorded message contains substr.
func (r *logRecorder) has(substr string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.messages {
		if strings.Contains(m, substr) {
			return true
		}
	}
	return false
}

// newTestStack builds a Netstack with one channel NIC, the given addresses,
// and a default route on the NIC.
func newTestStack(t *testing.T, mtu uint32, addrs ...netip.Prefix) (*stack.Stack, *channel.Endpoint) {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	ep := channel.New(tuning.Values{}.Int(tuning.WGQueueLength), mtu, "")
	const nic tcpip.NICID = 1
	if err := s.CreateNIC(nic, ep); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	for _, a := range addrs {
		pa := tcpip.ProtocolAddress{AddressWithPrefix: tcpip.AddressWithPrefix{PrefixLen: a.Bits()}}
		if a.Addr().Is4() {
			pa.Protocol = ipv4.ProtocolNumber
			pa.AddressWithPrefix.Address = tcpip.AddrFrom4(a.Addr().As4())
		} else {
			pa.Protocol = ipv6.ProtocolNumber
			pa.AddressWithPrefix.Address = tcpip.AddrFrom16(a.Addr().As16())
		}
		if err := s.AddProtocolAddress(nic, pa, stack.AddressProperties{}); err != nil {
			t.Fatalf("AddProtocolAddress(%s): %v", a, err)
		}
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nic},
		{Destination: header.IPv6EmptySubnet, NIC: nic},
	})
	t.Cleanup(func() {
		s.Close()
		ep.Close()
	})
	return s, ep
}

func fullAddr(addr netip.Addr, port uint16) tcpip.FullAddress {
	if addr.Is4() {
		return tcpip.FullAddress{Addr: tcpip.AddrFrom4(addr.As4()), Port: port}
	}
	return tcpip.FullAddress{Addr: tcpip.AddrFrom16(addr.As16()), Port: port}
}

func netProto(addr netip.Addr) tcpip.NetworkProtocolNumber {
	if addr.Is4() {
		return ipv4.ProtocolNumber
	}
	return ipv6.ProtocolNumber
}

// wgPeer is an independent wireguard-go device with its own Netstack. It uses
// conn.NewStdNetBind, not the Bind under test, so the guest side is tested
// against a separate implementation.
type wgPeer struct {
	dev    *device.Device
	stack  *stack.Stack
	port   uint16
	logs   *logRecorder
	closed sync.Once
}

type wgPeerOptions struct {
	key        wgKeyPair
	remotePub  [32]byte
	psk        [32]byte
	addrs      []netip.Prefix
	remoteIPs  []netip.Prefix
	endpoint   string
	keepalive  int
	listenPort uint16
}

func newWGPeer(t *testing.T, o wgPeerOptions) *wgPeer {
	t.Helper()
	s, ep := newTestStack(t, DefaultWireGuardMTU, o.addrs...)
	logs := newLogRecorder()
	dev := device.NewDevice(newChannelTUN(ep), conn.NewStdNetBind(), newWireGuardLogger(logs.logger()))
	var cfg strings.Builder
	fmt.Fprintf(&cfg, "private_key=%x\nlisten_port=%d\npublic_key=%x\n", o.key.private, o.listenPort, o.remotePub)
	if o.psk != [32]byte{} {
		fmt.Fprintf(&cfg, "preshared_key=%x\n", o.psk)
	}
	if o.endpoint != "" {
		fmt.Fprintf(&cfg, "endpoint=%s\n", o.endpoint)
	}
	fmt.Fprintf(&cfg, "persistent_keepalive_interval=%d\nreplace_allowed_ips=true\n", o.keepalive)
	for _, p := range o.remoteIPs {
		fmt.Fprintf(&cfg, "allowed_ip=%s\n", p)
	}
	if err := dev.IpcSet(cfg.String()); err != nil {
		dev.Close()
		t.Fatalf("peer IpcSet: %v", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		t.Fatalf("peer Up: %v", err)
	}
	p := &wgPeer{dev: dev, stack: s, logs: logs}
	p.port = p.listenPort(t)
	t.Cleanup(p.close)
	return p
}

func (p *wgPeer) close() { p.closed.Do(p.dev.Close) }

// ipc returns the device state as key to values.
func ipcGet(t *testing.T, dev *device.Device) map[string][]string {
	t.Helper()
	text, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	out := map[string][]string{}
	for _, line := range strings.Split(text, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			out[k] = append(out[k], v)
		}
	}
	return out
}

func (p *wgPeer) listenPort(t *testing.T) uint16 {
	t.Helper()
	v := ipcGet(t, p.dev)["listen_port"]
	if len(v) != 1 {
		t.Fatalf("peer has no listen_port: %v", v)
	}
	var port uint16
	if _, err := fmt.Sscanf(v[0], "%d", &port); err != nil {
		t.Fatalf("parse listen_port %q: %v", v[0], err)
	}
	return port
}

// handshakeTime returns the last handshake time of the only peer in dev, in seconds since the epoch.
func handshakeTime(t *testing.T, dev *device.Device) string {
	t.Helper()
	v := ipcGet(t, dev)["last_handshake_time_sec"]
	if len(v) != 1 {
		t.Fatalf("device has %d peers, want 1", len(v))
	}
	return v[0]
}

// tcpEchoServer accepts connections on l and echoes every byte. Cleanup closes
// the listener and every accepted connection, so a connection whose peer
// cannot send a FIN does not block the test.
func tcpEchoServer(t *testing.T, l net.Listener) {
	t.Helper()
	var (
		mu    sync.Mutex
		conns []net.Conn
		wg    sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
}

// udpEchoServer echoes each datagram of c to its sender until c closes.
func udpEchoServer(t *testing.T, c net.PacketConn) {
	t.Helper()
	udpEchoServerNotify(t, c, nil)
}

// udpEchoServerNotify echoes each datagram of c to its sender until c closes.
// When seen is not nil, it receives the payload of each datagram before the echo.
func udpEchoServerNotify(t *testing.T, c net.PacketConn, seen chan<- string) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			if seen != nil {
				seen <- string(buf[:n])
			}
			if _, err := c.WriteTo(buf[:n], from); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = c.Close()
		<-done
	})
}

// roundTripTCP sends payload over c and expects the same bytes back.
func roundTripTCP(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	errc := make(chan error, 1)
	go func() {
		_, err := c.Write(payload)
		errc <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echoed payload differs from the sent payload (%d bytes)", len(payload))
	}
}

// roundTripUDP sends one datagram over c and expects the same bytes back.
func roundTripUDP(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	if err := c.SetDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write datagram: %v", err)
	}
	buf := make([]byte, len(payload)+16)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("echoed datagram = %q, want %q", buf[:n], payload)
	}
}

// pingEcho sends one ICMP echo request through s and waits for the matching reply.
func pingEcho(ctx context.Context, t *testing.T, s *stack.Stack, dst netip.Addr) error {
	t.Helper()
	transProto := icmp.ProtocolNumber4
	reqType := byte(header.ICMPv4Echo)
	replyType := byte(header.ICMPv4EchoReply)
	if dst.Is6() {
		transProto = icmp.ProtocolNumber6
		reqType = byte(header.ICMPv6EchoRequest)
		replyType = byte(header.ICMPv6EchoReply)
	}
	var wq waiter.Queue
	ep, err := s.NewEndpoint(transProto, netProto(dst), &wq)
	if err != nil {
		return fmt.Errorf("new ICMP endpoint: %s", err)
	}
	defer ep.Close()
	entry, ready := waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&entry)
	defer wq.EventUnregister(&entry)

	payload := []byte("gvx-echo-payload")
	msg := make([]byte, 8+len(payload))
	msg[0] = reqType
	binaryBigEndianPut16(msg[6:8], 1)
	copy(msg[8:], payload)
	if dst.Is4() {
		binaryBigEndianPut16(msg[2:4], ^checksum.Checksum(msg, 0))
	}
	to := fullAddr(dst, 0)
	if _, werr := ep.Write(bytes.NewReader(msg), tcpip.WriteOptions{To: &to}); werr != nil {
		return fmt.Errorf("write echo request: %s", werr)
	}
	for {
		var out bytes.Buffer
		res, rerr := ep.Read(&out, tcpip.ReadOptions{})
		if _, wouldBlock := rerr.(*tcpip.ErrWouldBlock); wouldBlock {
			select {
			case <-ready:
				continue
			case <-ctx.Done():
				return fmt.Errorf("wait for echo reply: %w", ctx.Err())
			}
		}
		if rerr != nil {
			return fmt.Errorf("read echo reply: %s", rerr)
		}
		got := out.Bytes()
		if res.Count < 8 || got[0] != replyType || !bytes.Equal(got[8:], payload) {
			return fmt.Errorf("unexpected ICMP reply %x", got)
		}
		return nil
	}
}

func binaryBigEndianPut16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

// goroutinesMatching returns the stacks of live goroutines that contain any of substrs.
func goroutinesMatching(substrs ...string) []string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	var out []string
	for _, g := range strings.Split(string(buf), "\n\n") {
		for _, s := range substrs {
			if strings.Contains(g, s) {
				out = append(out, g)
				break
			}
		}
	}
	return out
}

// waitNoGoroutines waits until no goroutine stack contains any of substrs.
// wireguard-go stops some workers after a queue closes, so the check polls.
func waitNoGoroutines(ctx context.Context, substrs ...string) error {
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		left := goroutinesMatching(substrs...)
		if len(left) == 0 {
			return nil
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			return fmt.Errorf("%d goroutines remain, first:\n%s", len(left), left[0])
		}
	}
}
