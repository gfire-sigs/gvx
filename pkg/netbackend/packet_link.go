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
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/link/wgtun"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

const (
	// ModeLink selects the embedder-supplied framed L3 packet link network mode.
	ModeLink = "link"

	// DefaultPacketLinkMTU is the default initial L3 MTU of eth0 in link mode.
	DefaultPacketLinkMTU uint32 = 1500

	// PacketLinkMinMTU and PacketLinkMaxMTU bound eth0 L3 MTU and wire frames.
	PacketLinkMinMTU uint32 = 68
	PacketLinkMaxMTU uint32 = 65535

	packetLinkHeaderSize = 4
)

var (
	// ErrInvalidPacketLinkConfig marks invalid PacketLinkConfig fields.
	ErrInvalidPacketLinkConfig = errors.New("netbackend: invalid packet link configuration")

	packetLinkSockBufTargets = []int{4 << 20, 2 << 20, 1 << 20, 512 << 10, 256 << 10}
)

// PacketLinkConfig configures a PacketLink attaching guest eth0 to an
// embedder-supplied pre-connected byte stream carrying 4-byte big-endian
// length-prefixed L3 IPv4/IPv6 packets.
type PacketLinkConfig struct {
	// Conn is the pre-connected stream carrying framed L3 IP packets.
	// NewPacketLinkStack and NewPacketLinkForRestore take ownership of Conn and
	// close it on error or Close.
	Conn net.Conn

	// MTU sets the initial L3 MTU of eth0 (68..65535). Zero selects
	// DefaultPacketLinkMTU (1500).
	MTU uint32

	// GuestIPv4 sets the IPv4 address and prefix of eth0. Invalid defaults to
	// 10.0.2.15/24.
	GuestIPv4 netip.Prefix

	// GatewayIPv4 sets an optional IPv4 gateway for the default route on eth0.
	// When invalid, eth0 installs an on-link default route (0.0.0.0/0 on eth0).
	GatewayIPv4 netip.Addr

	// DNSServers lists nameserver IPs for default guest /etc/resolv.conf. Empty
	// defaults to 10.0.2.3.
	DNSServers []netip.Addr

	// Stack selects optional guest Netstack features (RawSockets, IPTables).
	Stack StackOptions

	// Tuning supplies queue sizes. Zero selects defaults.
	Tuning tuning.Values
}

type normalizedPacketLinkConfig struct {
	conn        net.Conn
	mtu         uint32
	guestIPv4   netip.Prefix
	gatewayIPv4 netip.Addr
	dnsServers  []netip.Addr
	stackOpts   StackOptions
	queueLen    int
}

// ValidatePacketLinkConn validates that conn is non-nil and is not a datagram
// socket. Non-socket stream implementations (such as net.Pipe) are accepted.
func ValidatePacketLinkConn(conn net.Conn) error {
	if conn == nil {
		return fmt.Errorf("%w: Conn must not be nil", ErrInvalidPacketLinkConfig)
	}
	if _, isUDP := conn.(*net.UDPConn); isUDP {
		return fmt.Errorf("%w: Conn must be a stream connection, not *net.UDPConn", ErrInvalidPacketLinkConfig)
	}
	if sc, ok := conn.(syscall.Conn); ok {
		return validateStreamSocket(sc)
	}
	return nil
}

func normalizePacketLinkConfig(cfg PacketLinkConfig) (normalizedPacketLinkConfig, error) {
	if err := ValidatePacketLinkConn(cfg.Conn); err != nil {
		return normalizedPacketLinkConfig{}, err
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = DefaultPacketLinkMTU
	}
	if mtu < PacketLinkMinMTU || mtu > PacketLinkMaxMTU {
		return normalizedPacketLinkConfig{}, fmt.Errorf("%w: MTU %d out of range [%d, %d]", ErrInvalidPacketLinkConfig, mtu, PacketLinkMinMTU, PacketLinkMaxMTU)
	}
	guestIPv4 := cfg.GuestIPv4
	if !guestIPv4.IsValid() {
		guestIPv4 = netip.PrefixFrom(netip.MustParseAddr(DefaultGuestIPv4), 24)
	} else {
		addr := guestIPv4.Addr()
		if !addr.Is4() || addr.Is4In6() || addr.IsUnspecified() || guestIPv4.Bits() < 1 || guestIPv4.Bits() > 32 {
			return normalizedPacketLinkConfig{}, fmt.Errorf("%w: invalid GuestIPv4 %q", ErrInvalidPacketLinkConfig, cfg.GuestIPv4)
		}
	}
	gatewayIPv4 := cfg.GatewayIPv4
	if gatewayIPv4.IsValid() {
		if !gatewayIPv4.Is4() || gatewayIPv4.Is4In6() || gatewayIPv4.IsUnspecified() || gatewayIPv4 == guestIPv4.Addr() {
			return normalizedPacketLinkConfig{}, fmt.Errorf("%w: invalid GatewayIPv4 %q", ErrInvalidPacketLinkConfig, cfg.GatewayIPv4)
		}
	}
	var dnsServers []netip.Addr
	if len(cfg.DNSServers) == 0 {
		dnsServers = []netip.Addr{netip.MustParseAddr(HostDNSIPv4)}
	} else {
		dnsServers = make([]netip.Addr, 0, len(cfg.DNSServers))
		for _, a := range cfg.DNSServers {
			if !a.IsValid() || a.Zone() != "" {
				return normalizedPacketLinkConfig{}, fmt.Errorf("%w: invalid DNS server %q", ErrInvalidPacketLinkConfig, a)
			}
			dnsServers = append(dnsServers, a.Unmap())
		}
	}
	return normalizedPacketLinkConfig{
		conn:        cfg.Conn,
		mtu:         mtu,
		guestIPv4:   guestIPv4,
		gatewayIPv4: gatewayIPv4,
		dnsServers:  dnsServers,
		stackOpts:   cfg.Stack,
		queueLen:    cfg.Tuning.Int(tuning.LinkQueueLength),
	}, nil
}

// tunePacketLinkConn raises socket buffers and disables Nagle before host
// lockdown when the connection exposes those controls. Errors are ignored so
// net.Pipe, custom streams, and restricted kernel buffer limits keep working.
func tunePacketLinkConn(conn net.Conn) {
	if tc, ok := conn.(interface{ SetNoDelay(bool) error }); ok {
		_ = tc.SetNoDelay(true)
	}
	if rc, ok := conn.(interface{ SetReadBuffer(int) error }); ok {
		for _, sz := range packetLinkSockBufTargets {
			if rc.SetReadBuffer(sz) == nil {
				break
			}
		}
	}
	if wc, ok := conn.(interface{ SetWriteBuffer(int) error }); ok {
		for _, sz := range packetLinkSockBufTargets {
			if wc.SetWriteBuffer(sz) == nil {
				break
			}
		}
	}
}

// packetLinkEndpoint wraps channel.Endpoint with stack.CapabilityNone (no
// checksum offload) and drops outbound packets while quiesced for checkpoint.
type packetLinkEndpoint struct {
	*channel.Endpoint
	quiesced *atomic.Bool
}

// WritePackets implements stack.LinkEndpoint.WritePackets.
func (e *packetLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	if e.quiesced.Load() {
		return pkts.Len(), nil
	}
	return e.Endpoint.WritePackets(pkts)
}

func configurePacketLinkNIC(s *stack.Stack, chEP *channel.Endpoint, quiesced *atomic.Bool, cfg normalizedPacketLinkConfig) error {
	linkEP := &packetLinkEndpoint{
		Endpoint: chEP,
		quiesced: quiesced,
	}
	if err := createNamedNICWithMTURange(s, Eth0NICID, Eth0NICName, linkEP, PacketLinkMinMTU, PacketLinkMaxMTU); err != nil {
		return err
	}
	v4 := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(cfg.guestIPv4.Addr().As4()),
			PrefixLen: cfg.guestIPv4.Bits(),
		},
	}
	if err := s.AddProtocolAddress(Eth0NICID, v4, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("netbackend: add packet link guest IPv4 address: %s", err)
	}
	defaultRoute := tcpip.Route{
		Destination: header.IPv4EmptySubnet,
		NIC:         Eth0NICID,
	}
	if cfg.gatewayIPv4.IsValid() {
		defaultRoute.Gateway = tcpip.AddrFrom4(cfg.gatewayIPv4.As4())
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4LoopbackSubnet, NIC: LoopbackNICID},
		defaultRoute,
	})
	return nil
}

// PacketLink bridges guest eth0 to an external peer over a 4-byte length-prefixed
// L3 IP packet stream.
//
// Lock order: mu -> injectMu; channel.Endpoint.Close and Drain are called under
// mu and never acquire mu or injectMu. drainLoop never acquires mu or injectMu.
// readLoop and writeLoop never hold mu or injectMu across conn I/O.
type PacketLink struct {
	cfg normalizedPacketLinkConfig

	mu               sync.Mutex
	stack            *stack.Stack
	channelEP        *channel.Endpoint
	started          bool
	transportClosed  bool
	inSaveQuiesce    bool
	pendingChEPClose bool
	chEPClosed       bool
	closed           bool

	quiesced atomic.Bool
	injectMu sync.RWMutex

	loopCtx     context.Context
	loopCancel  context.CancelFunc
	drainCancel context.CancelFunc

	// txCh decouples channel.Endpoint reads from conn.Write so QuiesceForSave
	// stops channel.Endpoint reads immediately without interrupting an active
	// conn.Write mid-frame. txCh is never closed; writeLoop exits via loopCtx.
	txCh    chan []byte
	wg      sync.WaitGroup
	drainWG sync.WaitGroup
}

func newPacketLink(cfg PacketLinkConfig) (*PacketLink, error) {
	norm, err := normalizePacketLinkConfig(cfg)
	if err != nil {
		if cfg.Conn != nil {
			_ = cfg.Conn.Close()
		}
		return nil, err
	}
	tunePacketLinkConn(norm.conn)
	loopCtx, loopCancel := context.WithCancel(context.Background())
	return &PacketLink{
		cfg:        norm,
		loopCtx:    loopCtx,
		loopCancel: loopCancel,
		txCh:       make(chan []byte, norm.queueLen),
	}, nil
}

// NewPacketLinkStack validates cfg, tunes socket buffers pre-lockdown, builds
// the guest Netstack with lo and eth0, and starts frame I/O goroutines. On
// error, NewPacketLinkStack closes cfg.Conn.
func NewPacketLinkStack(cfg PacketLinkConfig) (*stack.Stack, *PacketLink, error) {
	pl, err := newPacketLink(cfg)
	if err != nil {
		return nil, nil, err
	}
	s, err := NewLoopbackStack(pl.cfg.stackOpts)
	if err != nil {
		_ = pl.Close()
		return nil, nil, err
	}
	chEP := channel.New(pl.cfg.queueLen, pl.cfg.mtu, "")
	if err := configurePacketLinkNIC(s, chEP, &pl.quiesced, pl.cfg); err != nil {
		chEP.Close()
		s.Close()
		_ = pl.Close()
		return nil, nil, err
	}
	pl.mu.Lock()
	pl.stack = s
	pl.channelEP = chEP
	pl.started = true
	pl.startLoopsLocked(chEP)
	pl.mu.Unlock()
	return s, pl, nil
}

// NewPacketLinkForRestore validates cfg and tunes socket buffers pre-lockdown
// without creating a throwaway guest stack or starting I/O loops until
// AttachRestoredStack or AttachRestoredStackWithConfig attaches the restored
// stack. On error, NewPacketLinkForRestore closes cfg.Conn.
func NewPacketLinkForRestore(cfg PacketLinkConfig) (*PacketLink, error) {
	return newPacketLink(cfg)
}

// AttachRestoredStack rebinds a restored guest Netstack to l using default eth0
// settings and starts frame I/O goroutines.
func (l *PacketLink) AttachRestoredStack(restored *stack.Stack) error {
	return l.AttachRestoredStackWithConfig(restored, nil)
}

// AttachRestoredStackWithConfig rebinds a restored guest Netstack to l,
// reapplying saved eth0 settings when non-nil, restores transport endpoints,
// and starts frame I/O goroutines.
func (l *PacketLink) AttachRestoredStackWithConfig(restored *stack.Stack, eth0 *Eth0Config) error {
	if restored == nil {
		return errors.New("netbackend: restored stack is nil")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.transportClosed {
		return errors.New("netbackend: PacketLink is closed")
	}
	if l.started {
		return errors.New("netbackend: PacketLink is already attached")
	}
	restored.ResetConfig()
	if err := configureLoopbackNIC(restored, LoopbackNICID); err != nil {
		return err
	}
	chEP := channel.New(l.cfg.queueLen, l.cfg.mtu, "")
	if err := configurePacketLinkNIC(restored, chEP, &l.quiesced, l.cfg); err != nil {
		chEP.Close()
		return err
	}
	if eth0 != nil {
		_ = eth0.applyWithDefault(restored, tcpip.AddrFrom4(l.cfg.guestIPv4.Addr().As4()))
	}
	restored.Restore()
	l.stack = restored
	l.channelEP = chEP
	l.started = true
	l.startLoopsLocked(chEP)
	return nil
}

func (l *PacketLink) startLoopsLocked(chEP *channel.Endpoint) {
	l.wg.Add(2)
	go l.readLoop(chEP)
	go l.writeLoop()
	l.startDrainLocked(chEP)
}

func (l *PacketLink) startDrainLocked(chEP *channel.Endpoint) {
	drainCtx, drainCancel := context.WithCancel(l.loopCtx)
	l.drainCancel = drainCancel
	l.drainWG.Add(1)
	go l.drainLoop(drainCtx, chEP)
}

func (l *PacketLink) drainLoop(drainCtx context.Context, chEP *channel.Endpoint) {
	defer l.drainWG.Done()
	var scratch [PacketLinkMaxMTU]byte
	for {
		pkt := chEP.ReadContext(drainCtx)
		if pkt == nil {
			return
		}
		n, ok := wgtun.CopyPacket(pkt, scratch[:])
		pkt.DecRef()
		if !ok || n == 0 || n > int(PacketLinkMaxMTU) {
			continue
		}
		frame := make([]byte, packetLinkHeaderSize+n)
		binary.BigEndian.PutUint32(frame[:packetLinkHeaderSize], uint32(n))
		copy(frame[packetLinkHeaderSize:], scratch[:n])
		select {
		case l.txCh <- frame:
		case <-drainCtx.Done():
			return
		case <-l.loopCtx.Done():
			return
		}
	}
}

func (l *PacketLink) writeLoop() {
	defer l.wg.Done()
	for {
		select {
		case <-l.loopCtx.Done():
			return
		case frame := <-l.txCh:
			if err := writeFull(l.cfg.conn, frame); err != nil {
				_ = l.closeTransport()
				return
			}
		}
	}
}

func writeFull(w io.Writer, buf []byte) error {
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		buf = buf[n:]
	}
	return nil
}

func (l *PacketLink) readLoop(chEP *channel.Endpoint) {
	defer l.wg.Done()
	var hdr [packetLinkHeaderSize]byte
	var buf [PacketLinkMaxMTU]byte
	for {
		if _, err := io.ReadFull(l.cfg.conn, hdr[:]); err != nil {
			_ = l.closeTransport()
			return
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 || n > PacketLinkMaxMTU {
			_ = l.closeTransport()
			return
		}
		payload := buf[:n]
		if _, err := io.ReadFull(l.cfg.conn, payload); err != nil {
			_ = l.closeTransport()
			return
		}
		proto, err := wgtun.IPPacketProtocol(payload)
		if err != nil {
			continue
		}
		l.injectMu.RLock()
		if !l.quiesced.Load() && l.loopCtx.Err() == nil {
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(payload),
			})
			chEP.InjectInbound(proto, pkt)
			pkt.DecRef()
		}
		l.injectMu.RUnlock()
	}
}

// QuiesceForSave stops inbound packet injection, stops the channel.Endpoint
// reader, and drains queued outbound packets while the kernel saves state. It
// defers channel.Endpoint closure on concurrent peer disconnect until
// ResumeAfterSave or Close so state.Save never races with queue teardown.
// QuiesceForSave is idempotent and safe when the peer stalls on Conn.
func (l *PacketLink) QuiesceForSave() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.quiesced.Store(true)
	l.inSaveQuiesce = true
	l.injectMu.Lock()
	l.injectMu.Unlock()
	if l.drainCancel != nil {
		l.drainCancel()
		l.drainCancel = nil
	}
	l.drainWG.Wait()
	if l.channelEP != nil && !l.chEPClosed {
		l.channelEP.Drain()
	}
}

// ResumeAfterSave completes any deferred channel.Endpoint closure, restarts
// outbound channel.Endpoint draining, and resumes inbound packet injection
// after a pause or checkpoint. It is idempotent.
func (l *PacketLink) ResumeAfterSave() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.inSaveQuiesce = false
	if l.pendingChEPClose && l.channelEP != nil && !l.chEPClosed {
		l.pendingChEPClose = false
		l.chEPClosed = true
		l.channelEP.Close()
	}
	if l.closed || l.transportClosed || !l.started {
		return nil
	}
	l.quiesced.Store(false)
	if l.drainCancel == nil && l.channelEP != nil {
		l.startDrainLocked(l.channelEP)
	}
	return nil
}

// GuestResolvConf returns the /etc/resolv.conf content matching the configured
// DNS servers.
func (l *PacketLink) GuestResolvConf() string {
	var b strings.Builder
	for _, a := range l.cfg.dnsServers {
		b.WriteString("nameserver ")
		b.WriteString(a.String())
		b.WriteByte('\n')
	}
	return b.String()
}

// ChannelEndpoint returns the underlying eth0 channel.Endpoint, or nil before
// attachment.
func (l *PacketLink) ChannelEndpoint() *channel.Endpoint {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.channelEP
}

// Stack returns the guest Netstack owned by l, or nil before attachment.
func (l *PacketLink) Stack() *stack.Stack {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stack
}

// closeTransport tears down Conn and channelEP on framing error, peer EOF, or
// Close without closing l.stack, so guest loopback remains alive after peer
// death. While inSaveQuiesce is set, channelEP.Close is deferred to
// ResumeAfterSave or Close so state.Save observes an immutable queue.
// Safe to call concurrently and from readLoop or writeLoop.
func (l *PacketLink) closeTransport() error {
	l.mu.Lock()
	if l.transportClosed {
		l.mu.Unlock()
		return nil
	}
	l.transportClosed = true
	l.quiesced.Store(true)
	if l.drainCancel != nil {
		l.drainCancel()
		l.drainCancel = nil
	}
	if l.loopCancel != nil {
		l.loopCancel()
	}
	if l.channelEP != nil && !l.chEPClosed {
		if l.inSaveQuiesce {
			l.pendingChEPClose = true
		} else {
			l.chEPClosed = true
			l.channelEP.Close()
		}
	}
	l.mu.Unlock()

	_ = l.cfg.conn.SetDeadline(time.Now())
	err := l.cfg.conn.Close()
	if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}

// Close closes the underlying connection, stops all link goroutines, and closes
// the guest Netstack. Close is idempotent.
func (l *PacketLink) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.inSaveQuiesce = false
	if l.pendingChEPClose && l.channelEP != nil && !l.chEPClosed {
		l.pendingChEPClose = false
		l.chEPClosed = true
		l.channelEP.Close()
	}
	st := l.stack
	l.stack = nil
	l.mu.Unlock()

	connErr := l.closeTransport()
	l.drainWG.Wait()
	l.wg.Wait()
	if st != nil {
		st.Close()
	}
	return connErr
}
