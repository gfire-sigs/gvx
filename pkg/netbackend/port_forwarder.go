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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

const (
	// acceptBackoffMin and acceptBackoffMax bound the pause after a failed Accept.
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = time.Second
)

// PortForwardRule defines a single host-to-guest port mapping (-p host:guest).
type PortForwardRule struct {
	Proto     string
	HostIP    string
	HostPort  uint16
	GuestIP   string
	GuestPort uint16

	// HostSocket is the path of a host Unix socket that forwards each
	// connection to GuestPort over TCP. When it is set, HostIP and HostPort
	// are unused and Proto must be "tcp".
	HostSocket string
}

// unixSocketPrefix starts a publish specification for a host Unix socket.
const unixSocketPrefix = "unix:"

// ParsePortForwardSpecs parses a publish specification that can name more
// than one forward. It accepts every form of ParsePortForwardSpec, a port
// range on the host side and the guest side ("8000-8009:8000-8009",
// "127.0.0.1:8000-8009:9000-9009", or a guest range alone, "8000-8009"), and
// a host Unix socket ("unix:/path/docker.sock:2375"). Two ranges must have the
// same length. Each port of a range takes one host socket, so the tunable
// net.forward.max_port_range limits the length of a range.
func ParsePortForwardSpecs(spec string, allowSinglePort, strictBindIP bool, t tuning.Values) ([]PortForwardRule, error) {
	spec = strings.TrimSpace(spec)
	if strings.HasPrefix(spec, unixSocketPrefix) {
		rule, err := parseUnixSocketSpec(spec)
		if err != nil {
			return nil, err
		}
		return []PortForwardRule{rule}, nil
	}
	if !strings.Contains(spec, "-") {
		rule, err := ParsePortForwardSpec(spec, allowSinglePort, strictBindIP)
		if err != nil {
			return nil, err
		}
		return []PortForwardRule{rule}, nil
	}

	body, proto := spec, ""
	if i := strings.LastIndexByte(body, '/'); i != -1 {
		body, proto = body[:i], body[i:]
	}
	prefix, rest := "", body
	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "]:")
		if end < 0 {
			return nil, fmt.Errorf("netbackend: invalid port forward %q: an IPv6 address needs brackets and a port", spec)
		}
		prefix, rest = rest[:end+1], rest[end+2:]
	}
	parts := strings.Split(rest, ":")
	if prefix == "" && len(parts) == 3 {
		prefix, parts = parts[0], parts[1:]
	}
	var hostField, guestField string
	switch len(parts) {
	case 1:
		guestField = parts[0]
	case 2:
		hostField, guestField = parts[0], parts[1]
	default:
		return nil, fmt.Errorf("netbackend: invalid port forward format %q", spec)
	}
	guestLo, guestHi, err := parsePortRange(guestField)
	if err != nil {
		return nil, fmt.Errorf("netbackend: invalid guest port range %q in %q: %w", guestField, spec, err)
	}
	count := int(guestHi-guestLo) + 1
	hostLo := uint16(0)
	if hostField != "" {
		lo, hi, err := parsePortRange(hostField)
		if err != nil {
			return nil, fmt.Errorf("netbackend: invalid host port range %q in %q: %w", hostField, spec, err)
		}
		if int(hi-lo)+1 != count {
			return nil, fmt.Errorf("netbackend: invalid port forward %q: the host range and the guest range must have the same length", spec)
		}
		hostLo = lo
	}
	if maxRange := t.Int(tuning.ForwardMaxPortRange); count > maxRange {
		return nil, fmt.Errorf("netbackend: invalid port forward %q: a range has at most %d ports (tunable net.forward.max_port_range)", spec, maxRange)
	}

	rules := make([]PortForwardRule, 0, count)
	for i := range count {
		guest := strconv.Itoa(int(guestLo) + i)
		var one string
		switch {
		case len(parts) == 1 && prefix == "":
			one = guest
		case hostField == "":
			one = prefix + "::" + guest
		case prefix == "":
			one = strconv.Itoa(int(hostLo)+i) + ":" + guest
		default:
			one = prefix + ":" + strconv.Itoa(int(hostLo)+i) + ":" + guest
		}
		rule, err := ParsePortForwardSpec(one+proto, allowSinglePort, strictBindIP)
		if err != nil {
			return nil, fmt.Errorf("netbackend: invalid port forward %q: %w", spec, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// parsePortRange parses "N" or "N-M" with 1 <= N <= M.
func parsePortRange(s string) (lo, hi uint16, err error) {
	s = strings.TrimSpace(s)
	loText, hiText, isRange := strings.Cut(s, "-")
	if !isRange {
		hiText = loText
	}
	l, err := strconv.ParseUint(strings.TrimSpace(loText), 10, 16)
	if err != nil || l == 0 {
		return 0, 0, errors.New("want a port from 1 to 65535")
	}
	h, err := strconv.ParseUint(strings.TrimSpace(hiText), 10, 16)
	if err != nil || h < l {
		return 0, 0, errors.New("want an ascending range of ports from 1 to 65535")
	}
	return uint16(l), uint16(h), nil
}

// parseUnixSocketSpec parses "unix:PATH:GUESTPORT[/tcp]". The last colon
// ends the path, so a Windows path with a drive letter works.
func parseUnixSocketSpec(spec string) (PortForwardRule, error) {
	body := strings.TrimPrefix(spec, unixSocketPrefix)
	if i := strings.LastIndexByte(body, '/'); i != -1 && !strings.ContainsAny(body[i:], `:\`) {
		if proto := strings.ToLower(body[i+1:]); proto != "tcp" {
			return PortForwardRule{}, fmt.Errorf("netbackend: invalid port forward %q: a Unix socket forwards tcp only", spec)
		}
		body = body[:i]
	}
	i := strings.LastIndexByte(body, ':')
	if i <= 0 {
		return PortForwardRule{}, fmt.Errorf("netbackend: invalid port forward %q (want unix:PATH:GUESTPORT)", spec)
	}
	path, portText := body[:i], body[i+1:]
	port, err := strconv.ParseUint(strings.TrimSpace(portText), 10, 16)
	if err != nil || port == 0 {
		return PortForwardRule{}, fmt.Errorf("netbackend: invalid guest port %q in %q", portText, spec)
	}
	return PortForwardRule{Proto: "tcp", GuestIP: DefaultGuestIPv4, GuestPort: uint16(port), HostSocket: path}, nil
}

// listenUnixSocket binds a Unix socket at path for a forward. It removes a
// socket file that an earlier run left behind: that run could not remove it,
// because the host lockdown denies file removal. It refuses any other file.
func listenUnixSocket(path string) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("netbackend: %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("netbackend: remove the old socket %s: %w", path, err)
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("netbackend: bind unix %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("netbackend: restrict the socket %s to its owner: %w", path, err)
	}
	return ln, nil
}

// ParsePortForwardRule parses a CLI port-forward specification such as
// "8080:80", "127.0.0.1:8080:80", "8080:80/tcp", or "5353:53/udp".
func ParsePortForwardRule(spec string) (PortForwardRule, error) {
	return ParsePortForwardSpec(spec, false, false)
}

// ParsePortForwardSpec parses a port-forward specification. When allowSinglePort
// is true, Docker forms such as "80", "ip::80", and "[ipv6]:8080:80" are
// accepted. When strictBindIP is true, an explicit bind address must parse as
// an IPv4 or bracketed IPv6 address.
func ParsePortForwardSpec(spec string, allowSinglePort, strictBindIP bool) (PortForwardRule, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return PortForwardRule{}, errors.New("netbackend: empty port forward specification")
	}

	proto := "tcp"
	if slashIdx := strings.LastIndexByte(spec, '/'); slashIdx != -1 {
		proto = strings.ToLower(strings.TrimSpace(spec[slashIdx+1:]))
		spec = spec[:slashIdx]
		if proto != "tcp" && proto != "udp" {
			return PortForwardRule{}, fmt.Errorf("netbackend: unsupported protocol %q in port forward spec", proto)
		}
	}

	hostIP := "127.0.0.1"
	rest := spec
	if strings.HasPrefix(rest, "[") {
		end := strings.IndexByte(rest, ']')
		if end < 0 || end+1 >= len(rest) || rest[end+1] != ':' {
			return PortForwardRule{}, fmt.Errorf("netbackend: invalid port forward %q: an IPv6 address needs brackets and a port", spec)
		}
		hostIP, rest = rest[1:end], rest[end+2:]
		if ip, err := netip.ParseAddr(hostIP); err != nil || !ip.Is6() {
			return PortForwardRule{}, fmt.Errorf("netbackend: invalid IPv6 address %q in %q", hostIP, spec)
		}
	}

	parts := strings.Split(rest, ":")
	if hostIP == "127.0.0.1" && len(parts) == 3 {
		hostIP, parts = parts[0], parts[1:]
		if hostIP == "" && !strictBindIP {
			hostIP = "127.0.0.1"
		} else if strictBindIP {
			if ip, err := netip.ParseAddr(hostIP); err != nil || !ip.Is4() {
				return PortForwardRule{}, fmt.Errorf("netbackend: invalid bind address %q in %q (want an IPv4 address, or an IPv6 address in brackets)", hostIP, spec)
			}
		}
	}

	var hostPortStr, guestPortStr string
	switch {
	case len(parts) == 1 && allowSinglePort:
		guestPortStr = parts[0]
	case len(parts) == 2:
		hostPortStr, guestPortStr = parts[0], parts[1]
	default:
		return PortForwardRule{}, fmt.Errorf("netbackend: invalid port forward format %q", spec)
	}

	var hostPort uint64
	hostPortStr = strings.TrimSpace(hostPortStr)
	if hostPortStr != "" || !allowSinglePort {
		var err error
		hostPort, err = strconv.ParseUint(hostPortStr, 10, 16)
		if err != nil {
			return PortForwardRule{}, fmt.Errorf("netbackend: invalid host port %q: %w", hostPortStr, err)
		}
	}
	guestPort, err := strconv.ParseUint(strings.TrimSpace(guestPortStr), 10, 16)
	if err != nil || guestPort == 0 {
		return PortForwardRule{}, fmt.Errorf("netbackend: invalid guest port %q", guestPortStr)
	}

	return PortForwardRule{
		Proto:     proto,
		HostIP:    hostIP,
		HostPort:  uint16(hostPort),
		GuestIP:   DefaultGuestIPv4,
		GuestPort: uint16(guestPort),
	}, nil
}

type boundTCPForward struct {
	rule     PortForwardRule
	listener net.Listener
}

type boundUDPForward struct {
	rule       PortForwardRule
	packetConn *net.UDPConn

	// sessions maps a client address to its session. PortForwarder.mu guards it.
	sessions map[netip.AddrPort]*udpForwardSession
}

// udpForwardSession carries the datagrams of one host client. It owns one
// guest UDP endpoint, so the guest sees one stable source port per client.
type udpForwardSession struct {
	client netip.AddrPort
	guest  *gonet.UDPConn
	clock  *activityClock
}

// PortForwarder binds host TCP listeners and UDP packet sockets prior to
// hostlockdown.Apply() and forwards inbound traffic into Netstack via gonet.
type PortForwarder struct {
	mu      sync.Mutex
	stack   *stack.Stack
	tcpList []*boundTCPForward
	udpList []*boundUDPForward
	started bool
	closed  bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	// udpIdle is the time without a datagram after which a UDP session ends.
	udpIdle time.Duration
	// udpMaxSessions is the session limit of each UDP rule. The forwarder
	// drops a new client while the rule is at the limit.
	udpMaxSessions int
	// guestDialWindow is the time that a forwarded TCP client waits for the
	// guest to start listening on the target port.
	guestDialWindow time.Duration
	// guestDialInterval is the pause between guest dial attempts.
	guestDialInterval time.Duration
	accept            func(net.Listener) (net.Conn, error)
	log               *slog.Logger

	// resumed is non-nil between QuiesceForSave and ResumeAfterSave. It
	// closes when the pause ends. PortForwarder.mu guards it.
	resumed chan struct{}
}

// NewPortForwarder constructs an empty PortForwarder ready for PreBind. The
// tunables net.udp.idle_timeout, net.forward.udp_sessions,
// net.forward.guest_dial_window, and net.forward.guest_dial_interval set its
// limits.
func NewPortForwarder(t tuning.Values) *PortForwarder {
	ctx, cancel := context.WithCancel(context.Background())
	return &PortForwarder{
		ctx:               ctx,
		cancel:            cancel,
		udpIdle:           t.Duration(tuning.UDPIdleTimeout),
		udpMaxSessions:    t.Int(tuning.ForwardUDPSessions),
		guestDialWindow:   t.Duration(tuning.ForwardGuestDialWindow),
		guestDialInterval: t.Duration(tuning.ForwardGuestDialInterval),
		log:               discardLogger,
	}
}

// PreBind opens all host TCP listeners and UDP sockets for rules before
// hostlockdown.Apply() restricts new socket binds.
func (pf *PortForwarder) PreBind(rules []PortForwardRule) error {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	if pf.closed {
		return errors.New("netbackend: PortForwarder is closed")
	}

	for _, r := range rules {
		proto := strings.ToLower(r.Proto)
		if proto == "" {
			proto = "tcp"
		}
		hostIP := r.HostIP
		if hostIP == "" {
			hostIP = "127.0.0.1"
		}
		guestIP := r.GuestIP
		if guestIP == "" {
			guestIP = DefaultGuestIPv4
		}
		bindAddr := net.JoinHostPort(hostIP, strconv.Itoa(int(r.HostPort)))

		if r.HostSocket != "" {
			if proto != "tcp" {
				return fmt.Errorf("netbackend: the Unix socket %s forwards tcp only, not %s", r.HostSocket, proto)
			}
			ln, err := listenUnixSocket(r.HostSocket)
			if err != nil {
				return err
			}
			pf.tcpList = append(pf.tcpList, &boundTCPForward{
				rule:     PortForwardRule{Proto: "tcp", GuestIP: guestIP, GuestPort: r.GuestPort, HostSocket: r.HostSocket},
				listener: ln,
			})
			continue
		}

		switch proto {
		case "tcp":
			ln, err := net.Listen("tcp", bindAddr)
			if err != nil {
				return fmt.Errorf("netbackend: bind tcp %s: %w", bindAddr, err)
			}
			actualPort := r.HostPort
			if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
				actualPort = uint16(tcpAddr.Port)
			}
			pf.tcpList = append(pf.tcpList, &boundTCPForward{
				rule: PortForwardRule{
					Proto:     "tcp",
					HostIP:    hostIP,
					HostPort:  actualPort,
					GuestIP:   guestIP,
					GuestPort: r.GuestPort,
				},
				listener: ln,
			})
		case "udp":
			pc, err := net.ListenPacket("udp", bindAddr)
			if err != nil {
				return fmt.Errorf("netbackend: bind udp %s: %w", bindAddr, err)
			}
			udpConn, ok := pc.(*net.UDPConn)
			if !ok {
				_ = pc.Close()
				return fmt.Errorf("netbackend: bind udp %s: socket is %T, want *net.UDPConn", bindAddr, pc)
			}
			widenUDPSend(udpConn)
			actualPort := uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)
			pf.udpList = append(pf.udpList, &boundUDPForward{
				rule: PortForwardRule{
					Proto:     "udp",
					HostIP:    hostIP,
					HostPort:  actualPort,
					GuestIP:   guestIP,
					GuestPort: r.GuestPort,
				},
				packetConn: udpConn,
				sessions:   make(map[netip.AddrPort]*udpForwardSession),
			})
		default:
			return fmt.Errorf("netbackend: unsupported protocol %q", proto)
		}
	}
	return nil
}

// BoundRules returns the active port forward rules with resolved host ports.
func (pf *PortForwarder) BoundRules() []PortForwardRule {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	out := make([]PortForwardRule, 0, len(pf.tcpList)+len(pf.udpList))
	for _, b := range pf.tcpList {
		out = append(out, b.rule)
	}
	for _, b := range pf.udpList {
		out = append(out, b.rule)
	}
	return out
}

// SetAccept sets the accept function used for pre-bound TCP and Unix listeners.
// When fn is nil, PortForwarder calls net.Listener.Accept directly.
func (pf *PortForwarder) SetAccept(fn func(net.Listener) (net.Conn, error)) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	pf.accept = fn
}

// Start launches background relay workers for all pre-bound TCP and UDP ports
// targeting the given Netstack instance. It does nothing after Close and
// after the first call.
func (pf *PortForwarder) Start(s *stack.Stack) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	if pf.closed || pf.started {
		return
	}
	pf.stack = s
	pf.started = true
	for _, b := range pf.tcpList {
		pf.wg.Add(1)
		go pf.serveTCP(b)
	}
	for _, b := range pf.udpList {
		pf.wg.Add(1)
		go pf.serveUDP(b)
	}
}

// AttachRestoredStack rebinds all pre-bound TCP, Unix, and UDP port forwarders
// to target the restored guest Netstack s without opening new host sockets. If
// Start has not run yet, AttachRestoredStack starts the relay workers on s.
func (pf *PortForwarder) AttachRestoredStack(s *stack.Stack) error {
	if s == nil {
		return errors.New("netbackend: restored stack is nil")
	}
	pf.mu.Lock()
	if pf.closed {
		pf.mu.Unlock()
		return errors.New("netbackend: PortForwarder is closed")
	}
	if !pf.started {
		pf.stack = s
		pf.started = true
		for _, b := range pf.tcpList {
			pf.wg.Add(1)
			go pf.serveTCP(b)
		}
		for _, b := range pf.udpList {
			pf.wg.Add(1)
			go pf.serveUDP(b)
		}
		pf.mu.Unlock()
		return nil
	}
	pf.stack = s
	var staleGuests []*gonet.UDPConn
	for _, b := range pf.udpList {
		for client, sess := range b.sessions {
			staleGuests = append(staleGuests, sess.guest)
			delete(b.sessions, client)
		}
	}
	pf.mu.Unlock()
	for _, g := range staleGuests {
		_ = g.Close()
	}
	return nil
}

// RebindRestore rebinds all pre-bound port forwarders to target s.
func (pf *PortForwarder) RebindRestore(s *stack.Stack) error {
	return pf.AttachRestoredStack(s)
}

// RebindStack updates the target Netstack for all pre-bound port forwarders.
func (pf *PortForwarder) RebindStack(s *stack.Stack) {
	_ = pf.AttachRestoredStack(s)
}

func (pf *PortForwarder) targetStack() *stack.Stack {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	return pf.stack
}

// QuiesceForSave holds back new host clients and the writes of running relays
// into the guest Netstack until ResumeAfterSave runs. A client that connects
// during the pause waits in the listener backlog, and a datagram waits in the
// socket buffer.
func (pf *PortForwarder) QuiesceForSave() {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	if pf.resumed == nil {
		pf.resumed = make(chan struct{})
	}
}

// ResumeAfterSave ends the pause that QuiesceForSave started.
func (pf *PortForwarder) ResumeAfterSave() error {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	if pf.resumed != nil {
		close(pf.resumed)
		pf.resumed = nil
	}
	return nil
}

// waitResumed blocks while the forwarder is quiesced. It returns when the
// pause ends or the forwarder closes.
func (pf *PortForwarder) waitResumed() {
	pf.mu.Lock()
	ch := pf.resumed
	pf.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case <-ch:
	case <-pf.ctx.Done():
	}
}

// quiescedGuestConn gates the writes of a relay into the guest Netstack on
// the pause of PortForwarder.QuiesceForSave.
type quiescedGuestConn struct {
	*gonet.TCPConn
	wait func()
}

// Write implements net.Conn.Write.
func (c quiescedGuestConn) Write(p []byte) (int, error) {
	c.wait()
	return c.TCPConn.Write(p)
}

// spawn runs fn on a tracked goroutine. It returns false after Close, so that
// no goroutine starts while Close waits.
func (pf *PortForwarder) spawn(fn func()) bool {
	return spawnTracked(&pf.mu, &pf.closed, &pf.wg, fn)
}

func (pf *PortForwarder) serveTCP(b *boundTCPForward) {
	defer pf.wg.Done()
	pf.mu.Lock()
	acceptFn := pf.accept
	pf.mu.Unlock()
	if acceptFn == nil {
		acceptFn = net.Listener.Accept
	}
	guestAddr := parseGuestFullAddr(b.rule.GuestIP, b.rule.GuestPort)
	var backoff time.Duration
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		hostConn, err := acceptFn(b.listener)
		if err != nil {
			if pf.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			// A transient error such as EMFILE must not end the listener.
			backoff = min(max(2*backoff, acceptBackoffMin), acceptBackoffMax)
			pf.log.Warn("netbackend: accept on forwarded port failed", "port", b.rule.HostPort, "retry_in", backoff, "error", err)
			if timer == nil {
				timer = time.NewTimer(backoff)
			} else {
				timer.Reset(backoff)
			}
			select {
			case <-pf.ctx.Done():
				return
			case <-timer.C:
			}
			continue
		}
		backoff = 0
		pf.waitResumed()
		if !pf.spawn(func() { pf.relayTCPClient(guestAddr, hostConn) }) {
			_ = hostConn.Close()
			return
		}
	}
}

// relayTCPClient connects hostConn to the guest endpoint and relays both
// streams. The guest may start listening after the host client connects, so
// the dial retries during the guest dial window.
func (pf *PortForwarder) relayTCPClient(guestAddr tcpip.FullAddress, hostConn net.Conn) {
	defer func() { _ = hostConn.Close() }()

	ctx, cancel := context.WithTimeout(pf.ctx, pf.guestDialWindow)
	defer cancel()
	var guestConn *gonet.TCPConn
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		var err error
		if s := pf.targetStack(); s != nil {
			guestConn, err = gonet.DialContextTCP(ctx, s, guestAddr, ipv4.ProtocolNumber)
			if err == nil {
				break
			}
		} else {
			err = errors.New("target stack is nil")
		}
		if timer == nil {
			timer = time.NewTimer(pf.guestDialInterval)
		} else {
			timer.Reset(pf.guestDialInterval)
		}
		select {
		case <-ctx.Done():
			pf.log.Debug("netbackend: dial guest for forwarded connection", "guest", guestAddr.Addr, "port", guestAddr.Port, "error", err)
			return
		case <-timer.C:
		}
	}
	defer func() { _ = guestConn.Close() }()
	relayBidirectional(pf.ctx, hostConn, quiescedGuestConn{TCPConn: guestConn, wait: pf.waitResumed})
}

func (pf *PortForwarder) serveUDP(b *boundUDPForward) {
	defer pf.wg.Done()
	guestAddr := parseGuestFullAddr(b.rule.GuestIP, b.rule.GuestPort)
	buf := make([]byte, maxUDPDatagram)
	var backoff time.Duration
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		n, client, err := b.packetConn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if pf.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			backoff = min(max(2*backoff, acceptBackoffMin), acceptBackoffMax)
			pf.log.Warn("netbackend: read on forwarded UDP port failed", "port", b.rule.HostPort, "retry_in", backoff, "error", err)
			if timer == nil {
				timer = time.NewTimer(backoff)
			} else {
				timer.Reset(backoff)
			}
			select {
			case <-pf.ctx.Done():
				return
			case <-timer.C:
			}
			continue
		}
		backoff = 0
		pf.waitResumed()
		sess := pf.udpSession(b, guestAddr, client)
		if sess == nil {
			continue
		}
		sess.clock.touch()
		if _, err := sess.guest.Write(buf[:n]); err != nil {
			pf.log.Debug("netbackend: write forwarded datagram to guest", "client", client, "error", err)
		}
	}
}

// udpSession returns the session of client. It creates the session and its
// reply goroutine on the first datagram. It returns nil when the forwarder is
// closed, the rule is at its session limit, or the guest endpoint fails.
func (pf *PortForwarder) udpSession(b *boundUDPForward, guestAddr tcpip.FullAddress, client netip.AddrPort) *udpForwardSession {
	pf.mu.Lock()
	if pf.closed || pf.stack == nil {
		pf.mu.Unlock()
		return nil
	}
	if sess, ok := b.sessions[client]; ok {
		pf.mu.Unlock()
		return sess
	}
	if len(b.sessions) >= pf.udpMaxSessions {
		pf.mu.Unlock()
		pf.log.Warn("netbackend: UDP forward session limit reached", "port", b.rule.HostPort, "client", client)
		return nil
	}
	s := pf.stack
	pf.mu.Unlock()

	guest, err := gonet.DialUDP(s, nil, &guestAddr, ipv4.ProtocolNumber)
	if err != nil {
		pf.log.Debug("netbackend: open guest UDP endpoint", "client", client, "error", err)
		return nil
	}
	sess := &udpForwardSession{client: client, guest: guest, clock: newActivityClock()}

	// Only this rule's serveUDP goroutine inserts sessions, so the earlier
	// lookup cannot race with another insert for the same key.
	pf.mu.Lock()
	if pf.closed || pf.stack != s {
		pf.mu.Unlock()
		_ = guest.Close()
		return nil
	}
	b.sessions[client] = sess
	pf.wg.Add(1)
	pf.mu.Unlock()
	go pf.runUDPSession(b, sess)
	return sess
}

// runUDPSession forwards every guest reply to the host client until the
// session is idle in both directions or its guest endpoint closes.
func (pf *PortForwarder) runUDPSession(b *boundUDPForward, sess *udpForwardSession) {
	defer pf.wg.Done()
	defer func() {
		pf.mu.Lock()
		if b.sessions[sess.client] == sess {
			delete(b.sessions, sess.client)
		}
		pf.mu.Unlock()
		_ = sess.guest.Close()
	}()
	pumpDatagrams(sess.guest, func(p []byte) error {
		_, err := b.packetConn.WriteToUDPAddrPort(p, sess.client)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			pf.log.Debug("netbackend: write guest reply to host client", "client", sess.client, "error", err)
		}
		return err
	}, sess.clock, pf.udpIdle)
}

func parseGuestFullAddr(ipStr string, port uint16) tcpip.FullAddress {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil || !addr.Is4() {
		return tcpip.FullAddress{
			NIC:  Eth0NICID,
			Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 15}),
			Port: port,
		}
	}
	return tcpip.FullAddress{
		NIC:  Eth0NICID,
		Addr: tcpip.AddrFrom4(addr.As4()),
		Port: port,
	}
}

// Close stops all pre-bound host listeners, closes every UDP session, and
// waits for active relays. It closes the session endpoints before it waits,
// so a guest that never answers cannot block Close.
func (pf *PortForwarder) Close() error {
	pf.mu.Lock()
	if pf.closed {
		pf.mu.Unlock()
		return nil
	}
	pf.closed = true
	pf.cancel()
	var errs []error
	for _, b := range pf.tcpList {
		if err := b.listener.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	var guests []*gonet.UDPConn
	for _, b := range pf.udpList {
		if err := b.packetConn.Close(); err != nil {
			errs = append(errs, err)
		}
		for _, sess := range b.sessions {
			guests = append(guests, sess.guest)
		}
	}
	pf.mu.Unlock()
	for _, g := range guests {
		_ = g.Close()
	}
	pf.wg.Wait()
	return errors.Join(errs...)
}
