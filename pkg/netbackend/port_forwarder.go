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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/waiter"
)

const (
	// acceptBackoffMin and acceptBackoffMax bound the pause after a failed Accept.
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = time.Second
)

var errPublishedTCPDenied = errors.New("netbackend: NAT policy denied every target for published TCP connection")

// PortSource identifies how a published port forward rule was created.
const (
	PortSourceStatic  = "static"
	PortSourceAuto    = "auto"
	PortSourceDynamic = "dynamic"
)

// ErrStaticRuleRequiresForce reports an attempt to remove a startup -p rule
// without Force enabled.
var ErrStaticRuleRequiresForce = errors.New("netbackend: removing a static port rule requires force")

// ErrPortRuleExists reports a conflicting port forward binding.
var ErrPortRuleExists = errors.New("netbackend: port forward rule already exists")

// ErrPortRuleNotFound reports that no active port forward matched a remove spec.
var ErrPortRuleNotFound = errors.New("netbackend: port forward rule not found")

// ErrDynamicPortLimit reports that binding another dynamic rule would exceed
// net.forward.max_dynamic_ports.
var ErrDynamicPortLimit = errors.New("netbackend: dynamic port limit reached")

// BoundPortRule pairs an active PortForwardRule with its origin ("static",
// "auto", or "dynamic").
type BoundPortRule struct {
	Rule   PortForwardRule
	Source string
}

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
	// PortForwarder.mu guards rule.
	rule     PortForwardRule
	listener net.Listener
}

type boundUDPForward struct {
	// PortForwarder.mu guards rule, closed, and sessions.
	rule       PortForwardRule
	packetConn *net.UDPConn

	// closed is set when this rule is unpublished or PortForwarder closes.
	closed   bool
	sessions map[netip.AddrPort]*udpForwardSession
}

// detachSessions invalidates queued sends before the caller closes the sessions.
// The caller holds PortForwarder.mu.
func (b *boundUDPForward) detachSessions(dst []*udpForwardSession) []*udpForwardSession {
	for _, sess := range b.sessions {
		dst = append(dst, sess)
	}
	clear(b.sessions)
	return dst
}

// udpForwardSession carries the datagrams of one host client. It owns one
// guest UDP endpoint, so the guest sees one stable source port per client.
type udpForwardSession struct {
	client netip.AddrPort
	guest  *gonet.UDPConn
	ep     tcpip.Endpoint
	ctx    context.Context
	clock  *activityClock
	rx     BandwidthFlow
}

func (s *udpForwardSession) close() {
	s.clock.stop()
	_ = s.guest.Close()
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
	// Set before starting the relay workers. The sandbox owns the shaper.
	bandwidth *BandwidthShaper
	// Set before starting the relay workers. The sandbox owns the policy.
	natPolicy *NATPolicy

	// UDP sends share this gate. Save, rebind, and close drain active guest writes.
	// Acquire it before mu when an operation needs both.
	udpHandoff sync.RWMutex

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

	// Dynamic host loopback publishing state. dynMu serializes
	// reconcileDynamicPorts calls (lock order: dynMu before mu); mu guards the
	// fields below.
	dynMu      sync.Mutex
	dynEnabled bool
	dynOpts    DynamicForwardOptions
	dynPollCh  chan struct{}
	dynTCP     map[dynPortKey]*boundTCPForward
	dynUDP     map[dynPortKey]*boundUDPForward
	dynFailed  map[dynPortKey]struct{}

	// Control-socket dynamic rules (precedence: static > dynamic > auto).
	maxDynamicPorts int
	manualTCP       []*boundTCPForward
	manualUDP       []*boundUDPForward
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
		maxDynamicPorts:   t.Int(tuning.ForwardMaxDynamicPorts),
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
// Static rules appear first in PreBind order, followed by dynamic control rules,
// followed by active auto-published loopback rules sorted by protocol and port.
func (pf *PortForwarder) BoundRules() []PortForwardRule {
	withSrc := pf.BoundRulesWithSource()
	out := make([]PortForwardRule, len(withSrc))
	for i, b := range withSrc {
		out[i] = b.Rule
	}
	return out
}

// BoundRulesWithSource returns all active port forward rules tagged with their
// origin ("static", "dynamic", or "auto").
func (pf *PortForwarder) BoundRulesWithSource() []BoundPortRule {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	out := make([]BoundPortRule, 0, len(pf.tcpList)+len(pf.udpList)+len(pf.manualTCP)+len(pf.manualUDP)+len(pf.dynTCP)+len(pf.dynUDP))
	for _, b := range pf.tcpList {
		out = append(out, BoundPortRule{Rule: b.rule, Source: PortSourceStatic})
	}
	for _, b := range pf.udpList {
		out = append(out, BoundPortRule{Rule: b.rule, Source: PortSourceStatic})
	}
	for _, b := range pf.manualTCP {
		out = append(out, BoundPortRule{Rule: b.rule, Source: PortSourceDynamic})
	}
	for _, b := range pf.manualUDP {
		out = append(out, BoundPortRule{Rule: b.rule, Source: PortSourceDynamic})
	}
	if len(pf.dynTCP)+len(pf.dynUDP) > 0 {
		keys := make([]dynPortKey, 0, len(pf.dynTCP)+len(pf.dynUDP))
		for k := range pf.dynTCP {
			keys = append(keys, k)
		}
		for k := range pf.dynUDP {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, compareDynPortKey)
		for _, k := range keys {
			if k.proto == "tcp" {
				if b, ok := pf.dynTCP[k]; ok {
					out = append(out, BoundPortRule{Rule: b.rule, Source: PortSourceAuto})
				}
			} else if b, ok := pf.dynUDP[k]; ok {
				out = append(out, BoundPortRule{Rule: b.rule, Source: PortSourceAuto})
			}
		}
	}
	return out
}

// SetGuestDialWindow updates the guest dial retry window for future TCP forwards.
func (pf *PortForwarder) SetGuestDialWindow(d time.Duration) {
	if d <= 0 {
		return
	}
	pf.mu.Lock()
	pf.guestDialWindow = d
	pf.mu.Unlock()
}

// SetUDPIdleTimeout updates the idle timeout for future UDP forward sessions.
func (pf *PortForwarder) SetUDPIdleTimeout(d time.Duration) {
	if d <= 0 {
		return
	}
	pf.mu.Lock()
	pf.udpIdle = d
	pf.mu.Unlock()
}

// SetDynamicPollInterval updates the reconcile interval of auto-published ports.
func (pf *PortForwarder) SetDynamicPollInterval(d time.Duration) {
	if d <= 0 {
		return
	}
	pf.mu.Lock()
	pf.dynOpts.PollInterval = d
	ch := pf.dynPollCh
	pf.mu.Unlock()
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// SetAccept sets the accept function used for pre-bound TCP and Unix listeners.
// When fn is nil, PortForwarder calls net.Listener.Accept directly.
func (pf *PortForwarder) SetAccept(fn func(net.Listener) (net.Conn, error)) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	pf.accept = fn
}

// SetBandwidthShaper shares the sandbox's bandwidth budget with all port rules.
// It has no effect after the forwarder starts or closes.
func (pf *PortForwarder) SetBandwidthShaper(shaper *BandwidthShaper) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	if !pf.started && !pf.closed {
		pf.bandwidth = shaper
	}
}

// SetNATPolicy shares the sandbox's ingress policy with all port rules.
// It has no effect after the forwarder starts or closes.
func (pf *PortForwarder) SetNATPolicy(policy *NATPolicy) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	if !pf.started && !pf.closed {
		pf.natPolicy = policy
	}
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
	for _, b := range pf.manualTCP {
		pf.wg.Add(1)
		go pf.serveTCP(b)
	}
	for _, b := range pf.udpList {
		pf.wg.Add(1)
		go pf.serveUDP(b)
	}
	for _, b := range pf.manualUDP {
		pf.wg.Add(1)
		go pf.serveUDP(b)
	}
	if pf.dynEnabled {
		pf.wg.Add(1)
		go pf.runDynamicLoop()
	}
}

// AttachRestoredStack rebinds all pre-bound TCP, Unix, and UDP port forwarders
// to target the restored guest Netstack s without opening new host sockets. If
// Start has not run yet, AttachRestoredStack starts the relay workers on s.
func (pf *PortForwarder) AttachRestoredStack(s *stack.Stack) error {
	if s == nil {
		return errors.New("netbackend: restored stack is nil")
	}
	pf.udpHandoff.Lock()
	defer pf.udpHandoff.Unlock()
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
		for _, b := range pf.manualTCP {
			pf.wg.Add(1)
			go pf.serveTCP(b)
		}
		for _, b := range pf.udpList {
			pf.wg.Add(1)
			go pf.serveUDP(b)
		}
		for _, b := range pf.manualUDP {
			pf.wg.Add(1)
			go pf.serveUDP(b)
		}
		if pf.dynEnabled {
			pf.wg.Add(1)
			go pf.runDynamicLoop()
		}
		pf.mu.Unlock()
		return nil
	}
	pf.stack = s
	clear(pf.dynFailed)
	var stale []*udpForwardSession
	for _, b := range pf.udpList {
		stale = b.detachSessions(stale)
	}
	for _, b := range pf.manualUDP {
		stale = b.detachSessions(stale)
	}
	for _, b := range pf.dynUDP {
		stale = b.detachSessions(stale)
	}
	pf.mu.Unlock()
	for _, sess := range stale {
		sess.close()
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
	pf.udpHandoff.Lock()
	defer pf.udpHandoff.Unlock()
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

// waitResumed blocks while the forwarder is quiesced or until ctx ends.
func (pf *PortForwarder) waitResumed(ctx context.Context) {
	pf.mu.Lock()
	ch := pf.resumed
	pf.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case <-ch:
	case <-ctx.Done():
	}
}

// quiescedGuestConn gates the writes of a relay into the guest Netstack on
// the pause of PortForwarder.QuiesceForSave.
type quiescedGuestConn struct {
	*gonet.TCPConn
	ctx  context.Context
	wait func(context.Context)
}

// Write implements net.Conn.Write.
func (c quiescedGuestConn) Write(p []byte) (int, error) {
	c.wait(c.ctx)
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
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
	hostPort := b.rule.HostPort
	pf.mu.Unlock()
	if acceptFn == nil {
		acceptFn = net.Listener.Accept
	}
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
			pf.log.Warn("netbackend: accept on forwarded port failed", "port", hostPort, "retry_in", backoff, "error", err)
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
		pf.waitResumed(pf.ctx)
		pf.mu.Lock()
		r := b.rule
		pf.mu.Unlock()
		guestAddr := parseGuestFullAddr(r.GuestIP, r.GuestPort)
		fallback := allowsLoopbackFallback(r.GuestIP)
		var client netip.Addr
		if pf.natPolicy != nil && r.HostSocket == "" {
			if addr, ok := hostConn.RemoteAddr().(*net.TCPAddr); ok {
				client = addr.AddrPort().Addr().Unmap()
			}
		}
		// Unix publications have no IP identity. Track them as unknown so that activating policy revokes them.
		if !pf.spawn(func() { pf.relayTCPClient(guestAddr, fallback, client, hostConn) }) {
			_ = hostConn.Close()
			return
		}
	}
}

// relayTCPClient connects hostConn to the guest endpoint and relays both
// streams. The guest may start listening after the host client connects, so
// the dial retries during the guest dial window.
func (pf *PortForwarder) relayTCPClient(guestAddr tcpip.FullAddress, fallback bool, client netip.Addr, hostConn net.Conn) {
	defer func() { _ = hostConn.Close() }()

	pf.mu.Lock()
	dialWindow := pf.guestDialWindow
	dialInterval := pf.guestDialInterval
	pf.mu.Unlock()
	ctx, cancel := context.WithTimeout(pf.ctx, dialWindow)
	defer cancel()
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for ctx.Err() == nil {
		var err error
		if s := pf.targetStack(); s != nil {
			guestConn, flowCtx, untrack, dialErr := pf.dialGuestTCP(ctx, s, guestAddr, fallback, client)
			if dialErr == nil {
				cancel()
				defer untrack()
				defer func() { _ = guestConn.Close() }()
				if flowCtx.Err() == nil {
					relayBidirectional(flowCtx, quiescedGuestConn{TCPConn: guestConn, ctx: flowCtx, wait: pf.waitResumed}, hostConn, pf.bandwidth)
				}
				return
			}
			if dialErr == errPublishedTCPDenied {
				return
			}
			err = dialErr
		} else {
			err = errors.New("target stack is nil")
		}
		if ctx.Err() != nil {
			return
		}
		if timer == nil {
			timer = time.NewTimer(dialInterval)
		} else {
			timer.Reset(dialInterval)
		}
		select {
		case <-ctx.Done():
			pf.log.Debug("netbackend: dial guest for forwarded connection", "guest", guestAddr.Addr, "port", guestAddr.Port, "error", err)
			return
		case <-timer.C:
		}
	}
}

func (pf *PortForwarder) dialGuestTCP(ctx context.Context, s *stack.Stack, guestAddr tcpip.FullAddress, fallback bool, client netip.Addr) (*gonet.TCPConn, context.Context, func(), error) {
	targets := [2]tcpip.FullAddress{guestAddr}
	count := 1
	if fallback {
		targets[1] = guestLoopbackAddr(guestAddr.Port)
		count++
		if prefersGuestLoopback(s, header.TCPProtocolNumber, guestAddr) {
			targets[0], targets[1] = targets[1], targets[0]
		}
	}
	lastErr := errPublishedTCPDenied
	for _, target := range targets[:count] {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, err
		}
		flowCtx, untrack, allowed := pf.trackPublishedFlow(header.TCPProtocolNumber, client, target)
		if !allowed {
			continue
		}
		dialCtx := ctx
		var cancel context.CancelFunc
		if pf.natPolicy != nil {
			// The dial window must not end an established relay.
			deadline, _ := ctx.Deadline()
			dialCtx, cancel = context.WithDeadline(flowCtx, deadline)
		}
		conn, err := gonet.DialContextTCP(dialCtx, s, target, ipv4.ProtocolNumber)
		if cancel != nil {
			cancel()
		}
		if err == nil {
			return conn, flowCtx, untrack, nil
		}
		lastErr = err
		untrack()
	}
	return nil, nil, nil, lastErr
}

func (pf *PortForwarder) trackPublishedFlow(proto tcpip.TransportProtocolNumber, client netip.Addr, target tcpip.FullAddress) (context.Context, func(), bool) {
	guest := target.Addr
	if guest.Unspecified() {
		// Netstack connects an unbound endpoint with an unspecified destination to loopback.
		guest = guestLoopbackIPv4
	}
	return pf.natPolicy.Track(pf.ctx, NATPolicyFlow{
		Direction: NATPolicyIngress,
		Protocol:  uint8(proto),
		Guest:     netip.AddrFrom4(guest.As4()),
		Remote:    client,
		Port:      target.Port,
		PortKnown: true,
	})
}

func (pf *PortForwarder) serveUDP(b *boundUDPForward) {
	defer pf.wg.Done()
	pf.mu.Lock()
	hostPort := b.rule.HostPort
	pf.mu.Unlock()
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
			pf.log.Warn("netbackend: read on forwarded UDP port failed", "port", hostPort, "retry_in", backoff, "error", err)
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
		pf.waitResumed(pf.ctx)
		sess := pf.udpSession(b, client)
		if sess == nil {
			continue
		}
		pf.forwardUDPToGuest(b, sess, buf[:n])
	}
}

func (pf *PortForwarder) forwardUDPToGuest(b *boundUDPForward, sess *udpForwardSession, p []byte) {
	if sess.ctx.Err() != nil || !sess.clock.beginSend() {
		return
	}
	shaper := pf.bandwidth
	if shaper.Enabled(BandwidthRX) || sess.rx.Pending() {
		ctx, ok := sess.clock.sendContext(sess.ctx)
		if !ok {
			sess.clock.finishSend(false)
			return
		}
		pkt := bytes.Clone(p)
		var attempted bool
		shaper.EnqueueOrdered(ctx, BandwidthRX, &sess.rx, len(pkt), func() (int, error) {
			n, err := pf.sendPublishedDatagram(b, sess, pkt)
			attempted = !errors.Is(err, net.ErrClosed)
			return n, err
		}, func() { sess.clock.finishSend(attempted) })
		return
	}
	var err error
	if sess.ctx.Err() != nil {
		err = net.ErrClosed
	} else if shaper == nil {
		_, err = sess.guest.Write(p)
	} else {
		_, err = pf.sendPublishedDatagram(b, sess, p)
	}
	sess.clock.finishSend(!errors.Is(err, net.ErrClosed))
	if err != nil && !errors.Is(err, net.ErrClosed) {
		pf.log.Debug("netbackend: write forwarded datagram to guest", "client", sess.client, "error", err)
	}
}

func (pf *PortForwarder) sendPublishedDatagram(b *boundUDPForward, sess *udpForwardSession, p []byte) (int, error) {
	pf.udpHandoff.RLock()
	defer pf.udpHandoff.RUnlock()
	pf.mu.Lock()
	active := !pf.closed && pf.resumed == nil && b.sessions[sess.client] == sess
	pf.mu.Unlock()
	if !active || sess.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	// The scheduler must not wait on gonet's writable event when the endpoint cannot send.
	n, err := sess.ep.Write(bytes.NewReader(p), tcpip.WriteOptions{Atomic: true})
	if err != nil {
		return int(n), errors.New(err.String())
	}
	return int(n), nil
}

// udpSession returns the session of client. It creates the session and its
// reply goroutine on the first datagram. It returns nil when the forwarder is
// closed, the rule is at its session limit, or the guest endpoint fails.
func (pf *PortForwarder) udpSession(b *boundUDPForward, client netip.AddrPort) *udpForwardSession {
	pf.mu.Lock()
	if pf.closed || b.closed || pf.stack == nil {
		pf.mu.Unlock()
		return nil
	}
	if sess, ok := b.sessions[client]; ok {
		if sess.ctx.Err() == nil {
			pf.mu.Unlock()
			return sess
		}
		delete(b.sessions, client)
	}
	if len(b.sessions) >= pf.udpMaxSessions {
		hostPort := b.rule.HostPort
		pf.mu.Unlock()
		pf.log.Warn("netbackend: UDP forward session limit reached", "port", hostPort, "client", client)
		return nil
	}
	s := pf.stack
	r := b.rule
	pf.mu.Unlock()

	guestAddr := parseGuestFullAddr(r.GuestIP, r.GuestPort)
	fallback := allowsLoopbackFallback(r.GuestIP)
	target := guestAddr
	if fallback && prefersGuestLoopback(s, header.UDPProtocolNumber, guestAddr) {
		target = guestLoopbackAddr(guestAddr.Port)
	}
	flowCtx, untrack, allowed := pf.trackPublishedFlow(header.UDPProtocolNumber, client.Addr().Unmap(), target)
	if !allowed {
		return nil
	}
	var ep tcpip.Endpoint
	var guest *gonet.UDPConn
	if pf.bandwidth == nil {
		var err error
		guest, err = gonet.DialUDP(s, nil, &target, ipv4.ProtocolNumber)
		if err != nil {
			untrack()
			pf.log.Debug("netbackend: open guest UDP endpoint", "client", client, "error", err)
			return nil
		}
	} else {
		var wq waiter.Queue
		var err tcpip.Error
		ep, err = s.NewEndpoint(header.UDPProtocolNumber, ipv4.ProtocolNumber, &wq)
		if err != nil {
			untrack()
			pf.log.Debug("netbackend: open guest UDP endpoint", "client", client, "error", err.String())
			return nil
		}
		if err := ep.Connect(target); err != nil {
			ep.Close()
			untrack()
			pf.log.Debug("netbackend: connect guest UDP endpoint", "client", client, "error", err.String())
			return nil
		}
		guest = gonet.NewUDPConn(&wq, ep)
	}
	sess := &udpForwardSession{client: client, guest: guest, ep: ep, ctx: flowCtx, clock: newActivityClock()}

	// Only this rule's serveUDP goroutine inserts sessions, so the earlier
	// lookup cannot race with another insert for the same key.
	pf.mu.Lock()
	if pf.closed || b.closed || pf.stack != s || b.rule != r || flowCtx.Err() != nil {
		pf.mu.Unlock()
		untrack()
		_ = guest.Close()
		return nil
	}
	b.sessions[client] = sess
	pf.wg.Add(1)
	pf.mu.Unlock()
	go pf.runUDPSession(b, sess, untrack)
	return sess
}

// runUDPSession forwards every guest reply to the host client until the
// session is idle in both directions or its guest endpoint closes.
func (pf *PortForwarder) runUDPSession(b *boundUDPForward, sess *udpForwardSession, untrack func()) {
	defer pf.wg.Done()
	defer untrack()
	if pf.natPolicy != nil {
		stop := context.AfterFunc(sess.ctx, func() { _ = sess.guest.Close() })
		defer stop()
	}
	defer func() {
		pf.mu.Lock()
		if b.sessions[sess.client] == sess {
			delete(b.sessions, sess.client)
		}
		pf.mu.Unlock()
		sess.close()
	}()
	pf.mu.Lock()
	udpIdle := pf.udpIdle
	pf.mu.Unlock()
	pumpDatagrams(sess.guest, func(p []byte) error {
		err := sendRelayDatagram(sess.ctx, sess.clock, pf.bandwidth, BandwidthTX, len(p), func() (int, error) {
			if sess.ctx.Err() != nil {
				return 0, net.ErrClosed
			}
			return b.packetConn.WriteToUDPAddrPort(p, sess.client)
		})
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, errBandwidthQueueFull) {
			pf.log.Debug("netbackend: write guest reply to host client", "client", sess.client, "error", err)
		}
		return err
	}, sess.clock, udpIdle)
}

var guestLoopbackIPv4 = tcpip.AddrFrom4([4]byte{127, 0, 0, 1})

func guestLoopbackAddr(port uint16) tcpip.FullAddress {
	return tcpip.FullAddress{
		NIC:  LoopbackNICID,
		Addr: guestLoopbackIPv4,
		Port: port,
	}
}

func allowsLoopbackFallback(guestIP string) bool {
	return guestIP == "" || guestIP == DefaultGuestIPv4
}

func prefersGuestLoopback(s *stack.Stack, transProto tcpip.TransportProtocolNumber, guestAddr tcpip.FullAddress) bool {
	if s.HasBoundEndpoint(header.IPv4ProtocolNumber, transProto, guestAddr.Addr, guestAddr.Port) {
		return false
	}
	if s.HasBoundEndpoint(header.IPv4ProtocolNumber, transProto, tcpip.Address{}, guestAddr.Port) {
		return false
	}
	return s.HasBoundEndpoint(header.IPv4ProtocolNumber, transProto, guestLoopbackIPv4, guestAddr.Port)
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
	nic := Eth0NICID
	if addr.IsLoopback() {
		nic = LoopbackNICID
	}
	return tcpip.FullAddress{
		NIC:  nic,
		Addr: tcpip.AddrFrom4(addr.As4()),
		Port: port,
	}
}

// Close stops all pre-bound host listeners, closes every UDP session, and
// waits for active relays. It closes the session endpoints before it waits,
// so a guest that never answers cannot block Close.
func (pf *PortForwarder) Close() error {
	pf.udpHandoff.Lock()
	pf.mu.Lock()
	if pf.closed {
		pf.mu.Unlock()
		pf.udpHandoff.Unlock()
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
	for _, b := range pf.manualTCP {
		if err := b.listener.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	pf.manualTCP = nil
	for _, b := range pf.dynTCP {
		if err := b.listener.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	clear(pf.dynTCP)
	var sessions []*udpForwardSession
	for _, b := range pf.udpList {
		b.closed = true
		if err := b.packetConn.Close(); err != nil {
			errs = append(errs, err)
		}
		sessions = b.detachSessions(sessions)
	}
	for _, b := range pf.manualUDP {
		b.closed = true
		if err := b.packetConn.Close(); err != nil {
			errs = append(errs, err)
		}
		sessions = b.detachSessions(sessions)
	}
	pf.manualUDP = nil
	for _, b := range pf.dynUDP {
		b.closed = true
		if err := b.packetConn.Close(); err != nil {
			errs = append(errs, err)
		}
		sessions = b.detachSessions(sessions)
	}
	clear(pf.dynUDP)
	clear(pf.dynFailed)
	pf.mu.Unlock()
	pf.udpHandoff.Unlock()
	for _, sess := range sessions {
		sess.close()
	}
	pf.wg.Wait()
	return errors.Join(errs...)
}
