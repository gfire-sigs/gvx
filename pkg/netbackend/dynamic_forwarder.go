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
	"cmp"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

const (
	defaultDynamicMaxPorts     = 64
	defaultDynamicPollInterval = 200 * time.Millisecond
)

// DynamicForwardOptions configures automatic host loopback publishing of guest
// TCP listeners and iptables NAT DNAT published ports.
type DynamicForwardOptions struct {
	// ListenTCP binds a host loopback TCP listener. Defaults to net.Listen.
	ListenTCP func(network, address string) (net.Listener, error)

	// ListenUDP binds a host loopback UDP socket. Defaults to net.ListenPacket.
	ListenUDP func(network, address string) (net.PacketConn, error)

	// MaxPorts bounds how many dynamic host listeners may stay open at once.
	MaxPorts int

	// PollInterval sets how often the guest stack is reconciled.
	PollInterval time.Duration

	// OnPublish is called after a dynamic forward opens (added=true) or closes
	// (added=false).
	OnPublish func(rule PortForwardRule, added bool)

	// OnBindError is called once per guest port when binding on 127.0.0.1 fails.
	OnBindError func(proto string, port uint16, err error)
}

type dynPortKey struct {
	proto string
	port  uint16
}

type dstPortRangeMatcher interface {
	DestinationPortRange() (start, end uint16, inverted bool)
}

type dnatTargetMarker interface {
	IsDNATTarget() bool
}

// EnableDynamicLoopback configures automatic host 127.0.0.1 publishing for
// guest TCP listeners and iptables NAT DNAT ports. Static rules bound by
// PreBind take precedence and are never shadowed by dynamic binds.
func (pf *PortForwarder) EnableDynamicLoopback(opts DynamicForwardOptions) {
	if opts.ListenTCP == nil {
		opts.ListenTCP = net.Listen
	}
	if opts.ListenUDP == nil {
		opts.ListenUDP = net.ListenPacket
	}
	if opts.MaxPorts <= 0 {
		opts.MaxPorts = defaultDynamicMaxPorts
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = defaultDynamicPollInterval
	}

	pf.mu.Lock()
	if pf.closed {
		pf.mu.Unlock()
		return
	}
	alreadyRunning := pf.dynEnabled && pf.started
	pf.dynEnabled = true
	pf.dynOpts = opts
	if pf.dynPollCh == nil {
		pf.dynPollCh = make(chan struct{}, 1)
	}
	if pf.dynTCP == nil {
		pf.dynTCP = make(map[dynPortKey]*boundTCPForward)
	}
	if pf.dynUDP == nil {
		pf.dynUDP = make(map[dynPortKey]*boundUDPForward)
	}
	if pf.dynFailed == nil {
		pf.dynFailed = make(map[dynPortKey]struct{})
	}
	startNow := pf.started && !alreadyRunning
	if startNow {
		pf.wg.Add(1)
	}
	pf.mu.Unlock()

	if startNow {
		go pf.runDynamicLoop()
	}
}

func (pf *PortForwarder) runDynamicLoop() {
	defer pf.wg.Done()
	pf.reconcileDynamicPorts()
	pf.mu.Lock()
	interval := pf.dynOpts.PollInterval
	pollCh := pf.dynPollCh
	pf.mu.Unlock()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-pf.ctx.Done():
			return
		case <-pollCh:
			pf.mu.Lock()
			next := pf.dynOpts.PollInterval
			pf.mu.Unlock()
			if next > 0 && next != interval {
				interval = next
				ticker.Reset(interval)
			}
		case <-ticker.C:
			pf.reconcileDynamicPorts()
		}
	}
}

type dynCandidate struct {
	key     dynPortKey
	guestIP string
}

type removedDynTCP struct {
	fwd *boundTCPForward
}

type removedDynUDP struct {
	fwd      *boundUDPForward
	sessions []*udpForwardSession
}

func (pf *PortForwarder) reconcileDynamicPorts() {
	pf.dynMu.Lock()
	defer pf.dynMu.Unlock()

	pf.mu.Lock()
	if pf.closed || pf.resumed != nil || pf.stack == nil || !pf.dynEnabled {
		pf.mu.Unlock()
		return
	}
	s := pf.stack
	opts := pf.dynOpts
	staticKeys := make(map[dynPortKey]struct{}, len(pf.tcpList)+len(pf.udpList)+len(pf.manualTCP)+len(pf.manualUDP))
	for _, b := range pf.tcpList {
		staticKeys[dynPortKey{proto: "tcp", port: b.rule.GuestPort}] = struct{}{}
	}
	for _, b := range pf.udpList {
		staticKeys[dynPortKey{proto: "udp", port: b.rule.GuestPort}] = struct{}{}
	}
	for _, b := range pf.manualTCP {
		staticKeys[dynPortKey{proto: "tcp", port: b.rule.GuestPort}] = struct{}{}
		staticKeys[dynPortKey{proto: "tcp", port: b.rule.HostPort}] = struct{}{}
	}
	for _, b := range pf.manualUDP {
		staticKeys[dynPortKey{proto: "udp", port: b.rule.GuestPort}] = struct{}{}
		staticKeys[dynPortKey{proto: "udp", port: b.rule.HostPort}] = struct{}{}
	}
	pf.mu.Unlock()

	discovered := discoverGuestPublishedPorts(s)

	var remTCP []removedDynTCP
	var remUDP []removedDynUDP
	var toAdd []dynCandidate

	pf.mu.Lock()
	if pf.closed || pf.resumed != nil || pf.stack != s {
		pf.mu.Unlock()
		return
	}
	for k, b := range pf.dynTCP {
		if guestIP, ok := discovered[k]; !ok || guestIP != b.rule.GuestIP {
			delete(pf.dynTCP, k)
			remTCP = append(remTCP, removedDynTCP{fwd: b})
		}
	}
	for k, b := range pf.dynUDP {
		if guestIP, ok := discovered[k]; !ok || guestIP != b.rule.GuestIP {
			b.closed = true
			delete(pf.dynUDP, k)
			remUDP = append(remUDP, removedDynUDP{fwd: b, sessions: b.detachSessions(nil)})
		}
	}
	for k := range pf.dynFailed {
		if _, ok := discovered[k]; !ok {
			delete(pf.dynFailed, k)
		}
	}

	activeCount := len(pf.dynTCP) + len(pf.dynUDP)
	keys := make([]dynPortKey, 0, len(discovered))
	for k := range discovered {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, compareDynPortKey)
	for _, k := range keys {
		if activeCount+len(toAdd) >= opts.MaxPorts {
			break
		}
		if _, isStatic := staticKeys[k]; isStatic {
			continue
		}
		if _, failed := pf.dynFailed[k]; failed {
			continue
		}
		if k.proto == "tcp" {
			if _, ok := pf.dynTCP[k]; ok {
				continue
			}
		} else {
			if _, ok := pf.dynUDP[k]; ok {
				continue
			}
		}
		toAdd = append(toAdd, dynCandidate{key: k, guestIP: discovered[k]})
	}
	pf.mu.Unlock()

	for _, r := range remTCP {
		_ = r.fwd.listener.Close()
		if opts.OnPublish != nil {
			opts.OnPublish(r.fwd.rule, false)
		}
	}
	for _, r := range remUDP {
		_ = r.fwd.packetConn.Close()
		for _, sess := range r.sessions {
			sess.close()
		}
		if opts.OnPublish != nil {
			opts.OnPublish(r.fwd.rule, false)
		}
	}

	for _, cand := range toAdd {
		pf.bindDynamicCandidate(s, opts, cand)
	}
}

func (pf *PortForwarder) bindDynamicCandidate(s *stack.Stack, opts DynamicForwardOptions, cand dynCandidate) {
	bindAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(cand.key.port)))
	rule := PortForwardRule{
		Proto:     cand.key.proto,
		HostIP:    "127.0.0.1",
		HostPort:  cand.key.port,
		GuestIP:   cand.guestIP,
		GuestPort: cand.key.port,
	}

	switch cand.key.proto {
	case "tcp":
		ln, err := opts.ListenTCP("tcp4", bindAddr)
		if err != nil {
			pf.recordDynamicBindError(opts, cand.key, err)
			return
		}
		entry := &boundTCPForward{rule: rule, listener: ln}
		pf.mu.Lock()
		if pf.closed || pf.resumed != nil || pf.stack != s || len(pf.dynTCP)+len(pf.dynUDP) >= opts.MaxPorts {
			pf.mu.Unlock()
			_ = ln.Close()
			return
		}
		if _, exists := pf.dynTCP[cand.key]; exists {
			pf.mu.Unlock()
			_ = ln.Close()
			return
		}
		pf.dynTCP[cand.key] = entry
		pf.wg.Add(1)
		pf.mu.Unlock()
		go pf.serveTCP(entry)
		if opts.OnPublish != nil {
			opts.OnPublish(rule, true)
		}

	case "udp":
		pc, err := opts.ListenUDP("udp4", bindAddr)
		if err != nil {
			pf.recordDynamicBindError(opts, cand.key, err)
			return
		}
		udpConn, ok := pc.(*net.UDPConn)
		if !ok {
			_ = pc.Close()
			pf.recordDynamicBindError(opts, cand.key, fmt.Errorf("netbackend: dynamic udp socket is %T, want *net.UDPConn", pc))
			return
		}
		widenUDPSend(udpConn)
		entry := &boundUDPForward{
			rule:       rule,
			packetConn: udpConn,
			sessions:   make(map[netip.AddrPort]*udpForwardSession),
		}
		pf.mu.Lock()
		if pf.closed || pf.resumed != nil || pf.stack != s || len(pf.dynTCP)+len(pf.dynUDP) >= opts.MaxPorts {
			pf.mu.Unlock()
			_ = udpConn.Close()
			return
		}
		if _, exists := pf.dynUDP[cand.key]; exists {
			pf.mu.Unlock()
			_ = udpConn.Close()
			return
		}
		pf.dynUDP[cand.key] = entry
		pf.wg.Add(1)
		pf.mu.Unlock()
		go pf.serveUDP(entry)
		if opts.OnPublish != nil {
			opts.OnPublish(rule, true)
		}
	}
}

func (pf *PortForwarder) recordDynamicBindError(opts DynamicForwardOptions, key dynPortKey, err error) {
	notify := false
	pf.mu.Lock()
	if !pf.closed {
		if _, seen := pf.dynFailed[key]; !seen {
			pf.dynFailed[key] = struct{}{}
			notify = true
		}
	}
	pf.mu.Unlock()
	if notify && opts.OnBindError != nil {
		opts.OnBindError(key.proto, key.port, err)
	}
}

func compareDynPortKey(a, b dynPortKey) int {
	if c := cmp.Compare(a.proto, b.proto); c != 0 {
		return c
	}
	return cmp.Compare(a.port, b.port)
}

var defaultGuestIPv4Addr = tcpip.AddrFrom4([4]byte{10, 0, 2, 15})

func ipv4MatchesSubnet(addr, dst, mask tcpip.Address) bool {
	if dst.Len() == 0 || mask.Len() == 0 {
		return true
	}
	if addr.Len() != 4 || dst.Len() != 4 || mask.Len() != 4 {
		return false
	}
	a := addr.As4()
	d := dst.As4()
	m := mask.As4()
	return (a[0]&m[0]) == (d[0]&m[0]) &&
		(a[1]&m[1]) == (d[1]&m[1]) &&
		(a[2]&m[2]) == (d[2]&m[2]) &&
		(a[3]&m[3]) == (d[3]&m[3])
}

// discoverGuestPublishedPorts collects TCP listening endpoints and IPv4
// iptables NAT DNAT rules in s that target wildcard, eth0 (10.0.2.15), or
// loopback (127.0.0.1) addresses.
func discoverGuestPublishedPorts(s *stack.Stack) map[dynPortKey]string {
	out := make(map[dynPortKey]string)
	if s == nil {
		return out
	}

	for _, ep := range s.ListeningEndpoints() {
		if ep.LocalPort == 0 || ep.TransProto != header.TCPProtocolNumber {
			continue
		}
		guestIP, ok := guestIPForListener(ep.NetProto, ep.LocalAddr)
		if !ok {
			continue
		}
		key := dynPortKey{proto: "tcp", port: ep.LocalPort}
		if prev, exists := out[key]; !exists || (prev == "127.0.0.1" && guestIP == DefaultGuestIPv4) {
			out[key] = guestIP
		}
	}

	if it := s.IPTables(); it != nil {
		natTable := it.GetTable(stack.NATID, false)
		for _, rule := range natTable.Rules {
			dt, isDNAT := rule.Target.(dnatTargetMarker)
			if !isDNAT || !dt.IsDNATTarget() {
				continue
			}
			if !rule.Filter.CheckProtocol {
				continue
			}
			var proto string
			switch rule.Filter.Protocol {
			case header.TCPProtocolNumber:
				proto = "tcp"
			case header.UDPProtocolNumber:
				proto = "udp"
			default:
				continue
			}
			guestIP, ok := guestIPForDNATFilter(rule.Filter)
			if !ok {
				continue
			}
			for _, m := range rule.Matchers {
				pm, ok := m.(dstPortRangeMatcher)
				if !ok {
					continue
				}
				start, end, inverted := pm.DestinationPortRange()
				if inverted || start == 0 || start != end {
					continue
				}
				key := dynPortKey{proto: proto, port: start}
				if prev, exists := out[key]; !exists || (prev == "127.0.0.1" && guestIP == DefaultGuestIPv4) {
					out[key] = guestIP
				}
			}
		}
	}
	return out
}

// guestIPForListener maps IPv4 listening endpoints (including the IPv4 entry
// registered by dual-stack [::] sockets) to a dialable guest IPv4 address.
// IPv6-only listeners are skipped because PortForwarder dials guest IPv4 only.
func guestIPForListener(netProto tcpip.NetworkProtocolNumber, addr tcpip.Address) (string, bool) {
	if netProto != header.IPv4ProtocolNumber {
		return "", false
	}
	if addr.Len() == 0 || addr == defaultGuestIPv4Addr {
		return DefaultGuestIPv4, true
	}
	if addr == guestLoopbackIPv4 {
		return "127.0.0.1", true
	}
	return "", false
}

func guestIPForDNATFilter(f stack.IPHeaderFilter) (string, bool) {
	if f.DstInvert {
		return "", false
	}
	if ipv4MatchesSubnet(defaultGuestIPv4Addr, f.Dst, f.DstMask) {
		return DefaultGuestIPv4, true
	}
	if ipv4MatchesSubnet(guestLoopbackIPv4, f.Dst, f.DstMask) {
		return "127.0.0.1", true
	}
	return "", false
}
