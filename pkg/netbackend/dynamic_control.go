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
	"net"
	"net/netip"
	"strconv"
	"strings"
)

func portBindingsMatch(a, b PortForwardRule) bool {
	if a.Proto != b.Proto {
		return false
	}
	if a.HostSocket != "" || b.HostSocket != "" {
		return a.HostSocket != "" && a.HostSocket == b.HostSocket
	}
	return a.HostPort != 0 && a.HostPort == b.HostPort && a.HostIP == b.HostIP
}

type dynamicUndoKind uint8

const (
	undoAddedTCP dynamicUndoKind = iota + 1
	undoAddedUDP
	undoReplaceManualTCP
	undoPromoteAutoTCP
	undoReplaceManualUDP
	undoPromoteAutoUDP
)

type dynamicRuleUndo struct {
	kind     dynamicUndoKind
	tcpEntry *boundTCPForward
	udpEntry *boundUDPForward
	prevRule PortForwardRule
	autoKey  dynPortKey
}

// AddDynamicRule binds one runtime control-socket port forward rule and starts
// relaying immediately when the PortForwarder is already started. Static rules
// always win; an auto-published rule on the same host binding is promoted in place.
func (pf *PortForwarder) AddDynamicRule(
	rule PortForwardRule,
	replace bool,
	listenTCP func(network, address string) (net.Listener, error),
	listenUDP func(network, address string) (net.PacketConn, error),
) (PortForwardRule, error) {
	pf.dynMu.Lock()
	defer pf.dynMu.Unlock()
	bound, _, err := pf.addDynamicRuleLocked(rule, replace, listenTCP, listenUDP)
	return bound, err
}

// AddDynamicRules binds a batch of runtime control-socket port forward rules
// atomically under dynMu. If any rule fails, earlier entries in the batch are
// rolled back in reverse order: newly bound sockets are closed and in-place
// replacements are restored to their prior rules without closing live sockets.
func (pf *PortForwarder) AddDynamicRules(
	rules []PortForwardRule,
	replace bool,
	listenTCP func(network, address string) (net.Listener, error),
	listenUDP func(network, address string) (net.PacketConn, error),
) ([]PortForwardRule, error) {
	pf.dynMu.Lock()
	defer pf.dynMu.Unlock()

	bound := make([]PortForwardRule, 0, len(rules))
	undos := make([]dynamicRuleUndo, 0, len(rules))
	for _, r := range rules {
		b, undo, err := pf.addDynamicRuleLocked(r, replace, listenTCP, listenUDP)
		if err != nil {
			pf.rollbackDynamicRulesLocked(undos)
			return nil, err
		}
		bound = append(bound, b)
		undos = append(undos, undo)
	}
	return bound, nil
}

func (pf *PortForwarder) rollbackDynamicRulesLocked(undos []dynamicRuleUndo) {
	if len(undos) == 0 {
		return
	}
	var (
		closeTCP     []*boundTCPForward
		closeUDP     []*boundUDPForward
		closeUDPConn []gonetUDPCloser
	)
	pf.mu.Lock()
	if pf.closed {
		pf.mu.Unlock()
		return
	}
	for i := len(undos) - 1; i >= 0; i-- {
		u := undos[i]
		switch u.kind {
		case undoAddedTCP:
			pf.manualTCP = removeTCPForwardEntry(pf.manualTCP, u.tcpEntry)
			closeTCP = append(closeTCP, u.tcpEntry)
		case undoAddedUDP:
			pf.manualUDP = removeUDPForwardEntry(pf.manualUDP, u.udpEntry)
			u.udpEntry.closed = true
			for c, s := range u.udpEntry.sessions {
				closeUDPConn = append(closeUDPConn, s.guest)
				delete(u.udpEntry.sessions, c)
			}
			closeUDP = append(closeUDP, u.udpEntry)
		case undoReplaceManualTCP:
			u.tcpEntry.rule = u.prevRule
		case undoPromoteAutoTCP:
			pf.manualTCP = removeTCPForwardEntry(pf.manualTCP, u.tcpEntry)
			u.tcpEntry.rule = u.prevRule
			if pf.dynTCP == nil {
				pf.dynTCP = make(map[dynPortKey]*boundTCPForward)
			}
			pf.dynTCP[u.autoKey] = u.tcpEntry
		case undoReplaceManualUDP:
			u.udpEntry.rule = u.prevRule
			for c, s := range u.udpEntry.sessions {
				closeUDPConn = append(closeUDPConn, s.guest)
				delete(u.udpEntry.sessions, c)
			}
		case undoPromoteAutoUDP:
			pf.manualUDP = removeUDPForwardEntry(pf.manualUDP, u.udpEntry)
			u.udpEntry.rule = u.prevRule
			for c, s := range u.udpEntry.sessions {
				closeUDPConn = append(closeUDPConn, s.guest)
				delete(u.udpEntry.sessions, c)
			}
			if pf.dynUDP == nil {
				pf.dynUDP = make(map[dynPortKey]*boundUDPForward)
			}
			pf.dynUDP[u.autoKey] = u.udpEntry
		}
	}
	pf.mu.Unlock()

	for _, b := range closeTCP {
		_ = b.listener.Close()
	}
	for _, b := range closeUDP {
		_ = b.packetConn.Close()
	}
	for _, g := range closeUDPConn {
		_ = g.Close()
	}
}

func removeTCPForwardEntry(list []*boundTCPForward, target *boundTCPForward) []*boundTCPForward {
	for i, b := range list {
		if b == target {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

func removeUDPForwardEntry(list []*boundUDPForward, target *boundUDPForward) []*boundUDPForward {
	for i, b := range list {
		if b == target {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

func (pf *PortForwarder) addDynamicRuleLocked(
	rule PortForwardRule,
	replace bool,
	listenTCP func(network, address string) (net.Listener, error),
	listenUDP func(network, address string) (net.PacketConn, error),
) (PortForwardRule, dynamicRuleUndo, error) {
	if listenTCP == nil {
		listenTCP = net.Listen
	}
	if listenUDP == nil {
		listenUDP = net.ListenPacket
	}
	proto := strings.ToLower(strings.TrimSpace(rule.Proto))
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" && proto != "udp" {
		return PortForwardRule{}, dynamicRuleUndo{}, fmt.Errorf("netbackend: unsupported protocol %q", proto)
	}
	if rule.GuestPort == 0 {
		return PortForwardRule{}, dynamicRuleUndo{}, errors.New("netbackend: guest port must be non-zero")
	}
	if rule.HostSocket != "" && proto != "tcp" {
		return PortForwardRule{}, dynamicRuleUndo{}, fmt.Errorf("netbackend: unix socket %s forwards tcp only", rule.HostSocket)
	}
	hostIP := rule.HostIP
	if hostIP == "" && rule.HostSocket == "" {
		hostIP = "127.0.0.1"
	}
	guestIP := rule.GuestIP
	if guestIP == "" {
		guestIP = DefaultGuestIPv4
	}
	norm := PortForwardRule{
		Proto:      proto,
		HostIP:     hostIP,
		HostPort:   rule.HostPort,
		GuestIP:    guestIP,
		GuestPort:  rule.GuestPort,
		HostSocket: rule.HostSocket,
	}

	var evictUDPSessions []*gonetUDPCloserHolder

	pf.mu.Lock()
	if pf.closed {
		pf.mu.Unlock()
		return PortForwardRule{}, dynamicRuleUndo{}, errors.New("netbackend: PortForwarder is closed")
	}
	// Check capacity and static conflicts before mutating any active listener.
	var (
		matchManualTCP *boundTCPForward
		matchDynTCPKey dynPortKey
		matchDynTCP    *boundTCPForward
		matchManualUDP *boundUDPForward
		matchDynUDPKey dynPortKey
		matchDynUDP    *boundUDPForward
	)
	if norm.HostPort != 0 || norm.HostSocket != "" {
		for _, b := range pf.tcpList {
			if portBindingsMatch(b.rule, norm) {
				pf.mu.Unlock()
				return PortForwardRule{}, dynamicRuleUndo{}, fmt.Errorf("%w: static rule already bound", ErrPortRuleExists)
			}
		}
		for _, b := range pf.udpList {
			if portBindingsMatch(b.rule, norm) {
				pf.mu.Unlock()
				return PortForwardRule{}, dynamicRuleUndo{}, fmt.Errorf("%w: static rule already bound", ErrPortRuleExists)
			}
		}
		if proto == "tcp" {
			for _, b := range pf.manualTCP {
				if portBindingsMatch(b.rule, norm) {
					if !replace {
						pf.mu.Unlock()
						return PortForwardRule{}, dynamicRuleUndo{}, fmt.Errorf("%w: dynamic rule already bound", ErrPortRuleExists)
					}
					matchManualTCP = b
					break
				}
			}
			for k, b := range pf.dynTCP {
				if portBindingsMatch(b.rule, norm) {
					matchDynTCPKey = k
					matchDynTCP = b
					break
				}
			}
		} else {
			for _, b := range pf.manualUDP {
				if portBindingsMatch(b.rule, norm) {
					if !replace {
						pf.mu.Unlock()
						return PortForwardRule{}, dynamicRuleUndo{}, fmt.Errorf("%w: dynamic rule already bound", ErrPortRuleExists)
					}
					matchManualUDP = b
					break
				}
			}
			for k, b := range pf.dynUDP {
				if portBindingsMatch(b.rule, norm) {
					matchDynUDPKey = k
					matchDynUDP = b
					break
				}
			}
		}
	}

	// Atomically update an existing dynamic or auto-published binding in place
	// so replacing a rule never drops the bound host socket on rebind failure.
	if matchManualTCP != nil {
		prev := matchManualTCP.rule
		matchManualTCP.rule = norm
		pf.mu.Unlock()
		return norm, dynamicRuleUndo{
			kind:     undoReplaceManualTCP,
			tcpEntry: matchManualTCP,
			prevRule: prev,
		}, nil
	}
	if matchDynTCP != nil {
		prev := matchDynTCP.rule
		delete(pf.dynTCP, matchDynTCPKey)
		matchDynTCP.rule = norm
		pf.manualTCP = append(pf.manualTCP, matchDynTCP)
		pf.mu.Unlock()
		return norm, dynamicRuleUndo{
			kind:     undoPromoteAutoTCP,
			tcpEntry: matchDynTCP,
			prevRule: prev,
			autoKey:  matchDynTCPKey,
		}, nil
	}
	if matchManualUDP != nil {
		prev := matchManualUDP.rule
		matchManualUDP.rule = norm
		for c, s := range matchManualUDP.sessions {
			evictUDPSessions = append(evictUDPSessions, &gonetUDPCloserHolder{c: s.guest})
			delete(matchManualUDP.sessions, c)
		}
		pf.mu.Unlock()
		for _, h := range evictUDPSessions {
			_ = h.c.Close()
		}
		return norm, dynamicRuleUndo{
			kind:     undoReplaceManualUDP,
			udpEntry: matchManualUDP,
			prevRule: prev,
		}, nil
	}
	if matchDynUDP != nil {
		prev := matchDynUDP.rule
		delete(pf.dynUDP, matchDynUDPKey)
		matchDynUDP.rule = norm
		for c, s := range matchDynUDP.sessions {
			evictUDPSessions = append(evictUDPSessions, &gonetUDPCloserHolder{c: s.guest})
			delete(matchDynUDP.sessions, c)
		}
		pf.manualUDP = append(pf.manualUDP, matchDynUDP)
		pf.mu.Unlock()
		for _, h := range evictUDPSessions {
			_ = h.c.Close()
		}
		return norm, dynamicRuleUndo{
			kind:     undoPromoteAutoUDP,
			udpEntry: matchDynUDP,
			prevRule: prev,
			autoKey:  matchDynUDPKey,
		}, nil
	}

	activeDynamic := len(pf.manualTCP) + len(pf.manualUDP) + len(pf.dynTCP) + len(pf.dynUDP)
	if pf.maxDynamicPorts > 0 && activeDynamic >= pf.maxDynamicPorts {
		pf.mu.Unlock()
		return PortForwardRule{}, dynamicRuleUndo{}, fmt.Errorf("%w (%d active)", ErrDynamicPortLimit, pf.maxDynamicPorts)
	}
	pf.mu.Unlock()

	if norm.HostSocket != "" {
		if proto != "tcp" {
			return PortForwardRule{}, dynamicRuleUndo{}, fmt.Errorf("netbackend: unix socket %s forwards tcp only", norm.HostSocket)
		}
		ln, err := listenUnixSocket(norm.HostSocket)
		if err != nil {
			return PortForwardRule{}, dynamicRuleUndo{}, err
		}
		entry := &boundTCPForward{rule: norm, listener: ln}
		pf.mu.Lock()
		if pf.closed {
			pf.mu.Unlock()
			_ = ln.Close()
			return PortForwardRule{}, dynamicRuleUndo{}, errors.New("netbackend: PortForwarder is closed")
		}
		pf.manualTCP = append(pf.manualTCP, entry)
		start := pf.started
		if start {
			pf.wg.Add(1)
		}
		pf.mu.Unlock()
		if start {
			go pf.serveTCP(entry)
		}
		return norm, dynamicRuleUndo{kind: undoAddedTCP, tcpEntry: entry}, nil
	}

	bindAddr := net.JoinHostPort(norm.HostIP, strconv.Itoa(int(norm.HostPort)))
	switch proto {
	case "tcp":
		ln, err := listenTCP("tcp", bindAddr)
		if err != nil {
			return PortForwardRule{}, dynamicRuleUndo{}, fmt.Errorf("netbackend: bind tcp %s: %w", bindAddr, err)
		}
		if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
			norm.HostPort = uint16(tcpAddr.Port)
		}
		entry := &boundTCPForward{rule: norm, listener: ln}
		pf.mu.Lock()
		if pf.closed {
			pf.mu.Unlock()
			_ = ln.Close()
			return PortForwardRule{}, dynamicRuleUndo{}, errors.New("netbackend: PortForwarder is closed")
		}
		pf.manualTCP = append(pf.manualTCP, entry)
		start := pf.started
		if start {
			pf.wg.Add(1)
		}
		pf.mu.Unlock()
		if start {
			go pf.serveTCP(entry)
		}
		return norm, dynamicRuleUndo{kind: undoAddedTCP, tcpEntry: entry}, nil

	case "udp":
		pc, err := listenUDP("udp", bindAddr)
		if err != nil {
			return PortForwardRule{}, dynamicRuleUndo{}, fmt.Errorf("netbackend: bind udp %s: %w", bindAddr, err)
		}
		udpConn, ok := pc.(*net.UDPConn)
		if !ok {
			_ = pc.Close()
			return PortForwardRule{}, dynamicRuleUndo{}, fmt.Errorf("netbackend: bind udp %s: socket is %T, want *net.UDPConn", bindAddr, pc)
		}
		widenUDPSend(udpConn)
		if udpAddr, ok := udpConn.LocalAddr().(*net.UDPAddr); ok {
			norm.HostPort = uint16(udpAddr.Port)
		}
		entry := &boundUDPForward{
			rule:       norm,
			packetConn: udpConn,
			sessions:   make(map[netip.AddrPort]*udpForwardSession),
		}
		pf.mu.Lock()
		if pf.closed {
			pf.mu.Unlock()
			_ = udpConn.Close()
			return PortForwardRule{}, dynamicRuleUndo{}, errors.New("netbackend: PortForwarder is closed")
		}
		pf.manualUDP = append(pf.manualUDP, entry)
		start := pf.started
		if start {
			pf.wg.Add(1)
		}
		pf.mu.Unlock()
		if start {
			go pf.serveUDP(entry)
		}
		return norm, dynamicRuleUndo{kind: undoAddedUDP, udpEntry: entry}, nil
	}
	return PortForwardRule{}, dynamicRuleUndo{}, fmt.Errorf("netbackend: unsupported protocol %q", proto)
}

type gonetUDPCloserHolder struct {
	c gonetUDPCloser
}

func ruleMatchesRemoveQuery(rule, query PortForwardRule) bool {
	if query.Proto != "" && rule.Proto != query.Proto {
		return false
	}
	if query.HostSocket != "" {
		return rule.HostSocket == query.HostSocket
	}
	if query.HostPort != 0 {
		if rule.HostPort != query.HostPort {
			return false
		}
		if query.HostIP != "" && rule.HostIP != query.HostIP {
			return false
		}
		if query.GuestPort != 0 && rule.GuestPort != query.GuestPort {
			return false
		}
		return true
	}
	if query.GuestPort != 0 {
		return rule.GuestPort == query.GuestPort
	}
	return false
}

// RemoveRule closes and removes every active port forward matching query.
// Removing a static (-p) rule fails with ErrStaticRuleRequiresForce unless
// force is true.
func (pf *PortForwarder) RemoveRule(query PortForwardRule, force bool) ([]BoundPortRule, error) {
	pf.dynMu.Lock()
	defer pf.dynMu.Unlock()

	var (
		removed      []BoundPortRule
		closeTCP     []*boundTCPForward
		closeUDP     []*boundUDPForward
		closeUDPConn []gonetUDPCloser
	)

	pf.mu.Lock()
	if pf.closed {
		pf.mu.Unlock()
		return nil, errors.New("netbackend: PortForwarder is closed")
	}

	// Check whether any static rule matches before mutating anything.
	if !force {
		for _, b := range pf.tcpList {
			if ruleMatchesRemoveQuery(b.rule, query) {
				pf.mu.Unlock()
				return nil, ErrStaticRuleRequiresForce
			}
		}
		for _, b := range pf.udpList {
			if ruleMatchesRemoveQuery(b.rule, query) {
				pf.mu.Unlock()
				return nil, ErrStaticRuleRequiresForce
			}
		}
	}

	if force {
		keptTCP := pf.tcpList[:0]
		for _, b := range pf.tcpList {
			if ruleMatchesRemoveQuery(b.rule, query) {
				removed = append(removed, BoundPortRule{Rule: b.rule, Source: PortSourceStatic})
				closeTCP = append(closeTCP, b)
			} else {
				keptTCP = append(keptTCP, b)
			}
		}
		pf.tcpList = keptTCP

		keptUDP := pf.udpList[:0]
		for _, b := range pf.udpList {
			if ruleMatchesRemoveQuery(b.rule, query) {
				b.closed = true
				for c, s := range b.sessions {
					closeUDPConn = append(closeUDPConn, s.guest)
					delete(b.sessions, c)
				}
				removed = append(removed, BoundPortRule{Rule: b.rule, Source: PortSourceStatic})
				closeUDP = append(closeUDP, b)
			} else {
				keptUDP = append(keptUDP, b)
			}
		}
		pf.udpList = keptUDP
	}

	keptManualTCP := pf.manualTCP[:0]
	for _, b := range pf.manualTCP {
		if ruleMatchesRemoveQuery(b.rule, query) {
			removed = append(removed, BoundPortRule{Rule: b.rule, Source: PortSourceDynamic})
			closeTCP = append(closeTCP, b)
		} else {
			keptManualTCP = append(keptManualTCP, b)
		}
	}
	pf.manualTCP = keptManualTCP

	keptManualUDP := pf.manualUDP[:0]
	for _, b := range pf.manualUDP {
		if ruleMatchesRemoveQuery(b.rule, query) {
			b.closed = true
			for c, s := range b.sessions {
				closeUDPConn = append(closeUDPConn, s.guest)
				delete(b.sessions, c)
			}
			removed = append(removed, BoundPortRule{Rule: b.rule, Source: PortSourceDynamic})
			closeUDP = append(closeUDP, b)
		} else {
			keptManualUDP = append(keptManualUDP, b)
		}
	}
	pf.manualUDP = keptManualUDP

	for k, b := range pf.dynTCP {
		if ruleMatchesRemoveQuery(b.rule, query) {
			delete(pf.dynTCP, k)
			removed = append(removed, BoundPortRule{Rule: b.rule, Source: PortSourceAuto})
			closeTCP = append(closeTCP, b)
		}
	}
	for k, b := range pf.dynUDP {
		if ruleMatchesRemoveQuery(b.rule, query) {
			b.closed = true
			for c, s := range b.sessions {
				closeUDPConn = append(closeUDPConn, s.guest)
				delete(b.sessions, c)
			}
			delete(pf.dynUDP, k)
			removed = append(removed, BoundPortRule{Rule: b.rule, Source: PortSourceAuto})
			closeUDP = append(closeUDP, b)
		}
	}
	pf.mu.Unlock()

	for _, b := range closeTCP {
		_ = b.listener.Close()
	}
	for _, b := range closeUDP {
		_ = b.packetConn.Close()
	}
	for _, g := range closeUDPConn {
		_ = g.Close()
	}
	if len(removed) == 0 {
		return nil, ErrPortRuleNotFound
	}
	return removed, nil
}

// RemoveAllDynamic closes and removes all dynamically added control-socket
// port rules while keeping static and auto-published rules intact.
func (pf *PortForwarder) RemoveAllDynamic() []BoundPortRule {
	pf.dynMu.Lock()
	defer pf.dynMu.Unlock()

	var (
		removed      []BoundPortRule
		closeTCP     []*boundTCPForward
		closeUDP     []*boundUDPForward
		closeUDPConn []gonetUDPCloser
	)

	pf.mu.Lock()
	for _, b := range pf.manualTCP {
		removed = append(removed, BoundPortRule{Rule: b.rule, Source: PortSourceDynamic})
		closeTCP = append(closeTCP, b)
	}
	pf.manualTCP = nil

	for _, b := range pf.manualUDP {
		b.closed = true
		for c, s := range b.sessions {
			closeUDPConn = append(closeUDPConn, s.guest)
			delete(b.sessions, c)
		}
		removed = append(removed, BoundPortRule{Rule: b.rule, Source: PortSourceDynamic})
		closeUDP = append(closeUDP, b)
	}
	pf.manualUDP = nil
	pf.mu.Unlock()

	for _, b := range closeTCP {
		_ = b.listener.Close()
	}
	for _, b := range closeUDP {
		_ = b.packetConn.Close()
	}
	for _, g := range closeUDPConn {
		_ = g.Close()
	}
	return removed
}
