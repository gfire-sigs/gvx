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

// AddDynamicRule binds one runtime control-socket port forward rule and starts
// relaying immediately when the PortForwarder is already started. Static rules
// always win; an auto-published rule on the same host binding is evicted first.
func (pf *PortForwarder) AddDynamicRule(
	rule PortForwardRule,
	replace bool,
	listenTCP func(network, address string) (net.Listener, error),
	listenUDP func(network, address string) (net.PacketConn, error),
) (PortForwardRule, error) {
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
		return PortForwardRule{}, fmt.Errorf("netbackend: unsupported protocol %q", proto)
	}
	if rule.GuestPort == 0 {
		return PortForwardRule{}, errors.New("netbackend: guest port must be non-zero")
	}
	if rule.HostSocket != "" && proto != "tcp" {
		return PortForwardRule{}, fmt.Errorf("netbackend: unix socket %s forwards tcp only", rule.HostSocket)
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

	pf.dynMu.Lock()
	defer pf.dynMu.Unlock()

	var evictTCP []*boundTCPForward
	var evictUDP []*boundUDPForward
	var evictUDPSessions []*gonetUDPCloserHolder

	pf.mu.Lock()
	if pf.closed {
		pf.mu.Unlock()
		return PortForwardRule{}, errors.New("netbackend: PortForwarder is closed")
	}
	// Check capacity before evicting any active listener.
	var willEvict int
	if norm.HostPort != 0 || norm.HostSocket != "" {
		for _, b := range pf.tcpList {
			if portBindingsMatch(b.rule, norm) {
				pf.mu.Unlock()
				return PortForwardRule{}, fmt.Errorf("%w: static rule already bound", ErrPortRuleExists)
			}
		}
		for _, b := range pf.udpList {
			if portBindingsMatch(b.rule, norm) {
				pf.mu.Unlock()
				return PortForwardRule{}, fmt.Errorf("%w: static rule already bound", ErrPortRuleExists)
			}
		}
		if proto == "tcp" {
			for _, b := range pf.manualTCP {
				if portBindingsMatch(b.rule, norm) {
					if !replace {
						pf.mu.Unlock()
						return PortForwardRule{}, fmt.Errorf("%w: dynamic rule already bound", ErrPortRuleExists)
					}
					willEvict++
				}
			}
			for _, b := range pf.dynTCP {
				if portBindingsMatch(b.rule, norm) {
					willEvict++
				}
			}
		} else {
			for _, b := range pf.manualUDP {
				if portBindingsMatch(b.rule, norm) {
					if !replace {
						pf.mu.Unlock()
						return PortForwardRule{}, fmt.Errorf("%w: dynamic rule already bound", ErrPortRuleExists)
					}
					willEvict++
				}
			}
			for _, b := range pf.dynUDP {
				if portBindingsMatch(b.rule, norm) {
					willEvict++
				}
			}
		}
	}
	activeDynamic := len(pf.manualTCP) + len(pf.manualUDP) + len(pf.dynTCP) + len(pf.dynUDP)
	if pf.maxDynamicPorts > 0 && activeDynamic-willEvict >= pf.maxDynamicPorts {
		pf.mu.Unlock()
		return PortForwardRule{}, fmt.Errorf("%w (%d active)", ErrDynamicPortLimit, pf.maxDynamicPorts)
	}
	if norm.HostPort != 0 || norm.HostSocket != "" {
		// Evict replaced dynamic/auto rules now that validation and capacity succeeded.
		if proto == "tcp" {
			for i := 0; i < len(pf.manualTCP); i++ {
				if portBindingsMatch(pf.manualTCP[i].rule, norm) {
					evictTCP = append(evictTCP, pf.manualTCP[i])
					pf.manualTCP = append(pf.manualTCP[:i], pf.manualTCP[i+1:]...)
					i--
				}
			}
			for k, b := range pf.dynTCP {
				if portBindingsMatch(b.rule, norm) {
					delete(pf.dynTCP, k)
					evictTCP = append(evictTCP, b)
				}
			}
		} else {
			for i := 0; i < len(pf.manualUDP); i++ {
				if portBindingsMatch(pf.manualUDP[i].rule, norm) {
					b := pf.manualUDP[i]
					b.closed = true
					for c, s := range b.sessions {
						evictUDPSessions = append(evictUDPSessions, &gonetUDPCloserHolder{c: s.guest})
						delete(b.sessions, c)
					}
					evictUDP = append(evictUDP, b)
					pf.manualUDP = append(pf.manualUDP[:i], pf.manualUDP[i+1:]...)
					i--
				}
			}
			for k, b := range pf.dynUDP {
				if portBindingsMatch(b.rule, norm) {
					b.closed = true
					for c, s := range b.sessions {
						evictUDPSessions = append(evictUDPSessions, &gonetUDPCloserHolder{c: s.guest})
						delete(b.sessions, c)
					}
					delete(pf.dynUDP, k)
					evictUDP = append(evictUDP, b)
				}
			}
		}
	}
	pf.mu.Unlock()

	for _, b := range evictTCP {
		_ = b.listener.Close()
	}
	for _, b := range evictUDP {
		_ = b.packetConn.Close()
	}
	for _, h := range evictUDPSessions {
		_ = h.c.Close()
	}

	if norm.HostSocket != "" {
		if proto != "tcp" {
			return PortForwardRule{}, fmt.Errorf("netbackend: unix socket %s forwards tcp only", norm.HostSocket)
		}
		ln, err := listenUnixSocket(norm.HostSocket)
		if err != nil {
			return PortForwardRule{}, err
		}
		entry := &boundTCPForward{rule: norm, listener: ln}
		pf.mu.Lock()
		if pf.closed {
			pf.mu.Unlock()
			_ = ln.Close()
			return PortForwardRule{}, errors.New("netbackend: PortForwarder is closed")
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
		return entry.rule, nil
	}

	bindAddr := net.JoinHostPort(norm.HostIP, strconv.Itoa(int(norm.HostPort)))
	switch proto {
	case "tcp":
		ln, err := listenTCP("tcp", bindAddr)
		if err != nil {
			return PortForwardRule{}, fmt.Errorf("netbackend: bind tcp %s: %w", bindAddr, err)
		}
		if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
			norm.HostPort = uint16(tcpAddr.Port)
		}
		entry := &boundTCPForward{rule: norm, listener: ln}
		pf.mu.Lock()
		if pf.closed {
			pf.mu.Unlock()
			_ = ln.Close()
			return PortForwardRule{}, errors.New("netbackend: PortForwarder is closed")
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
		return entry.rule, nil

	case "udp":
		pc, err := listenUDP("udp", bindAddr)
		if err != nil {
			return PortForwardRule{}, fmt.Errorf("netbackend: bind udp %s: %w", bindAddr, err)
		}
		udpConn, ok := pc.(*net.UDPConn)
		if !ok {
			_ = pc.Close()
			return PortForwardRule{}, fmt.Errorf("netbackend: bind udp %s: socket is %T, want *net.UDPConn", bindAddr, pc)
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
			return PortForwardRule{}, errors.New("netbackend: PortForwarder is closed")
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
		return entry.rule, nil
	}
	return PortForwardRule{}, fmt.Errorf("netbackend: unsupported protocol %q", proto)
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
