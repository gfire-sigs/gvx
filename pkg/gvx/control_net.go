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

package gvx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"

	"z.gfire.dev/gvx/pkg/gvx/control"
	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/netbackend"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
)

func toPortRuleInfo(b netbackend.BoundPortRule) control.PortRuleInfo {
	return control.PortRuleInfo{
		Proto:      b.Rule.Proto,
		HostIP:     b.Rule.HostIP,
		HostPort:   b.Rule.HostPort,
		HostSocket: b.Rule.HostSocket,
		GuestIP:    b.Rule.GuestIP,
		GuestPort:  b.Rule.GuestPort,
		Source:     b.Source,
	}
}

func (s *Sandbox) listPortRuleInfos() []control.PortRuleInfo {
	if s.portForwarder == nil {
		return nil
	}
	bound := s.portForwarder.BoundRulesWithSource()
	out := make([]control.PortRuleInfo, 0, len(bound))
	for _, b := range bound {
		out = append(out, toPortRuleInfo(b))
	}
	return out
}

func (s *Sandbox) handlePortList(_ context.Context, stream *control.Stream) error {
	return stream.Reply(control.PortListResponse{Ports: s.listPortRuleInfos()})
}

func isLoopbackBindIP(ipStr string) bool {
	if ipStr == "" || ipStr == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(ipStr)
	return err == nil && addr.Zone() == "" && addr.Unmap().IsLoopback()
}

func hasLoopbackBindAddr(addrs []string) bool {
	for _, s := range addrs {
		if isLoopbackBindIP(s) {
			return true
		}
	}
	return false
}

func hasNonLoopbackBindAddr(addrs []string) bool {
	for _, s := range addrs {
		if !isLoopbackBindIP(s) {
			return true
		}
	}
	return false
}

func dynamicBindAddrAllowed(allowed []string, ipStr string) bool {
	if len(allowed) == 0 {
		return false
	}
	if ipStr == "" {
		ipStr = "127.0.0.1"
	}
	target, err := netip.ParseAddr(ipStr)
	if err != nil || target.Zone() != "" {
		return false
	}
	target = target.Unmap()
	for _, raw := range allowed {
		a, err := netip.ParseAddr(raw)
		if err == nil && a.Zone() == "" && a.Unmap() == target {
			return true
		}
	}
	return false
}

func portEventAttrs(source string, rule netbackend.PortForwardRule) map[string]string {
	attrs := map[string]string{
		"source":     source,
		"proto":      rule.Proto,
		"guest_port": strconv.Itoa(int(rule.GuestPort)),
	}
	if rule.HostSocket != "" {
		attrs["host_socket"] = rule.HostSocket
	} else {
		attrs["host_ip"] = rule.HostIP
		attrs["host_port"] = strconv.Itoa(int(rule.HostPort))
	}
	return attrs
}

func (s *Sandbox) handlePortAdd(_ context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.PortAddRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	if len(req.Specs) == 0 {
		return control.NewError(control.CodeInvalidArgument, "at least one port spec is required")
	}
	if s.cfg.NetworkMode != NetModeNAT || s.portForwarder == nil {
		return control.NewError(control.CodeUnsupported, "host port publishing requires -net=nat; use port-forward for client-side tunneling")
	}

	s.mu.Lock()
	locked := s.lockdown.Applied
	canLoopback := !locked || s.cfg.AutoPublishPorts || s.cfg.DynamicPorts
	allowedAddrs := slices.Clone(s.cfg.DynamicPortAddrs)
	curTune := s.cfg.Tuning
	s.mu.Unlock()

	caps := s.ControlCapabilities()
	var parsed []netbackend.PortForwardRule
	for _, spec := range req.Specs {
		rules, err := netbackend.ParsePortForwardSpecs(spec, true, true, curTune)
		if err != nil {
			return control.NewError(control.CodeInvalidArgument, err.Error())
		}
		for _, r := range rules {
			if r.HostSocket != "" {
				if locked {
					return control.NewError(control.CodeLockdownDenied, "dynamic Unix socket publishing is denied under host lockdown; use -lockdown=false or port-forward")
				}
				if !slices.Contains(caps, control.CapPortAnyBind) {
					return control.NewError(control.CodeForbiddenByPolicy, "dynamic Unix socket publishing is disabled by control policy")
				}
			} else {
				hostIP := r.HostIP
				if hostIP == "" {
					hostIP = "127.0.0.1"
				}
				addr, err := parseBareIPAddr(hostIP)
				if err != nil {
					return control.NewErrorf(control.CodeInvalidArgument, "invalid bind IP %q: %v", r.HostIP, err)
				}
				r.HostIP = addr.String()
				if !addr.IsLoopback() {
					listed := dynamicBindAddrAllowed(allowedAddrs, r.HostIP)
					if locked {
						if !listed {
							return control.NewErrorf(control.CodeLockdownDenied, "binding non-loopback address %q is denied under host lockdown; start sandbox with --dynamic-ports-addr %s, bind 127.0.0.1, or use port-forward", r.HostIP, r.HostIP)
						}
						if !slices.Contains(caps, control.CapPortDynamicAny) {
							return control.NewErrorf(control.CodeForbiddenByPolicy, "non-loopback dynamic port publishing (%s) is disabled by control policy", control.CapPortDynamicAny)
						}
					} else if !slices.Contains(caps, control.CapPortAnyBind) && !(listed && slices.Contains(caps, control.CapPortDynamicAny)) {
						return control.NewError(control.CodeForbiddenByPolicy, "non-loopback dynamic port publishing is disabled by control policy")
					}
				} else {
					if !canLoopback && !dynamicBindAddrAllowed(allowedAddrs, r.HostIP) {
						return control.NewError(control.CodeLockdownDenied, "dynamic loopback port publishing is disabled under lockdown; start sandbox with --dynamic-ports or --auto-publish, or use rungv port-forward")
					}
					if !slices.Contains(caps, control.CapPortDynamicLoopback) && !slices.Contains(caps, control.CapPortAnyBind) {
						return control.NewError(control.CodeForbiddenByPolicy, "dynamic loopback port publishing is disabled by control policy")
					}
				}
			}
			parsed = append(parsed, r)
		}
	}

	listenTCP := net.Listen
	listenUDP := net.ListenPacket
	if locked {
		listenTCP = hostlockdown.ListenAllowed
		listenUDP = hostlockdown.ListenPacketAllowed
	}

	boundRules, err := s.portForwarder.AddDynamicRules(parsed, req.Replace, listenTCP, listenUDP)
	if err != nil {
		if errors.Is(err, netbackend.ErrPortRuleExists) {
			return control.NewError(control.CodeAlreadyExists, err.Error())
		}
		if errors.Is(err, netbackend.ErrDynamicPortLimit) {
			return control.NewError(control.CodeLimitExceeded, err.Error())
		}
		return control.NewError(control.CodeInternal, err.Error())
	}
	added := make([]control.PortRuleInfo, 0, len(boundRules))
	for _, bound := range boundRules {
		added = append(added, toPortRuleInfo(netbackend.BoundPortRule{Rule: bound, Source: netbackend.PortSourceDynamic}))
		s.emitEvent("port", "add", portEventAttrs(netbackend.PortSourceDynamic, bound))
	}
	return stream.Reply(control.PortAddResponse{Ports: added})
}

func parsePortRemoveQuery(spec string) (netbackend.PortForwardRule, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return netbackend.PortForwardRule{}, errors.New("empty port specification")
	}
	if strings.HasPrefix(s, "unix:") {
		return netbackend.PortForwardRule{Proto: "tcp", HostSocket: strings.TrimPrefix(s, "unix:")}, nil
	}
	proto := ""
	if idx := strings.LastIndexByte(s, '/'); idx != -1 {
		proto = strings.ToLower(strings.TrimSpace(s[idx+1:]))
		s = s[:idx]
		if proto != "tcp" && proto != "udp" {
			return netbackend.PortForwardRule{}, fmt.Errorf("unsupported protocol %q", proto)
		}
	}
	if !strings.Contains(s, ":") {
		port, err := strconv.ParseUint(s, 10, 16)
		if err != nil || port == 0 {
			return netbackend.PortForwardRule{}, fmt.Errorf("invalid port %q", spec)
		}
		return netbackend.PortForwardRule{Proto: proto, HostPort: uint16(port)}, nil
	}
	rule, err := netbackend.ParsePortForwardSpec(spec, true, false)
	if err != nil {
		return netbackend.PortForwardRule{}, err
	}
	if proto == "" {
		rule.Proto = ""
	}
	return rule, nil
}

func (s *Sandbox) handlePortRemove(_ context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.PortRemoveRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	if s.portForwarder == nil {
		return control.NewError(control.CodeNotFound, "no port forwarder active")
	}
	if req.AllDynamic {
		removed := s.portForwarder.RemoveAllDynamic()
		out := make([]control.PortRuleInfo, 0, len(removed))
		for _, b := range removed {
			out = append(out, toPortRuleInfo(b))
			s.emitEvent("port", "remove", portEventAttrs(b.Source, b.Rule))
		}
		return stream.Reply(control.PortRemoveResponse{Removed: out})
	}
	if len(req.Specs) == 0 {
		return control.NewError(control.CodeInvalidArgument, "provide port specs or --all-dynamic")
	}
	var allRemoved []control.PortRuleInfo
	for _, spec := range req.Specs {
		q, err := parsePortRemoveQuery(spec)
		if err != nil {
			return control.NewError(control.CodeInvalidArgument, err.Error())
		}
		removed, err := s.portForwarder.RemoveRule(q, req.Force)
		if err != nil {
			if errors.Is(err, netbackend.ErrStaticRuleRequiresForce) {
				return control.NewError(control.CodeInvalidArgument, "static -p port rule requires --force to remove")
			}
			if errors.Is(err, netbackend.ErrPortRuleNotFound) {
				return control.NewErrorf(control.CodeNotFound, "no active port rule matches %q", spec)
			}
			return control.NewError(control.CodeInternal, err.Error())
		}
		for _, b := range removed {
			allRemoved = append(allRemoved, toPortRuleInfo(b))
			s.emitEvent("port", "remove", portEventAttrs(b.Source, b.Rule))
		}
	}
	return stream.Reply(control.PortRemoveResponse{Removed: allRemoved})
}

func (s *Sandbox) handleNetDial(ctx context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.NetDialRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	proto := strings.ToLower(strings.TrimSpace(req.Proto))
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" {
		return control.NewErrorf(control.CodeUnsupported, "net.dial currently supports tcp only, got %q", proto)
	}
	if req.GuestPort == 0 {
		return control.NewError(control.CodeInvalidArgument, "guest_port must be non-zero")
	}
	if _, _, err := s.activeKernelChecked(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	st := s.netStack
	netMode := s.cfg.NetworkMode
	s.mu.Unlock()
	if st == nil {
		return control.NewError(control.CodeUnsupported, "sandbox network stack is not available")
	}

	guestIP := strings.TrimSpace(req.GuestIP)
	fallback := req.LoopbackFallback
	if guestIP == "" {
		if netMode == NetModeNone {
			guestIP = "127.0.0.1"
		} else {
			guestIP = netbackend.DefaultGuestIPv4
			fallback = true
		}
	}

	dialAddr := func(ipStr string) (*gonet.TCPConn, string, error) {
		addr, err := netip.ParseAddr(ipStr)
		if err != nil || !addr.Is4() {
			return nil, "", control.NewErrorf(control.CodeInvalidArgument, "invalid guest IPv4 %q", ipStr)
		}
		nic := netbackend.Eth0NICID
		if addr.IsLoopback() {
			nic = netbackend.LoopbackNICID
		}
		full := tcpip.FullAddress{
			NIC:  nic,
			Addr: tcpip.AddrFrom4(addr.As4()),
			Port: req.GuestPort,
		}
		conn, dErr := gonet.DialContextTCP(ctx, st, full, ipv4.ProtocolNumber)
		if dErr != nil {
			return nil, "", dErr
		}
		return conn, net.JoinHostPort(ipStr, strconv.Itoa(int(req.GuestPort))), nil
	}

	guestConn, remoteAddr, err := dialAddr(guestIP)
	if err != nil && fallback && guestIP != "127.0.0.1" {
		if fbConn, fbAddr, fbErr := dialAddr("127.0.0.1"); fbErr == nil {
			guestConn, remoteAddr, err = fbConn, fbAddr, nil
		}
	}
	if err != nil {
		return control.NewErrorf(control.CodeNotFound, "dial guest %s:%d: %v", guestIP, req.GuestPort, err)
	}
	defer guestConn.Close()

	if err := stream.SendResponse(control.NetDialResponse{RemoteAddr: remoteAddr}); err != nil {
		return err
	}

	stop := context.AfterFunc(ctx, func() { _ = guestConn.Close() })
	defer stop()

	var wg sync.WaitGroup
	wg.Add(2)
	// Client -> Guest
	go func() {
		defer wg.Done()
		_, _ = io.Copy(guestConn, stream.ChannelReader(ctx, control.ChannelGeneric))
		_ = guestConn.CloseWrite()
	}()
	// Guest -> Client
	go func() {
		defer wg.Done()
		w := stream.ChannelWriter(ctx, control.ChannelGeneric, false)
		_, _ = io.Copy(w, guestConn)
		_ = w.Close()
	}()
	wg.Wait()
	return nil
}
