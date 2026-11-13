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

package netstack

import (
	"errors"
	"maps"
	"slices"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// useXplatRoutes enables policy-routing hooks while keeping upstream route
// methods intact in stack.go.
var useXplatRoutes = true

// Route limits and attribute numbers from include/uapi/linux/rtnetlink.h.
const (
	// rtaxMTU is RTAX_MTU, the MTU entry of RTA_METRICS.
	rtaxMTU = 2
	// rtnMax is the highest route type of Linux.
	rtnMax = 11
	// ipv6UserMetric is IP6_RT_PRIO_USER, the metric of an IPv6 route that a
	// client adds without a metric.
	ipv6UserMetric = 1024
	// ipv6AddrconfMetric is IP6_RT_PRIO_ADDRCONF, the metric of the prefix
	// route that the stack adds for an IPv6 address.
	ipv6AddrconfMetric = 256
)

// routeRequest is a parsed RTM_NEWROUTE or RTM_DELROUTE message.
type routeRequest struct {
	// route holds the destination, the next hop, and the attributes.
	route tcpip.Route
	// msgScope, msgType, and msgTable are the raw fields of struct rtmsg. A
	// delete request treats scope NOWHERE, type UNSPEC, and table 0 as unset.
	msgScope uint8
	msgType  uint8
	msgTable uint8
	// priority is RTA_PRIORITY, or 0 when the request has none.
	priority uint32
	v6       bool
}

// parseRouteRequest parses the route from a netlink message as
// rtm_to_fib_config() does in Linux. A delete request skips type validation.
func (s *Stack) parseRouteRequest(msg *nlmsg.Message) (routeRequest, *syserr.Error) {
	var rtMsg linux.RouteMessage
	attrs, ok := msg.GetData(&rtMsg)
	if !ok {
		return routeRequest{}, syserr.ErrInvalidArgument
	}
	var zero []byte
	switch rtMsg.Family {
	case linux.AF_INET:
		zero = tcpip.IPv4Zero
	case linux.AF_INET6:
		zero = tcpip.IPv6Zero
	default:
		return routeRequest{}, syserr.ErrNotSupported
	}
	req := routeRequest{
		msgScope: rtMsg.Scope,
		msgType:  rtMsg.Type,
		msgTable: rtMsg.Table,
		v6:       rtMsg.Family == linux.AF_INET6,
	}
	var dst, gateway, prefSrc []byte
	table := uint32(rtMsg.Table)
	var mtu uint32
	oif := int32(0)
	for !attrs.Empty() {
		ahdr, value, rest, ok := attrs.ParseFirst()
		if !ok {
			return routeRequest{}, syserr.ErrInvalidArgument
		}
		attrs = rest
		switch ahdr.Type {
		case linux.RTA_DST:
			if len(value) < len(zero) {
				return routeRequest{}, syserr.ErrInvalidArgument
			}
			dst = value[:len(zero)]
		case linux.RTA_OIF:
			view := nlmsg.BytesView(value)
			v, ok := view.Int32()
			if !ok {
				return routeRequest{}, syserr.ErrInvalidArgument
			}
			// An output interface of 0 means that the request names no
			// device. github.com/vishvananda/netlink, and so Calico Felix,
			// sends RTA_OIF 0 for a route without a device.
			if _, exist := s.Interfaces()[v]; v != 0 && !exist {
				return routeRequest{}, syserr.ErrNoDevice
			}
			oif = v
		case linux.RTA_GATEWAY:
			if len(value) < len(zero) {
				return routeRequest{}, syserr.ErrInvalidArgument
			}
			gateway = value[:len(zero)]
		case linux.RTA_PRIORITY:
			view := nlmsg.BytesView(value)
			v, ok := view.Uint32()
			if !ok {
				return routeRequest{}, syserr.ErrInvalidArgument
			}
			req.priority = v
		case linux.RTA_PREFSRC:
			if len(value) < len(zero) {
				return routeRequest{}, syserr.ErrInvalidArgument
			}
			prefSrc = value[:len(zero)]
		case linux.RTA_TABLE:
			view := nlmsg.BytesView(value)
			v, ok := view.Uint32()
			if !ok {
				return routeRequest{}, syserr.ErrInvalidArgument
			}
			table = v
		case linux.RTA_METRICS:
			m, err := routeMTU(value)
			if err != nil {
				return routeRequest{}, err
			}
			mtu = m
		case linux.RTA_MULTIPATH, linux.RTA_VIA, linux.RTA_ENCAP, linux.RTA_ENCAP_TYPE:
			return routeRequest{}, syserr.ErrNotSupported
		case linux.RTA_SRC:
			// Linux ignores a source for the routes of this stack.
		default:
			log.Debugf("Ignoring route attribute %d", ahdr.Type)
		}
	}

	dest, err := routeDestination(dst, rtMsg.DstLen, zero)
	if err != nil {
		return routeRequest{}, err
	}
	if table == 0 {
		table = tcpip.RouteTableMain
	}
	metric := req.priority
	if req.v6 && metric == 0 {
		metric = ipv6UserMetric
	}
	req.route = tcpip.Route{
		Destination: dest,
		Gateway:     tcpip.AddrFromSlice(gateway),
		NIC:         tcpip.NICID(oif),
		MTU:         mtu,
		RouteAttrs: tcpip.RouteAttrs{
			Table:    table,
			Metric:   metric,
			Protocol: rtMsg.Protocol,
			Scope:    rtMsg.Scope,
			ScopeSet: true,
			Type:     tcpip.RouteType(rtMsg.Type),
			TOS:      rtMsg.TOS,
			Flags:    rtMsg.Flags & linux.RTNH_F_ONLINK,
		},
	}
	if len(prefSrc) != 0 {
		req.route.SourceHint = tcpip.AddrFromSlice(prefSrc)
	}
	return req, nil
}

// routeDestination returns the destination subnet of a request. Linux rejects
// an IPv4 prefix with host bits.
func routeDestination(dst []byte, dstLen uint8, zero []byte) (tcpip.Subnet, *syserr.Error) {
	if int(dstLen) > len(zero)*8 {
		return tcpip.Subnet{}, syserr.ErrInvalidArgument
	}
	addr := tcpip.AddrFromSlice(zero)
	if dst != nil {
		addr = tcpip.AddrFromSlice(dst)
	}
	subnet := tcpip.AddressWithPrefix{Address: addr, PrefixLen: int(dstLen)}.Subnet()
	if len(zero) == header.IPv4AddressSize && !subnet.ID().Equal(addr) {
		return tcpip.Subnet{}, syserr.ErrInvalidArgument
	}
	return subnet, nil
}

// routeMTU reads the RTAX_MTU entry of an RTA_METRICS attribute.
func routeMTU(metrics []byte) (uint32, *syserr.Error) {
	attrs := nlmsg.AttrsView(metrics)
	var mtu uint32
	for !attrs.Empty() {
		ahdr, value, rest, ok := attrs.ParseFirst()
		if !ok {
			return 0, syserr.ErrInvalidArgument
		}
		attrs = rest
		if ahdr.Type != rtaxMTU {
			continue
		}
		view := nlmsg.BytesView(value)
		v, ok := view.Uint32()
		if !ok {
			return 0, syserr.ErrInvalidArgument
		}
		mtu = v
	}
	return mtu, nil
}

// validateNewRoute validates route types as fib_create_info() does and sets the
// default type when omitted.
//
// Linux assigns device-less IPv6 route types to the loopback link regardless of
// the requested device. loopback is the index of that link.
func (req *routeRequest) validateNewRoute(loopback tcpip.NICID) *syserr.Error {
	rt := &req.route
	switch t := req.msgType; t {
	case linux.RTN_UNICAST:
	case linux.RTN_UNSPEC:
		if !req.v6 {
			return syserr.ErrInvalidArgument
		}
		rt.Type = tcpip.RouteTypeUnicast
	case linux.RTN_BLACKHOLE, linux.RTN_UNREACHABLE, linux.RTN_PROHIBIT, linux.RTN_THROW:
		if !req.v6 && (rt.Gateway.BitLen() != 0 || rt.NIC != 0) {
			return syserr.ErrInvalidArgument
		}
		rt.NIC = 0
		if req.v6 {
			rt.NIC = loopback
		}
		rt.Gateway = tcpip.Address{}
	case linux.RTN_NAT, linux.RTN_XRESOLVE, linux.RTN_LOCAL, linux.RTN_BROADCAST, linux.RTN_ANYCAST, linux.RTN_MULTICAST:
		return syserr.ErrNotSupported
	default:
		return syserr.ErrInvalidArgument
	}
	if rt.RouteType() == tcpip.RouteTypeUnicast && rt.Gateway.BitLen() == 0 && rt.NIC == 0 {
		return syserr.ErrNoDevice
	}
	return nil
}

// loopbackID returns the lowest loopback NIC index, or 0 when the stack has
// none.
func (s *Stack) loopbackID() tcpip.NICID {
	var id tcpip.NICID
	for i, nic := range s.Interfaces() {
		if nic.Flags&linux.IFF_LOOPBACK != 0 && (id == 0 || tcpip.NICID(i) < id) {
			id = tcpip.NICID(i)
		}
	}
	return id
}

// makeInetRouteXplat converts a netstack route into the inet.Route format that
// RTM_GETROUTE reports.
func makeInetRouteXplat(rt tcpip.Route) (inet.Route, bool) {
	var family uint8
	switch rt.Destination.ID().BitLen() {
	case header.IPv4AddressSizeBits:
		family = linux.AF_INET
	case header.IPv6AddressSizeBits:
		family = linux.AF_INET6
	default:
		log.Warningf("Unknown network protocol in route %+v", rt)
		return inet.Route{}, false
	}

	dstAddr := rt.Destination.ID()
	out := inet.Route{
		Family:          family,
		DstLen:          uint8(rt.Destination.Prefix()), // The CIDR prefix for the destination.
		TOS:             rt.TOS,
		Table:           rt.TableID(),
		Protocol:        rt.Protocol,
		Scope:           rt.EffectiveScope(rt.Gateway.BitLen() != 0),
		Type:            uint8(rt.RouteType()),
		Flags:           rt.Flags,
		DstAddr:         dstAddr.AsSlice(),
		OutputInterface: int32(rt.NIC),
		GatewayAddr:     rt.Gateway.AsSlice(),
		Priority:        rt.Metric,
		MTU:             rt.MTU,
	}
	if rt.SourceHint.BitLen() != 0 {
		out.PrefSrc = rt.SourceHint.AsSlice()
	}
	return out, true
}

// removeRouteXplat removes the first route that matches every attribute of the
// request, as fib_table_delete() does.
func (s *Stack) removeRouteXplat(ctx context.Context, msg *nlmsg.Message) *syserr.Error {
	req, err := s.parseRouteRequest(msg)
	if err != nil {
		return err
	}
	m := stack.RouteMatch{
		Table:       req.route.Table,
		Destination: req.route.Destination,
		TOS:         req.route.TOS,
		Metric:      req.priority,
		Type:        tcpip.RouteType(req.msgType),
		Scope:       req.msgScope,
		HasScope:    req.msgScope != linux.RT_SCOPE_NOWHERE,
		Protocol:    req.route.Protocol,
		Gateway:     req.route.Gateway,
		NIC:         req.route.NIC,
		PrefSrc:     req.route.SourceHint,
	}
	removed, found := s.Stack.DeleteRoute(m)
	if !found {
		return syserr.ErrNoProcess
	}
	s.sendRouteEvent(ctx, removed, false /* added */, 0)
	return nil
}

// newRouteXplat validates and inserts a route from an RTM_NEWROUTE message.
func (s *Stack) newRouteXplat(ctx context.Context, msg *nlmsg.Message) *syserr.Error {
	req, err := s.parseRouteRequest(msg)
	if err != nil {
		return err
	}
	if err := req.validateNewRoute(s.loopbackID()); err != nil {
		return err
	}
	route := req.route
	if err := s.checkLinkUp(route.NIC); err != nil {
		return err
	}
	if route.RouteType() == tcpip.RouteTypeUnicast {
		if err := s.checkGateway(msg, &route); err != nil {
			return err
		}
	}
	flags := msg.Header().Flags
	res, insertErr := s.Stack.InsertRoute(route, stack.RouteInsert{
		Create:  flags&linux.NLM_F_CREATE != 0,
		Excl:    flags&linux.NLM_F_EXCL != 0,
		Replace: flags&linux.NLM_F_REPLACE != 0,
		Append:  flags&linux.NLM_F_APPEND != 0,
	})
	switch {
	case errors.Is(insertErr, stack.ErrRouteExists):
		return syserr.ErrExists
	case errors.Is(insertErr, stack.ErrRouteNotFound):
		return syserr.ErrNoFileOrDir
	case insertErr != nil:
		return syserr.ErrInvalidArgument
	case res.Replaced:
		s.sendRouteEvent(ctx, route, true /* added */, linux.NLM_F_REPLACE)
	case res.Added:
		s.sendRouteEvent(ctx, route, true /* added */, newRouteFlags(route, res.SameDestination, flags))
	}
	return nil
}

// checkGatewayXplat validates the gateway of route against the target table
// first and all tables second, as fib_check_nh() does.
func (s *Stack) checkGatewayXplat(msg *nlmsg.Message, route *tcpip.Route) *syserr.Error {
	var rtMsg linux.RouteMessage
	if _, ok := msg.GetData(&rtMsg); !ok {
		return syserr.ErrInvalidArgument
	}
	gw := route.Gateway
	if gw.Unspecified() || header.IsV6LinkLocalUnicastAddress(gw) || rtMsg.Flags&linux.RTNH_F_ONLINK != 0 {
		return nil
	}
	// fib_check_nh() searches the table of the route first and every table
	// second. A non-unicast route such as a blackhole rejects the gateway.
	routes := s.Stack.GetRouteTable()
	for _, ownTable := range []bool{true, false} {
		for _, rt := range routes {
			if ownTable && rt.TableID() != route.TableID() {
				continue
			}
			if !rt.Gateway.Unspecified() || !rt.Destination.Contains(gw) {
				continue
			}
			if rt.RouteType() != tcpip.RouteTypeUnicast {
				return syserr.ErrInvalidArgument
			}
			if route.NIC == 0 || rt.NIC == route.NIC {
				route.NIC = rt.NIC
				return nil
			}
		}
	}
	nics := s.Stack.NICInfo()
	for _, id := range slices.Sorted(maps.Keys(nics)) {
		if route.NIC != 0 && id != route.NIC {
			continue
		}
		for _, a := range nics[id].ProtocolAddresses {
			if subnet := a.AddressWithPrefix.Subnet(); subnet.Contains(gw) {
				route.NIC = id
				return nil
			}
		}
	}
	if rtMsg.Family == linux.AF_INET6 {
		return syserr.ErrHostUnreachable
	}
	return syserr.ErrNetworkUnreachable
}

// addPrefixRoute inserts the main-table subnet route for a new interface
// address and emits a kernel route event.
func (s *Stack) addPrefixRoute(ctx context.Context, addr tcpip.AddressWithPrefix, nicID tcpip.NICID) {
	localRoute := prefixRoute(addr.Subnet(), nicID)

	sameDst := false
	for _, rt := range s.Stack.GetRouteTable() {
		if isPrefixRoute(rt, localRoute) {
			return
		}
		if rt.Destination.Equal(localRoute.Destination) {
			sameDst = true
		}
	}

	s.Stack.AddRoute(localRoute)
	var reqFlags uint16
	if addr.Address.Len() == header.IPv4AddressSize {
		reqFlags = linux.NLM_F_APPEND
	}
	s.sendRouteEvent(inet.WithNetlinkOrigin(ctx, inet.NetlinkOrigin{}), localRoute, true /* added */, newRouteFlags(localRoute, sameDst, reqFlags))
}

// removePrefixRoute removes the main-table subnet route for a deleted interface
// address and emits kernel route events.
func (s *Stack) removePrefixRoute(ctx context.Context, protocolAddress tcpip.ProtocolAddress, nicID tcpip.NICID) {
	localRoute := prefixRoute(protocolAddress.AddressWithPrefix.Subnet(), nicID)
	var removed []tcpip.Route
	s.Stack.RemoveRoutes(func(rt tcpip.Route) bool {
		if !isPrefixRoute(rt, localRoute) {
			return false
		}
		removed = append(removed, rt)
		return true
	})
	for _, rt := range removed {
		s.sendRouteEvent(inet.WithNetlinkOrigin(ctx, inet.NetlinkOrigin{}), rt, false /* added */, 0)
	}
}

// RouteFlow holds the RTM_GETROUTE fields that select a route in LookupRoute.
type RouteFlow struct {
	Family      uint8
	Dst, Src    []byte
	OutputIfIdx int32
	InputIfIdx  int32
	Mark        uint32
}

// LookupRoute resolves a destination route for a non-dump RTM_GETROUTE request
// using the routing rules, mark, and interfaces of f.
func (s *Stack) LookupRoute(f RouteFlow) (inet.Route, *syserr.Error) {
	proto := header.IPv4ProtocolNumber
	if f.Family == linux.AF_INET6 {
		proto = header.IPv6ProtocolNumber
	}
	var src tcpip.Address
	if len(f.Src) != 0 {
		src = tcpip.AddrFromSlice(f.Src)
	}
	rt, err := s.Stack.LookupRoute(stack.RouteFlow{Mark: f.Mark, InputNIC: tcpip.NICID(f.InputIfIdx)},
		tcpip.NICID(f.OutputIfIdx), src, tcpip.AddrFromSlice(f.Dst), proto)
	if err != nil {
		return inet.Route{}, syserr.TranslateNetstackError(err)
	}
	r, ok := makeInetRoute(rt)
	if !ok {
		return inet.Route{}, syserr.ErrNetworkUnreachable
	}
	return r, nil
}

// prefixRoute builds the main-table prefix route for an interface address, as
// fib_magic() and addrconf_prefix_route() do.
func prefixRoute(subnet tcpip.Subnet, nicID tcpip.NICID) tcpip.Route {
	rt := tcpip.Route{
		Destination: subnet,
		NIC:         nicID,
		RouteAttrs: tcpip.RouteAttrs{
			Protocol: linux.RTPROT_KERNEL,
			Scope:    linux.RT_SCOPE_LINK,
			ScopeSet: true,
			Type:     tcpip.RouteTypeUnicast,
		},
	}
	if subnet.ID().BitLen() == header.IPv6AddressSizeBits {
		rt.Metric = ipv6AddrconfMetric
	}
	return rt
}

// isPrefixRoute reports whether rt is a main-table route equal to want.
func isPrefixRoute(rt, want tcpip.Route) bool {
	return rt.TableID() == tcpip.RouteTableMain && rt.Equal(want)
}
