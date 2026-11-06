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

package tcpip

// Routing table identifiers. The values are the RT_TABLE_* constants of Linux.
const (
	// RouteTableDefault is the table "default".
	RouteTableDefault uint32 = 253
	// RouteTableMain is the table "main". A route with table 0 belongs to it.
	RouteTableMain uint32 = 254
	// RouteTableLocal is the table "local".
	RouteTableLocal uint32 = 255
)

// RouteType is the type of a route. The values are the RTN_* constants of
// Linux. Type 0 stands for a unicast route.
type RouteType uint8

// Route types that the stack can route.
const (
	// RouteTypeUnicast is a route to a gateway or a link.
	RouteTypeUnicast RouteType = 1
	// RouteTypeBlackhole drops a packet without a reply. A local sender gets
	// EINVAL.
	RouteTypeBlackhole RouteType = 6
	// RouteTypeUnreachable drops a packet and answers with "host unreachable".
	// A local sender gets EHOSTUNREACH.
	RouteTypeUnreachable RouteType = 7
	// RouteTypeProhibit drops a packet and answers with "administratively
	// prohibited". A local sender gets EACCES.
	RouteTypeProhibit RouteType = 8
	// RouteTypeThrow ends the lookup in its table, so the next rule applies.
	RouteTypeThrow RouteType = 9
)

// RouteAttrs holds the attributes of a route that a netlink client sets. The
// zero value describes a unicast route in the table main, as the boot
// configuration of a stack adds it.
type RouteAttrs struct {
	// Table is the routing table. 0 means the table main.
	Table uint32

	// Metric is the priority of the route. A lower value wins between routes
	// with the same prefix length.
	Metric uint32

	// Protocol is the origin of the route, an RTPROT_* constant of Linux.
	Protocol uint8

	// Scope is the distance to the destination, an RT_SCOPE_* constant of
	// Linux. ScopeSet tells whether the stack or a client chose it.
	Scope    uint8
	ScopeSet bool

	// Type is the route type. 0 means RouteTypeUnicast.
	Type RouteType

	// TOS is the type of service that a lookup must match. The stack looks
	// up routes with the type of service 0, so a route with another value
	// never matches.
	TOS uint8

	// Flags are the RTNH_F_* flags of the next hop and the RTM_F_* flags.
	Flags uint32
}

// TableID returns the routing table of the route, with 0 resolved to the table
// main.
func (a RouteAttrs) TableID() uint32 {
	if a.Table == 0 {
		return RouteTableMain
	}
	return a.Table
}

// EffectiveScope returns the scope of the route. A route that no client gave a
// scope has the scope link, or the scope universe when it has a gateway. The
// values are RT_SCOPE_LINK and RT_SCOPE_UNIVERSE of Linux.
func (a RouteAttrs) EffectiveScope(hasGateway bool) uint8 {
	switch {
	case a.ScopeSet:
		return a.Scope
	case hasGateway:
		return 0
	}
	return 253
}

// RouteType returns the type of the route, with 0 resolved to a unicast route.
func (a RouteAttrs) RouteType() RouteType {
	if a.Type == 0 {
		return RouteTypeUnicast
	}
	return a.Type
}

// IsReject reports whether a route of this type has no next hop and ends the
// lookup with an error.
func (t RouteType) IsReject() bool {
	switch t {
	case RouteTypeBlackhole, RouteTypeUnreachable, RouteTypeProhibit:
		return true
	}
	return false
}

// ErrRouteBlackhole indicates that a blackhole route matched the destination.
// It maps to EINVAL, as in Linux.
type ErrRouteBlackhole struct{}

func (*ErrRouteBlackhole) isError() {}

// IgnoreStats implements Error.
func (*ErrRouteBlackhole) IgnoreStats() bool {
	return false
}
func (*ErrRouteBlackhole) String() string { return "invalid argument" }

// ErrRouteProhibited indicates that a prohibit route matched the destination.
// It maps to EACCES, as in Linux.
type ErrRouteProhibited struct{}

func (*ErrRouteProhibited) isError() {}

// IgnoreStats implements Error.
func (*ErrRouteProhibited) IgnoreStats() bool {
	return false
}
func (*ErrRouteProhibited) String() string { return "permission denied" }
