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

package stack

import (
	"cmp"
	"slices"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
)

// weakHostRouteRLocked finds the route for a reply of a forwarding stack, when
// the NIC that FindRoute got does not own localAddr. A host that forwards
// packets holds the address that a peer connects to on another NIC, for
// example the address of eth0 that a pod reaches through the bridge. The strong
// host model of FindRoute then has no route for the NIC of the packet.
//
// Linux has no such limit: the routing table picks the interface of a reply, and
// any address of the host can be the source address. This function does the
// same. A route through the NIC of the packet wins when one matches the remote
// address. Without such a route, the first route of the table that matches
// decides, as for FindRoute with no NIC.
//
// It returns nil when localAddr is not set, because the stack would then pick
// the source address of any NIC. It also returns nil for a remote address that
// needs no route, such as a multicast address.
//
// +checklocksread:s.mu
func (s *Stack) weakHostRouteRLocked(flow RouteFlow, pinned *nic, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber, multicastLoop bool) *Route {
	if localAddr.BitLen() == 0 || remoteAddr.BitLen() == 0 {
		return nil
	}
	if header.IsV6LinkLocalUnicastAddress(remoteAddr) || header.IsV6LinkLocalMulticastAddress(remoteAddr) ||
		header.IsV4MulticastAddress(remoteAddr) || header.IsV6MulticastAddress(remoteAddr) ||
		remoteAddr == header.IPv4Broadcast || header.IsV4LoopbackAddress(remoteAddr) || header.IsV6LoopbackAddress(remoteAddr) {
		return nil
	}

	var chosen *tcpip.Route
	lookup := newRouteLookup(flow, 0, localAddr, remoteAddr, netProto)
	s.routeMu.RLock()
	for route := range s.fibRoutes(&lookup) {
		if nic, ok := s.nics[route.NIC]; !ok || !nic.Enabled() { // +checklocksforce: the loop body runs with s.mu held
			continue
		}
		if route.NIC == pinned.ID() {
			chosen = route
			break
		}
		if chosen == nil {
			chosen = route
		}
	}
	var r tcpip.Route
	if chosen != nil {
		r = *chosen
	}
	s.routeMu.RUnlock()
	if chosen == nil {
		return nil
	}

	outgoing, ok := s.nics[r.NIC]
	if !ok {
		return nil
	}
	// A route through the pinned NIC may take the local address of another NIC
	// without forwarding, as Linux does for a reply and for SO_BINDTODEVICE. A
	// route through another NIC would break SO_BINDTODEVICE, so it needs
	// forwarding on the pinned NIC, as before the weak host model.
	sameNIC := outgoing == pinned
	if !sameNIC && !isNICForwarding(pinned, netProto) {
		return nil
	}
	route := s.findRouteWithLocalAddrFromAnyInterfaceRLocked(outgoing, localAddr, remoteAddr, r.SourceHint, r.Gateway, netProto, multicastLoop, r.MTU)
	if route != nil && sameNIC {
		route.weakHost = true
	}
	return route
}

// sourceNICOrderRLocked returns the NICs in the order that Linux uses to pick a
// source address (inet_select_addr): the NICs in ascending order of ID, and the
// loopback NICs last. The order does not depend on the iteration order of a
// map, so the same host gets the same source address each time. The stack
// keeps the sorted slice between calls and sorts again after a NIC joins or
// leaves, so a call allocates nothing. The caller must not change the slice.
//
// +checklocksread:s.mu
func (s *Stack) sourceNICOrderRLocked() []*nic {
	gen := s.fib.nicGen.Load()
	snap := s.fib.nicOrder.Load()
	if snap == nil || snap.gen != gen {
		snap = &nicOrderSnapshot{gen: gen, nics: make([]*nic, 0, len(s.nics))}
		for _, n := range s.nics {
			snap.nics = append(snap.nics, n)
		}
		slices.SortFunc(snap.nics, func(a, b *nic) int {
			if al, bl := a.IsLoopback(), b.IsLoopback(); al != bl {
				if bl {
					return -1
				}
				return 1
			}
			return cmp.Compare(a.id, b.id)
		})
		s.fib.nicOrder.Store(snap)
	}
	return snap.nics
}

// nicOrderSnapshot holds the NICs in the order of sourceNICOrderRLocked at the
// generation gen.
type nicOrderSnapshot struct {
	gen  uint64
	nics []*nic
}

// nicsChanged marks the snapshots that depend on the set of NICs stale. The
// caller holds s.mu for writing.
func (s *Stack) nicsChanged() {
	s.fib.nicGen.Add(1)
	s.invalidateHostAddrs()
}
