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
func (s *Stack) weakHostRouteRLocked(pinned *nic, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber, multicastLoop bool) *Route {
	if localAddr.BitLen() == 0 || remoteAddr.BitLen() == 0 {
		return nil
	}
	if header.IsV6LinkLocalUnicastAddress(remoteAddr) || header.IsV6LinkLocalMulticastAddress(remoteAddr) ||
		header.IsV4MulticastAddress(remoteAddr) || header.IsV6MulticastAddress(remoteAddr) ||
		remoteAddr == header.IPv4Broadcast || header.IsV4LoopbackAddress(remoteAddr) || header.IsV6LoopbackAddress(remoteAddr) {
		return nil
	}

	var chosen *tcpip.Route
	s.routeMu.RLock()
	for route := s.routeTable.Front(); route != nil; route = route.Next() {
		if !route.Destination.Contains(remoteAddr) {
			continue
		}
		if nic, ok := s.nics[route.NIC]; !ok || !nic.Enabled() {
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
	return s.findRouteWithLocalAddrFromAnyInterfaceRLocked(outgoing, localAddr, remoteAddr, r.SourceHint, r.Gateway, netProto, multicastLoop, r.MTU)
}
