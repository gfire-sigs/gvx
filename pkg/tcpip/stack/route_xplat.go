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

import "z.gfire.dev/gvx/pkg/tcpip"

// weakHostRouteRLocked finds the route for a reply of the stack to a packet that
// arrived on inNIC, when inNIC does not own the local address of the reply.
// Linux uses the weak host model here: the routing table alone picks the
// interface, and any address of the host can be the source address. A host
// that forwards packets holds the address that a peer connects to on another
// NIC, for example the address of eth0 that a pod reaches through the bridge.
// The strong host model of the caller then has no route for the pinned NIC.
//
// The weak host route applies only when the route table sends the reply through
// inNIC. Any other pin of a NIC stays an error.
//
// +checklocksread:s.mu
func (s *Stack) weakHostRouteRLocked(inNIC, outNIC *nic, route tcpip.Route, gateway, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber, multicastLoop bool) *Route {
	if inNIC != outNIC {
		return nil
	}
	return s.findRouteWithLocalAddrFromAnyInterfaceRLocked(outNIC, localAddr, remoteAddr, route.SourceHint, gateway, netProto, multicastLoop, route.MTU)
}
