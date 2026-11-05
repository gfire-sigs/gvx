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

package ipv6

import (
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// ownerOfOtherNICAddress returns the endpoint of another NIC that owns addr,
// or nil. Linux delivers a packet for a global address of any interface
// locally, but a link-local address belongs to its own link only.
func (e *endpoint) ownerOfOtherNICAddress(addr tcpip.Address) *endpoint {
	if header.IsV6LinkLocalUnicastAddress(addr) {
		return nil
	}
	return e.protocol.findEndpointWithAddress(addr)
}

// deliverForOtherNIC delivers a packet to the transport layer when its
// destination address belongs to another NIC of the stack. Linux treats such a
// packet as local: it passes PREROUTING and INPUT, but not FORWARD, and it
// needs no forwarding and no hop limit left. The packet stays on the interface
// where it arrived, and the route table picks the interface of the reply.
//
// The NIC of the packet stays the receiving NIC. Several NICs can own the
// address, for example the loopback NIC with a temporary address, and the
// stack picks one of them in random order. A reply then used the route of the
// NIC that owned the address instead of the route to the peer. The receiving
// NIC already counted the packet and checked its source address, and IPv6 has
// no broadcast address, so the owner adds no check.
func (e *endpoint) deliverForOtherNIC(h header.IPv6, pkt *stack.PacketBuffer) {
	e.deliverPacketLocally(h, pkt, e.nic.Name())
}
