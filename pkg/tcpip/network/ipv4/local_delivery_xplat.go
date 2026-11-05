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

package ipv4

import (
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// deliverForwardedLocally delivers a packet to the transport layer when its
// destination address belongs to another NIC of the stack. Linux does the same
// for a packet that arrives on one interface for an address of another
// interface: the packet stays on the interface where it arrived, and the route
// table picks the interface of the reply.
//
// The NIC of the packet stays the receiving NIC. The owner of the address is
// not a good choice. Several NICs can own the address, for example the
// loopback NIC with a temporary address, and the stack picks one of them in
// random order. A reply then used the route of the NIC that owns the address, which
// is the default route of eth0, instead of the bridge of the peer.
func (e *endpoint) deliverForwardedLocally(h header.IPv4, pkt *stack.PacketBuffer) {
	e.deliverPacketLocally(h, pkt, e.nic.Name())
}
