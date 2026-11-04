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
	"sync/atomic"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/link/nested"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// hostFilterEndpoint drops the unicast frames that the Ethernet layer of a veth
// end marks as addressed to another host, before they reach the IP layer. Linux
// does the same in ip_rcv for PACKET_OTHERHOST. A bridge floods a frame to every
// port while it has no FDB entry for the destination address. Without the drop,
// a network namespace with IP forwarding would forward the frames of its
// neighbors, and the copies would loop between the namespaces.
//
// Packet sockets sit below this endpoint and still see every frame. The drop
// does not apply to a veth end that is a bridge port, because the bridge must
// forward frames for other hosts.
type hostFilterEndpoint struct {
	nested.Endpoint
	bridged atomic.Bool
}

// newHostFilterEndpoint wraps child, the endpoint that parses Ethernet headers.
func newHostFilterEndpoint(child stack.LinkEndpoint) *hostFilterEndpoint {
	e := &hostFilterEndpoint{}
	e.Endpoint.Init(child, e)
	return e
}

// Attach implements stack.LinkEndpoint.Attach. It records whether the NIC
// became a bridge port.
func (e *hostFilterEndpoint) Attach(d stack.NetworkDispatcher) {
	e.bridged.Store(d != nil && stack.IsBridgePort(d))
	e.Endpoint.Attach(d)
}

// DeliverNetworkPacket implements stack.NetworkDispatcher.
func (e *hostFilterEndpoint) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if pkt.PktType == tcpip.PacketOtherHost && !e.bridged.Load() {
		return
	}
	e.Endpoint.DeliverNetworkPacket(protocol, pkt)
}
