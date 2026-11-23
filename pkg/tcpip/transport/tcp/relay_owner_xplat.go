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

package tcp

import (
	"context"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/waiter"
)

// NATRelayOwner identifies a private NAT endpoint. The forwarder sets its owner
// before it registers the endpoint or sends the first SYN-ACK.
func (e *Endpoint) NATRelayOwner() *stack.NATRelayOwner {
	owner, _ := e.owner.(*stack.NATRelayOwner)
	return owner
}

// CreateNATRelayEndpoint starts a handshake for an admitted private NAT flow.
// Cancellation aborts the handshake. The caller must still complete the request.
func (r *ForwarderRequest) CreateNATRelayEndpoint(ctx context.Context, queue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	return r.createEndpoint(queue, ctx.Done(), true)
}

// CompleteNATRejection admits the retained SYN as packet-only traffic before
// sending a rejection. A nil reply sends a TCP reset. The caller gives up
// ownership of the request, even when the meter drops the SYN.
func (r *ForwarderRequest) CompleteNATRejection(reply func(stack.TransportEndpointID)) {
	syn := r.segment.pkt
	input := syn.NATInput()
	complete := func() {
		if reply != nil {
			reply(r.ID())
		}
		r.Complete(reply == nil)
	}
	if input == nil {
		complete()
		return
	}
	var completed bool
	input.AdmitWithRelease(syn, func(*stack.PacketBuffer) {
		completed = true
		complete()
	}, func() {
		if !completed {
			r.Complete(false)
		}
	})
}
