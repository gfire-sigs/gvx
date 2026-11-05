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
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/waiter"
)

// failConnecting moves a connecting endpoint to the error state after an ICMP
// error. It runs in a new goroutine. An iptables REJECT rule of the OUTPUT
// chain sends the error back over the loopback link inside the call that
// sends the SYN. That call belongs to Connect, which holds e.mu, so a wait
// for e.mu in the caller of the error handler never ends. The goroutine
// waits for Connect to return, and then it checks the state again, because a
// reply from the peer can move the endpoint out of the connecting states first.
func (e *Endpoint) failConnecting(err tcpip.Error) {
	go func() {
		e.mu.Lock()
		if !e.EndpointState().connecting() {
			e.mu.Unlock()
			return
		}
		if e.h != nil && e.h.listenEP != nil {
			lEP := e.h.listenEP
			// Remove from listening endpoints pending list.
			lEP.acceptMu.Lock()
			delete(lEP.acceptQueue.pendingEndpoints, e)
			lEP.acceptMu.Unlock()
			lEP.stats.FailedConnectionAttempts.Increment()
		}
		e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
		e.cleanupLocked()
		e.hardError = err
		e.setEndpointState(StateError)
		e.mu.Unlock()
		e.drainClosingSegmentQueue()
		e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
	}()
}
