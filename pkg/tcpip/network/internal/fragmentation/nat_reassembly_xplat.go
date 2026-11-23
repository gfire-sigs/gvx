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

package fragmentation

import "z.gfire.dev/gvx/pkg/tcpip/stack"

type natFragmentation Fragmentation

func (n *natFragmentation) Release() {
	f := (*Fragmentation)(n)
	f.Release()
	f.mu.Lock()
	f.releaseJob.Cancel()
	f.mu.Unlock()
}

// ProcessOnIngress uses a separate reassembler for each private NAT pipe
// epoch. Packets on other links use the ordinary protocol reassembler.
func (f *Fragmentation) ProcessOnIngress(id FragmentID, first, last uint16, more bool, proto uint8, pkt *stack.PacketBuffer) (*stack.PacketBuffer, uint8, bool, error) {
	input := pkt.NATInput()
	if input == nil {
		return f.Process(id, first, last, more, proto, pkt)
	}
	return stack.ReassembleNAT(input, pkt.NetworkProtocolNumber, func() *natFragmentation {
		var timeout TimeoutHandler
		if f.timeoutHandler != nil {
			timeout = input.GuardReassemblyTimeout(f.timeoutHandler.OnReassemblyTimeout)
		}
		return (*natFragmentation)(NewFragmentation(f.blockSize, f.highLimit, f.lowLimit, f.timeout, f.clock, timeout))
	}, func(n *natFragmentation) (*stack.PacketBuffer, uint8, bool, error) {
		return (*Fragmentation)(n).Process(id, first, last, more, proto, pkt)
	})
}
