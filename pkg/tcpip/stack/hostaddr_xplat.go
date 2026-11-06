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

// The reverse path check asks for each received packet whether the source
// address belongs to the host. A scan over every NIC takes one lock for each
// NIC, so the cost of a packet grew with the count of veth links. The stack
// keeps a snapshot of the IPv4 addresses of its NICs instead. Each change of
// an address, or of the state of a NIC, makes the snapshot stale by raising a
// generation counter, and the next lookup builds a new one.

// hostAddrSnapshot holds the IPv4 addresses that a NIC owns at the generation
// gen.
type hostAddrSnapshot struct {
	gen uint64
	v4  map[tcpip.Address]struct{}
}

// invalidateHostAddrs makes the snapshot of the host addresses stale. The NIC
// calls it after a change of an address or of the state of the NIC.
func (s *Stack) invalidateHostAddrs() {
	s.fib.hostAddrGen.Add(1)
}

// hostAddress reports whether addr belongs to a NIC. An IPv4 address comes from
// the snapshot. Another protocol scans the NICs, because the state of an IPv6
// address changes without a call of the NIC, when duplicate address detection
// ends.
//
// +checklocksread:s.mu
func (s *Stack) hostAddress(addr tcpip.Address, proto tcpip.NetworkProtocolNumber) bool {
	if proto != header.IPv4ProtocolNumber {
		for _, nic := range s.nics {
			if nic.hasAddress(proto, addr) {
				return true
			}
		}
		return false
	}
	gen := s.fib.hostAddrGen.Load()
	snap := s.fib.hostAddrs.Load()
	if snap == nil || snap.gen != gen {
		snap = &hostAddrSnapshot{gen: gen, v4: make(map[tcpip.Address]struct{})}
		for _, nic := range s.nics {
			for _, pa := range nic.allPermanentAddresses() {
				a := pa.AddressWithPrefix.Address
				if pa.Protocol == header.IPv4ProtocolNumber && nic.hasAddress(pa.Protocol, a) {
					snap.v4[a] = struct{}{}
				}
			}
		}
		s.fib.hostAddrs.Store(snap)
	}
	_, ok := snap.v4[addr]
	return ok
}
