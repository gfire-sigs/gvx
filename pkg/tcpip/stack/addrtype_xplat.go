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
)

// This file holds the NIC lookups for the iptables "addrtype" match.
// The match needs a strict "is this address on this NIC" test, which
// CheckLocalAddress does not give for IPv4 when a NIC is named.

// NICIDByName returns the ID of the NIC with the given name.
// It returns 0 if no NIC has that name.
func (s *Stack) NICIDByName(name string) tcpip.NICID {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for id, nic := range s.nics {
		if nic.Name() == name {
			return id
		}
	}
	return 0
}

// NICIsLoopback returns true if the NIC with the given ID is a loopback NIC.
func (s *Stack) NICIsLoopback(id tcpip.NICID) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	return ok && nic.IsLoopback()
}

// AddressAssignedOnNIC returns true if addr is assigned to the NIC with the
// given ID. If nicID is 0, any NIC of the stack can own the address.
//
// WHY: Stack.CheckLocalAddress returns true for every IPv4 address when a NIC
// is named. The addrtype match must test the address itself.
func (s *Stack) AddressAssignedOnNIC(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nicID != 0 {
		nic, ok := s.nics[nicID]
		return ok && nic.CheckLocalAddress(protocol, addr)
	}
	for _, nic := range s.nics {
		if nic.CheckLocalAddress(protocol, addr) {
			return true
		}
	}
	return false
}
