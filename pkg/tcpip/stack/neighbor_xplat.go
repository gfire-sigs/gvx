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

// neighborCacheOf returns the neighbor cache of a NIC for a network protocol.
func (s *Stack) neighborCacheOf(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber) (*neighborCache, tcpip.Error) {
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	s.mu.RUnlock()
	if !ok {
		return nil, &tcpip.ErrUnknownNICID{}
	}
	linkRes, ok := nic.linkAddrResolvers[protocol]
	if !ok {
		return nil, &tcpip.ErrNotSupported{}
	}
	return &linkRes.neigh, nil
}

// NeighborLookup returns the entry for addr in the neighbor table of a NIC. It
// reads one entry, where Neighbors copies the whole table.
func (s *Stack) NeighborLookup(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) (NeighborEntry, bool, tcpip.Error) {
	n, err := s.neighborCacheOf(nicID, protocol)
	if err != nil {
		return NeighborEntry{}, false, err
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	entry, ok := n.mu.cache[addr]
	if !ok {
		return NeighborEntry{}, false, nil
	}
	entry.mu.RLock()
	defer entry.mu.RUnlock()
	return entry.mu.neigh, true, nil
}

// StaticNeighborCount returns the count of static entries in the neighbor table
// of a NIC. The table does not bound them, so callers that add entries on
// behalf of a guest use the count to bound them.
func (s *Stack) StaticNeighborCount(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber) (int, tcpip.Error) {
	n, err := s.neighborCacheOf(nicID, protocol)
	if err != nil {
		return 0, err
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.mu.cache) - int(n.mu.dynamic.count), nil
}
