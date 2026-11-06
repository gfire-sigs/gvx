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

// RPFilterPolicy returns the reverse path settings of a NIC. It models
// net.ipv4.conf.<link>.rp_filter and net.ipv4.conf.all.rp_filter, which give
// mode. The value 0 turns the check off, 1 selects the strict mode, and 2
// selects the loose mode. It also models src_valid_mark: when it is true, the
// check of the source address uses the mark of the packet.
type RPFilterPolicy func(nic tcpip.NICID) (mode int32, srcValidMark bool)

// SetRPFilterPolicy installs the policy of the stack. A stack without a policy
// does not check the source address of received packets.
func (s *Stack) SetRPFilterPolicy(p RPFilterPolicy) {
	if p == nil {
		s.fib.rpFilter.Store(nil)
		return
	}
	s.fib.rpFilter.Store(&p)
}

// SourceAddressValid reports whether an IPv4 packet that arrived on the NIC
// may pass the reverse path check of the NIC. It follows fib_validate_source()
// of Linux:
//
//   - A packet passes when the mode of the NIC is 0.
//   - The mark is part of the route lookup only with src_valid_mark.
//   - A packet to the address 255.255.255.255 with an unspecified source
//     passes, as DHCP needs it. A packet to a multicast address with an
//     unspecified source passes when the address is link-local multicast or
//     the protocol is IGMP. Any other packet with an unspecified source fails,
//     because it is a martian packet.
//   - The source must be valid for ReversePathValid in the selected mode. An
//     address of the host is not valid.
func (s *Stack) SourceAddressValid(nicID tcpip.NICID, src, dst tcpip.Address, mark uint32, transport tcpip.TransportProtocolNumber) bool {
	policy := s.fib.rpFilter.Load()
	if policy == nil {
		return true
	}
	mode, srcValidMark := (*policy)(nicID)
	if mode != 1 && mode != 2 {
		return true
	}
	if src.Unspecified() {
		switch {
		case dst == header.IPv4Broadcast:
			return true
		case header.IsV4MulticastAddress(dst):
			return header.IsV4LinkLocalMulticastAddress(dst) || transport == header.IGMPProtocolNumber
		}
		return false
	}
	if !srcValidMark {
		mark = 0
	}
	rpMode := ReversePathStrict
	if mode == 2 {
		rpMode = ReversePathLoose
	}
	return s.ReversePathValid(nicID, src, dst, mark, header.IPv4ProtocolNumber, rpMode, false /* acceptLocal */)
}
