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

import "z.gfire.dev/gvx/pkg/tcpip"

// The stack keeps some state of a link outside of the tcpip stack: the ethtool
// features and the rp_filter value. These two functions are the seams that
// tie that state to the life of the link.

// dropLinkState forgets the state of a link that leaves the stack, because
// the guest removed it or moved it to another network namespace.
func (s *Stack) dropLinkState(id tcpip.NICID) {
	s.dropLinkFeatures(id)
	s.dropLinkRPFilter(id)
}

// moveLinkState hands the state of a link to the stack dst when the link
// moves to another network namespace. The ethtool features belong to the
// device and move with it. Linux creates a new IPv4 configuration for the
// device in the new namespace, so the rp_filter value starts again from the
// default of that namespace, and dropLinkState removes the old value.
func (s *Stack) moveLinkState(id tcpip.NICID, dst *Stack, newID tcpip.NICID) {
	s.moveLinkFeatures(id, dst, newID)
}
