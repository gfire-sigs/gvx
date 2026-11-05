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
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

const (
	// ethernetMinMTU is the smallest MTU that a Linux Ethernet link accepts
	// (ETH_MIN_MTU), which is the IPv4 minimum of RFC 791.
	ethernetMinMTU = header.IPv4MinimumMTU
	// ethernetMaxMTU is the largest MTU of a Linux veth or bridge link
	// (ETH_MAX_MTU), which is the largest IPv4 packet.
	ethernetMaxMTU = 65535
)

// vethLink is the link end that the Ethernet wrapper of a veth link sits on.
// The veth pair carries Ethernet frames, so its endpoint MTU counts the 14
// bytes of the Ethernet header. The wrapper above reports the MTU without
// them, as Linux does for the MTU of a link. A change of the MTU through
// netlink must add the header again, or the link would read 14 bytes less than
// the value that the guest set.
type vethLink struct {
	stack.LinkEndpoint
}

// SetMTU implements stack.LinkEndpoint.SetMTU. It takes the MTU without the
// Ethernet header.
func (l vethLink) SetMTU(mtu uint32) {
	l.LinkEndpoint.SetMTU(mtu + header.EthernetMinimumSize)
}

// vethPairMTU is the MTU that veth.NewPair takes for a link with the MTU mtu.
func vethPairMTU(mtu uint32) uint32 {
	return mtu + header.EthernetMinimumSize
}
