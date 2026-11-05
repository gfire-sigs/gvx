// Copyright 2018 The gVisor Authors.
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

// Linux stops IPv6 on a link whose MTU is below IPV6_MIN_MTU (1280): the
// notifier addrconf_notify removes the IPv6 addresses and the IPv6 routes of
// the link, and the link accepts no IPv6 address until the MTU is 1280 or more
// again. A NIC with MTU bounds follows the same rule. Such a NIC is a link that
// the guest can resize. A NIC without bounds, and a loopback NIC, keep IPv6 at
// every MTU.

// ipv6Blocked reports whether the MTU of n stops the network protocol proto.
// Only IPv6 can be stopped.
func (n *nic) ipv6Blocked(proto tcpip.NetworkProtocolNumber) bool {
	if proto != header.IPv6ProtocolNumber || n.minMTU == 0 || n.IsLoopback() {
		return false
	}
	return n.MTU() < header.IPv6MinimumMTU
}

// ipv6MTUChanged applies a change of the MTU of n from oldMTU to the current
// MTU. A fall below the IPv6 minimum removes the IPv6 addresses and routes and
// disables the IPv6 endpoint. A return to the minimum enables the endpoint
// again. The endpoint then generates its link-local address if the IPv6
// protocol has the option AutoGenLinkLocal. The caller holds Stack.mu.
func (n *nic) ipv6MTUChanged(oldMTU uint32) {
	if n.minMTU == 0 || n.IsLoopback() {
		return
	}
	wasBlocked := oldMTU < header.IPv6MinimumMTU
	isBlocked := n.ipv6Blocked(header.IPv6ProtocolNumber)
	if wasBlocked == isBlocked {
		return
	}
	ep := n.getNetworkEndpoint(header.IPv6ProtocolNumber)
	if ep == nil {
		return
	}

	n.enableDisableMu.Lock()
	defer n.enableDisableMu.Unlock()
	if !isBlocked {
		if n.Enabled() {
			// Enable fails only when the NIC is disabled, which the check above excludes.
			_ = ep.Enable()
		}
		return
	}

	if addressable, ok := ep.(AddressableEndpoint); ok {
		for _, a := range addressable.PermanentAddresses() {
			if header.IsV6UnicastAddress(a.Address) {
				_ = addressable.RemovePermanentAddress(a.Address)
			}
		}
	}
	ep.Disable()
	n.stack.RemoveRoutes(func(r tcpip.Route) bool {
		return r.NIC == n.id && r.Destination.ID().Len() == header.IPv6AddressSize
	})
}
