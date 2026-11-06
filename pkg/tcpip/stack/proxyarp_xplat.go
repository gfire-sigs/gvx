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

// ProxyARPPolicy tells whether a NIC answers ARP requests for addresses that
// the host routes to another NIC. It models net.ipv4.conf.<link>.proxy_arp and
// net.ipv4.conf.all.proxy_arp.
type ProxyARPPolicy func(nic tcpip.NICID) bool

// SetProxyARPPolicy installs the policy of the stack. A stack without a policy
// answers only for its own addresses.
func (s *Stack) SetProxyARPPolicy(p ProxyARPPolicy) {
	s.fib.proxyARP.Store(&p)
}

// ProxyARPReply reports whether the NIC answers an ARP request from sender for
// target with its own link address, as arp_process() of Linux does for
// proxy_arp. The NIC must have the policy and forward packets. The routing
// rules and tables must send a packet for the target through another NIC, and
// the route must not be a reject route. Calico relies on this: a workload asks
// for the gateway 169.254.1.1, and the host answers because the default route
// leads out of another NIC.
func (s *Stack) ProxyARPReply(nicID tcpip.NICID, sender, target tcpip.Address) bool {
	policy := s.fib.proxyARP.Load()
	if policy == nil || !(*policy)(nicID) {
		return false
	}
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	forwarding := ok && isNICForwarding(nic, header.IPv4ProtocolNumber)
	s.mu.RUnlock()
	if !forwarding {
		return false
	}
	rt, err := s.LookupRoute(RouteFlow{InputNIC: nicID, Source: sender}, 0, tcpip.Address{}, target, header.IPv4ProtocolNumber)
	return err == nil && rt.NIC != nicID && rt.RouteType() == tcpip.RouteTypeUnicast
}
