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

// BridgeNetfilter reports whether the bridges of the network namespace pass the
// IP frames that they forward through the iptables hooks. It is
// net/bridge/bridge-nf-call-iptables for IPv4 and bridge-nf-call-ip6tables for IPv6.
func (s *Stack) BridgeNetfilter(protocol tcpip.NetworkProtocolNumber) bool {
	return s.Stack.BridgeNetfilter(protocol)
}

// SetBridgeNetfilter sets what BridgeNetfilter reports.
func (s *Stack) SetBridgeNetfilter(protocol tcpip.NetworkProtocolNumber, enable bool) {
	s.Stack.SetBridgeNetfilter(protocol, enable)
}
