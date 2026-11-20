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

// BoundEndpoint identifies a local transport endpoint registered in a Stack.
type BoundEndpoint struct {
	NetProto   tcpip.NetworkProtocolNumber
	TransProto tcpip.TransportProtocolNumber
	LocalAddr  tcpip.Address
	LocalPort  uint16
}

// ListeningEndpoints returns every registered TCP listening endpoint in s.
// Listening TCP endpoints register with no remote address or remote port.
// Dual-stack wildcard listeners yield one entry per network protocol (IPv4 and
// IPv6). The returned slice order is unspecified.
func (s *Stack) ListeningEndpoints() []BoundEndpoint {
	if s == nil || s.demux == nil {
		return nil
	}
	var out []BoundEndpoint
	for _, netProto := range []tcpip.NetworkProtocolNumber{header.IPv4ProtocolNumber, header.IPv6ProtocolNumber} {
		eps, ok := s.demux.protocol[protocolIDs{network: netProto, transport: header.TCPProtocolNumber}]
		if !ok {
			continue
		}
		eps.mu.RLock()
		for id := range eps.endpoints {
			if id.LocalPort != 0 && id.RemotePort == 0 && id.RemoteAddress.Len() == 0 {
				out = append(out, BoundEndpoint{
					NetProto:   netProto,
					TransProto: header.TCPProtocolNumber,
					LocalAddr:  id.LocalAddress,
					LocalPort:  id.LocalPort,
				})
			}
		}
		eps.mu.RUnlock()
	}
	return out
}

// HasBoundEndpoint reports whether s has a registered endpoint for netProto,
// transProto, localAddr, and localPort with no remote peer.
func (s *Stack) HasBoundEndpoint(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, localAddr tcpip.Address, localPort uint16) bool {
	if s == nil || s.demux == nil || localPort == 0 {
		return false
	}
	eps, ok := s.demux.protocol[protocolIDs{network: netProto, transport: transProto}]
	if !ok {
		return false
	}
	id := TransportEndpointID{
		LocalPort:    localPort,
		LocalAddress: localAddr,
	}
	eps.mu.RLock()
	_, found := eps.endpoints[id]
	eps.mu.RUnlock()
	return found
}

// IsDNATTarget reports that DNATTarget (and any wrapper type embedding it,
// such as netfilter's dnatTarget) is an iptables DNAT rule target.
func (*DNATTarget) IsDNATTarget() bool {
	return true
}
