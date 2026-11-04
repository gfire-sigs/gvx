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

package tcp

import (
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
)

// reservedAddr returns the address under which the endpoint holds its port
// reservation. A client that binds a port on the wildcard address and then
// connects gets a local address from the route, but Bind reserved the wildcard
// address. The release has to name that address, or the port stays reserved
// after the connection closes and a later bind to the same port fails with
// EADDRINUSE.
func (e *Endpoint) reservedAddr() tcpip.Address {
	if e.boundWildcard {
		return tcpip.Address{}
	}
	return e.TransportEndpointInfo.ID.LocalAddress
}

// reservedNetworks returns the networks under which the endpoint holds its port
// reservation.
func (e *Endpoint) reservedNetworks() []tcpip.NetworkProtocolNumber {
	if e.boundWildcard {
		return e.boundNetworks
	}
	return e.effectiveNetProtos
}

// dropBoundV4 removes IPv4 from the networks of the bind reservation, after
// connect released the IPv4 part of the reservation of a dual-stack endpoint.
func (e *Endpoint) dropBoundV4() {
	kept := make([]tcpip.NetworkProtocolNumber, 0, len(e.boundNetworks))
	for _, n := range e.boundNetworks {
		if n != header.IPv4ProtocolNumber {
			kept = append(kept, n)
		}
	}
	e.boundNetworks = kept
}
