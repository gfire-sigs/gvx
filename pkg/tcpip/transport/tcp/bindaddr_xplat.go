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

import "z.gfire.dev/gvx/pkg/tcpip"

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
