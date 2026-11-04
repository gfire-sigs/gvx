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

package tcpip

import "time"

// TCPKeepaliveDefaultsOption is used by SetTransportProtocolOption and
// TransportProtocolOption to set or get the keepalive parameters that new TCP
// endpoints of a stack start with. It models net.ipv4.tcp_keepalive_time,
// tcp_keepalive_intvl, and tcp_keepalive_probes. A socket option on an
// endpoint overrides these values for that endpoint.
type TCPKeepaliveDefaultsOption struct {
	// Idle is the idle time before the first probe.
	Idle time.Duration
	// Interval is the time between two probes.
	Interval time.Duration
	// Count is the number of unanswered probes that end the connection.
	Count int
}

func (*TCPKeepaliveDefaultsOption) isGettableTransportProtocolOption() {}

func (*TCPKeepaliveDefaultsOption) isSettableTransportProtocolOption() {}
