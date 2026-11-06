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
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// SetNeighborGCThresholds sets gc_thresh1, gc_thresh2, and gc_thresh3 of the
// neighbor table of the protocol. It models net.ipv4.neigh.default.gc_thresh* for
// IPv4 and net.ipv6.neigh.default.gc_thresh* for IPv6.
func (s *Stack) SetNeighborGCThresholds(protocol tcpip.NetworkProtocolNumber, thresh1, thresh2, thresh3 int32) error {
	th := stack.NeighborGCThresholds{Thresh1: thresh1, Thresh2: thresh2, Thresh3: thresh3}
	return syserr.TranslateNetstackError(s.Stack.SetNeighborGCThresholds(protocol, th)).ToError()
}
