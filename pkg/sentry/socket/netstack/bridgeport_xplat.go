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
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
)

// iflaBrportMode is IFLA_BRPORT_MODE of include/uapi/linux/if_link.h. It is the
// hairpin switch of a bridge port.
const iflaBrportMode = 4

// setBridgePortInfo applies the IFLA_PROTINFO attribute of an RTM_SETLINK
// request on a bridge port. dockerd sets the hairpin mode on the host side of
// each veth pair when it runs with --userland-proxy=false.
//
// The bridge of the stack writes every frame that its own IP layer sends to
// every port, including the port of the original sender. A DNAT rule that
// sends a connection of a container back to the same container therefore
// works, and the hairpin mode needs no state. The bridge does not reflect a
// frame between two MAC addresses behind one port.
func (s *Stack) setBridgePortInfo(id tcpip.NICID, protinfo nlmsg.BytesView) *syserr.Error {
	if _, ok := s.Stack.GetNICCoordinatorID(id); !ok {
		// Linux accepts bridge port attributes only for bridge ports.
		return syserr.ErrNotSupported
	}
	attrs, ok := nlmsg.AttrsView(protinfo).Parse()
	if !ok {
		return syserr.ErrInvalidArgument
	}
	for t, v := range attrs {
		if t&linux.NLA_TYPE_MASK != iflaBrportMode {
			return syserr.ErrNotSupported
		}
		if len(v) != 1 || v[0] > 1 {
			return syserr.ErrInvalidArgument
		}
	}
	return nil
}
