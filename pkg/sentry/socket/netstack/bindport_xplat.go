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
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
)

// checkPrivilegedPort returns EACCES when addr names a port below
// net.ipv4.ip_unprivileged_port_start of the network namespace of the socket
// and the caller lacks CAP_NET_BIND_SERVICE in that namespace. Linux applies the
// rule to TCP and UDP sockets of both IP families. A bind to port 0 never
// fails here, because the stack picks an ephemeral port.
func (s *sock) checkPrivilegedPort(t *kernel.Task, addr tcpip.FullAddress) *syserr.Error {
	if s.family != linux.AF_INET && s.family != linux.AF_INET6 {
		return nil
	}
	if s.skType != linux.SOCK_STREAM && s.skType != linux.SOCK_DGRAM {
		return nil
	}
	if s.protocol != int(header.TCPProtocolNumber) && s.protocol != int(header.UDPProtocolNumber) {
		return nil
	}
	stack, ok := s.namespace.Stack().(*Stack)
	if !ok || addr.Port == 0 || int(addr.Port) >= stack.UnprivilegedPortStart() {
		return nil
	}
	if t.HasCapabilityIn(linux.CAP_NET_BIND_SERVICE, s.namespace.UserNamespace()) {
		return nil
	}
	return syserr.ErrPermissionDenied
}
