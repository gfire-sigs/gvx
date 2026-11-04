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
	"strconv"

	"z.gfire.dev/gvx/pkg/sync"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
)

// A network namespace has one Stack, so the Stack keeps the /proc/sys/net
// values that the network stack itself does not own: a value that a write
// stored, the forwarding switches, and ip_unprivileged_port_start.

const (
	// UnprivilegedPortStartKey is the key of net/ipv4/ip_unprivileged_port_start.
	UnprivilegedPortStartKey = "ipv4/ip_unprivileged_port_start"
	// DefaultUnprivilegedPortStart is the value of a network namespace that the
	// guest creates, as on Linux.
	DefaultUnprivilegedPortStart = 1024
)

// sysctlValues stores the text of the sysctl files of one Stack. A key that no
// write stored has no entry, and the reader uses the default of the file.
type sysctlValues struct {
	mu     sync.Mutex
	values map[string]string
}

// SysctlValue returns the stored text of the sysctl key. It reports false when
// no write stored a value.
func (s *Stack) SysctlValue(key string) (string, bool) {
	s.sysctls.mu.Lock()
	defer s.sysctls.mu.Unlock()
	v, ok := s.sysctls.values[key]
	return v, ok
}

// SetSysctlValue stores the text of the sysctl key.
func (s *Stack) SetSysctlValue(key, value string) {
	s.sysctls.mu.Lock()
	defer s.sysctls.mu.Unlock()
	if s.sysctls.values == nil {
		s.sysctls.values = make(map[string]string)
	}
	s.sysctls.values[key] = value
}

// UnprivilegedPortStart returns net/ipv4/ip_unprivileged_port_start. A bind to
// a lower port needs CAP_NET_BIND_SERVICE.
func (s *Stack) UnprivilegedPortStart() int {
	if v, ok := s.SysctlValue(UnprivilegedPortStartKey); ok {
		if port, err := strconv.Atoi(v); err == nil {
			return port
		}
	}
	return DefaultUnprivilegedPortStart
}

// SetUnprivilegedPortStart sets net/ipv4/ip_unprivileged_port_start.
func (s *Stack) SetUnprivilegedPortStart(port int) {
	s.SetSysctlValue(UnprivilegedPortStartKey, strconv.Itoa(port))
}

// forwardingKey returns the key of the forwarding switch of an IP family. The
// all switch also stands for ip_forward.
func forwardingKey(protocol tcpip.NetworkProtocolNumber, isDefault bool) string {
	family := "ipv4"
	if protocol == ipv6.ProtocolNumber {
		family = "ipv6"
	}
	if isDefault {
		return family + "/forwarding_default"
	}
	return family + "/forwarding_all"
}

// Forwarding returns the value of conf/all/forwarding, or of
// conf/default/forwarding when isDefault is set, for the IP family.
func (s *Stack) Forwarding(protocol tcpip.NetworkProtocolNumber, isDefault bool) bool {
	v, _ := s.SysctlValue(forwardingKey(protocol, isDefault))
	return v == "1"
}

// SetForwardingSwitch sets conf/all/forwarding, which ip_forward shares, or
// conf/default/forwarding when isDefault is set. As on Linux, the all switch
// also sets the default and every link that exists, and the default switch
// changes only the links that the guest creates later.
func (s *Stack) SetForwardingSwitch(protocol tcpip.NetworkProtocolNumber, isDefault, enable bool) error {
	value := "0"
	if enable {
		value = "1"
	}
	if isDefault {
		s.Stack.SetForwardingDefault(protocol, enable)
		s.SetSysctlValue(forwardingKey(protocol, true), value)
		return nil
	}
	if err := s.SetForwarding(protocol, enable); err != nil {
		return err
	}
	s.SetSysctlValue(forwardingKey(protocol, true), value)
	s.SetSysctlValue(forwardingKey(protocol, false), value)
	return nil
}

// InheritForwarding gives the IPv4 forwarding switches of the stack the values
// of the stack of the root network namespace, as Linux does when it creates a
// network namespace with net.core.devconf_inherit_init_net at 0. The IPv6
// switches keep their defaults.
func (s *Stack) InheritForwarding(root *Stack) error {
	if err := s.SetForwardingSwitch(ipv4.ProtocolNumber, false, root.Forwarding(ipv4.ProtocolNumber, false)); err != nil {
		return err
	}
	return s.SetForwardingSwitch(ipv4.ProtocolNumber, true, root.Forwarding(ipv4.ProtocolNumber, true))
}
