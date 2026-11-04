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

package inet

import (
	"strconv"

	"z.gfire.dev/gvx/pkg/sync"
)

// UnprivilegedPortStartKey is the key of net/ipv4/ip_unprivileged_port_start
// in the sysctl values of a network namespace.
const UnprivilegedPortStartKey = "ipv4/ip_unprivileged_port_start"

// DefaultUnprivilegedPortStart is the value of ip_unprivileged_port_start in a
// new network namespace.
const DefaultUnprivilegedPortStart = 1024

// sysctlValues stores the text of the sysctl files of one network namespace
// that the network stack does not own. A key that was never written has no
// entry, and the reader uses the default of the file.
type sysctlValues struct {
	mu     sync.Mutex
	values map[string]string
}

// SysctlValue returns the stored text of the sysctl key. It reports false when
// no write stored a value.
func (n *Namespace) SysctlValue(key string) (string, bool) {
	n.sysctls.mu.Lock()
	defer n.sysctls.mu.Unlock()
	v, ok := n.sysctls.values[key]
	return v, ok
}

// SetSysctlValue stores the text of the sysctl key.
func (n *Namespace) SetSysctlValue(key, value string) {
	n.sysctls.mu.Lock()
	defer n.sysctls.mu.Unlock()
	if n.sysctls.values == nil {
		n.sysctls.values = make(map[string]string)
	}
	n.sysctls.values[key] = value
}

// UnprivilegedPortStart returns net/ipv4/ip_unprivileged_port_start of the
// namespace. A bind to a lower port needs CAP_NET_BIND_SERVICE.
func (n *Namespace) UnprivilegedPortStart() int {
	if v, ok := n.SysctlValue(UnprivilegedPortStartKey); ok {
		if port, err := strconv.Atoi(v); err == nil {
			return port
		}
	}
	return DefaultUnprivilegedPortStart
}
