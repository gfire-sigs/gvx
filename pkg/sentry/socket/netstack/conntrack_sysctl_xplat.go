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
	"time"

	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// The methods below give /proc/sys/net/netfilter access to the connection
// tracker of the stack. The timeouts belong to the network namespace. The
// limit nf_conntrack_max belongs to the kernel, as on Linux, so the stack of a
// network namespace that the guest creates shares the limit of the root stack.

// InitConntrackLimit sets the limit nf_conntrack_max of the stack. The stack of
// the root network namespace passes nil and gets the default limit. The stack
// of another namespace passes the root stack and shares its limit.
func (s *Stack) InitConntrackLimit(root *Stack) {
	if root == nil {
		s.Stack.SetConntrackLimit(stack.NewConntrackLimit(stack.DefaultConntrackMax))
		return
	}
	s.Stack.SetConntrackLimit(root.Stack.ConntrackLimit())
}

// ConntrackMax returns nf_conntrack_max as Linux prints it: a signed integer
// that holds the unsigned limit. 0 means no limit.
func (s *Stack) ConntrackMax() int32 {
	if l := s.Stack.ConntrackLimit(); l != nil {
		return int32(l.Max())
	}
	return 0
}

// SetConntrackMax sets nf_conntrack_max for every stack of the kernel.
func (s *Stack) SetConntrackMax(max int32) {
	if l := s.Stack.ConntrackLimit(); l != nil {
		l.SetMax(uint32(max))
		return
	}
	s.Stack.SetConntrackLimit(stack.NewConntrackLimit(uint32(max)))
}

// ConntrackCount returns nf_conntrack_count of the network namespace.
func (s *Stack) ConntrackCount() int {
	return s.Stack.ConntrackCount()
}

// ConntrackBuckets returns nf_conntrack_buckets.
func (s *Stack) ConntrackBuckets() int {
	return s.Stack.ConntrackBuckets()
}

// ConntrackTimeout returns the timeout that a sysctl file of
// /proc/sys/net/netfilter sets for the network namespace.
func (s *Stack) ConntrackTimeout(t stack.ConntrackTimeout) time.Duration {
	return s.Stack.ConntrackTimeout(t)
}

// SetConntrackTimeout sets the timeout of the connection tracker of the
// network namespace.
func (s *Stack) SetConntrackTimeout(t stack.ConntrackTimeout, d time.Duration) {
	s.Stack.SetConntrackTimeout(t, d)
}

// SetConntrackTCPMaxRetrans sets nf_conntrack_tcp_max_retrans.
func (s *Stack) SetConntrackTCPMaxRetrans(n uint8) {
	s.Stack.SetConntrackTCPMaxRetrans(n)
}
