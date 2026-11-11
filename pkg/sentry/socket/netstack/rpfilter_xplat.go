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
	"z.gfire.dev/gvx/pkg/sync"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
)

// The IPv4 sysctl rp_filter has three files in each network namespace:
// conf/all/rp_filter, conf/default/rp_filter, and conf/<link>/rp_filter. The
// files follow net/ipv4/devinet.c of Linux:
//
//   - Each file holds one integer. The proc handler is proc_dointvec, so any
//     integer is stored, and the stack gives the values 0, 1, and 2 a meaning.
//   - A link follows conf/default/rp_filter until the guest writes the file of
//     the link. A write to the default changes every link that has no value of
//     its own (devinet_copy_dflt_conf), and a new link starts with the default.
//   - A write to conf/all/rp_filter changes no link. The check of a packet takes
//     the larger of the all value and the value of the link (IN_DEV_RPFILTER).
//
// The stack stores the values and gives them to the reverse path check of the
// IPv4 receive path through EffectiveRPFilter. The initial value is 0, the
// default of the Linux kernel.

// rpFilterState holds the rp_filter values of one network stack.
//
// +stateify savable
type rpFilterState struct {
	mu sync.RWMutex `state:"nosave"`
	// all and def are conf/all/rp_filter and conf/default/rp_filter.
	all, def int32
	// links holds the value of each link that the guest wrote.
	links map[tcpip.NICID]int32
}

// RPFilterAll returns conf/all/rp_filter.
func (s *Stack) RPFilterAll() int32 {
	s.rpFilter.mu.RLock()
	defer s.rpFilter.mu.RUnlock()
	return s.rpFilter.all
}

// SetRPFilterAll sets conf/all/rp_filter. No link changes.
func (s *Stack) SetRPFilterAll(v int32) {
	s.rpFilter.mu.Lock()
	defer s.rpFilter.mu.Unlock()
	s.rpFilter.all = v
}

// RPFilterDefault returns conf/default/rp_filter.
func (s *Stack) RPFilterDefault() int32 {
	s.rpFilter.mu.RLock()
	defer s.rpFilter.mu.RUnlock()
	return s.rpFilter.def
}

// SetRPFilterDefault sets conf/default/rp_filter. A link that has no value of
// its own follows the new value.
func (s *Stack) SetRPFilterDefault(v int32) {
	s.rpFilter.mu.Lock()
	defer s.rpFilter.mu.Unlock()
	s.rpFilter.def = v
}

// LinkRPFilter returns conf/<link>/rp_filter of the link with the index id.
func (s *Stack) LinkRPFilter(id int32) (int32, error) {
	if _, ok := s.Stack.SingleNICInfo(tcpip.NICID(id)); !ok {
		return 0, syserr.ErrUnknownNICID.ToError()
	}
	return s.linkRPFilter(tcpip.NICID(id)), nil
}

func (s *Stack) linkRPFilter(id tcpip.NICID) int32 {
	s.rpFilter.mu.RLock()
	defer s.rpFilter.mu.RUnlock()
	if v, ok := s.rpFilter.links[id]; ok {
		return v
	}
	return s.rpFilter.def
}

// SetLinkRPFilter sets conf/<link>/rp_filter of the link with the index id. The
// link keeps the value when conf/default/rp_filter changes.
func (s *Stack) SetLinkRPFilter(id int32, v int32) error {
	nic := tcpip.NICID(id)
	if _, ok := s.Stack.SingleNICInfo(nic); !ok {
		return syserr.ErrUnknownNICID.ToError()
	}
	s.rpFilter.mu.Lock()
	defer s.rpFilter.mu.Unlock()
	// Drop the values of links that ended without an event of this stack, as
	// the removal of the peer of a veth link does.
	for other := range s.rpFilter.links {
		if _, ok := s.Stack.SingleNICInfo(other); !ok {
			delete(s.rpFilter.links, other)
		}
	}
	if s.rpFilter.links == nil {
		s.rpFilter.links = make(map[tcpip.NICID]int32)
	}
	s.rpFilter.links[nic] = v
	return nil
}

// EffectiveRPFilter returns the value that the reverse path check of the link
// with the index id uses: the larger of conf/all/rp_filter and the value of the
// link. The value 0 turns the check off, 1 selects strict mode, and 2 selects
// loose mode.
func (s *Stack) EffectiveRPFilter(id tcpip.NICID) int32 {
	s.rpFilter.mu.RLock()
	defer s.rpFilter.mu.RUnlock()
	v, ok := s.rpFilter.links[id]
	if !ok {
		v = s.rpFilter.def
	}
	return max(s.rpFilter.all, v)
}

// InheritRPFilter gives conf/all/rp_filter and conf/default/rp_filter of the
// stack the values of the stack of the root network namespace, as Linux does for
// IPv4 when it creates a network namespace with net.core.devconf_inherit_init_net
// at 0.
func (s *Stack) InheritRPFilter(root *Stack) {
	all, def := root.RPFilterAll(), root.RPFilterDefault()
	s.rpFilter.mu.Lock()
	defer s.rpFilter.mu.Unlock()
	s.rpFilter.all, s.rpFilter.def = all, def
}

// dropLinkRPFilter forgets the value of a link that left the stack.
func (s *Stack) dropLinkRPFilter(id tcpip.NICID) {
	s.rpFilter.mu.Lock()
	defer s.rpFilter.mu.Unlock()
	delete(s.rpFilter.links, id)
}
