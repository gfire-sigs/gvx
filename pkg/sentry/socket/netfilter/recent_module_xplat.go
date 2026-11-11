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

package netfilter

import (
	"errors"
	"sync"

	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

const stackRecentModuleKey = "nf_recent.module"

// RecentModule holds the module parameters of xt_recent. Linux has one set for
// the whole kernel, and the network namespaces of a kernel share it. The zero
// value holds the defaults.
//
// Linux reads the parameters when it loads the module, so a running system
// cannot change them (mode 0400 in /sys/module/xt_recent/parameters). gvx has no
// module load, so it accepts a change while no recent list exists, as if the
// module was unloaded and loaded again with new options.
//
// +stateify savable
type RecentModule struct {
	// listTot is ip_list_tot. The value 0 stands for the default.
	listTot atomicbitops.Uint32
	// pktListTot is ip_pkt_list_tot. The value 0 means "not set", as in Linux.
	pktListTot atomicbitops.Uint32

	// mu serializes the change of a parameter and the creation of a list.
	mu sync.Mutex `state:"nosave"`
	// lists is the count of lists of all network namespaces.
	lists int `state:"nosave"`
}

const (
	// RecentDefaultListTot is the default of ip_list_tot.
	RecentDefaultListTot = 100
	// recentModuleStampLimit is XT_RECENT_MAX_NSTAMPS. recent_mt_init refuses a
	// load with ip_pkt_list_tot at this value or above.
	recentModuleStampLimit = recentMaxStamps
)

// Errors of RecentModule.Set. The caller maps them to errno values.
var (
	// ErrRecentModuleBusy means that a recent list exists, so the module
	// parameters are fixed.
	ErrRecentModuleBusy = errors.New("netfilter: xt_recent has a list, so its parameters are fixed")
	// ErrRecentParam means that the value is one that recent_mt_init refuses.
	ErrRecentParam = errors.New("netfilter: invalid xt_recent parameter")
)

// ListTot returns ip_list_tot, the count of addresses that one list remembers.
func (m *RecentModule) ListTot() uint32 {
	if v := m.listTot.Load(); v != 0 {
		return v
	}
	return RecentDefaultListTot
}

// PktListTot returns ip_pkt_list_tot. The value 0 means that the parameter is
// not set.
func (m *RecentModule) PktListTot() uint32 { return m.pktListTot.Load() }

// SetListTot sets ip_list_tot. recent_mt_init refuses the value 0.
func (m *RecentModule) SetListTot(v uint32) error {
	if v == 0 {
		return ErrRecentParam
	}
	return m.set(&m.listTot, v)
}

// SetPktListTot sets ip_pkt_list_tot. recent_mt_init refuses a value of 65536
// or more. The value 0 restores the default.
func (m *RecentModule) SetPktListTot(v uint32) error {
	if v >= recentModuleStampLimit {
		return ErrRecentParam
	}
	return m.set(&m.pktListTot, v)
}

func (m *RecentModule) set(p *atomicbitops.Uint32, v uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lists > 0 {
		return ErrRecentModuleBusy
	}
	p.Store(v)
	return nil
}

// RecentModuleOf returns the module parameters of the kernel of stk. A stack
// that no ShareRecentModule call linked has parameters of its own.
func RecentModuleOf(stk *stack.Stack) *RecentModule {
	if stk == nil {
		return new(RecentModule)
	}
	return stk.LoadOrStoreExtensionState(stackRecentModuleKey, func() any {
		return new(RecentModule)
	}).(*RecentModule)
}

// ShareRecentModule makes child use the module parameters of parent. A new
// network namespace calls it with the stack of the root network namespace.
// Call it before the first rule of child names a list.
func ShareRecentModule(child, parent *stack.Stack) {
	if child == nil || parent == nil {
		return
	}
	child.SetExtensionState(stackRecentModuleKey, RecentModuleOf(parent))
}
