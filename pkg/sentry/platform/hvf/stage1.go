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

package hvf

import (
	"errors"
	"sync"
	"sync/atomic"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/ring0/pagetables"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// errPageTableReleased reports a mapping request on a released page table.
var errPageTableReleased = errors.New("hvf: page table released")

type pageAllocator = hvcommon.PagePool
type tableAlloc = hvcommon.PTAllocator

func newTableAlloc(pages pageAllocator) *tableAlloc {
	return hvcommon.NewPTAllocator(pages)
}

const (
	reserveForUnmap  = hvcommon.SplitReserve
	kernelTablePages = hvcommon.KernelTablePages
)

// stage1Tables is the Stage-1 translation tree of one address space, below
// TTBR0_EL1 on arm64 and CR3 on amd64. pkg/ring0/pagetables walks and updates
// the tree. This type adds what the hypervisor needs on top: the table pages
// come from the VM, and every vCPU learns from generation counters when its
// cached state is stale.
type stage1Tables struct {
	id uint64

	mu       sync.Mutex
	pt       *pagetables.PageTables
	alloc    *tableAlloc
	released bool

	tlbGen atomic.Uint64
	icGen  atomic.Uint64
	dead   atomic.Bool
}

var nextStage1ID atomic.Uint64

func newStage1Tables(pages pageAllocator, kernel *pagetables.PageTables) (*stage1Tables, error) {
	alloc := newTableAlloc(pages)
	if err := alloc.Reserve(2); err != nil {
		alloc.Drain()
		return nil, err
	}
	return &stage1Tables{
		id:    nextStage1ID.Add(1),
		pt:    pagetables.NewWithUpper(alloc, kernel, userUpperStart),
		alloc: alloc,
	}, nil
}

func (s *stage1Tables) generations() (tlb, ic uint64) {
	return s.tlbGen.Load(), s.icGen.Load()
}

func (s *stage1Tables) mapRange(va, ipa, length uint64, at hostarch.AccessType) (invalidated bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released {
		return false, errPageTableReleased
	}
	if err := s.alloc.Reserve(hvcommon.ReserveForMap(length / pageSize4K)); err != nil {
		return false, err
	}
	replaced := s.pt.Map(hostarch.Addr(va), uintptr(length), pagetables.MapOpts{AccessType: at, User: true}, uintptr(ipa))
	if at.Execute {
		s.icGen.Add(1)
	}
	return s.noteChange(replaced), nil
}

func (s *stage1Tables) unmapRange(va, length uint64) (invalidated bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released || length == 0 {
		return false
	}
	_ = s.alloc.Reserve(reserveForUnmap)
	return s.noteChange(s.pt.Unmap(hostarch.Addr(va), uintptr(length)))
}

func (s *stage1Tables) noteChange(changed bool) bool {
	if changed || s.alloc.Quarantined() > 0 {
		s.tlbGen.Add(1)
		return true
	}
	return false
}

func (s *stage1Tables) recycle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alloc.Recycle()
}

func (s *stage1Tables) markDead() {
	s.dead.Store(true)
	s.tlbGen.Add(1)
}

func (s *stage1Tables) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released {
		return
	}
	s.released = true
	s.alloc.Drain()
}
