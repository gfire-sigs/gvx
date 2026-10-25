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

//go:build arm64

package hvf

import (
	"errors"
	"slices"
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/ring0/pagetables"
)

// fakeAllocator hands out zeroed heap pages with synthetic guest addresses.
type fakeAllocator struct {
	next   uint64
	live   map[uint64][]byte
	freed  int
	failAt int // Allocation number that fails; zero never fails.
	calls  int
}

func newFakeAllocator() *fakeAllocator {
	return &fakeAllocator{next: 0x1_0000_0000, live: make(map[uint64][]byte)}
}

func (a *fakeAllocator) AllocPage() ([]byte, uint64, error) {
	a.calls++
	if a.failAt != 0 && a.calls == a.failAt {
		return nil, 0, errors.New("allocator failure")
	}
	// A page-aligned slice: allocate 8KB and cut at the boundary.
	raw := make([]byte, 2*pageSize4K)
	page := raw[:pageSize4K:pageSize4K]
	ipa := a.next
	a.next += pageSize4K
	a.live[ipa] = page
	return page, ipa, nil
}

func (a *fakeAllocator) FreePage(page []byte, ipa uint64) {
	if a.live[ipa] == nil || &a.live[ipa][0] != &page[0] {
		panic("freePage of a page that is not live")
	}
	delete(a.live, ipa)
	a.freed++
}

// newTestKernel returns an empty kernel tree that user trees share.
func newTestKernel(a *fakeAllocator) *pagetables.PageTables {
	initPageTables()
	kernel := pagetables.New(newTableAlloc(a))
	kernel.MarkReadOnlyShared()
	return kernel
}

// newStage1On returns user tables that share kernel.
func newStage1On(t testing.TB, a *fakeAllocator, kernel *pagetables.PageTables) *stage1Tables {
	t.Helper()
	s, err := newStage1Tables(a, kernel)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// newTestStage1 returns user tables over an empty kernel tree.
func newTestStage1(t testing.TB, a *fakeAllocator) *stage1Tables {
	t.Helper()
	return newStage1On(t, a, newTestKernel(a))
}

// translate returns the guest physical address that the tree maps at va, the
// size of the descriptor that maps it, and the permissions.
func translate(s *stage1Tables, va uint64) (ipa uint64, size uintptr, opts pagetables.MapOpts) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, physical, size, opts := s.pt.Lookup(hostarch.Addr(va), false)
	if size == 0 {
		return 0, 0, opts
	}
	// A block descriptor holds the address of its first byte.
	return uint64(physical) + (va & uint64(size-1)), size, opts
}

func TestMapRangeEncodesTheRequestedPermissions(t *testing.T) {
	cases := []struct {
		name string
		at   hostarch.AccessType
	}{
		{"read", hostarch.Read},
		{"read write", hostarch.ReadWrite},
		{"read execute", hostarch.AccessType{Read: true, Execute: true}},
		{"read write execute", hostarch.AnyAccess},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStage1(t, newFakeAllocator())
			const va, ipa = 0x7f12_3456_7000, 0x2_0000_5000
			if _, err := s.mapRange(va, ipa, pageSize4K, tc.at); err != nil {
				t.Fatalf("mapRange: %v", err)
			}
			got, size, opts := translate(s, va)
			if size == 0 || got != ipa {
				t.Fatalf("the page maps %#x with size %#x, want %#x", got, size, uint64(ipa))
			}
			if opts.AccessType != tc.at {
				t.Errorf("permissions = %v, want %v", opts.AccessType, tc.at)
			}
			if !opts.User {
				t.Error("EL0 or Ring 3 cannot reach the page: the user bit is clear")
			}
			if opts.Global {
				t.Error("a user page is global: it must belong to one address space")
			}
		})
	}
}

func TestGenerationsTrackInvalidationsOnly(t *testing.T) {
	s := newTestStage1(t, newFakeAllocator())
	const va = 0x400000
	tlb0, ic0 := s.generations()

	if inv, _ := s.mapRange(va, 0x2_0000_0000, pageSize4K, hostarch.ReadWrite); inv {
		t.Error("a new mapping reported an invalidation")
	}
	if tlb, ic := s.generations(); tlb != tlb0 || ic != ic0 {
		t.Errorf("a new data mapping changed the generations: tlb %d->%d ic %d->%d", tlb0, tlb, ic0, ic)
	}
	if inv, _ := s.mapRange(va, 0x2_0000_0000, pageSize4K, hostarch.ReadWrite); inv {
		t.Error("an identical mapping reported an invalidation")
	}
	if inv, _ := s.mapRange(va, 0x2_0000_4000, pageSize4K, hostarch.ReadWrite); !inv {
		t.Error("a new output address did not report an invalidation")
	}
	if tlb1, _ := s.generations(); tlb1 != tlb0+1 {
		t.Errorf("TLB generation = %d, want %d", tlb1, tlb0+1)
	}
	if inv, _ := s.mapRange(va, 0x2_0000_4000, pageSize4K, hostarch.Read); !inv {
		t.Error("a permission change did not report an invalidation")
	}

	_, icBefore := s.generations()
	if _, err := s.mapRange(va+pageSize4K, 0x2_0000_8000, 3*pageSize4K, hostarch.AccessType{Read: true, Execute: true}); err != nil {
		t.Fatal(err)
	}
	if _, ic := s.generations(); ic != icBefore+1 {
		t.Errorf("an executable range moved the instruction-cache generation %d->%d, want +1", icBefore, ic)
	}

	tlbBefore, _ := s.generations()
	if !s.unmapRange(va, pageSize4K) {
		t.Error("unmapRange of a mapped page reported no invalidation")
	}
	if tlb, _ := s.generations(); tlb != tlbBefore+1 {
		t.Errorf("unmap moved the TLB generation %d->%d, want +1", tlbBefore, tlb)
	}
	if s.unmapRange(va, pageSize4K) {
		t.Error("unmapRange of an unmapped page reported an invalidation")
	}
	if s.unmapRange(0x7000_0000_0000, pageSize4K) {
		t.Error("unmapRange of a page without tables reported an invalidation")
	}
	if _, size, _ := translate(s, va); size != 0 {
		t.Error("the page is still mapped after unmapRange")
	}
}

// The tree frees an empty table page when an unmap empties it. A vCPU can keep
// a cached walk through that page until it flushes, so the page must not serve
// a new table before recycle.
func TestFreedTablePagesWaitForRecycle(t *testing.T) {
	a := newFakeAllocator()
	s := newTestStage1(t, a)
	// The ipa is not 2 MiB aligned, so the range needs a table of 4KB descriptors.
	const va, ipa = 0x7f00_0000_0000, 0x2_0000_1000
	if _, err := s.mapRange(va, ipa, 2<<20, hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	tlb, _ := s.generations()
	if !s.unmapRange(va, 2<<20) {
		t.Fatal("unmapRange reported no invalidation")
	}
	if n := s.alloc.Quarantined(); n != 1 {
		t.Fatalf("%d pages wait in quarantine, want the one table that the unmap emptied", n)
	}
	if tlbAfter, _ := s.generations(); tlbAfter != tlb+1 {
		t.Errorf("TLB generation = %d, want %d", tlbAfter, tlb+1)
	}
	for _, p := range s.alloc.Quarantine {
		for _, r := range s.alloc.Ready {
			if p == r {
				t.Fatal("a quarantined page is ready for reuse before recycle")
			}
		}
	}
	freed := slices.Clone(s.alloc.Quarantine)
	s.recycle()
	if n := s.alloc.Quarantined(); n != 0 {
		t.Errorf("%d pages stay in quarantine after recycle", n)
	}
	for _, p := range freed {
		if !slices.Contains(s.alloc.Ready, p) {
			t.Error("a recycled page is not ready for reuse")
		}
		for _, v := range p {
			if v != 0 {
				t.Fatal("a recycled page still holds descriptors")
			}
		}
	}
	if _, err := s.mapRange(va, ipa, 2<<20, hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	if got, size, _ := translate(s, va+0x5000); size == 0 || got != ipa+0x5000 {
		t.Errorf("the page maps %#x (size %#x) after the recycle", got, size)
	}
}

func TestReleaseFreesEveryTablePage(t *testing.T) {
	a := newFakeAllocator()
	kernel := newTestKernel(a)
	kernelPages := len(a.live)
	for round := range 3 {
		s := newStage1On(t, a, kernel)
		// Addresses in different level-0, level-1 and level-2 slots.
		for _, va := range []uint64{0x400000, 0x7f00_0000_0000, 0x1234_5678_9000, 0x8000_0000, uint64(round) * 0x20_0000} {
			if _, err := s.mapRange(va, 0x2_0000_0000, pageSize4K, hostarch.ReadWrite); err != nil {
				t.Fatal(err)
			}
		}
		// A table that an unmap empties goes to quarantine. A partial unmap keeps its tables.
		if _, err := s.mapRange(0x1_0000_0000, 0x2_0000_1000, 2<<20, hostarch.ReadWrite); err != nil {
			t.Fatal(err)
		}
		s.unmapRange(0x1_0000_0000, 2<<20)
		if len(a.live) < kernelPages+6 {
			t.Fatalf("only %d table pages are live: the test needs distinct paths", len(a.live)-kernelPages)
		}
		s.markDead()
		s.release()
		if got := len(a.live); got != kernelPages {
			t.Fatalf("round %d: %d pages are live after release, want the %d pages of the kernel tree", round, got, kernelPages)
		}
		if _, err := s.mapRange(0x400000, 0x2_0000_0000, pageSize4K, hostarch.Read); !errors.Is(err, errPageTableReleased) {
			t.Errorf("mapRange after release = %v, want errPageTableReleased", err)
		}
		s.release() // A second release is harmless.
	}
}

func TestTableIDsNeverRepeat(t *testing.T) {
	a := newFakeAllocator()
	kernel := newTestKernel(a)
	seen := make(map[uint64]bool)
	for range 50 {
		s := newStage1On(t, a, kernel)
		if seen[s.id] || s.id == 0 {
			t.Fatalf("table id %d repeats or is zero", s.id)
		}
		seen[s.id] = true
		s.release()
	}
}

func TestMapRangeSurfacesAllocatorFailure(t *testing.T) {
	a := newFakeAllocator()
	s := newTestStage1(t, a)
	a.failAt = a.calls + 2 // Fail while mapRange reserves its table pages.
	if _, err := s.mapRange(0x400000, 0x2_0000_0000, pageSize4K, hostarch.Read); err == nil {
		t.Fatal("mapRange hid the allocator failure")
	}
	// The tables stay consistent: a later retry works.
	a.failAt = 0
	if _, err := s.mapRange(0x400000, 0x2_0000_0000, pageSize4K, hostarch.Read); err != nil {
		t.Fatalf("mapRange after the failure: %v", err)
	}
	s.release()

	failing := newFakeAllocator()
	failing.failAt = 1
	if _, err := newStage1Tables(failing, nil); err == nil {
		t.Error("newStage1Tables hid the root allocation failure")
	}
	if len(failing.live) != 0 {
		t.Errorf("%d pages leaked after a failed start", len(failing.live))
	}
}

// A range whose virtual and guest physical addresses share the alignment
// needs no 4KB descriptors: the tree writes one descriptor for each 2 MiB.
func TestAlignedRangesUseBlockDescriptors(t *testing.T) {
	s := newTestStage1(t, newFakeAllocator())
	const va, ipa = 0x4000_0000, 0x4_0000_0000
	if _, err := s.mapRange(va, ipa, 4<<20, hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	for _, off := range []uint64{0, 0x1000, 2<<20 - 0x1000, 2 << 20, 4<<20 - 0x1000} {
		got, size, _ := translate(s, va+off)
		if got != ipa+off {
			t.Fatalf("offset %#x maps %#x, want %#x", off, got, ipa+off)
		}
		if size != 2<<20 {
			t.Fatalf("offset %#x maps through a descriptor of %#x bytes, want one block of 2 MiB", off, size)
		}
	}
	// A range at an unaligned guest physical address falls back to 4KB descriptors.
	if _, err := s.mapRange(va+8<<20, ipa+0x1000, 4<<20, hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	if got, size, _ := translate(s, va+8<<20+0x5000); got != ipa+0x6000 || size != pageSize4K {
		t.Errorf("the unaligned range maps %#x with descriptor size %#x, want %#x and 4KB", got, size, uint64(ipa+0x6000))
	}
}

// An unmap inside a block descriptor must split the block and keep the other
// pages with their address and permissions.
func TestUnmapInsideABlockKeepsTheNeighbours(t *testing.T) {
	s := newTestStage1(t, newFakeAllocator())
	const va, ipa = 0x4000_0000, 0x4_0000_0000
	at := hostarch.AccessType{Read: true, Execute: true}
	if _, err := s.mapRange(va, ipa, 4<<20, at); err != nil {
		t.Fatal(err)
	}
	if !s.unmapRange(va+0x3000, 2*pageSize4K) {
		t.Fatal("unmapRange reported no invalidation")
	}
	s.recycle()
	for _, off := range []uint64{0, 0x1000, 0x2000, 0x5000, 0x1f_f000, 0x20_0000, 0x3f_f000} {
		got, size, opts := translate(s, va+off)
		if size == 0 || got != ipa+off || opts.AccessType != at {
			t.Errorf("offset %#x maps (%#x, size %#x, %v), want (%#x, mapped, %v)", off, got, size, opts.AccessType, ipa+off, at)
		}
	}
	for _, off := range []uint64{0x3000, 0x4000} {
		if _, size, _ := translate(s, va+off); size != 0 {
			t.Errorf("offset %#x is still mapped", off)
		}
	}
}

func TestUnmapRangeOfThe47BitSpaceClearsDistantMappings(t *testing.T) {
	s := newTestStage1(t, newFakeAllocator())
	vas := []uint64{0x400000, 0x7f00_0000_0000, 0x1234_5000_0000}
	for _, va := range vas {
		if _, err := s.mapRange(va, 0x2_0000_0000, 16*pageSize4K, hostarch.ReadWrite); err != nil {
			t.Fatal(err)
		}
	}
	if !s.unmapRange(pageSize4K, 1<<47) {
		t.Fatal("unmapRange reported no invalidation")
	}
	for _, va := range vas {
		if _, size, _ := translate(s, va); size != 0 {
			t.Errorf("the page at %#x survived an unmap of the whole range", va)
		}
	}
}
