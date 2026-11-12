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

//go:build darwin

package hvf

import (
	"errors"
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// newFakeVM returns VM state over backends that count Stage-2 calls. No
// hypervisor is involved, so the tests run on every Mac. The returned backend
// counts the calls for guest memory only. A second backend takes the calls
// for table pages, which grow the slab when a mapping needs new tables.
func newFakeVM(t testing.TB) (*vmState, *fakeStage2) {
	t.Helper()
	vm, err := newVMStateOn(&fakeStage2{}, 36, 4)
	if err != nil {
		t.Fatalf("newVMStateOn: %v", err)
	}
	t.Cleanup(vm.releaseSlabs)
	be := &fakeStage2{}
	vm.regions.setBackend(be)
	return vm, be
}

func newFakeAddressSpace(t testing.TB, vm *vmState) *AddressSpace {
	t.Helper()
	as, err := newAddressSpace(vm)
	if err != nil {
		t.Fatalf("newAddressSpace: %v", err)
	}
	t.Cleanup(as.Release)
	return as
}

// guestIPA returns the guest physical address that the Stage-1 tables of as
// map at va.
func guestIPA(as *AddressSpace, va uint64) (uint64, bool) {
	ipa, size, _ := translate(as.pt, va)
	return ipa, size != 0
}

const (
	fourMiB = 4 << 20
	// bigVA is aligned to 2 MiB.
	bigVA = hostarch.Addr(0x4000_0000)
)

func TestMapFileOfFourMiBMakesBoundedStage2Calls(t *testing.T) {
	for _, tc := range []struct {
		name string
		file func() (memmap.File, []byte)
	}{
		{"memory file", func() (memmap.File, []byte) {
			f := newTestChunkFile(1, 16<<20)
			return f, f.chunks[0]
		}},
		{"other file", func() (memmap.File, []byte) {
			f := &plainFile{mem: alignedMem(16 << 20)}
			return f, f.mem
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vm, be := newFakeVM(t)
			as := newFakeAddressSpace(t, vm)
			file, _ := tc.file()
			baseMaps, _ := be.counts()

			fr := memmap.FileRange{Start: 4 << 20, End: 4<<20 + fourMiB}
			if err := as.MapFile(bigVA, file, fr, hostarch.ReadWrite, false); err != nil {
				t.Fatalf("MapFile: %v", err)
			}
			maps, unmaps := be.counts()
			if maps-baseMaps != 1 || unmaps != 0 {
				t.Errorf("a 4 MiB MapFile made %d hv_vm_map and %d hv_vm_unmap calls, want 1 and 0", maps-baseMaps, unmaps)
			}
			// Every page of the range reaches its host page through one linear run.
			first, ok := guestIPA(as, uint64(bigVA))
			if !ok {
				t.Fatal("the first page is not mapped")
			}
			for off := uint64(0); off < fourMiB; off += 256 << 10 {
				if ipa, ok := guestIPA(as, uint64(bigVA)+off); !ok || ipa != first+off {
					t.Fatalf("page at +%#x maps %#x (mapped=%v), want %#x", off, ipa, ok, first+off)
				}
			}
			if ipa, ok := guestIPA(as, uint64(bigVA)+fourMiB-pageSize4K); !ok || ipa != first+fourMiB-pageSize4K {
				t.Errorf("last page maps %#x (mapped=%v), want %#x", ipa, ok, first+fourMiB-pageSize4K)
			}
		})
	}
}

func TestUnmapMakesNoStage2Call(t *testing.T) {
	vm, be := newFakeVM(t)
	as := newFakeAddressSpace(t, vm)
	file := newTestChunkFile(1, 16<<20)
	fr := memmap.FileRange{Start: 0, End: fourMiB}
	if err := as.MapFile(bigVA, file, fr, hostarch.ReadWrite, false); err != nil {
		t.Fatal(err)
	}
	baseMaps, baseUnmaps := be.counts()

	as.Unmap(bigVA+pageSize4K, 8*pageSize4K)
	if _, ok := guestIPA(as, uint64(bigVA)+pageSize4K); ok {
		t.Error("a page is still mapped inside the unmapped range")
	}
	if _, ok := guestIPA(as, uint64(bigVA)); !ok {
		t.Error("the page before the unmapped range lost its mapping")
	}
	if _, ok := guestIPA(as, uint64(bigVA)+9*pageSize4K); !ok {
		t.Error("the page after the unmapped range lost its mapping")
	}
	as.Unmap(bigVA, fourMiB)
	for _, off := range []uint64{0, 9 * pageSize4K, fourMiB - pageSize4K} {
		if _, ok := guestIPA(as, uint64(bigVA)+off); ok {
			t.Errorf("the page at +%#x is still mapped after Unmap", off)
		}
	}
	if maps, unmaps := be.counts(); maps != baseMaps || unmaps != baseUnmaps {
		t.Errorf("Unmap made %d hv_vm_map and %d hv_vm_unmap calls, want 0 and 0", maps-baseMaps, unmaps-baseUnmaps)
	}
}

func TestRemapOfTheSameRangeMakesNoStage2Call(t *testing.T) {
	vm, be := newFakeVM(t)
	as := newFakeAddressSpace(t, vm)
	file := newTestChunkFile(1, 16<<20)
	fr := memmap.FileRange{Start: 0, End: fourMiB}
	if err := as.MapFile(bigVA, file, fr, hostarch.ReadWrite, false); err != nil {
		t.Fatal(err)
	}
	baseMaps, baseUnmaps := be.counts()
	for round := range 3 {
		as.Unmap(bigVA, fourMiB)
		if err := as.MapFile(bigVA, file, fr, hostarch.ReadWrite, false); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		// A permission change and a different part of the file also stay in Stage-1.
		if err := as.MapFile(bigVA, file, fr, hostarch.Read, false); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if err := as.MapFile(bigVA+fourMiB, file, memmap.FileRange{Start: 8 << 20, End: 12 << 20}, hostarch.ReadWrite, false); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
	}
	if maps, unmaps := be.counts(); maps != baseMaps || unmaps != baseUnmaps {
		t.Errorf("remapping made %d hv_vm_map and %d hv_vm_unmap calls, want 0 and 0", maps-baseMaps, unmaps-baseUnmaps)
	}
}

// A replacement of the only mapping of a region leaves nothing that names the
// old memory, so the region of the old file leaves Stage-2 with the call. A
// stale translation cannot reach the old memory, because MapFile stops the
// vCPUs first.
func TestReplacementReleasesTheOldRegion(t *testing.T) {
	vm, be := newFakeVM(t)
	as, err := newAddressSpace(vm)
	if err != nil {
		t.Fatal(err)
	}
	a := &plainFile{mem: alignedMem(1 << 20)}
	b := &plainFile{mem: alignedMem(1 << 20)}
	fr := memmap.FileRange{Start: 0, End: 1 << 20}
	if err := as.MapFile(bigVA, a, fr, hostarch.ReadWrite, false); err != nil {
		t.Fatal(err)
	}
	ipaA, _ := guestIPA(as, uint64(bigVA))
	if err := as.MapFile(bigVA, b, fr, hostarch.ReadWrite, false); err != nil {
		t.Fatal(err)
	}
	ipaB, ok := guestIPA(as, uint64(bigVA))
	if !ok || ipaB == ipaA {
		t.Fatalf("the replacement maps %#x (mapped=%v), want a new address, not %#x", ipaB, ok, ipaA)
	}
	if _, unmaps := be.counts(); unmaps != 1 {
		t.Errorf("the replacement made %d hv_vm_unmap calls, want 1: the region of the old file", unmaps)
	}
	if got := vm.regions.regionCount(); got != 1 {
		t.Errorf("regions after the replacement = %d, want only the region of the new file", got)
	}
	as.Release()
	if _, unmaps := be.counts(); unmaps != 2 {
		t.Errorf("Release made %d hv_vm_unmap calls in total, want 2: one per file", unmaps)
	}
	if got := vm.regions.regionCount(); got != 0 {
		t.Errorf("regions after Release = %d, want 0", got)
	}
}

func TestReleaseLeavesNoGuestMapping(t *testing.T) {
	vm, be := newFakeVM(t)
	before := vm.slabStats()
	as, err := newAddressSpace(vm)
	if err != nil {
		t.Fatal(err)
	}
	memFile := newTestChunkFile(1, 16<<20)
	other := &plainFile{mem: alignedMem(1 << 20)}
	if err := as.MapFile(bigVA, memFile, memmap.FileRange{Start: 0, End: fourMiB}, hostarch.ReadWrite, false); err != nil {
		t.Fatal(err)
	}
	if err := as.MapFile(0x7f00_0000_0000, other, memmap.FileRange{Start: 0, End: 1 << 20}, hostarch.Read, false); err != nil {
		t.Fatal(err)
	}
	if got := vm.slabStats().pagesInUse; got <= before.pagesInUse {
		t.Fatalf("pages in use = %d: the mappings need table pages", got)
	}
	baseMaps, _ := be.counts()
	as.Release()

	// No table page is left, so no translation reaches memory that the Sentry can reuse.
	if got := vm.slabStats().pagesInUse; got != before.pagesInUse {
		t.Errorf("table pages in use after Release = %d, want %d: a table page stays", got, before.pagesInUse)
	}
	if _, err := as.pt.mapRange(uint64(bigVA), 0x2_0000_0000, pageSize4K, hostarch.Read); !errors.Is(err, errPageTableReleased) {
		t.Errorf("mapRange on a released table = %v, want errPageTableReleased", err)
	}
	var segv platform.SegmentationFault
	if err := as.MapFile(bigVA, memFile, memmap.FileRange{Start: 0, End: pageSize4K}, hostarch.Read, false); !errors.As(err, &segv) {
		t.Errorf("MapFile after Release = %v, want SegmentationFault", err)
	}
	// The region of the memory file stays: the VM keeps it. The other region goes.
	maps, unmaps := be.counts()
	if maps != baseMaps || unmaps != 1 {
		t.Errorf("Release made %d hv_vm_map and %d hv_vm_unmap calls, want 0 and 1", maps-baseMaps, unmaps)
	}
	if got := vm.regions.regionCount(); got != 1 {
		t.Errorf("regions after Release = %d, want the memory file chunk", got)
	}
}

func TestUnmapOfAWideRangeClearsDistantMappings(t *testing.T) {
	vm, be := newFakeVM(t)
	as := newFakeAddressSpace(t, vm)
	file := &plainFile{mem: alignedMem(1 << 20)}
	fr := memmap.FileRange{Start: 0, End: 1 << 20}
	vas := []hostarch.Addr{0x400000, 0x7f00_0000_0000, 0x1234_5000_0000, 0x7fe0_0000_0000}
	for _, va := range vas {
		if err := as.MapFile(va, file, fr, hostarch.ReadWrite, false); err != nil {
			t.Fatalf("MapFile at %#x: %v", uint64(va), err)
		}
	}
	_, baseUnmaps := be.counts()
	as.Unmap(pageSize4K, maxUserAddress)
	for _, va := range vas {
		if _, ok := guestIPA(as, uint64(va)); ok {
			t.Errorf("the page at %#x survived an Unmap of the whole user range", uint64(va))
		}
	}
	// Four mappings share one region. The region leaves Stage-2 with the last
	// mapping, and not before.
	if _, unmaps := be.counts(); unmaps != baseUnmaps+1 {
		t.Errorf("Unmap made %d hv_vm_unmap calls, want 1: the region of the file", unmaps-baseUnmaps)
	}
	if got := vm.regions.regionCount(); got != 0 {
		t.Errorf("regions after the unmap = %d, want 0", got)
	}
	// An empty address space handles the same call at once.
	as.Unmap(0, ^uint64(0))
}

func TestMapFileRejectsRangesOutsideTheUserAddressSpace(t *testing.T) {
	vm, _ := newFakeVM(t)
	as := newFakeAddressSpace(t, vm)
	file := &plainFile{mem: alignedMem(1 << 20)}
	var segv platform.SegmentationFault
	for _, tc := range []struct {
		name string
		addr hostarch.Addr
		fr   memmap.FileRange
	}{
		{"past the end", hostarch.Addr(maxUserAddress) - pageSize4K, memmap.FileRange{Start: 0, End: 2 * pageSize4K}},
		{"wraps around", hostarch.Addr(^uint64(0)) - 0xfff, memmap.FileRange{Start: 0, End: 2 * pageSize4K}},
	} {
		if err := as.MapFile(tc.addr, file, tc.fr, hostarch.Read, false); !errors.As(err, &segv) {
			t.Errorf("%s: MapFile = %v, want SegmentationFault", tc.name, err)
		}
	}
	if err := as.MapFile(0x400000, file, memmap.FileRange{Start: 0, End: pageSize4K}, hostarch.NoAccess, false); !errors.As(err, &segv) {
		t.Errorf("a mapping without access: MapFile = %v, want SegmentationFault", err)
	}
}

// An Unmap of a part of a mapping keeps the region while another page names it.
// The last page that names it frees it.
func TestUnmapKeepsARegionWhileAPageNamesIt(t *testing.T) {
	vm, be := newFakeVM(t)
	as := newFakeAddressSpace(t, vm)
	file := &plainFile{mem: alignedMem(1 << 20)}
	fr := memmap.FileRange{Start: 0, End: 16 * pageSize4K}
	if err := as.MapFile(bigVA, file, fr, hostarch.ReadWrite, false); err != nil {
		t.Fatal(err)
	}
	_, base := be.counts()
	as.Unmap(bigVA, 8*pageSize4K)
	if _, unmaps := be.counts(); unmaps != base {
		t.Fatalf("a partial Unmap made %d hv_vm_unmap calls, want 0: eight pages still name the region", unmaps-base)
	}
	as.Unmap(bigVA+8*pageSize4K, 8*pageSize4K)
	if _, unmaps := be.counts(); unmaps != base+1 {
		t.Errorf("the last Unmap made %d hv_vm_unmap calls, want 1", unmaps-base)
	}
	if got := vm.regions.regionCount(); got != 0 {
		t.Errorf("regions after the last Unmap = %d, want 0", got)
	}
}

// A mapping of a memory file range never releases the region of the file,
// because the file outlives its mappings. This keeps a fault of 4 MiB free of
// hypervisor calls.
func TestUnmapKeepsTheRegionOfAMemoryFile(t *testing.T) {
	vm, _ := newFakeVM(t)
	as := newFakeAddressSpace(t, vm)
	file := newTestChunkFile(1, 16<<20)
	if err := as.MapFile(bigVA, file, memmap.FileRange{Start: 0, End: fourMiB}, hostarch.ReadWrite, false); err != nil {
		t.Fatal(err)
	}
	want := vm.regions.regionCount()
	as.Unmap(bigVA, fourMiB)
	if got := vm.regions.regionCount(); got != want {
		t.Errorf("regions after Unmap of a memory file = %d, want %d", got, want)
	}
}
