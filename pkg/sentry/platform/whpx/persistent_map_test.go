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

package whpx

import (
	"errors"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// fileOf returns a non-persistent memmap.File that serves data for the whole range.
func fileOf(data []byte) *fakeFile {
	return &fakeFile{blocks: []safemem.Block{safemem.BlockFromSafeSlice(data)}}
}

// syntheticVAFile is a non-persistent memmap.File located at an explicit
// 64-bit host virtual address for testing high-entropy Windows ASLR and host VA
// recycling on any OS.
type syntheticVAFile struct {
	memmap.File
	base uintptr
}

func (f *syntheticVAFile) hostBlocks(fr memmap.FileRange, _ hostarch.AccessType) ([]hvcommon.HostBlock, error) {
	return []hvcommon.HostBlock{{
		Addr: f.base + uintptr(fr.Start),
		Len:  uintptr(fr.Length()),
	}}, nil
}

// checkWritableEntriesHaveWritableMemory verifies that no page-table entry of
// as grants write access to guest memory that the partition maps read-only.
func checkWritableEntriesHaveWritableMemory(t *testing.T, fb *fakeBackend, as *AddressSpace, va uint64, pages int) {
	t.Helper()
	for i := range pages {
		gpa, opts, _, ok := translate(as, va+uint64(i)*pageSize)
		if !ok || !opts.Write {
			continue
		}
		if mp, _, mapped := fb.mappingOf(gpa); !mapped || mp.flags&mapFlagWrite == 0 {
			t.Errorf("page %d is writable in the page tables but maps read-only memory in the partition", i)
		}
	}
}

func TestMapFileOfFourMiBRegistersHostMemoryOnce(t *testing.T) {
	requireGuestPageSize(t)
	const size = 4 << 20
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := pageAlignedHost(t, size)
	file := &chunkedSliceFile{sliceMemmapFile: sliceMemmapFile{mem: mem}}
	fr := memmap.FileRange{Start: 0, End: size}

	maps0, unmaps0 := fb.calls()
	if err := as.MapFile(0x400000, file, fr, hostarch.ReadWrite, false); err != nil {
		t.Fatal(err)
	}
	maps, unmaps := fb.calls()
	if maps-maps0 != 1 || unmaps != unmaps0 {
		t.Fatalf("MapFile of %d pages made %d map calls and %d unmap calls, want 1 and 0", size/pageSize, maps-maps0, unmaps-unmaps0)
	}
	first, _, _, ok := translate(as, 0x400000)
	if !ok {
		t.Fatal("the first page is not mapped")
	}
	for _, i := range []uint64{1, 511, 512, size/pageSize - 1} {
		gpa, got, user, ok := translate(as, 0x400000+i*pageSize)
		if !ok || !user || !got.Write || gpa != first+i*pageSize {
			t.Fatalf("page %d translates to %#x (mapped %v, %+v), want %#x", i, gpa, ok, got, first+i*pageSize)
		}
		if host, _ := hostOf(fb, gpa); host != uintptr(unsafe.Pointer(&mem[i*pageSize])) {
			t.Fatalf("page %d maps host %#x, want %p", i, host, &mem[i*pageSize])
		}
	}

	// Unmap on a persistent memory file clears only guest page-table entries.
	as.Unmap(0x400000, size)
	if maps2, unmaps2 := fb.calls(); maps2 != maps || unmaps2 != unmaps {
		t.Errorf("Unmap of %d pages made %d map calls and %d unmap calls", size/pageSize, maps2-maps, unmaps2-unmaps)
	}
	if _, _, _, ok := translate(as, 0x400000+size/2); ok {
		t.Error("a page stays mapped after Unmap")
	}

	// Mapping the same memory file again, at another address or in another
	// address space, makes no Stage-2 call.
	other := newTestAS(t, p)
	for _, target := range []*AddressSpace{as, other} {
		if err := target.MapFile(0x10000000, file, fr, hostarch.ReadWrite, false); err != nil {
			t.Fatal(err)
		}
	}
	if maps3, unmaps3 := fb.calls(); maps3 != maps || unmaps3 != unmaps {
		t.Errorf("remapping made %d map calls and %d unmap calls", maps3-maps, unmaps3-unmaps)
	}
	if g, _, _, _ := translate(other, 0x10000000+size-pageSize); g != first+size-pageSize {
		t.Errorf("the second address space maps the last page at %#x, want %#x", g, first+size-pageSize)
	}
}

func TestMapFileCallsDoNotGrowWithTheRange(t *testing.T) {
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	// One call registers each range, whatever its page count.
	for i, size := range []int{pageSize, 64 * pageSize, 2 << 20, 16 << 20} {
		mem := pageAlignedHost(t, size)
		maps0, _ := fb.calls()
		fr := memmap.FileRange{Start: 0, End: uint64(size)}
		if err := as.MapFile(hostarch.Addr(0x400000+uint64(i)<<28), fileOf(mem), fr, hostarch.ReadWrite, false); err != nil {
			t.Fatal(err)
		}
		if maps, _ := fb.calls(); maps-maps0 != 1 {
			t.Errorf("MapFile of %d pages made %d map calls, want 1", size/pageSize, maps-maps0)
		}
	}
}

func TestMapFileOfAReadOnlyViewNeverGrantsWrite(t *testing.T) {
	const size = 8 * pageSize
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := pageAlignedHost(t, size)
	file := &sliceMemmapFile{mem: mem}
	fr := memmap.FileRange{Start: 0, End: size}

	// Keep a second read-only view at 0xc00000 so roGPA stays referenced
	// during the writable upgrade at 0x400000, then verify roGPA unmaps once
	// 0xc00000 unmaps.
	if err := as.MapFile(0x400000, file, fr, hostarch.Read, false); err != nil {
		t.Fatal(err)
	}
	if err := as.MapFile(0xc00000, file, fr, hostarch.Read, false); err != nil {
		t.Fatal(err)
	}
	roGPA, _, _, _ := translate(as, 0x400000)
	if mp, _, _ := fb.mappingOf(roGPA); mp.flags&mapFlagWrite != 0 {
		t.Fatalf("a read-only request maps with flags %#x", mp.flags)
	}
	maps0, unmaps0 := fb.calls()

	if err := as.MapFile(0x400000, file, fr, hostarch.ReadWrite, false); err != nil {
		t.Fatal(err)
	}
	rwGPA, got, _, _ := translate(as, 0x400000)
	if rwGPA == roGPA || !got.Write {
		t.Fatalf("the upgraded entry maps %#x with %+v, want a writable page in a new range", rwGPA, got)
	}
	if maps, unmaps := fb.calls(); maps-maps0 != 1 || unmaps != unmaps0 {
		t.Errorf("the upgrade made %d map calls and %d unmap calls, want 1 and 0", maps-maps0, unmaps-unmaps0)
	}
	if mp, host, ok := fb.mappingOf(roGPA); !ok || mp.flags&mapFlagWrite != 0 || host != uintptr(unsafe.Pointer(&mem[0])) {
		t.Error("the read-only range changed while 0xc00000 still mapped it")
	}
	checkWritableEntriesHaveWritableMemory(t, fb, as, 0x400000, size/pageSize)

	// Unmapping the last read-only user unmaps roGPA immediately.
	as.Unmap(0xc00000, size)
	if _, _, ok := fb.mappingOf(roGPA); ok {
		t.Error("roGPA stayed mapped after its last guest mapping unmapped")
	}

	// A read request after the upgrade reuses the writable range.
	maps1, _ := fb.calls()
	if err := as.MapFile(0x800000, file, fr, hostarch.Read, false); err != nil {
		t.Fatal(err)
	}
	if g, _, _, _ := translate(as, 0x800000); g != rwGPA {
		t.Errorf("a read mapping uses %#x, want the writable range at %#x", g, rwGPA)
	}
	if maps, _ := fb.calls(); maps != maps1 {
		t.Error("a read mapping of a writable range made a map call")
	}
}

// memoryFileFake is a fakeFile that reports the host size of a memory file.
type memoryFileFake struct {
	*fakeFile
	total uint64
}

func (f memoryFileFake) TotalSize() uint64 { return f.total }

func TestMemoryFileMappedReadOnlyThenWritableRegistersOnce(t *testing.T) {
	const size = 8 * pageSize
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	mem := pageAlignedHost(t, size)
	file := memoryFileFake{fakeFile: fileOf(mem), total: size}
	fr := memmap.FileRange{Start: 0, End: size}
	maps0, unmaps0 := fb.calls()

	// A fork copy-on-write page starts read-only. The page tables forbid the
	// write, and the partition maps the memory writable, because the memory
	// file owns it with write access.
	if err := as.MapFile(0x400000, file, fr, hostarch.Read, false); err != nil {
		t.Fatal(err)
	}
	gpa, got, _, ok := translate(as, 0x400000)
	if !ok || got.Write {
		t.Fatalf("the read-only request maps %#x with %+v (mapped %v), want a read-only entry", gpa, got, ok)
	}
	if mp, _, mapped := fb.mappingOf(gpa); !mapped || mp.flags&mapFlagWrite == 0 {
		t.Fatal("the partition maps the memory file read-only, so a later write needs a second range")
	}
	if !file.lastAT.Write {
		t.Error("MapInternal got a read-only access type for a memory file")
	}
	maps1, _ := fb.calls()
	if maps1-maps0 != 1 {
		t.Fatalf("the first request made %d map calls, want 1", maps1-maps0)
	}

	// The write after the copy-on-write break reuses the registered range.
	if err := as.MapFile(0x400000, file, fr, hostarch.ReadWrite, false); err != nil {
		t.Fatal(err)
	}
	rwGPA, got, _, _ := translate(as, 0x400000)
	if rwGPA != gpa || !got.Write {
		t.Fatalf("the write request maps %#x with %+v, want %#x and a writable entry", rwGPA, got, gpa)
	}
	if maps, unmaps := fb.calls(); maps != maps1 || unmaps != unmaps0 {
		t.Errorf("the write request made %d map calls and %d unmap calls, want 0 and 0", maps-maps1, unmaps-unmaps0)
	}
	checkWritableEntriesHaveWritableMemory(t, fb, as, 0x400000, size/pageSize)
}

func TestLargeEntriesSplitOnPartialUnmap(t *testing.T) {
	requireGuestPageSize(t)
	const size = 4 << 20
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)

	// Allocate one 4KB mapping first to verify that a subsequent 2 MiB aligned
	// host range still receives a 2 MiB aligned GPA for large entries.
	prefix := pageAlignedHost(t, pageSize)
	if err := as.MapFile(0x200000, fileOf(prefix), memmap.FileRange{Start: 0, End: pageSize}, hostarch.ReadWrite, false); err != nil {
		t.Fatal(err)
	}

	buf := pageAlignedHost(t, size+2<<20)
	base := uintptr(unsafe.Pointer(&buf[0]))
	off := int(((base + 2<<20 - 1) &^ (2<<20 - 1)) - base)
	mem := buf[off : off+size : off+size]
	file := &sliceMemmapFile{mem: mem}
	fr := memmap.FileRange{Start: 0, End: size}
	const va = 0x40000000
	if err := as.MapFile(va, file, fr, hostarch.ReadWrite, false); err != nil {
		t.Fatal(err)
	}
	first, _, _, _ := translate(as, va)
	if _, _, entry, _ := as.pt.Lookup(va, false); entry != 2<<20 {
		t.Fatalf("the page tables use entries of %d bytes, want 2 MiB entries", entry)
	}

	// Remap one page inside the first large entry with fewer permissions.
	if err := as.MapFile(va+7*pageSize, file, memmap.FileRange{Start: 7 * pageSize, End: 8 * pageSize}, hostarch.Read, false); err != nil {
		t.Fatal(err)
	}
	if _, got, _, ok := translate(as, va+7*pageSize); !ok || got.Write {
		t.Errorf("the remapped page is mapped %v with %+v, want read-only", ok, got)
	}

	hole := uint64(va + 2<<20 + 5*pageSize)
	as.Unmap(hostarch.Addr(hole), pageSize)
	if _, _, _, ok := translate(as, hole); ok {
		t.Error("the unmapped page stays mapped")
	}
	for _, i := range []uint64{0, 6, 8, 511, 512, 512 + 4, 512 + 6, size/pageSize - 1} {
		gpa, got, _, ok := translate(as, va+i*pageSize)
		if !ok || gpa != first+i*pageSize || !got.Write {
			t.Errorf("page %d translates to %#x (mapped %v), want %#x", i, gpa, ok, first+i*pageSize)
		}
	}
	checkWritableEntriesHaveWritableMemory(t, fb, as, va, size/pageSize)
}

func TestConcurrentMapFileRegistersOnce(t *testing.T) {
	const size = 2 << 20
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	mem := pageAlignedHost(t, size)
	file := &chunkedSliceFile{sliceMemmapFile: sliceMemmapFile{mem: mem}}
	fr := memmap.FileRange{Start: 0, End: size}
	spaces := make([]*AddressSpace, 8)
	for i := range spaces {
		spaces[i] = newTestAS(t, p)
	}
	maps0, _ := fb.calls()

	var wg sync.WaitGroup
	for _, as := range spaces {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 4 {
				if err := as.MapFile(0x400000, file, fr, hostarch.ReadWrite, false); err != nil {
					t.Error(err)
				}
				as.Unmap(0x400000, size)
			}
			if err := as.MapFile(0x400000, file, fr, hostarch.ReadWrite, false); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if maps, _ := fb.calls(); maps-maps0 != 1 {
		t.Errorf("eight address spaces made %d map calls for one host range, want 1", maps-maps0)
	}
	want, _, _, _ := translate(spaces[0], 0x400000)
	for i, as := range spaces {
		if got, _, _, ok := translate(as, 0x400000); !ok || got != want {
			t.Errorf("address space %d maps %#x (mapped %v), want %#x", i, got, ok, want)
		}
	}
}

func TestUnmapAndReuseSameHostVAMapsNewFileInStage2(t *testing.T) {
	requireGuestPageSize(t)
	const (
		reusedHostVA = uintptr(0x7ff0_0000_0000)
		gva          = hostarch.Addr(0x400000)
		size         = 4 * pageSize
	)

	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	as := newTestAS(t, p)
	fr := memmap.FileRange{Start: 0, End: size}

	fileA := &syntheticVAFile{base: reusedHostVA}
	fileB := &syntheticVAFile{base: reusedHostVA}
	fileC := &syntheticVAFile{base: reusedHostVA}

	maps0, unmaps0 := fb.calls()
	if err := as.MapFile(gva, fileA, fr, hostarch.Read, false); err != nil {
		t.Fatalf("MapFile(fileA): %v", err)
	}
	gpaA, _, _, ok := translate(as, uint64(gva))
	if !ok {
		t.Fatal("fileA page is not mapped in Stage-1")
	}
	if host, mapped := hostOf(fb, gpaA); !mapped || host != reusedHostVA {
		t.Fatalf("fileA GPA %#x maps host %#x (mapped=%v), want %#x", gpaA, host, mapped, reusedHostVA)
	}
	if maps, unmaps := fb.calls(); maps-maps0 != 1 || unmaps != unmaps0 {
		t.Fatalf("after MapFile(fileA): maps=%d unmaps=%d, want 1 and 0", maps-maps0, unmaps-unmaps0)
	}

	// Unmap while a virtual processor runs on as: VP cancellation must complete
	// before WHvUnmapGpaRange removes fileA from Stage-2.
	stopsBeforeReturn(t, p, fb, as, uint64(gva), gpaA, func() {
		as.Unmap(gva, size)
	})
	if _, _, stillMapped := fb.mappingOf(gpaA); stillMapped {
		t.Fatalf("fileA GPA %#x remained in Stage-2 after Unmap", gpaA)
	}
	if maps, unmaps := fb.calls(); maps-maps0 != 1 || unmaps-unmaps0 != 1 {
		t.Fatalf("after Unmap(fileA): maps=%d unmaps=%d, want 1 and 1", maps-maps0, unmaps-unmaps0)
	}

	// Map fileB at the exact same host VA 0x7ff0_0000_0000: must invoke mapGPA
	// anew and never skip Stage-2 registration.
	if err := as.MapFile(gva, fileB, fr, hostarch.Read, false); err != nil {
		t.Fatalf("MapFile(fileB): %v", err)
	}
	gpaB, _, _, ok := translate(as, uint64(gva))
	if !ok {
		t.Fatal("fileB page is not mapped in Stage-1")
	}
	if maps, unmaps := fb.calls(); maps-maps0 != 2 || unmaps-unmaps0 != 1 {
		t.Fatalf("after MapFile(fileB): maps=%d unmaps=%d, want 2 and 1", maps-maps0, unmaps-unmaps0)
	}
	if host, mapped := hostOf(fb, gpaB); !mapped || host != reusedHostVA {
		t.Fatalf("fileB GPA %#x maps host %#x (mapped=%v), want %#x", gpaB, host, mapped, reusedHostVA)
	}

	// Direct MapFile overwrite with fileC at the same host VA without prior Unmap
	// must map fileC at a distinct GPA and unmap fileB's GPA.
	if err := as.MapFile(gva, fileC, fr, hostarch.ReadWrite, false); err != nil {
		t.Fatalf("MapFile(fileC): %v", err)
	}
	gpaC, optsC, _, ok := translate(as, uint64(gva))
	if !ok || !optsC.Write || gpaC == gpaB {
		t.Fatalf("fileC mapped at %#x (%+v, ok=%v), want new writable GPA != %#x", gpaC, optsC, ok, gpaB)
	}
	if _, _, stillMapped := fb.mappingOf(gpaB); stillMapped {
		t.Fatalf("fileB GPA %#x remained mapped after direct MapFile replacement", gpaB)
	}
	if maps, unmaps := fb.calls(); maps-maps0 != 3 || unmaps-unmaps0 != 2 {
		t.Fatalf("after MapFile(fileC): maps=%d unmaps=%d, want 3 and 2", maps-maps0, unmaps-unmaps0)
	}
}

func TestFiveThousandScatteredNonChunkedMappingsReclaimGPASpace(t *testing.T) {
	requireGuestPageSize(t)
	const (
		totalOps    = 5000
		batchWidth  = 32
		windowPages = 64
	)

	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	// Restrict the guest memory window to 64 pages (256 KiB) so any leak
	// exhausts GPA space within 65 iterations.
	_ = p.mem.close()
	p.mem = newMemoryMap(fb, gpaTableEnd, gpaTableEnd+windowPages*pageSize)

	as := newTestAS(t, p)
	fr := memmap.FileRange{Start: 0, End: pageSize}
	rng := rand.New(rand.NewPCG(0x57485058, 0x35303030))
	maps0, unmaps0 := fb.calls()

	activeGVAs := make([]hostarch.Addr, 0, batchWidth)
	unmapOne := func(idx int) {
		va := activeGVAs[idx]
		activeGVAs[idx] = activeGVAs[len(activeGVAs)-1]
		activeGVAs = activeGVAs[:len(activeGVAs)-1]
		as.Unmap(va, pageSize)
	}

	for i := range totalOps {
		if len(activeGVAs) == batchWidth {
			unmapOne(rng.IntN(len(activeGVAs)))
		}
		hostVA := uintptr(0x0000_0100_0000_0000) + uintptr(rng.Uint64N(1<<34))*pageSize
		gva := hostarch.Addr(0x1000_0000 + uint64(i)*pageSize)
		f := &syntheticVAFile{base: hostVA}
		at := hostarch.Read
		if i%2 == 0 {
			at = hostarch.ReadWrite
		}
		if err := as.MapFile(gva, f, fr, at, false); err != nil {
			t.Fatalf("iteration %d (hostVA=%#x): MapFile failed: %v", i, hostVA, err)
		}
		activeGVAs = append(activeGVAs, gva)
	}
	for len(activeGVAs) > 0 {
		unmapOne(len(activeGVAs) - 1)
	}

	maps, unmaps := fb.calls()
	if maps-maps0 != totalOps || unmaps-unmaps0 != totalOps {
		t.Fatalf("Stage-2 calls: maps=%d unmaps=%d, want %d and %d", maps-maps0, unmaps-unmaps0, totalOps, totalOps)
	}
	if got := p.mem.inner.RegionCount(); got != 0 {
		t.Fatalf("RegionCount() = %d, want 0", got)
	}
}

func TestConcurrentMapFileUnmapAndReleaseMaintainExactStage2Refs(t *testing.T) {
	requireGuestPageSize(t)
	fb := newFakeBackend()
	var badUnmaps atomic.Int64
	fb.unmapErr = func(gpa uint64) error {
		if _, ok := fb.mapped[gpa]; !ok {
			badUnmaps.Add(1)
		}
		return nil
	}
	p := newTestPlatform(t, fb, Options{})

	files := [4]*syntheticVAFile{
		{base: 0x7ff1_0000_0000},
		{base: 0x7ff2_0000_0000},
		{base: 0x7ff3_0000_0000},
		{base: 0x7ff4_0000_0000},
	}
	const baseGVA = uint64(0x400000)

	for round := range 12 {
		maps0, unmaps0 := fb.calls()
		asIface, err := p.NewAddressSpace(platformASOptions)
		if err != nil {
			t.Fatalf("round %d: NewAddressSpace: %v", round, err)
		}
		as := asIface.(*AddressSpace)

		var wg sync.WaitGroup
		start := make(chan struct{})
		for w := range 6 {
			wg.Add(1)
			go func(worker int) {
				defer wg.Done()
				rng := rand.New(rand.NewPCG(uint64(round+1), uint64(worker+1)))
				<-start
				for step := range 80 {
					slot := uint64(rng.IntN(8))
					pages := uint64(1 + rng.IntN(2))
					if slot+pages > 8 {
						pages = 1
					}
					va := hostarch.Addr(baseGVA + slot*pageSize)
					if step%3 == 2 {
						as.Unmap(va, pages*pageSize)
						continue
					}
					f := files[rng.IntN(len(files))]
					fr := memmap.FileRange{Start: slot * pageSize, End: (slot + pages) * pageSize}
					at := hostarch.Read
					if step%2 == 0 {
						at = hostarch.ReadWrite
					}
					if err := as.MapFile(va, f, fr, at, false); err != nil {
						var segv platform.SegmentationFault
						if !errors.As(err, &segv) {
							t.Errorf("round %d worker %d: MapFile returned %v", round, worker, err)
						}
					}
				}
			}(w)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 20 {
				as.Unmap(hostarch.Addr(baseGVA+2*pageSize), 4*pageSize)
			}
			as.Release()
		}()

		close(start)
		wg.Wait()
		as.Release()

		if bad := badUnmaps.Load(); bad != 0 {
			t.Fatalf("round %d: detected %d double or invalid Stage-2 unmaps", round, bad)
		}
		maps, unmaps := fb.calls()
		if maps-maps0 != unmaps-unmaps0 {
			t.Fatalf("round %d: maps=%d unmaps=%d, want equal counts", round, maps-maps0, unmaps-unmaps0)
		}
		if got := p.mem.inner.RegionCount(); got != 0 {
			t.Fatalf("round %d: RegionCount() = %d, want 0", round, got)
		}
		free, next := p.mem.inner.AllocatorStateForTest()
		if len(free) != 0 || next != gpaTableEnd {
			t.Fatalf("round %d: allocator state free=%+v next=%#x, want empty and %#x", round, free, next, uint64(gpaTableEnd))
		}
	}
}
