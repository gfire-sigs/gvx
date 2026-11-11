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
	"testing"
	"unsafe"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

func newTestMemoryMap(fb *fakeBackend) *memoryMap {
	return newMemoryMap(fb, gpaTableEnd, maxGPAWindowEnd)
}

// pageAlignedHost returns size bytes of page-aligned host memory.
func pageAlignedHost(t testing.TB, size int) []byte {
	t.Helper()
	buf := make([]byte, size+pageSize)
	base := uintptr(unsafe.Pointer(&buf[0]))
	skip := int(-base & pageMask)
	return buf[skip : skip+size : skip+size]
}

// sliceMemmapFile is a non-persistent memmap.File backed by a single host slice.
type sliceMemmapFile struct {
	memmap.File
	mem []byte
}

func (f *sliceMemmapFile) MapInternal(fr memmap.FileRange, _ hostarch.AccessType) (safemem.BlockSeq, error) {
	return safemem.BlockSeqOf(safemem.BlockFromSafeSlice(f.mem[fr.Start:fr.End])), nil
}

// chunkedSliceFile is a persistent ChunkedFile backed by a single host slice.
type chunkedSliceFile struct {
	sliceMemmapFile
}

func (f *chunkedSliceFile) TotalSize() uint64 { return uint64(len(f.mem)) }

var testResolveNextGVA uint64 = 0x1000_0000

func resolveSlice(m *memoryMap, u *hvcommon.RegionUser, f memmap.File, data []byte, write bool) ([]gpaRun, error) {
	if len(data) == 0 {
		return nil, errors.New("empty slice")
	}
	block := hvcommon.HostBlock{
		Addr:  uintptr(unsafe.Pointer(unsafe.SliceData(data))),
		Len:   uintptr(len(data)),
		Slice: data,
	}
	runs, err := m.inner.ResolvePinnedBlocks(u, f, []hvcommon.HostBlock{block}, write)
	if err != nil {
		return nil, err
	}
	gva := testResolveNextGVA
	testResolveNextGVA += uint64(len(data)) + pageSize
	var acq, drop []*hvcommon.Region
	if u != nil {
		acq, drop = u.RecordRuns(gva, runs)
	}
	m.inner.FinishPin(runs, acq, drop)
	return runs, nil
}

func TestGPAAllocatorAlignedRuns(t *testing.T) {
	a := newGPAAllocator(gpaWindowBase, gpaTableEnd)
	first, err := a.allocPage()
	if err != nil || first != gpaWindowBase {
		t.Fatalf("first page is %#x, %v", first, err)
	}
	run, err := a.allocRunAligned(16, 16)
	if err != nil {
		t.Fatal(err)
	}
	if run%(16*pageSize) != 0 || run < gpaWindowBase+pageSize {
		t.Errorf("run starts at %#x", run)
	}
	// The skipped pages between the first page and the aligned run stay
	// usable and never overlap the run.
	seen := map[uint64]bool{}
	for {
		p, err := a.allocPage()
		if err != nil {
			t.Fatal(err)
		}
		if p >= run && p < run+16*pageSize {
			t.Fatalf("page %#x overlaps the run", p)
		}
		if seen[p] {
			t.Fatalf("page %#x handed out twice", p)
		}
		seen[p] = true
		if p >= run+16*pageSize {
			break
		}
	}
}

func TestGPAAllocatorExhaustion(t *testing.T) {
	a := newGPAAllocator(gpaWindowBase, gpaWindowBase+2*pageSize)
	for range 2 {
		if _, err := a.allocPage(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.allocPage(); !errors.Is(err, errGPAExhausted) {
		t.Errorf("allocation past the window returned %v", err)
	}
	if _, err := a.allocRun(1); !errors.Is(err, errGPAExhausted) {
		t.Errorf("run past the window returned %v", err)
	}
}

func TestMemoryMapChunkedFileRegistersOnceInAnyOrder(t *testing.T) {
	fb := newFakeBackend()
	m := newTestMemoryMap(fb)
	mem, _ := fb.allocHost(ptSlabSize)
	f := &chunkedSliceFile{sliceMemmapFile: sliceMemmapFile{mem: mem[:16*pageSize]}}
	page := func(from, to int) []byte { return mem[from*pageSize : to*pageSize] }
	var u hvcommon.RegionUser

	runs, err := resolveSlice(m, &u, f, page(8, 12), true)
	if err != nil || len(runs) != 1 {
		t.Fatalf("first resolve returned %v, %v", runs, err)
	}
	top := runs[0]
	maps0, _ := fb.calls()

	runs, err = resolveSlice(m, &u, f, page(4, 8), true)
	if err != nil || len(runs) != 1 || runs[0].GPA+runs[0].Size != top.GPA {
		t.Fatalf("a range below the first one got %v, want end %#x (%v)", runs, top.GPA, err)
	}
	if runs, err = resolveSlice(m, &u, f, page(12, 16), true); err != nil || len(runs) != 1 || runs[0].GPA != top.GPA+4*pageSize {
		t.Fatalf("a range above the first one got %v (%v)", runs, err)
	}
	runs, err = resolveSlice(m, &u, f, page(0, 16), true)
	if err != nil || len(runs) != 1 || runs[0].Size != 16*pageSize {
		t.Fatalf("the full range got %v (%v)", runs, err)
	}
	if maps, _ := fb.calls(); maps != maps0 {
		t.Errorf("subsequent resolves made %d map calls, want 0", maps-maps0)
	}
	host, ok := hostOf(fb, runs[0].GPA)
	if !ok || host != uintptr(unsafe.Pointer(&mem[0])) {
		t.Errorf("the first guest page maps host %#x, want %p", host, &mem[0])
	}
}

func TestMemoryMapKeepsWritableAndReadOnlyRangesApart(t *testing.T) {
	fb := newFakeBackend()
	m := newTestMemoryMap(fb)
	mem, _ := fb.allocHost(ptSlabSize)
	f := &sliceMemmapFile{mem: mem}
	var u hvcommon.RegionUser

	ro, err := resolveSlice(m, &u, f, mem[:2*pageSize], false)
	if err != nil || len(ro) != 1 {
		t.Fatalf("read-only resolve returned %v, %v", ro, err)
	}
	if mp, _, _ := fb.mappingOf(ro[0].GPA); mp.flags != mapFlagRead|mapFlagExecute {
		t.Errorf("a read-only request maps with flags %#x", mp.flags)
	}

	maps0, unmaps0 := fb.calls()
	rw, err := resolveSlice(m, &u, f, mem[:2*pageSize], true)
	if err != nil || len(rw) != 1 {
		t.Fatalf("writable resolve returned %v, %v", rw, err)
	}
	if rw[0].GPA == ro[0].GPA {
		t.Fatal("a write request reuses the read-only guest range")
	}
	if mp, host, _ := fb.mappingOf(rw[0].GPA); mp.flags != mapFlagRead|mapFlagWrite|mapFlagExecute || host != uintptr(unsafe.Pointer(&mem[0])) {
		t.Errorf("a write request maps host %#x with flags %#x", host, mp.flags)
	}
	if mp, _, ok := fb.mappingOf(ro[0].GPA); !ok || mp.flags != mapFlagRead|mapFlagExecute {
		t.Error("the read-only range changed when the writable range registered")
	}
	if maps, unmaps := fb.calls(); maps-maps0 != 1 || unmaps != unmaps0 {
		t.Errorf("the upgrade made %d map calls and %d unmap calls, want 1 and 0", maps-maps0, unmaps-unmaps0)
	}

	// A later read request reuses the writable range without a call.
	again, err := resolveSlice(m, &u, f, mem[:2*pageSize], false)
	if err != nil || len(again) != 1 || again[0].GPA != rw[0].GPA {
		t.Fatalf("read after write got %v, want the writable range (%v)", again, err)
	}
	if maps, _ := fb.calls(); maps-maps0 != 1 {
		t.Error("a read of a writable range made a map call")
	}

	// A read request over a writable part and an unregistered part takes the
	// first from the writable range and registers the rest read-only.
	mixed, err := resolveSlice(m, &u, f, mem[:4*pageSize], false)
	if err != nil || len(mixed) != 2 {
		t.Fatalf("mixed resolve returned %v, %v", mixed, err)
	}
	if mixed[0].GPA != rw[0].GPA || mixed[0].Size != 2*pageSize || mixed[1].Size != 2*pageSize {
		t.Errorf("mixed resolve returned %v", mixed)
	}
	if mp, _, _ := fb.mappingOf(mixed[1].GPA); mp.flags != mapFlagRead|mapFlagExecute {
		t.Errorf("the unregistered part maps with flags %#x", mp.flags)
	}
}

func TestMemoryMapFailedRegistrationChangesNothing(t *testing.T) {
	fb := newFakeBackend()
	m := newTestMemoryMap(fb)
	mem, _ := fb.allocHost(ptSlabSize)
	f := &sliceMemmapFile{mem: mem}
	var u hvcommon.RegionUser

	boom := errors.New("map refused")
	fb.mapErr = func(uint64) error { return boom }
	if _, err := resolveSlice(m, &u, f, mem[:pageSize], true); !errors.Is(err, boom) {
		t.Fatalf("resolve returned %v, want the backend error", err)
	}
	free, next := m.inner.AllocatorStateForTest()
	if m.inner.RegionCount() != 0 || len(free) != 0 || next != gpaTableEnd {
		t.Errorf("a failed registration left %d regions, free=%+v, next=%#x", m.inner.RegionCount(), free, next)
	}
	fb.mapErr = nil
	runs, err := resolveSlice(m, &u, f, mem[:pageSize], true)
	if err != nil || len(runs) != 1 || runs[0].GPA != gpaTableEnd {
		t.Fatalf("retry returned %v, %v, want GPA %#x", runs, err, uint64(gpaTableEnd))
	}
}

func TestMemoryMapCloseUnmapsEveryRegistration(t *testing.T) {
	fb := newFakeBackend()
	m := newTestMemoryMap(fb)
	mem, _ := fb.allocHost(ptSlabSize)
	f := &sliceMemmapFile{mem: mem}
	var u hvcommon.RegionUser
	for _, c := range []struct {
		from, to int
		write    bool
	}{{0, 2, true}, {4, 6, true}, {2, 4, true}, {8, 9, false}} {
		if _, err := resolveSlice(m, &u, f, mem[c.from*pageSize:c.to*pageSize], c.write); err != nil {
			t.Fatal(err)
		}
	}
	if len(fb.mapped) != 4 {
		t.Fatalf("%d mappings, want 4", len(fb.mapped))
	}
	if err := m.close(); err != nil {
		t.Fatal(err)
	}
	if len(fb.mapped) != 0 {
		t.Errorf("close leaves %d mappings", len(fb.mapped))
	}
	if err := m.close(); err != nil {
		t.Errorf("second close returned %v", err)
	}
	if _, unmaps := fb.calls(); unmaps != 4 {
		t.Errorf("close made %d unmap calls, want 4", unmaps)
	}
	if _, err := resolveSlice(m, &u, f, mem[:pageSize], true); !errors.Is(err, errClosed) {
		t.Errorf("resolve after close returned %v", err)
	}

	boom := errors.New("unmap refused")
	fb2 := newFakeBackend()
	m2 := newTestMemoryMap(fb2)
	mem2, _ := fb2.allocHost(ptSlabSize)
	f2 := &sliceMemmapFile{mem: mem2}
	var u2 hvcommon.RegionUser
	if _, err := resolveSlice(m2, &u2, f2, mem2[:pageSize], true); err != nil {
		t.Fatal(err)
	}
	fb2.unmapErr = func(uint64) error { return boom }
	if err := m2.close(); !errors.Is(err, boom) {
		t.Errorf("close returned %v, want the backend error", err)
	}
}

func TestMemoryMapRejectsBadSlices(t *testing.T) {
	fb := newFakeBackend()
	m := newTestMemoryMap(fb)
	mem, _ := fb.allocHost(ptSlabSize)
	f := &sliceMemmapFile{mem: mem}
	var u hvcommon.RegionUser
	if _, err := resolveSlice(m, &u, f, mem[:pageSize-1], false); err == nil {
		t.Error("short slice accepted")
	}
	if _, err := resolveSlice(m, &u, f, mem[1:1+pageSize], false); err == nil {
		t.Error("misaligned slice accepted")
	}
	if _, err := m.resolveRaw(&u, nil, false); err == nil {
		t.Error("empty slice accepted")
	}
	if maps, _ := fb.calls(); maps != 0 {
		t.Errorf("rejected slices made %d map calls", maps)
	}
}

func TestSelectGPABitsAndDynamicGPAWindow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arm64   bool
		capBits uint32
		cpuBits uint32
		want    uint32
		wantIPS uint64
	}{
		{"zero defaults to 36", false, 0, 0, 36, 1},
		{"zero capability ignores larger cpu width", false, 0, 48, 36, 1},
		{"36-bit x64 host", false, 36, 36, 36, 1},
		{"39-bit Intel client x64", false, 39, 39, 39, 1},
		{"cpu caps hypervisor on x64", false, 48, 39, 39, 1},
		{"48-bit x64 clamps to 40", false, 48, 48, 40, 2},
		{"39-bit arm64 steps down to 36 IPS=1", true, 39, 0, 36, 1},
		{"40-bit arm64 uses IPS=2", true, 40, 0, 40, 2},
		{"48-bit arm64 clamps to 40 IPS=2", true, 48, 0, 40, 2},
	} {
		got := selectGPABits(tc.arm64, tc.capBits, tc.cpuBits)
		if got != tc.want {
			t.Errorf("%s: selectGPABits(%v, %d, %d) = %d, want %d", tc.name, tc.arm64, tc.capBits, tc.cpuBits, got, tc.want)
		}
		if tc.arm64 {
			ips := (a64TCRForBits(got) >> 32) & 0x7
			if ips != tc.wantIPS {
				t.Errorf("%s: TCR_EL1.IPS = %d, want %d", tc.name, ips, tc.wantIPS)
			}
		}
	}

	for _, tc := range []struct {
		bits    uint32
		wantIPS uint64
	}{
		{36, 1},
		{37, 2},
		{39, 2},
		{40, 2},
	} {
		if got := (a64TCRForBits(tc.bits) >> 32) & 0x7; got != tc.wantIPS {
			t.Errorf("a64TCRForBits(%d) IPS = %d, want %d", tc.bits, got, tc.wantIPS)
		}
	}

	fb := newFakeBackend()
	fb.feats.physicalAddressBits = 36
	p36 := newTestPlatform(t, fb, Options{})
	if p36.gpaEnd != minGPAWindowEnd {
		t.Errorf("36-bit platform gpaEnd = %#x, want %#x", p36.gpaEnd, uint64(minGPAWindowEnd))
	}

	fb48 := newFakeBackend()
	fb48.feats.physicalAddressBits = 48
	p48 := newTestPlatform(t, fb48, Options{})
	wantBits := selectGPABits(p48.arm64, 48, hostCPUPABits())
	if p48.gpaEnd != uint64(1)<<wantBits {
		t.Errorf("48-bit platform gpaEnd = %#x, want %#x", p48.gpaEnd, uint64(1)<<wantBits)
	}
}
