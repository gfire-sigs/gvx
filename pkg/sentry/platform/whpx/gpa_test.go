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
)

func newTestMemoryMap(fb *fakeBackend) *memoryMap {
	return newMemoryMap(fb, gpaTableEnd, gpaWindowEnd)
}

// straddlingHost returns size bytes of host memory that cross a boundary
// between two arenas. Half of the bytes lie on each side.
func straddlingHost(t testing.TB, size int) []byte {
	t.Helper()
	buf := make([]byte, arenaSize+size)
	base := uintptr(unsafe.Pointer(&buf[0]))
	boundary := (base + arenaMask) &^ arenaMask
	for boundary < base+uintptr(size/2) {
		boundary += arenaSize
	}
	start := int(boundary-base) - size/2
	if start < 0 || start+size > len(buf) || (base+uintptr(start))&pageMask != 0 {
		t.Fatalf("no page-aligned straddling range in a buffer at %#x", base)
	}
	return buf[start : start+size : start+size]
}

// withinOneArena returns size bytes of host memory that stay inside one
// arena.
func withinOneArena(t testing.TB, size int) []byte {
	t.Helper()
	buf := make([]byte, 2*size)
	base := uintptr(unsafe.Pointer(&buf[0]))
	start := 0
	if boundary := (base + arenaMask) &^ arenaMask; boundary > base && boundary < base+uintptr(size) {
		start = int(boundary - base)
	}
	if (base+uintptr(start))&pageMask != 0 {
		t.Fatalf("buffer at %#x is not page aligned", base)
	}
	return buf[start : start+size : start+size]
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

func TestMemoryMapJoinsRangesInAnyOrder(t *testing.T) {
	fb := newFakeBackend()
	m := newTestMemoryMap(fb)
	mem, _ := fb.allocHost(ptSlabSize)
	page := func(from, to int) []byte { return mem[from*pageSize : to*pageSize] }

	// A later call below the first one, as a top-down allocation does.
	runs, err := m.resolve(page(8, 12), true, nil)
	if err != nil || len(runs) != 1 {
		t.Fatalf("first resolve returned %v, %v", runs, err)
	}
	top := runs[0]
	runs, err = m.resolve(page(4, 8), true, nil)
	if err != nil || len(runs) != 1 || runs[0].GPA+runs[0].Size != top.GPA {
		t.Fatalf("a range below the first one got %v, want it to end at %#x (%v)", runs, top.GPA, err)
	}
	// A call above, as a bottom-up allocation does.
	if runs, err = m.resolve(page(12, 16), true, nil); err != nil || len(runs) != 1 || runs[0].GPA != top.GPA+4*pageSize {
		t.Fatalf("a range above the first one got %v (%v)", runs, err)
	}
	// The whole range is one run now and needs no further call.
	maps0, _ := fb.calls()
	runs, err = m.resolve(page(4, 16), true, nil)
	if err != nil || len(runs) != 1 || runs[0].Size != 12*pageSize || runs[0].GPA != top.GPA-4*pageSize {
		t.Fatalf("the joined range got %v (%v)", runs, err)
	}
	// Only the gap below page 4 registers, and the whole range joins again.
	runs, err = m.resolve(page(0, 16), true, nil)
	if err != nil || len(runs) != 1 || runs[0].Size != 16*pageSize {
		t.Fatalf("the full range got %v (%v)", runs, err)
	}
	if maps, _ := fb.calls(); maps-maps0 != 1 {
		t.Errorf("two resolves made %d map calls, want 1", maps-maps0)
	}
	host, ok := hostOf(fb, runs[0].GPA)
	if !ok || host != unsafe.Pointer(&mem[0]) {
		t.Errorf("the first guest page maps host %p, want %p", host, &mem[0])
	}
}

func TestMemoryMapKeepsWritableAndReadOnlyRangesApart(t *testing.T) {
	fb := newFakeBackend()
	m := newTestMemoryMap(fb)
	mem, _ := fb.allocHost(ptSlabSize)

	ro, err := m.resolve(mem[:2*pageSize], false, nil)
	if err != nil || len(ro) != 1 {
		t.Fatalf("read-only resolve returned %v, %v", ro, err)
	}
	if mp, _, _ := fb.mappingOf(ro[0].GPA); mp.flags != mapFlagRead|mapFlagExecute {
		t.Errorf("a read-only request maps with flags %#x", mp.flags)
	}

	// A write request must not use the read-only range. It registers the
	// same host memory again with write permission and keeps the old range.
	maps0, unmaps0 := fb.calls()
	rw, err := m.resolve(mem[:2*pageSize], true, nil)
	if err != nil || len(rw) != 1 {
		t.Fatalf("writable resolve returned %v, %v", rw, err)
	}
	if rw[0].GPA == ro[0].GPA {
		t.Fatal("a write request reuses the read-only guest range")
	}
	if mp, host, _ := fb.mappingOf(rw[0].GPA); mp.flags != mapFlagRead|mapFlagWrite|mapFlagExecute || host != unsafe.Pointer(&mem[0]) {
		t.Errorf("a write request maps host %p with flags %#x", host, mp.flags)
	}
	if mp, _, ok := fb.mappingOf(ro[0].GPA); !ok || mp.flags != mapFlagRead|mapFlagExecute {
		t.Error("the read-only range changed when the writable range registered")
	}
	if maps, unmaps := fb.calls(); maps-maps0 != 1 || unmaps != unmaps0 {
		t.Errorf("the upgrade made %d map calls and %d unmap calls, want 1 and 0", maps-maps0, unmaps-unmaps0)
	}

	// A later read request reuses the writable range without a call.
	again, err := m.resolve(mem[:2*pageSize], false, nil)
	if err != nil || len(again) != 1 || again[0].GPA != rw[0].GPA {
		t.Fatalf("read after write got %v, want the writable range (%v)", again, err)
	}
	if maps, _ := fb.calls(); maps-maps0 != 1 {
		t.Error("a read of a writable range made a map call")
	}

	// A read request over a writable part and an unregistered part takes the
	// first from the writable range and registers the rest read-only.
	mixed, err := m.resolve(mem[:4*pageSize], false, nil)
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

	boom := errors.New("map refused")
	fb.mapErr = func(uint64) error { return boom }
	if _, err := m.resolve(mem[:pageSize], true, nil); !errors.Is(err, boom) {
		t.Fatalf("resolve returned %v, want the backend error", err)
	}
	if len(m.arenas) != 0 || m.next != gpaTableEnd {
		t.Errorf("a failed registration left %d arenas and moved the window to %#x", len(m.arenas), m.next)
	}
	fb.mapErr = nil
	runs, err := m.resolve(mem[:pageSize], true, nil)
	if err != nil || len(runs) != 1 || runs[0].GPA < gpaTableEnd || runs[0].GPA >= gpaTableEnd+arenaSize {
		t.Fatalf("retry returned %v, %v, want the first arena", runs, err)
	}
}

func TestMemoryMapSpansTwoArenas(t *testing.T) {
	fb := newFakeBackend()
	m := newTestMemoryMap(fb)
	mem := straddlingHost(t, 4<<20)

	maps0, _ := fb.calls()
	runs, err := m.resolve(mem, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if maps, _ := fb.calls(); maps-maps0 != 2 {
		t.Errorf("a range over two arenas made %d map calls, want 2", maps-maps0)
	}
	// Two fresh arenas take neighbouring windows, so the range stays whole.
	if len(runs) != 1 || runs[0].Size != uint64(len(mem)) {
		t.Errorf("resolve returned %v, want one run of %d bytes", runs, len(mem))
	}
	host, ok := hostOf(fb, runs[0].GPA+uint64(len(mem))-pageSize)
	if !ok || host != unsafe.Pointer(&mem[len(mem)-pageSize]) {
		t.Errorf("the last guest page maps host %p, want %p", host, &mem[len(mem)-pageSize])
	}

	// With one window left, the second arena has no room.
	m2 := newMemoryMap(newFakeBackend(), gpaTableEnd, gpaTableEnd+arenaSize)
	if _, err := m2.resolve(mem, true, nil); !errors.Is(err, errGPAExhausted) {
		t.Errorf("resolve past the last window returned %v", err)
	}
}

func TestMemoryMapCloseUnmapsEveryRegistration(t *testing.T) {
	fb := newFakeBackend()
	m := newTestMemoryMap(fb)
	mem, _ := fb.allocHost(ptSlabSize)
	for _, c := range []struct {
		from, to int
		write    bool
	}{{0, 2, true}, {4, 6, true}, {2, 4, true}, {8, 9, false}} {
		if _, err := m.resolve(mem[c.from*pageSize:c.to*pageSize], c.write, nil); err != nil {
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
	if _, err := m.resolve(mem[:pageSize], true, nil); !errors.Is(err, errClosed) {
		t.Errorf("resolve after close returned %v", err)
	}

	boom := errors.New("unmap refused")
	fb2 := newFakeBackend()
	m2 := newTestMemoryMap(fb2)
	mem2, _ := fb2.allocHost(ptSlabSize)
	if _, err := m2.resolve(mem2[:pageSize], true, nil); err != nil {
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
	if _, err := m.resolve(mem[:pageSize-1], false, nil); err == nil {
		t.Error("short slice accepted")
	}
	if _, err := m.resolve(mem[1:1+pageSize], false, nil); err == nil {
		t.Error("misaligned slice accepted")
	}
	if _, err := m.resolve(nil, false, nil); err == nil {
		t.Error("empty slice accepted")
	}
	if maps, _ := fb.calls(); maps != 0 {
		t.Errorf("rejected slices made %d map calls", maps)
	}
}
