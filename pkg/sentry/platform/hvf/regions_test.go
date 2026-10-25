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
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
	"unsafe"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

const (
	testGranule = 16 << 10
	testIPABase = uint64(0x2_0000_0000)
)

var errTestRefused = errors.New("refused by the fake hypervisor")

// fakeStage2 records the Stage-2 calls of a regionMap.
type fakeStage2 struct {
	mu     sync.Mutex
	maps   []fakeMapCall
	unmaps []fakeMapCall
	copies int
	freed  int
	// refuse makes mapHost fail for the host addresses that it accepts.
	refuse func(host uintptr) bool
}

type fakeMapCall struct {
	host uintptr
	ipa  uint64
	size uintptr
}

func (f *fakeStage2) mapHost(host uintptr, ipa uint64, size uintptr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.maps = append(f.maps, fakeMapCall{host, ipa, size})
	if f.refuse != nil && f.refuse(host) {
		return fmt.Errorf("fake hv_vm_map: %w", errTestRefused)
	}
	return nil
}

func (f *fakeStage2) unmapIPA(ipa uint64, size uintptr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unmaps = append(f.unmaps, fakeMapCall{ipa: ipa, size: size})
	return nil
}

func (f *fakeStage2) refusedMemory(err error) bool { return errors.Is(err, errTestRefused) }

func (f *fakeStage2) allocCopy(size uintptr) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.copies++
	return make([]byte, size), nil
}

func (f *fakeStage2) freeCopy([]byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.freed++
	return nil
}

func (f *fakeStage2) counts() (maps, unmaps int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.maps), len(f.unmaps)
}

// copyCount returns the number of regions that hold a private copy.
func (m *regionMap) copyCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, o := range m.owners {
		for _, r := range o.regions {
			if r.copied != nil {
				n++
			}
		}
	}
	return n
}

// alignedMem returns size bytes of host memory at a host page boundary.
func alignedMem(size int) []byte {
	raw := make([]byte, size+testGranule)
	skip := int(-uintptr(unsafe.Pointer(&raw[0])) & (testGranule - 1))
	return raw[skip : skip+size : skip+size]
}

func blocksOf(chunks ...[]byte) safemem.BlockSeq {
	blocks := make([]safemem.Block, len(chunks))
	for i, c := range chunks {
		blocks[i] = safemem.BlockFromSafeSlice(c)
	}
	return safemem.BlockSeqFromSlice(blocks)
}

// plainFile is a memmap.File that returns one fixed host range.
type plainFile struct {
	memmap.File
	mem []byte
}

func (f *plainFile) MapInternal(fr memmap.FileRange, _ hostarch.AccessType) (safemem.BlockSeq, error) {
	return blocksOf(f.mem[fr.Start:fr.End]), nil
}

// chunkFile models a memory file: equal chunks that stay mapped.
type chunkFile struct {
	memmap.File
	chunks [][]byte
}

func (f *chunkFile) TotalSize() uint64 { return uint64(len(f.chunks)) * uint64(len(f.chunks[0])) }

func (f *chunkFile) MapInternal(fr memmap.FileRange, _ hostarch.AccessType) (safemem.BlockSeq, error) {
	size := uint64(len(f.chunks[0]))
	var out [][]byte
	for i := fr.Start / size; i*size < fr.End; i++ {
		lo, hi := max(fr.Start, i*size)-i*size, min(fr.End, (i+1)*size)-i*size
		out = append(out, f.chunks[i][lo:hi])
	}
	return blocksOf(out...), nil
}

func newTestChunkFile(chunks, size int) *chunkFile {
	f := &chunkFile{}
	for range chunks {
		f.chunks = append(f.chunks, alignedMem(size))
	}
	return f
}

func newTestRegionMap(be stage2Backend, limit uint64) *regionMap {
	return newRegionMap(be, testGranule, testIPABase, limit)
}

func TestFourMiBBlockNeedsOneStage2Map(t *testing.T) {
	be := &fakeStage2{}
	m := newTestRegionMap(be, testIPABase+1<<30)
	file := &plainFile{mem: alignedMem(4 << 20)}
	var u regionUser

	bs, _ := file.MapInternal(memmap.FileRange{Start: 0, End: 4 << 20}, hostarch.ReadWrite)
	segs, err := m.resolve(&u, file, bs, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 || segs[0].Size != 4<<20 {
		t.Fatalf("segments = %+v, want one run of 4 MiB", segs)
	}
	if maps, _ := be.counts(); maps != 1 {
		t.Errorf("a 4 MiB block made %d hv_vm_map calls, want 1", maps)
	}

	// The same range again, and a part of it, add no Stage-2 call.
	for _, fr := range []memmap.FileRange{{Start: 0, End: 4 << 20}, {Start: 1 << 20, End: 2 << 20}, {Start: 4<<20 - 4096, End: 4 << 20}} {
		bs, _ := file.MapInternal(fr, hostarch.ReadWrite)
		if _, err := m.resolve(&u, file, bs, true); err != nil {
			t.Fatal(err)
		}
	}
	if maps, unmaps := be.counts(); maps != 1 || unmaps != 0 {
		t.Errorf("repeated resolves made %d maps and %d unmaps in total, want 1 and 0", maps, unmaps)
	}
}

func TestResolveKeepsGuestPhysicalOffsetsOfTheHostRange(t *testing.T) {
	be := &fakeStage2{}
	m := newTestRegionMap(be, testIPABase+1<<30)
	file := &plainFile{mem: alignedMem(1 << 20)}
	var u regionUser
	first, _ := file.MapInternal(memmap.FileRange{Start: 0, End: 1 << 20}, hostarch.ReadWrite)
	a, err := m.resolve(&u, file, first, true)
	if err != nil {
		t.Fatal(err)
	}
	later, _ := file.MapInternal(memmap.FileRange{Start: 64 << 10, End: 128 << 10}, hostarch.ReadWrite)
	b, err := m.resolve(&u, file, later, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := a[0].GPA + 64<<10; b[0].GPA != want {
		t.Errorf("ipa of the second range = %#x, want %#x", b[0].GPA, want)
	}
}

func TestMemoryFileMapsEveryChunkOnce(t *testing.T) {
	be := &fakeStage2{}
	m := newTestRegionMap(be, testIPABase+1<<30)
	file := newTestChunkFile(3, 1<<20)
	var u regionUser

	one, _ := file.MapInternal(memmap.FileRange{Start: 1 << 20, End: 1<<20 + 4096}, hostarch.ReadWrite)
	if _, err := m.resolve(&u, file, one, true); err != nil {
		t.Fatal(err)
	}
	if maps, _ := be.counts(); maps != 3 {
		t.Fatalf("the first use of a memory file made %d hv_vm_map calls, want one per chunk (3)", maps)
	}
	all, _ := file.MapInternal(memmap.FileRange{Start: 0, End: 3 << 20}, hostarch.ReadWrite)
	segs, err := m.resolve(&u, file, all, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 || segs[0].Size != 3<<20 {
		t.Errorf("segments = %+v, want one contiguous run: the chunks sit side by side", segs)
	}
	if maps, unmaps := be.counts(); maps != 3 || unmaps != 0 {
		t.Errorf("later resolves made %d maps and %d unmaps in total, want 3 and 0", maps, unmaps)
	}

	// The last address space leaves: the memory file keeps its regions.
	m.release(&u)
	if maps, unmaps := be.counts(); maps != 3 || unmaps != 0 {
		t.Errorf("release made %d maps and %d unmaps in total, want 3 and 0", maps, unmaps)
	}
	if got := m.regionCount(); got != 3 {
		t.Errorf("regions after release = %d, want the 3 chunks", got)
	}
}

func TestOtherFilesLoseTheirRegionWithTheLastUser(t *testing.T) {
	be := &fakeStage2{}
	m := newTestRegionMap(be, testIPABase+1<<30)
	file := &plainFile{mem: alignedMem(1 << 20)}
	var a, b regionUser
	bs, _ := file.MapInternal(memmap.FileRange{Start: 0, End: 1 << 20}, hostarch.ReadWrite)
	first, err := m.resolve(&a, file, bs, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.resolve(&b, file, bs, true); err != nil {
		t.Fatal(err)
	}
	m.release(&a)
	if _, unmaps := be.counts(); unmaps != 0 {
		t.Fatalf("a region went away while a user holds it: %d unmaps", unmaps)
	}
	m.release(&b)
	if _, unmaps := be.counts(); unmaps != 1 {
		t.Fatalf("unmaps = %d after the last user left, want 1", unmaps)
	}
	if got := m.regionCount(); got != 0 {
		t.Errorf("regions = %d, want 0", got)
	}
	// The guest physical range is free again.
	var c regionUser
	again, err := m.resolve(&c, file, bs, true)
	if err != nil {
		t.Fatal(err)
	}
	if again[0].GPA != first[0].GPA {
		t.Errorf("ipa after reuse = %#x, want the released %#x", again[0].GPA, first[0].GPA)
	}
}

// A file can unmap its memory and a later file can get the same host
// addresses. The stale region must never serve the new file.
func TestAFileNeverUsesTheRegionOfAnotherFile(t *testing.T) {
	be := &fakeStage2{}
	m := newTestRegionMap(be, testIPABase+1<<30)
	mem := alignedMem(1 << 20)
	old, reused := &plainFile{mem: mem}, &plainFile{mem: mem}
	var a, b regionUser
	bs, _ := old.MapInternal(memmap.FileRange{Start: 0, End: 1 << 20}, hostarch.ReadWrite)
	first, err := m.resolve(&a, old, bs, true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.resolve(&b, reused, bs, true)
	if err != nil {
		t.Fatal(err)
	}
	if maps, _ := be.counts(); maps != 2 {
		t.Errorf("hv_vm_map calls = %d, want 2: each file needs its own region", maps)
	}
	if first[0].GPA == second[0].GPA {
		t.Error("two files share one guest physical range")
	}
}

type sliceKeyFile struct {
	memmap.File
	tag []int // A slice field makes the type unhashable.
	mem []byte
}

func (f sliceKeyFile) MapInternal(fr memmap.FileRange, _ hostarch.AccessType) (safemem.BlockSeq, error) {
	return blocksOf(f.mem[fr.Start:fr.End]), nil
}

func TestUnhashableFileIsNotCached(t *testing.T) {
	be := &fakeStage2{}
	m := newTestRegionMap(be, testIPABase+1<<30)
	file := sliceKeyFile{tag: []int{1}, mem: alignedMem(1 << 20)}
	var u regionUser
	bs, _ := file.MapInternal(memmap.FileRange{Start: 0, End: 1 << 20}, hostarch.ReadWrite)
	if _, err := m.resolve(&u, file, bs, true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.resolve(&u, file, bs, true); err != nil {
		t.Fatal(err)
	}
	if maps, _ := be.counts(); maps != 2 {
		t.Errorf("hv_vm_map calls = %d, want 2: no lookup can find the region of an unhashable file", maps)
	}
	m.release(&u)
	if _, unmaps := be.counts(); unmaps != 2 {
		t.Errorf("unmaps = %d, want 2", unmaps)
	}
}

func TestReadOnlyMemoryGetsACopyForReadsOnly(t *testing.T) {
	be := &fakeStage2{}
	mem := alignedMem(64 << 10)
	for i := range mem {
		mem[i] = byte(i)
	}
	base := uintptr(unsafe.Pointer(&mem[0]))
	be.refuse = func(host uintptr) bool { return host >= base && host < base+uintptr(len(mem)) }
	m := newTestRegionMap(be, testIPABase+1<<30)
	file := &plainFile{mem: mem}
	var u regionUser
	bs, _ := file.MapInternal(memmap.FileRange{Start: 0, End: 32 << 10}, hostarch.Read)

	if _, err := m.resolve(&u, file, bs, true); !errors.Is(err, errHostBlockRejected) {
		t.Fatalf("writable resolve = %v, want errHostBlockRejected", err)
	}
	if got := m.copyCount(); got != 0 {
		t.Fatalf("a writable request made %d copies, want 0: a copy of writable memory would diverge", got)
	}
	segs, err := m.resolve(&u, file, bs, false)
	if err != nil {
		t.Fatalf("read-only resolve: %v", err)
	}
	if len(segs) != 1 || m.copyCount() != 1 || be.copies != 1 {
		t.Fatalf("segments %+v, copies %d: want one segment and one private copy", segs, m.copyCount())
	}
	// A writable request must not use the copy that a read-only request made.
	if _, err := m.resolve(&u, file, bs, true); !errors.Is(err, errHostBlockRejected) {
		t.Errorf("writable resolve over a copy = %v, want errHostBlockRejected", err)
	}
	m.release(&u)
	if be.freed != 1 {
		t.Errorf("freed copies = %d, want 1", be.freed)
	}
	if _, unmaps := be.counts(); unmaps != 1 {
		t.Errorf("unmaps = %d, want 1", unmaps)
	}
}

// copiedRegion returns the only region of f, which must hold a private copy.
func copiedRegion(t *testing.T, m *regionMap, f memmap.File) *region {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	o := m.owners[f]
	if o == nil || len(o.regions) != 1 || o.regions[0].copied == nil {
		t.Fatalf("want one region with a private copy, owner = %+v", o)
	}
	return o.regions[0]
}

// patternMem returns host memory in which no byte is zero, so a copy of memory
// that the test did not ask for shows up.
func patternMem(size int) []byte {
	mem := alignedMem(size)
	for i := range mem {
		mem[i] = byte(i%251 + 1)
	}
	return mem
}

func refuseAll(be *fakeStage2, mem []byte) {
	base := uintptr(unsafe.Pointer(&mem[0]))
	be.refuse = func(host uintptr) bool { return host >= base && host < base+uintptr(len(mem)) }
}

func TestPrivateCopyHoldsOnlyTheBytesOfTheBlock(t *testing.T) {
	be := &fakeStage2{}
	mem := patternMem(64 << 10)
	refuseAll(be, mem)
	m := newTestRegionMap(be, testIPABase+1<<30)
	file := &plainFile{mem: mem}
	var u regionUser
	// The block is the second 4KB page of the host page [16KB, 32KB).
	const lo, hi = 20 << 10, 24 << 10
	bs, _ := file.MapInternal(memmap.FileRange{Start: lo, End: hi}, hostarch.Read)

	segs, err := m.resolve(&u, file, bs, false)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	r := copiedRegion(t, m, file)
	off := uintptr(unsafe.Pointer(&mem[lo])) - r.host
	if off != 4<<10 || r.size != testGranule {
		t.Fatalf("the block lies at %#x in a region of %#x bytes, want %#x in %#x", off, r.size, 4<<10, testGranule)
	}
	if len(segs) != 1 || segs[0].GPA != r.ipa+uint64(off) || segs[0].Size != hi-lo {
		t.Errorf("segments %+v, want one segment of the block at ipa %#x", segs, r.ipa+uint64(off))
	}
	if !bytes.Equal(r.copied[off:off+(hi-lo)], mem[lo:hi]) {
		t.Error("the copy differs from the block")
	}
	for i, b := range r.copied {
		if uintptr(i) >= off && uintptr(i) < off+(hi-lo) {
			continue
		}
		if b != 0 {
			t.Fatalf("byte %#x of the copy is %#x: the copy holds memory outside the block", i, b)
		}
	}
}

func TestAnotherBlockOfACopiedRegionGetsItsOwnBytes(t *testing.T) {
	be := &fakeStage2{}
	mem := patternMem(64 << 10)
	refuseAll(be, mem)
	m := newTestRegionMap(be, testIPABase+1<<30)
	file := &plainFile{mem: mem}
	var u regionUser
	resolve := func(lo, hi uint64) {
		t.Helper()
		bs, _ := file.MapInternal(memmap.FileRange{Start: lo, End: hi}, hostarch.Read)
		if _, err := m.resolve(&u, file, bs, false); err != nil {
			t.Fatalf("resolve [%#x, %#x): %v", lo, hi, err)
		}
	}
	resolve(20<<10, 24<<10)
	// The next 4KB page lies in the same host page, so the copy already covers it.
	resolve(24<<10, 28<<10)
	if be.copies != 1 || m.copyCount() != 1 {
		t.Fatalf("copies = %d, regions with a copy = %d, want one of each", be.copies, m.copyCount())
	}
	r := copiedRegion(t, m, file)
	for page := uintptr(0); page < r.size; page += 4 << 10 {
		src := mem[16<<10+page : 16<<10+page+4<<10]
		want := bytes.Equal(r.copied[page:page+4<<10], src)
		asked := page == 4<<10 || page == 8<<10
		if want != asked {
			t.Errorf("page %#x of the copy holds the memory = %v, want %v", page, want, asked)
		}
	}
}

func TestIdleRegionsGoWhenGuestPhysicalSpaceRunsOut(t *testing.T) {
	be := &fakeStage2{}
	// Room for exactly two 1 MiB regions.
	m := newTestRegionMap(be, testIPABase+2<<20)
	idle := newTestChunkFile(2, 1<<20)
	var a regionUser
	bs, _ := idle.MapInternal(memmap.FileRange{Start: 0, End: 4096}, hostarch.ReadWrite)
	if _, err := m.resolve(&a, idle, bs, true); err != nil {
		t.Fatal(err)
	}
	m.release(&a) // The memory file keeps both regions, and no address space uses them.
	if got := m.regionCount(); got != 2 {
		t.Fatalf("regions = %d, want 2", got)
	}

	other := &plainFile{mem: alignedMem(1 << 20)}
	var b regionUser
	bs, _ = other.MapInternal(memmap.FileRange{Start: 0, End: 1 << 20}, hostarch.ReadWrite)
	if _, err := m.resolve(&b, other, bs, true); err != nil {
		t.Fatalf("resolve after the space ran out: %v", err)
	}
	if _, unmaps := be.counts(); unmaps != 2 {
		t.Errorf("unmaps = %d, want the 2 idle regions", unmaps)
	}

	// A busy region is never dropped: a third range does not fit.
	third := &plainFile{mem: alignedMem(1 << 20)}
	var c regionUser
	bs, _ = third.MapInternal(memmap.FileRange{Start: 0, End: 1 << 20}, hostarch.ReadWrite)
	if _, err := m.resolve(&c, third, bs, true); err != nil {
		t.Fatalf("second range: %v", err)
	}
	fourth := &plainFile{mem: alignedMem(1 << 20)}
	bs, _ = fourth.MapInternal(memmap.FileRange{Start: 0, End: 1 << 20}, hostarch.ReadWrite)
	if _, err := m.resolve(&c, fourth, bs, true); !errors.Is(err, errIPAExhausted) {
		t.Errorf("resolve with every region busy = %v, want errIPAExhausted", err)
	}
}

func TestNewMemoryFileDropsTheIdleRegionsOfAnEarlierFile(t *testing.T) {
	be := &fakeStage2{}
	m := newTestRegionMap(be, testIPABase+1<<30)
	old := newTestChunkFile(2, 1<<20)
	busy := newTestChunkFile(1, 1<<20)
	var a, b regionUser
	bs, _ := old.MapInternal(memmap.FileRange{Start: 0, End: 2 << 20}, hostarch.ReadWrite)
	if _, err := m.resolve(&a, old, bs, true); err != nil {
		t.Fatal(err)
	}
	bs, _ = busy.MapInternal(memmap.FileRange{Start: 0, End: 4096}, hostarch.ReadWrite)
	if _, err := m.resolve(&b, busy, bs, true); err != nil {
		t.Fatal(err)
	}
	// The first file is idle now. Its address space is gone, and the file may be destroyed.
	m.release(&a)
	if _, unmaps := be.counts(); unmaps != 0 {
		t.Fatalf("unmaps = %d before the next file registers, want 0", unmaps)
	}
	next := newTestChunkFile(1, 1<<20)
	var c regionUser
	bs, _ = next.MapInternal(memmap.FileRange{Start: 0, End: 4096}, hostarch.ReadWrite)
	if _, err := m.resolve(&c, next, bs, true); err != nil {
		t.Fatal(err)
	}
	if _, unmaps := be.counts(); unmaps != 2 {
		t.Errorf("unmaps = %d after a new memory file registered, want the 2 idle chunks of the old file", unmaps)
	}
	if got := m.regionCount(); got != 2 {
		t.Errorf("regions = %d, want the busy file and the new file", got)
	}
}

func TestFreedGuestPhysicalRangesMerge(t *testing.T) {
	m := newTestRegionMap(&fakeStage2{}, testIPABase+1<<30)
	var ipas [3]uint64
	for i := range ipas {
		ipa, err := m.allocIPALocked(testGranule)
		if err != nil {
			t.Fatal(err)
		}
		ipas[i] = ipa
	}
	m.freeIPALocked(ipas[0], testGranule)
	m.freeIPALocked(ipas[2], testGranule)
	m.freeIPALocked(ipas[1], testGranule)
	if len(m.free) != 0 || m.next != testIPABase {
		t.Errorf("free list %+v and next %#x, want an empty list and the base address: the ranges must merge", m.free, m.next)
	}
	if ipa, _ := m.allocIPALocked(3 * testGranule); ipa != testIPABase {
		t.Errorf("a run of three granules starts at %#x, want %#x", ipa, testIPABase)
	}
}

func TestResolveFailsAfterClose(t *testing.T) {
	m := newTestRegionMap(&fakeStage2{}, testIPABase+1<<30)
	file := &plainFile{mem: alignedMem(1 << 20)}
	bs, _ := file.MapInternal(memmap.FileRange{Start: 0, End: 4096}, hostarch.ReadWrite)
	m.markClosed()
	var u regionUser
	if _, err := m.resolve(&u, file, bs, true); !errors.Is(err, errPlatformClosed) {
		t.Errorf("resolve after close = %v, want errPlatformClosed", err)
	}
	m.release(&u) // Must not touch freed state.
}
