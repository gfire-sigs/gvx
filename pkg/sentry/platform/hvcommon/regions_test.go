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

package hvcommon

import (
	"errors"
	"math/rand/v2"
	"sync"
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

const testGPABase = uint64(0x1_4000_0000)

var (
	errTestClosed    = errors.New("test: closed")
	errTestExhausted = errors.New("test: gpa exhausted")
)

type recordedCall struct {
	host     uintptr
	gpa      uint64
	size     uintptr
	writable bool
}

type recordingBackend struct {
	mu     sync.Mutex
	maps   []recordedCall
	unmaps []recordedCall
	live   map[uint64]recordedCall
}

func newRecordingBackend() *recordingBackend {
	return &recordingBackend{live: make(map[uint64]recordedCall)}
}

func (b *recordingBackend) MapHost(host uintptr, gpa uint64, size uintptr, writable bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	call := recordedCall{host: host, gpa: gpa, size: size, writable: writable}
	b.maps = append(b.maps, call)
	b.live[gpa] = call
	return nil
}

func (b *recordingBackend) UnmapGPA(gpa uint64, size uintptr) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.unmaps = append(b.unmaps, recordedCall{gpa: gpa, size: size})
	delete(b.live, gpa)
	return nil
}

func (*recordingBackend) RefusedMemory(error) bool          { return false }
func (*recordingBackend) AllocCopy(uintptr) ([]byte, error) { return nil, errTestExhausted }
func (*recordingBackend) FreeCopy([]byte) error             { return nil }

func (b *recordingBackend) counts() (maps, unmaps int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.maps), len(b.unmaps)
}

type tokenFile struct {
	memmap.File
	id int
}

func TestSameHostVAReuseAcrossFilesUnmapsOldAndMapsNew(t *testing.T) {
	const reusedHostVA = uintptr(0x7ff0_0000_0000)
	const size = 4 * PageSize4K
	const gva = uint64(0x400000)

	be := newRecordingBackend()
	m := NewRegionMap(be, RegionMapConfig{
		Granule:          PageSize4K,
		Base:             testGPABase,
		Limit:            testGPABase + (1 << 30),
		SeparateReadOnly: true,
		LogPrefix:        "test",
		ErrClosed:        errTestClosed,
		ErrExhausted:     errTestExhausted,
	})

	fileA := &tokenFile{id: 1}
	fileB := &tokenFile{id: 2}
	blocks := []HostBlock{{Addr: reusedHostVA, Len: size}}
	var u RegionUser

	runsA, err := m.ResolvePinnedBlocks(&u, fileA, blocks, false)
	if err != nil {
		t.Fatalf("ResolvePinnedBlocks(fileA): %v", err)
	}
	acqA, dropA := u.RecordRuns(gva, runsA)
	m.FinishPin(runsA, acqA, dropA)

	if maps, unmaps := be.counts(); maps != 1 || unmaps != 0 {
		t.Fatalf("after mapping fileA: maps=%d unmaps=%d, want 1 and 0", maps, unmaps)
	}
	gpaA := runsA[0].GPA

	dropped := u.ClearRange(gva, gva+size)
	m.ReleaseRegions(dropped)

	if maps, unmaps := be.counts(); maps != 1 || unmaps != 1 {
		t.Fatalf("after unmapping fileA: maps=%d unmaps=%d, want 1 and 1", maps, unmaps)
	}
	if _, stillLive := be.live[gpaA]; stillLive {
		t.Fatalf("fileA GPA %#x remained mapped after ClearRange", gpaA)
	}

	runsB, err := m.ResolvePinnedBlocks(&u, fileB, blocks, false)
	if err != nil {
		t.Fatalf("ResolvePinnedBlocks(fileB): %v", err)
	}
	acqB, dropB := u.RecordRuns(gva, runsB)
	m.FinishPin(runsB, acqB, dropB)

	if maps, unmaps := be.counts(); maps != 2 || unmaps != 1 {
		t.Fatalf("after mapping fileB at same host VA: maps=%d unmaps=%d, want 2 and 1", maps, unmaps)
	}
	if be.maps[1].host != reusedHostVA || be.maps[1].size != size {
		t.Fatalf("second MapHost = %+v, want host=%#x size=%#x", be.maps[1], reusedHostVA, size)
	}

	m.Release(&u)
	if maps, unmaps := be.counts(); maps != 2 || unmaps != 2 {
		t.Fatalf("after Release: maps=%d unmaps=%d, want 2 and 2", maps, unmaps)
	}
}

func TestFiveThousandScatteredMappingsReclaimGPAViaFreeList(t *testing.T) {
	const (
		totalOps   = 5000
		batchWidth = 32
		windowSize = 64 * PageSize4K
	)

	be := newRecordingBackend()
	m := NewRegionMap(be, RegionMapConfig{
		Granule:          PageSize4K,
		Base:             testGPABase,
		Limit:            testGPABase + windowSize,
		SeparateReadOnly: true,
		LogPrefix:        "test",
		ErrClosed:        errTestClosed,
		ErrExhausted:     errTestExhausted,
	})

	var u RegionUser
	rng := rand.New(rand.NewPCG(0x677678, 0x70723037))
	type activeSlot struct {
		gva uint64
	}
	active := make([]activeSlot, 0, batchWidth)

	unmapOne := func(idx int) {
		slot := active[idx]
		active[idx] = active[len(active)-1]
		active = active[:len(active)-1]
		dropped := u.ClearRange(slot.gva, slot.gva+PageSize4K)
		m.ReleaseRegions(dropped)
	}

	for i := range totalOps {
		if len(active) == batchWidth {
			unmapOne(rng.IntN(len(active)))
		}
		// Scatter 4KB mappings across the 47-bit Windows user virtual space.
		hostVA := uintptr(0x0000_0100_0000_0000) + uintptr(rng.Uint64N(1<<34))*PageSize4K
		gva := uint64(0x1000_0000) + uint64(i)*PageSize4K
		f := &tokenFile{id: i + 1}

		runs, err := m.ResolvePinnedBlocks(&u, f, []HostBlock{{Addr: hostVA, Len: PageSize4K}}, i%2 == 0)
		if err != nil {
			t.Fatalf("mapping %d at host VA %#x failed: %v", i, hostVA, err)
		}
		acq, drop := u.RecordRuns(gva, runs)
		m.FinishPin(runs, acq, drop)
		active = append(active, activeSlot{gva: gva})
	}

	for len(active) > 0 {
		unmapOne(len(active) - 1)
	}

	maps, unmaps := be.counts()
	if maps != totalOps || unmaps != totalOps {
		t.Fatalf("Stage-2 counts: maps=%d unmaps=%d, want %d and %d", maps, unmaps, totalOps, totalOps)
	}
	if got := m.RegionCount(); got != 0 {
		t.Fatalf("RegionCount() = %d, want 0", got)
	}
	free, next := m.AllocatorStateForTest()
	if len(free) != 0 || next != testGPABase {
		t.Fatalf("allocator state after full unmap: free=%+v next=%#x, want empty free list and %#x", free, next, testGPABase)
	}
}

func TestRegionUserSplitTrimAndCoalesceMaintainExactRefs(t *testing.T) {
	be := newRecordingBackend()
	m := NewRegionMap(be, RegionMapConfig{
		Granule:          PageSize4K,
		Base:             testGPABase,
		Limit:            testGPABase + (1 << 30),
		SeparateReadOnly: true,
		LogPrefix:        "test",
		ErrClosed:        errTestClosed,
		ErrExhausted:     errTestExhausted,
	})

	f := &tokenFile{id: 99}
	const hostBase = uintptr(0x7ff4_0000_0000)
	const baseGVA = uint64(0x800000)
	var u RegionUser

	// Hold one pin on the 4-page region while mapping 4 sequential pages one at
	// a time so RecordRuns coalesces their extents.
	initRuns, err := m.ResolvePinnedBlocks(&u, f, []HostBlock{{Addr: hostBase, Len: 4 * PageSize4K}}, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		pageBlock := []HostBlock{{Addr: hostBase + uintptr(i)*PageSize4K, Len: PageSize4K}}
		runs, err := m.ResolvePinnedBlocks(&u, f, pageBlock, true)
		if err != nil {
			t.Fatal(err)
		}
		acq, drop := u.RecordRuns(baseGVA+uint64(i)*PageSize4K, runs)
		m.FinishPin(runs, acq, drop)
	}
	m.FinishPin(initRuns, nil, nil)

	if len(u.extents) != 1 || u.extCounts[u.extents[0].region] != 1 {
		t.Fatalf("coalesced extents = %+v, counts = %+v, want 1 extent", u.extents, u.extCounts)
	}

	// Punch page 1 in the middle: splits into [0,1) and [2,4), region stays mapped.
	m.ReleaseRegions(u.ClearRange(baseGVA+PageSize4K, baseGVA+2*PageSize4K))
	if _, unmaps := be.counts(); unmaps != 0 {
		t.Fatalf("middle unmap triggered %d unmaps, want 0", unmaps)
	}

	// Trim page 0 and page 3; page 2 still holds the region.
	m.ReleaseRegions(u.ClearRange(baseGVA, baseGVA+PageSize4K))
	m.ReleaseRegions(u.ClearRange(baseGVA+3*PageSize4K, baseGVA+4*PageSize4K))
	if _, unmaps := be.counts(); unmaps != 0 {
		t.Fatalf("edge unmaps triggered %d unmaps while page 2 remained, want 0", unmaps)
	}

	// Unmap the last remaining page 2: region drops immediately.
	m.ReleaseRegions(u.ClearRange(baseGVA+2*PageSize4K, baseGVA+3*PageSize4K))
	if _, unmaps := be.counts(); unmaps != 1 {
		t.Fatalf("final page unmap triggered %d unmaps, want 1", unmaps)
	}
}
