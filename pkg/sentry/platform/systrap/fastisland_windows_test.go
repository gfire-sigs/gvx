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

package systrap

import (
	"errors"
	"testing"

	"z.gfire.dev/gvx/pkg/context"
)

const testIslandSite = 0x1234560

// newIslandOnlyAddressSpace returns an address space that has one island and
// no stub. The tests use the island bookkeeping only.
func newIslandOnlyAddressSpace(bases ...uint64) *addressSpace {
	as := &addressSpace{islands: make(map[uint64]*island), epochs: newSlotEpochs()}
	for _, base := range bases {
		as.islands[base] = &island{base: base}
	}
	return as
}

// publishSlot allocates, records, and returns the first slot of isl.
func publishSlot(t *testing.T, isl *island, site uint64) winSlotRef {
	t.Helper()
	off, ok := isl.alloc(winSlotSize)
	if !ok {
		t.Fatal("alloc failed")
	}
	isl.record(off, plainSlot(site, winSlotSize))
	return winSlotRef{isl: isl, off: off, size: winSlotSize}
}

func tailOf(ref winSlotRef) uint64 { return ref.isl.base + uint64(ref.off) + winSlotTailOffset }

// TestSlotAtTailDecodesAQuarantinedSlotUntilReclaim covers a trap that a thread
// publishes from a slot just before another thread drops the block of the
// slot. The Sentry must find the site of that slot while the thread can be
// inside it, and the bytes must stay until reclaim frees them.
func TestSlotAtTailDecodesAQuarantinedSlotUntilReclaim(t *testing.T) {
	const base = 0x47b0000
	as := newIslandOnlyAddressSpace(base)
	ref := publishSlot(t, as.islands[base], testIslandSite)
	// A thread entered the slot before the drop and has not trapped yet.
	reader := as.epochs.newReader()
	reader.goOnline()

	if got, ok := as.slotAtTail(tailOf(ref)); !ok || got != testIslandSite {
		t.Fatalf("slotAtTail of a live slot = (%#x, %v), want (%#x, true)", got, ok, uint64(testIslandSite))
	}
	as.mu.Lock()
	as.retireSlotsLocked([]winSlotRef{ref})
	freed := as.reclaimSlotsLocked()
	as.mu.Unlock()
	if freed != 0 {
		t.Fatalf("reclaim freed %d units while a thread can be inside the slot", freed)
	}
	if got, ok := as.slotAtTail(tailOf(ref)); !ok || got != testIslandSite {
		t.Fatalf("slotAtTail after the drop = (%#x, %v), want (%#x, true)", got, ok, uint64(testIslandSite))
	}
	// The thread traps. The Sentry decodes the trap and the thread waits.
	reader.goOffline(ref.isl.base + uint64(ref.off))
	as.mu.Lock()
	freed = as.reclaimSlotsLocked()
	as.mu.Unlock()
	if freed != 0 {
		t.Fatalf("reclaim freed %d units of the slot that a trapped thread holds as its pin", freed)
	}
	// A cold resume ends the pin.
	reader.clearPin()
	reader.goOnline()
	as.mu.Lock()
	freed = as.reclaimSlotsLocked()
	as.mu.Unlock()
	if freed == 0 {
		t.Fatal("reclaim kept the slot after every thread left it")
	}
	if got, ok := as.slotAtTail(tailOf(ref)); ok {
		t.Fatalf("slotAtTail after reclaim = (%#x, true), want no slot", got)
	}
}

func TestSlotContainingFindsAQuarantinedSlot(t *testing.T) {
	const base = 0x47b0000
	as := newIslandOnlyAddressSpace(base)
	ref := publishSlot(t, as.islands[base], testIslandSite)
	as.epochs.newReader().goOnline()
	as.mu.Lock()
	as.retireSlotsLocked([]winSlotRef{ref})
	as.mu.Unlock()
	s, va, ok := as.slotContaining(base + uint64(ref.off) + 3)
	if !ok || s.site != testIslandSite || va != base+uint64(ref.off) {
		t.Fatalf("slotContaining = (%+v, %#x, %v), want the quarantined slot", s, va, ok)
	}
}

// fillQuarantine fills every island of as with retired slots while a thread
// stays online, so that nothing can be reclaimed.
func fillQuarantine(t *testing.T, as *addressSpace) {
	t.Helper()
	var refs []winSlotRef
	for _, isl := range as.islands {
		for {
			off, ok := isl.alloc(winSlotSize)
			if !ok {
				break
			}
			isl.record(off, plainSlot(testIslandSite, winSlotSize))
			refs = append(refs, winSlotRef{isl: isl, off: off, size: winSlotSize})
		}
	}
	as.mu.Lock()
	as.retireSlotsLocked(refs)
	as.mu.Unlock()
}

func TestAllocSlotReusesReclaimedUnitsWithoutANewIsland(t *testing.T) {
	const base = testIslandSite &^ (blockSize - 1)
	as := newIslandOnlyAddressSpace(base + 0x10000)
	fillQuarantine(t, as)
	// No thread exists, so every quarantined slot can go.
	isl, off, err := as.allocSlot(context.Background(), nil, testIslandSite, winSlotSize)
	if err != nil {
		t.Fatalf("allocSlot: %v", err)
	}
	if isl != as.islands[base+0x10000] || off != 0 {
		t.Errorf("allocSlot = (island %#x, offset %#x), want the first slot of the existing island", isl.base, off)
	}
}

func TestAllocSlotFailsWhenAFullQuarantineStaysInUse(t *testing.T) {
	var bases []uint64
	for i := uint64(0); i < winQuarantineLimit/winIslandUnits; i++ {
		bases = append(bases, 0x2000000+i*blockSize)
	}
	as := newIslandOnlyAddressSpace(bases...)
	as.epochs.newReader().goOnline()
	fillQuarantine(t, as)
	as.mu.Lock()
	held := as.quarantineUnitsLocked()
	as.mu.Unlock()
	if held < winQuarantineLimit {
		t.Fatalf("the quarantine holds %d units, want at least %d", held, winQuarantineLimit)
	}
	_, _, err := as.allocSlot(context.Background(), nil, 0x2000000, winSlotSize)
	if !errors.Is(err, errSlotsQuarantined) {
		t.Fatalf("allocSlot with a full quarantine = %v, want errSlotsQuarantined", err)
	}
}
