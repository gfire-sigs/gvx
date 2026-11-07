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

//go:build darwin || windows

package systrap

import (
	"math/rand/v2"
	"sync"
	"testing"
)

const testIslandBase = 0x47b0000

func testSlotRecord(site uint64) islandSlot {
	return islandSlot{site: site, size: winSlotSize, jmpVA: site}
}

// allocLive allocates and records a slot for site.
func allocLive(t testing.TB, a *slotArena, site uint64) uint32 {
	t.Helper()
	off, ok := a.alloc(winSlotSize)
	if !ok {
		t.Fatalf("alloc for site %#x failed", site)
	}
	a.record(off, testSlotRecord(site))
	return off
}

func usedUnits(a *slotArena) int {
	n := 0
	for _, w := range a.used {
		for ; w != 0; w &= w - 1 {
			n++
		}
	}
	return n
}

func TestArenaAllocIsFirstFitAndDiscardFreesAtOnce(t *testing.T) {
	var a slotArena
	first := allocLive(t, &a, 0x1000)
	second := allocLive(t, &a, 0x2000)
	if first != 0 || second != winSlotSize {
		t.Fatalf("offsets = %#x, %#x; want 0 and %#x", first, second, winSlotSize)
	}
	a.discard(first, winSlotSize)
	if _, ok := a.lookup(first); ok {
		t.Error("a discarded slot still has a record")
	}
	if again, ok := a.alloc(winSlotSize); !ok || again != first {
		t.Errorf("alloc after discard = (%#x, %v), want (%#x, true)", again, ok, first)
	}
}

func TestArenaRetiredSlotKeepsUnitsAndRecordUntilReclaim(t *testing.T) {
	var a slotArena
	eps := newSlotEpochs()
	off := allocLive(t, &a, 0x1000)
	a.retire(off, winSlotSize, eps.retire())

	if s, ok := a.lookup(off); !ok || s.site != 0x1000 {
		t.Fatalf("lookup of a quarantined slot = (%+v, %v), want its record", s, ok)
	}
	if got := a.quarantineUnits; got != slotUnits(winSlotSize) {
		t.Errorf("quarantineUnits = %d, want %d", got, slotUnits(winSlotSize))
	}
	// alloc must not hand out the bytes of a quarantined slot.
	for range winIslandUnits / slotUnits(winSlotSize) {
		if got, ok := a.alloc(winSlotSize); ok && got == off {
			t.Fatalf("alloc returned the offset %#x of a quarantined slot", off)
		}
	}
	snap := eps.snapshot()
	if freed := a.reclaim(testIslandBase, &snap); freed != slotUnits(winSlotSize) {
		t.Fatalf("reclaim freed %d units, want %d", freed, slotUnits(winSlotSize))
	}
	if _, ok := a.lookup(off); ok {
		t.Error("a reclaimed slot still has a record")
	}
	if a.quarantineUnits != 0 {
		t.Errorf("quarantineUnits = %d after reclaim, want 0", a.quarantineUnits)
	}
}

func TestRetireWithoutRecordFreesAtOnce(t *testing.T) {
	var a slotArena
	off, _ := a.alloc(winSlotSize)
	a.retire(off, winSlotSize, 2)
	if usedUnits(&a) != 0 || a.quarantineUnits != 0 {
		t.Errorf("an unpublished slot stays: used %d, quarantined %d", usedUnits(&a), a.quarantineUnits)
	}
}

func TestOnlineReaderHoldsBackTheSlotUntilItGoesOfflineOrOnlineAgain(t *testing.T) {
	var a slotArena
	eps := newSlotEpochs()
	r := eps.newReader()
	r.goOnline()
	off := allocLive(t, &a, 0x1000)
	a.retire(off, winSlotSize, eps.retire())

	snap := eps.snapshot()
	if freed := a.reclaim(testIslandBase, &snap); freed != 0 {
		t.Fatalf("reclaim freed %d units while a thread has not passed a quiescent point", freed)
	}

	r.goOffline(0)
	snap = eps.snapshot()
	if freed := a.reclaim(testIslandBase, &snap); freed == 0 {
		t.Fatal("reclaim kept a slot that no thread can be inside")
	}
}

func TestReaderThatWentOnlineAfterTheRetireDoesNotHoldBack(t *testing.T) {
	var a slotArena
	eps := newSlotEpochs()
	r := eps.newReader()
	off := allocLive(t, &a, 0x1000)
	a.retire(off, winSlotSize, eps.retire())
	r.goOnline()
	snap := eps.snapshot()
	if freed := a.reclaim(testIslandBase, &snap); freed == 0 {
		t.Fatal("a thread that resumed after the retire cannot enter the slot, but reclaim kept it")
	}
}

func TestPinnedSlotStaysWhileThePinnedThreadRuns(t *testing.T) {
	var a slotArena
	eps := newSlotEpochs()
	r := eps.newReader()
	r.goOnline()
	pinned := allocLive(t, &a, 0x1000)
	other := allocLive(t, &a, 0x2000)
	a.retire(pinned, winSlotSize, eps.retire())
	a.retire(other, winSlotSize, eps.retire())

	// The thread trapped in the first slot and waits for the Sentry.
	r.goOffline(testIslandBase + uint64(pinned))
	snap := eps.snapshot()
	a.reclaim(testIslandBase, &snap)
	if _, ok := a.lookup(pinned); !ok {
		t.Error("reclaim freed the slot that a trapped thread holds as its pin")
	}
	if _, ok := a.lookup(other); ok {
		t.Error("reclaim kept a slot that no thread holds")
	}

	// A hot resume runs the tail, so the pin stays and the thread is online.
	r.goOnline()
	snap = eps.snapshot()
	if freed := a.reclaim(testIslandBase, &snap); freed != 0 {
		t.Error("reclaim freed the slot of a thread that runs its tail")
	}

	// A cold resume drops the pin.
	r.clearPin()
	snap = eps.snapshot()
	if freed := a.reclaim(testIslandBase, &snap); freed == 0 {
		t.Error("reclaim kept a slot after the thread resumed cold")
	}
}

func TestContainingFindsLiveAndQuarantinedSlots(t *testing.T) {
	var a slotArena
	eps := newSlotEpochs()
	live := allocLive(t, &a, 0x1000)
	gone := allocLive(t, &a, 0x2000)
	a.retire(gone, winSlotSize, eps.retire())
	for _, c := range []struct {
		off  uint32
		want uint64
	}{{live + 5, 0x1000}, {gone + winSlotSize - 1, 0x2000}} {
		s, off, ok := a.containing(c.off)
		if !ok || s.site != c.want || off != c.off-(c.off%winSlotSize) {
			t.Errorf("containing(%#x) = (%#x, %#x, %v), want the slot of site %#x", c.off, s.site, off, ok, c.want)
		}
	}
	if _, _, ok := a.containing(2 * winSlotSize); ok {
		t.Error("containing found a slot in free space")
	}
}

func TestSnapshotWithoutReadersAllowsEverything(t *testing.T) {
	eps := newSlotEpochs()
	snap := eps.snapshot()
	if !snap.allows(eps.retire(), 0x1000) {
		t.Error("with no thread, a retired slot must be reusable")
	}
}

// threadPos is the place of a modeled thread.
type threadPos int

const (
	posGuest    threadPos = iota // runs guest code, online
	posHead                      // entered a slot, has not trapped
	posSpill                     // published a trap, the Sentry has not decoded it
	posDecoded                   // the Sentry decoded the trap, the thread waits
	posTail                      // runs the tail or the entry of a slot after a resume
	posParked                    // suspended, offline
	posStarting                  // parked, the Sentry chose a slot address to start at
)

type modelThread struct {
	pos    threadPos
	slot   int // index into the model slots while pos is Head, Spill, Decoded, or Tail
	reader *epochReader
}

type modelSlot struct {
	off  uint32
	site uint64
	live bool
}

// TestModelNoThreadIsInsideAReusedSlot drives the arena and the readers with
// the operations that the engine performs, in random order. After each step,
// every thread that is inside a slot must find the record that it entered. A
// slot that reclaim handed to a new owner has another record.
func TestModelNoThreadIsInsideAReusedSlot(t *testing.T) {
	for seed := int64(1); seed <= 40; seed++ {
		rng := rand.New(rand.NewPCG(uint64(seed), 1))
		var a slotArena
		eps := newSlotEpochs()
		var slots []*modelSlot
		threads := make([]*modelThread, 4)
		for i := range threads {
			threads[i] = &modelThread{reader: eps.newReader()}
			threads[i].reader.goOffline(0)
			threads[i].pos = posParked
		}
		var next uint64 = 0x1000
		liveSlots := func() []int {
			var out []int
			for i, s := range slots {
				if s.live {
					out = append(out, i)
				}
			}
			return out
		}
		for step := 0; step < 4000; step++ {
			th := threads[rng.IntN(len(threads))]
			switch rng.IntN(8) {
			case 0: // the installer publishes a slot
				if off, ok := a.alloc(winSlotSize); ok {
					next += 0x10
					a.record(off, testSlotRecord(next))
					slots = append(slots, &modelSlot{off: off, site: next, live: true})
				}
			case 1: // a block drops: the branch disappears, then retire
				if l := liveSlots(); len(l) > 0 {
					s := slots[l[rng.IntN(len(l))]]
					s.live = false
					a.retire(s.off, winSlotSize, eps.retire())
				}
			case 2: // reclaim
				snap := eps.snapshot()
				a.reclaim(testIslandBase, &snap)
			case 3: // the thread enters a slot through a visible branch
				if th.pos == posGuest {
					if l := liveSlots(); len(l) > 0 {
						th.pos, th.slot = posHead, l[rng.IntN(len(l))]
					}
				}
			case 4: // the thread publishes its trap
				if th.pos == posHead {
					th.pos = posSpill
				}
			case 5: // the Sentry decodes the trap
				if th.pos == posSpill {
					s := slots[th.slot]
					rec, ok := a.lookup(s.off)
					if !ok || rec.site != s.site {
						t.Fatalf("seed %d step %d: decode of a trap found (%+v, %v), want the record of site %#x", seed, step, rec, ok, s.site)
					}
					th.reader.goOffline(testIslandBase + uint64(s.off))
					th.pos = posDecoded
				}
			case 6: // the Sentry resumes the thread
				switch th.pos {
				case posDecoded:
					if rng.IntN(2) == 0 {
						th.reader.goOnline()
						th.pos = posTail
					} else {
						th.reader.clearPin()
						th.reader.goOnline()
						th.pos = posGuest
					}
				case posTail:
					th.pos = posGuest
				case posParked:
					if l := liveSlots(); len(l) > 0 && rng.IntN(3) == 0 {
						// A clone child or a restart starts at a slot address.
						// The Sentry pins the slot while it looks the slot up. The
						// thread goes online in a later step, and a drop and a
						// reclaim can come between the two.
						idx := l[rng.IntN(len(l))]
						th.reader.setPin(testIslandBase + uint64(slots[idx].off))
						th.pos, th.slot = posStarting, idx
					} else {
						th.reader.goOnline()
						th.pos = posGuest
					}
				case posStarting:
					th.reader.goOnline()
					th.pos = posTail
				}
			case 7: // the thread stops in guest code and parks
				if th.pos == posGuest {
					th.reader.goOffline(0)
					th.pos = posParked
				}
			}
			for i, o := range threads {
				switch o.pos {
				case posHead, posSpill, posDecoded, posTail, posStarting:
					s := slots[o.slot]
					rec, ok := a.lookup(s.off)
					if !ok || rec.site != s.site {
						t.Fatalf("seed %d step %d: thread %d is inside the slot of site %#x, which has (%+v, %v)", seed, step, i, s.site, rec, ok)
					}
				}
			}
		}
	}
}

func TestReadersAndReclaimRaceSafely(t *testing.T) {
	var a slotArena
	eps := newSlotEpochs()
	const readers = 4
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range readers {
		r := eps.newReader()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				r.goOnline()
				r.goOffline(0x4000)
				r.clearPin()
			}
		}()
	}
	for range 200 {
		if off, ok := a.alloc(winSlotSize); ok {
			a.record(off, testSlotRecord(0x1000))
			a.retire(off, winSlotSize, eps.retire())
		}
		snap := eps.snapshot()
		a.reclaim(testIslandBase, &snap)
	}
	close(stop)
	wg.Wait()
	// Every reader ended offline without a pin, so nothing holds a slot.
	snap := eps.snapshot()
	a.reclaim(testIslandBase, &snap)
	if a.quarantineUnits != 0 || usedUnits(&a) != 0 {
		t.Errorf("after the readers stopped, %d units stay quarantined and %d stay used, want none", a.quarantineUnits, usedUnits(&a))
	}
}
