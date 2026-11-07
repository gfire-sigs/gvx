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
	"slices"
	"sync"
	"sync/atomic"
)

// This file holds the state machine of the trampoline slots of one address
// space. It has no host calls, so the unit tests run on every host. The
// contract that the states obey is in fastisland_windows.go.

const (
	// winSlotUnit is the allocation quantum in bytes of an island page.
	winSlotUnit = 16
	// winIslandBytes is the size of an island page. fastisland_windows.go checks
	// that it equals the block size.
	winIslandBytes = 4096
	// winIslandUnits is the number of allocation units in one island page.
	winIslandUnits = winIslandBytes / winSlotUnit
	// winQuarantineLimit is the number of allocation units that the freed
	// slots of an address space can hold back. Sixteen island pages cover the
	// slots of a large JIT cache that a guest drops at once.
	winQuarantineLimit = 16 * winIslandUnits
)

// quarantinedSlot is a slot that its block freed. The bytes and the record stay
// as they were, because a thread can still be inside the slot.
type quarantinedSlot struct {
	rec islandSlot
	// retiredAt is the epoch that the free started.
	retiredAt uint64
}

// slotArena is the allocation state of the slots in one island page.
type slotArena struct {
	// used marks the allocation units that a live or a quarantined slot owns.
	used [winIslandUnits / 64]uint64
	// live maps the offset of each recorded slot to its record.
	live map[uint32]islandSlot
	// quarantine maps the offset of each freed slot that no thread can be
	// proved to have left.
	quarantine map[uint32]quarantinedSlot
	// quarantineUnits is the number of units that quarantine holds.
	quarantineUnits int
}

func slotUnits(size uint32) int { return int((size + winSlotUnit - 1) / winSlotUnit) }

// alloc reserves a contiguous run of size bytes and returns its byte offset.
// Only free units qualify. A quarantined slot keeps its units.
func (a *slotArena) alloc(size uint32) (uint32, bool) {
	need := slotUnits(size)
	if need <= 0 || need > winIslandUnits {
		return 0, false
	}
	run, start := 0, 0
	for u := range winIslandUnits {
		if a.used[u/64]&(uint64(1)<<(u%64)) != 0 {
			run, start = 0, u+1
			continue
		}
		run++
		if run == need {
			a.setUnits(start, need, true)
			return uint32(start * winSlotUnit), true
		}
	}
	return 0, false
}

func (a *slotArena) setUnits(start, count int, used bool) {
	for k := start; k < start+count && k < winIslandUnits; k++ {
		if used {
			a.used[k/64] |= uint64(1) << (k % 64)
		} else {
			a.used[k/64] &^= uint64(1) << (k % 64)
		}
	}
}

// record makes rec the live record of the slot at off.
func (a *slotArena) record(off uint32, rec islandSlot) {
	if a.live == nil {
		a.live = make(map[uint32]islandSlot)
	}
	a.live[off] = rec
}

// discard frees a slot that no thread can have entered, because the branch to
// it never became visible to the stub. The units are free at once.
func (a *slotArena) discard(off, size uint32) {
	delete(a.live, off)
	a.setUnits(int(off/winSlotUnit), slotUnits(size), false)
}

// retire moves the live slot at off to the quarantine. The caller removed every
// branch to the slot first, and retiredAt is the epoch that retire started.
func (a *slotArena) retire(off, size uint32, retiredAt uint64) {
	rec, ok := a.live[off]
	if !ok {
		// No record means that no block published the slot.
		a.discard(off, size)
		return
	}
	delete(a.live, off)
	if a.quarantine == nil {
		a.quarantine = make(map[uint32]quarantinedSlot)
	}
	a.quarantine[off] = quarantinedSlot{rec: rec, retiredAt: retiredAt}
	a.quarantineUnits += slotUnits(size)
}

// reclaim frees every quarantined slot that snap allows and returns the number
// of units that it freed. base is the address of the island page.
func (a *slotArena) reclaim(base uint64, snap *epochSnapshot) int {
	freed := 0
	for off, q := range a.quarantine {
		if !snap.allows(q.retiredAt, base+uint64(off)) {
			continue
		}
		n := slotUnits(q.rec.size)
		a.setUnits(int(off/winSlotUnit), n, false)
		a.quarantineUnits -= n
		freed += n
		delete(a.quarantine, off)
	}
	return freed
}

// lookup returns the record of the slot that starts at off. A quarantined slot
// counts, because a thread can still be inside it.
func (a *slotArena) lookup(off uint32) (islandSlot, bool) {
	if s, ok := a.live[off]; ok {
		return s, true
	}
	q, ok := a.quarantine[off]
	return q.rec, ok
}

// containing returns the slot that holds the byte at rel and the offset of the
// slot. A quarantined slot counts.
func (a *slotArena) containing(rel uint32) (s islandSlot, off uint32, ok bool) {
	for o, s := range a.live {
		if rel >= o && rel < o+s.size {
			return s, o, true
		}
	}
	for o, q := range a.quarantine {
		if rel >= o && rel < o+q.rec.size {
			return q.rec, o, true
		}
	}
	return islandSlot{}, 0, false
}

// readerOffline is the epoch of a reader that cannot be inside a slot.
const readerOffline = ^uint64(0)

// slotEpochs counts the frees of slots in one address space and tracks the
// threads that the frees must wait for.
type slotEpochs struct {
	// cur is the current epoch. It starts at 1 and each retire adds 1.
	cur atomic.Uint64

	// mu guards readers. It is a leaf lock.
	mu      sync.Mutex
	readers []*epochReader
}

func newSlotEpochs() *slotEpochs {
	e := &slotEpochs{}
	e.cur.Store(1)
	return e
}

// retire starts a new epoch and returns it. A slot that a block frees takes
// the result as its retiredAt. Callers removed every branch to the slot first.
func (e *slotEpochs) retire() uint64 { return e.cur.Add(1) }

// newReader registers a thread that starts offline.
func (e *slotEpochs) newReader() *epochReader {
	r := &epochReader{eps: e}
	r.epoch.Store(readerOffline)
	e.mu.Lock()
	e.readers = append(e.readers, r)
	e.mu.Unlock()
	return r
}

// epochReader is the quiescence state of one guest thread.
//
// A reader is online while the thread can run guest code. The thread can then
// be inside a slot that a branch entered before the free. A reader is offline
// while the thread waits in the spill routine or is parked. The thread then
// leaves only through the slot that pin names, or through the Sentry.
type epochReader struct {
	eps *slotEpochs
	// epoch is readerOffline, or the epoch that was current when the thread went
	// online.
	epoch atomic.Uint64
	// pin is the address of the slot that the thread can still execute, or 0.
	// A decoded trap sets it, and so does a start at an island address.
	pin atomic.Uint64
}

// goOnline marks the thread as able to run guest code. The caller calls it
// before the thread resumes.
func (r *epochReader) goOnline() { r.epoch.Store(r.eps.cur.Load()) }

// goOffline marks the thread as unable to be inside a slot, except the slot at
// pin. A pin of 0 means no slot. The thread must wait in the spill routine or
// be suspended.
func (r *epochReader) goOffline(pin uint64) {
	r.pin.Store(pin)
	r.epoch.Store(readerOffline)
}

// setPin makes the thread hold the slot at va. The caller holds the lock that
// reclaim holds, and calls setPin before it starts the thread at an address in
// the slot.
func (r *epochReader) setPin(va uint64) { r.pin.Store(va) }

// clearPin drops the slot that the thread can execute. The caller calls it
// when the thread resumes without the slot tail.
func (r *epochReader) clearPin() { r.pin.Store(0) }

// epochSnapshot is the state of every reader at one time.
type epochSnapshot struct {
	// oldest is the smallest epoch of an online reader, or readerOffline.
	oldest uint64
	// pins holds the nonzero pin of every reader.
	pins []uint64
}

// snapshot reads every reader. It loads the epoch of a reader before the pin.
// goOffline stores the pin before the epoch. A reader that reads offline
// therefore also shows the pin that belongs to its trap.
func (e *slotEpochs) snapshot() epochSnapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := epochSnapshot{oldest: readerOffline, pins: make([]uint64, 0, len(e.readers))}
	for _, r := range e.readers {
		if ep := r.epoch.Load(); ep < s.oldest {
			s.oldest = ep
		}
		if p := r.pin.Load(); p != 0 {
			s.pins = append(s.pins, p)
		}
	}
	return s
}

// allows reports whether the slot at va, retired at retiredAt, can be reused.
// Every reader must be offline or have gone online after the retire, and no
// reader may hold the slot as its pin.
func (s *epochSnapshot) allows(retiredAt, va uint64) bool {
	return s.oldest >= retiredAt && !slices.Contains(s.pins, va)
}
