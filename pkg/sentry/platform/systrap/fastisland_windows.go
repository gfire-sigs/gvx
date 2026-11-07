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

//go:build windows

package systrap

import (
	"errors"
	"fmt"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// A trampoline island is one page of slots in the guest address space. A
// patched system call instruction jumps to a slot, so the slot must lie within
// the reach of the jump. The island is a sealed mapping that the memory manager
// knows, so that the guest cannot map over it. The engine maps a private page
// of slot code over the frame that the memory manager holds.
//
// # Slot lifecycle contract
//
// A slot is a range of bytes in an island page with a record (islandSlot). The
// bytes hold the entry code, the call of the spill routine, and the tail. The
// tail restores the registers and returns to the guest after a hot resume. A
// slot is in one of four states. islandarena_xplat.go implements the states.
//
//	Free        No thread runs the bytes. No record exists. alloc can return the units.
//	Allocated   alloc returned the units. The installer writes the bytes. No record
//	            exists, and no branch names the slot.
//	Live        The installer recorded the slot. The block of the slot maps its page,
//	            so a thread enters the slot through the branch at the site.
//	Quarantined The block dropped its page, so no branch to the slot is visible.
//	            A thread that entered before the drop can still be inside the slot.
//	            The bytes and the record stay as they were.
//
// Free becomes Allocated in alloc. Allocated becomes Live in record, and it
// becomes Free in discard when the encoder fails. Live becomes Free in discard
// only for a slot whose branch never became visible to the stub. Live becomes
// Quarantined in retire, and Quarantined becomes Free in reclaim. No other
// transition exists.
//
// Rules that every caller obeys:
//
//  1. retire runs after the stub lost the executable page that holds the
//     branch: after MapFile replaced the block, after Unmap, after
//     returnToDataLocked, or after the stub process ended. A thread that goes
//     online after retire cannot enter the slot.
//  2. Only the code that holds as.mu reads or writes a record. Decode
//     (fastTrapLocked), rewindToSite, svcSlotFault, and slotContaining read the
//     record of a Live or Quarantined slot, and copy it before they unlock. No
//     code reads the record of a Free or Allocated slot.
//  3. encode writes the bytes of an Allocated slot only. The page of the slot is
//     executable in the stub while encode writes, so no thread can be inside the
//     slot.
//  4. A thread is inside a slot from the branch at the site until it leaves the
//     tail or goes cold. The Sentry sees the thread leave when the thread traps
//     again or parks. Both are quiescent points of the thread (epochReader).
//  5. reclaim frees a Quarantined slot only when every thread is offline or went
//     online after the retire, and no thread holds the slot as its pin. A thread
//     that decoded a trap at the slot holds the pin until it resumes cold, traps
//     again, or parks. A thread that the Sentry sends to an island address gets
//     the pin while the Sentry holds as.mu. A clone child, a restart, and the
//     retry of a fault do this.
//  6. A hot resume runs the tail of the slot of the trap, whether the slot is
//     Live or Quarantined. Rule 5 keeps the bytes until the thread traps or
//     parks again. The tail jumps to the code behind the patched bytes of the
//     site (islandSlot.resume). A later patch of the block keeps that address
//     valid while the slot is Live or Quarantined, because patchBlock gives the
//     address to the planner. The Sentry never turns a hot resume into a cold
//     one because the block dropped.
//  7. allocSlot fails when no island has room and the quarantine holds
//     winQuarantineLimit units or more. The site then keeps its trap. One drop
//     can push the quarantine past the limit.
//
// A thread that stops inside a slot reports a guest address that the Sentry
// converted (guestPC, svcSlotFault, rewindToSite) before it parked the thread,
// or it continues in place without a park. One case has no conversion. A fault
// in a relocated instruction of a post-window slot reports the address of the
// slot. A signal handler of the guest can then resume inside the slot. That
// case is outside the contract.

// winIslandReach is the largest distance between a patched instruction and the
// island that holds its slot. A B instruction reaches 128MiB on arm64. The
// margin covers the page size and the slot branch back.
const winIslandReach = islandReach

// An island page has the size of a block.
const (
	_ = uint(blockSize - winIslandBytes)
	_ = uint(winIslandBytes - blockSize)
)

// errSlotsQuarantined is the error of allocSlot when no island has room and the
// quarantine holds winQuarantineLimit units that a thread can still enter.
var errSlotsQuarantined = errors.New("the freed trampoline slots are still in use by threads")

// winSlotRef identifies a range of bytes that an execBlock occupies in an island.
type winSlotRef struct {
	isl  *island
	off  uint32
	size uint32
}

// island is one page of trampoline slots.
type island struct {
	base uint64
	page privPage
	slotArena
}

// retireSlotsLocked moves every slot in refs to the quarantine. The caller
// removed the executable page that holds the branches first. Callers hold as.mu.
func (as *addressSpace) retireSlotsLocked(refs []winSlotRef) {
	if len(refs) == 0 {
		return
	}
	at := as.epochs.retire()
	for _, r := range refs {
		r.isl.retire(r.off, r.size, at)
	}
}

// discardSlotRefsLocked frees every slot in refs at once. Use it only for slots
// whose branch never became visible to the stub. Callers hold as.mu.
func discardSlotRefsLocked(refs []winSlotRef) {
	for _, r := range refs {
		r.isl.discard(r.off, r.size)
	}
}

// pinSlotLocked makes reader hold the slot that contains pc, when there is one.
// The Sentry calls it before it starts a thread at an island address, while it
// still holds as.mu. A reclaim also holds as.mu, so it sees the pin. A nil
// reader means that the thread has no fast slot, and the call does nothing.
func (as *addressSpace) pinSlotLocked(reader *epochReader, pc uint64) {
	if reader == nil {
		return
	}
	isl := as.islands[blockRound(pc)]
	if isl == nil {
		return
	}
	if _, off, ok := isl.containing(uint32(pc - isl.base)); ok {
		reader.setPin(isl.base + uint64(off))
	}
}

// quarantineUnitsLocked returns the number of units that the quarantine holds.
// Callers hold as.mu.
func (as *addressSpace) quarantineUnitsLocked() int {
	n := 0
	for _, isl := range as.islands {
		n += isl.quarantineUnits
	}
	return n
}

// reclaimSlotsLocked frees the quarantined slots that no thread can still
// enter and returns the number of units that it freed. Callers hold as.mu.
func (as *addressSpace) reclaimSlotsLocked() int {
	if as.quarantineUnitsLocked() == 0 {
		return 0
	}
	snap := as.epochs.snapshot()
	freed := 0
	for _, isl := range as.islands {
		freed += isl.reclaim(isl.base, &snap)
	}
	return freed
}

// islandRange tells MapFile what to do with a mapping that touches an island.
// The memory manager populates the sealed mapping of an island when it maps the
// island, and the island keeps its own page. skip is true for such a mapping.
// A mapping that covers an island partly is an error.
func (as *addressSpace) islandRange(va, n uint64) (skip bool, err error) {
	as.mu.Lock()
	defer as.mu.Unlock()
	if len(as.reserved) == 0 && len(as.islands) == 0 {
		return false, nil
	}
	if _, pending := as.reserved[va]; pending && n == blockSize {
		return true, nil
	}
	for base := range as.islands {
		if base < va+n && va < base+blockSize {
			if va == base && n == blockSize {
				return true, nil
			}
			return false, fmt.Errorf("mapping [%#x, %#x) overlaps the trampoline island at %#x", va, va+n, base)
		}
	}
	return false, nil
}

// dropIslandsLocked forgets the islands in [start, end) and frees their pages.
// Callers hold mu.
func (as *addressSpace) dropIslandsLocked(start, end uint64) {
	for base, isl := range as.islands {
		if base < end && start < base+blockSize {
			delete(as.islands, base)
			as.p.priv.release(isl.page)
		}
	}
}

// releaseIslandsLocked frees every island. Callers hold mu.
func (as *addressSpace) releaseIslandsLocked() {
	for base, isl := range as.islands {
		as.p.priv.release(isl.page)
		delete(as.islands, base)
	}
}

// slotStart returns the slot that starts at pc. A Quarantined slot counts,
// because a thread can have entered it before the free.
func (as *addressSpace) slotStart(pc uint64) (islandSlot, bool) {
	as.mu.Lock()
	defer as.mu.Unlock()
	isl := as.islands[blockRound(pc)]
	if isl == nil {
		return islandSlot{}, false
	}
	return isl.lookup(uint32(pc - isl.base))
}

// slotContaining returns the slot that contains pc and the start address of
// the slot. A Quarantined slot counts.
func (as *addressSpace) slotContaining(pc uint64) (s islandSlot, slotVA uint64, ok bool) {
	as.mu.Lock()
	defer as.mu.Unlock()
	isl := as.islands[blockRound(pc)]
	if isl == nil {
		return islandSlot{}, 0, false
	}
	s, off, ok := isl.containing(uint32(pc - isl.base))
	if !ok {
		return islandSlot{}, 0, false
	}
	return s, isl.base + uint64(off), true
}

// slotAtTail returns the site of the slot whose tail is at tail. It decodes a
// trap. A thread that published the trap is online, or it holds the slot as its
// pin, so the slot is Live or Quarantined.
func (as *addressSpace) slotAtTail(tail uint64) (uint64, bool) {
	s, ok := as.slotStart(tail - winSlotTailOffset)
	return s.site, ok
}

// guestPageOK reports whether the page at va lies in a guest window.
func (as *addressSpace) guestPageOK(va uint64) bool {
	p := as.p
	if va < p.userMin || va+blockSize > p.userMax {
		return false
	}
	return p.layout.contains(va, blockSize)
}

// installSlot allocates a slot of rec.size bytes within reach of rec.site, lets
// encode write the slot code, records rec for the slot, and returns the address
// and reference of the slot. The page of the slot is the private page that the
// stub maps for execution, so the slot is live as soon as the call returns and
// the instruction cache of the stub is flushed. No branch names the slot yet,
// so a failure frees the slot at once.
func (as *addressSpace) installSlot(ctx context.Context, mm platform.MemoryManager, rec islandSlot, encode func(buf []byte, slotVA uint64) error) (uint64, winSlotRef, error) {
	site, size := rec.site, rec.size
	isl, off, err := as.allocSlot(ctx, mm, site, size)
	if err != nil {
		return 0, winSlotRef{}, err
	}
	ref := winSlotRef{isl: isl, off: off, size: size}
	slotVA := isl.base + uint64(off)
	if err := encode(isl.page.bytes()[off:off+size], slotVA); err != nil {
		as.mu.Lock()
		isl.discard(off, size)
		as.mu.Unlock()
		return 0, winSlotRef{}, err
	}
	as.mu.Lock()
	isl.record(off, rec)
	as.mu.Unlock()
	if err := flushInstructionCache(as.sp.proc, uintptr(slotVA), uintptr(size)); err != nil {
		as.mu.Lock()
		isl.discard(off, size)
		as.mu.Unlock()
		return 0, winSlotRef{}, err
	}
	return slotVA, ref, nil
}

// allocSlot returns space for a slot of size bytes within reach of site. It
// reclaims quarantined slots when no island has room, and it creates an island
// through the memory manager when that is not enough. It fails with
// errSlotsQuarantined when the quarantine is full.
func (as *addressSpace) allocSlot(ctx context.Context, mm platform.MemoryManager, site uint64, size uint32) (*island, uint32, error) {
	for range 3 {
		as.mu.Lock()
		isl, off, ok := as.allocNearLocked(site, size)
		if !ok && as.reclaimSlotsLocked() > 0 {
			isl, off, ok = as.allocNearLocked(site, size)
		}
		full := as.quarantineUnitsLocked() >= winQuarantineLimit
		as.mu.Unlock()
		if ok {
			return isl, off, nil
		}
		if full {
			return nil, 0, errSlotsQuarantined
		}
		if err := as.newIsland(ctx, mm, site); err != nil {
			return nil, 0, err
		}
	}
	return nil, 0, errors.New("no trampoline island has room")
}

// allocNearLocked allocates size bytes in an island within reach of site.
// Callers hold as.mu.
func (as *addressSpace) allocNearLocked(site uint64, size uint32) (*island, uint32, bool) {
	for _, isl := range as.islands {
		if absDiff(isl.base, site) < winIslandReach {
			if off, ok := isl.alloc(size); ok {
				return isl, off, true
			}
		}
	}
	return nil, 0, false
}

// newIsland reserves a sealed mapping within reach of near through the memory
// manager and maps a private page of slots there.
func (as *addressSpace) newIsland(ctx context.Context, mm platform.MemoryManager, near uint64) error {
	return as.newIslandAt(ctx, mm, near, func(cand uint64) (uint64, bool) {
		return cand, as.guestPageOK(cand)
	})
}

// installIsland maps a zeroed private page as read and execute at base.
func (as *addressSpace) installIsland(base uint64) error {
	pg, err := as.p.priv.alloc()
	if err != nil {
		as.dropReservation(base)
		return err
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	delete(as.reserved, base)
	if as.released {
		as.p.priv.release(pg)
		return errAddressSpaceReleased
	}
	if err := as.win.Map(base, blockSize, &pg.chunk.ref, pg.off, viewReadExec); err != nil {
		as.p.priv.release(pg)
		return as.mapErr(err)
	}
	as.islands[base] = &island{base: base, page: pg}
	return flushInstructionCache(as.sp.proc, uintptr(base), blockSize)
}
