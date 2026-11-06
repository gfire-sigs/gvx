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

import "testing"

// TestSlotAtTailDecodesAFreedSlotUntilReuse covers a trap that a thread
// publishes from a slot just before another thread drops the block of the
// slot. The Sentry must still find the site of that slot, until a new slot
// reuses its bytes.
func TestSlotAtTailDecodesAFreedSlotUntilReuse(t *testing.T) {
	const base = 0x47b0000
	isl := &island{base: base, slots: make(map[uint32]islandSlot)}
	as := &addressSpace{islands: map[uint64]*island{base: isl}}

	off, ok := isl.alloc(winSlotSize)
	if !ok {
		t.Fatal("alloc of the first slot failed")
	}
	const site = 0x1234560
	isl.slots[off] = islandSlot{site: site, size: winSlotSize, jmpVA: site}
	tail := base + uint64(off) + winSlotTailOffset

	if got, ok := as.liveSlotAtTail(tail); !ok || got != site {
		t.Fatalf("liveSlotAtTail before free = (%#x, %v), want (%#x, true)", got, ok, uint64(site))
	}

	isl.free(off, winSlotSize)
	if got, ok := as.slotAtTail(tail); !ok || got != site {
		t.Fatalf("slotAtTail after free = (%#x, %v), want (%#x, true)", got, ok, uint64(site))
	}
	// A hot resume runs the tail again, and a new slot can overwrite the bytes
	// of the freed slot at any time, so the resume must go cold.
	if got, ok := as.liveSlotAtTail(tail); ok {
		t.Fatalf("liveSlotAtTail after free = (%#x, true), want no live slot", got)
	}

	reuse, ok := isl.alloc(winSlotSize)
	if !ok || reuse != off {
		t.Fatalf("alloc after free = (%#x, %v), want (%#x, true)", reuse, ok, off)
	}
	if got, ok := as.slotAtTail(tail); ok {
		t.Fatalf("slotAtTail after reuse = (%#x, true), want no slot until the new slot is recorded", got)
	}
}
