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

package chunkcache

import (
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

// noterMemory is chunk memory that reports Sentry writes.
type noterMemory struct {
	memmap.File
	buf   []byte
	notes []memmap.FileRange
}

func (m *noterMemory) AllocateChunk(length uint64) (memmap.FileRange, error) {
	m.buf = make([]byte, length)
	return memmap.FileRange{Start: 0x40000, End: 0x40000 + length}, nil
}

func (m *noterMemory) MapInternal(memmap.FileRange, hostarch.AccessType) (safemem.BlockSeq, error) {
	return safemem.BlockSeqOf(safemem.BlockFromSafeSlice(m.buf)), nil
}

func (m *noterMemory) DecRef(memmap.FileRange)          {}
func (m *noterMemory) NoteHostWrite(r memmap.FileRange) { m.notes = append(m.notes, r) }

func TestChunkWritesReachTheMemoryFile(t *testing.T) {
	mem := &noterMemory{}
	ch, err := NewChunk(mem)
	if err != nil {
		t.Fatalf("NewChunk: %v", err)
	}
	c := &Cache{Chunks: map[uint64]*Chunk{0: ch}}
	base := ch.FR.Start

	c.CopyThroughLocked(100, []byte{1, 2, 3})
	c.ZeroLocked(200, 300)
	dropped := c.ShrinkLocked(ChunkSize - 16)
	if len(dropped) != 0 {
		t.Fatalf("ShrinkLocked dropped %d chunks, want 0", len(dropped))
	}
	want := []memmap.FileRange{
		{Start: base + 100, End: base + 103},
		{Start: base + 200, End: base + 300},
		{Start: base + ChunkSize - 16, End: base + ChunkSize},
	}
	if len(mem.notes) != len(want) {
		t.Fatalf("reported writes = %v, want %v", mem.notes, want)
	}
	for i := range want {
		if mem.notes[i] != want[i] {
			t.Errorf("report %d = %v, want %v", i, mem.notes[i], want[i])
		}
	}
	ch.NoteWrite(5, 5)
	if len(mem.notes) != len(want) {
		t.Errorf("an empty write was reported")
	}
}
