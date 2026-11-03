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

package mm

import (
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
)

// The Windows systrap engine runs guest code from patched copies of memory-file
// pages, and it cannot see a write that the Sentry makes through an internal
// mapping. The wrappers below tell the memory file about each such write after
// it completes, so that the engine drops the copies of the written frames.
// The calls run inside withInternalMappings, where activeMu is held for
// reading and the pmas cannot change.

// hostWriteWrap returns f, or a function that calls f and then reports the
// write to ar. It returns f while no memory file has an observer.
func (mm *MemoryManager) hostWriteWrap(ar hostarch.AddrRange, f func(safemem.BlockSeq) (uint64, error)) func(safemem.BlockSeq) (uint64, error) {
	if !pgalloc.HostWritesObserved() {
		return f
	}
	return func(bs safemem.BlockSeq) (uint64, error) {
		n, err := f(bs)
		mm.noteHostWrite(ar)
		return n, err
	}
}

// hostWriteWrapVec is hostWriteWrap for a sequence of ranges.
func (mm *MemoryManager) hostWriteWrapVec(ars hostarch.AddrRangeSeq, f func(safemem.BlockSeq) (uint64, error)) func(safemem.BlockSeq) (uint64, error) {
	if !pgalloc.HostWritesObserved() {
		return f
	}
	return func(bs safemem.BlockSeq) (uint64, error) {
		n, err := f(bs)
		for rest := ars; !rest.IsEmpty(); rest = rest.Tail() {
			if ar := rest.Head(); ar.Length() != 0 {
				mm.noteHostWrite(ar)
			}
		}
		return n, err
	}
}

// noteHostWrite reports ar to the memory file of every pma that overlaps it.
//
// Preconditions: mm.activeMu is locked.
func (mm *MemoryManager) noteHostWrite(ar hostarch.AddrRange) {
	for pseg := mm.pmas.LowerBoundSegment(ar.Start); pseg.Ok() && pseg.Start() < ar.End; pseg = pseg.NextSegment() {
		if mf, ok := pseg.ValuePtr().file.(*pgalloc.MemoryFile); ok {
			mf.NoteHostWrite(pseg.fileRangeOf(pseg.Range().Intersect(ar)))
		}
	}
}
