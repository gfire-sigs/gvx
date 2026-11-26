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

//go:build windows || linux

package mm

import (
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
)

// hostWriteNoter is a memory file that reports Sentry writes. The file of a pma
// can wrap a pgalloc.MemoryFile, as the chunk memory of hostfs and ext4lite
// does, so the check names the method and not the type.
type hostWriteNoter interface {
	NoteHostWrite(fr memmap.FileRange)
}

// mapInternalOf returns the internal mapping of fr in file. It does not report
// a write for a pma that is only mapped, because the memory manager reports
// each write after it completes.
func mapInternalOf(file memmap.File, fr memmap.FileRange, perms hostarch.AccessType) (safemem.BlockSeq, error) {
	if u, ok := file.(interface {
		MapInternalUnreported(memmap.FileRange, hostarch.AccessType) (safemem.BlockSeq, error)
	}); ok {
		return u.MapInternalUnreported(fr, perms)
	}
	return file.MapInternal(fr, perms)
}

// The Windows systrap engine and Linux 16 KiB sub-block layer run guest code
// from copies of memory-file pages, so they cannot see a Sentry write made
// through an internal mapping. The helpers below run directly inside
// withInternalMappings and withVecInternalMappings after each write completes
// while mm.activeMu is held for reading. Avoiding a wrapper closure keeps the
// callback argument of withInternalMappings non-escaping, which generated
// gohacks.Noescape callers require for stack-growth safety.

// noteHostWrite reports ar to the memory file of every overlapping pma while at
// least one host-write observer is registered.
//
// Preconditions: mm.activeMu is locked for reading or writing.
//
// +checklocksread:mm.activeMu
func (mm *MemoryManager) noteHostWrite(ar hostarch.AddrRange) {
	if !pgalloc.HostWritesObserved() {
		return
	}
	mm.noteHostWriteLocked(ar)
}

// noteHostWriteVec is noteHostWrite for a sequence of ranges.
//
// Preconditions: mm.activeMu is locked for reading or writing.
//
// +checklocksread:mm.activeMu
func (mm *MemoryManager) noteHostWriteVec(ars hostarch.AddrRangeSeq) {
	if !pgalloc.HostWritesObserved() {
		return
	}
	for rest := ars; !rest.IsEmpty(); rest = rest.Tail() {
		if ar := rest.Head(); ar.Length() != 0 {
			mm.noteHostWriteLocked(ar)
		}
	}
}

// noteHostWriteLocked reports ar to the memory file of every pma that overlaps
// it.
//
// Preconditions: mm.activeMu is locked for reading or writing.
//
// +checklocksread:mm.activeMu
func (mm *MemoryManager) noteHostWriteLocked(ar hostarch.AddrRange) {
	for pseg := mm.pmas.LowerBoundSegment(ar.Start); pseg.Ok() && pseg.Start() < ar.End; pseg = pseg.NextSegment() {
		if n, ok := pseg.ValuePtr().file.(hostWriteNoter); ok {
			n.NoteHostWrite(pseg.fileRangeOf(pseg.Range().Intersect(ar)))
		}
	}
}
