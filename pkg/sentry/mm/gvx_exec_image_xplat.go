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

package mm

import (
	"errors"
	"io"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

var (
	_ platform.ExecImageProvider = (*MemoryManager)(nil)
	_ platform.SubBlockPopulator = (*MemoryManager)(nil)
)

// ExecImageAt implements platform.ExecImageProvider.ExecImageAt.
//
// +checklocksexclude:mm.mappingMu
func (mm *MemoryManager) ExecImageAt(ctx context.Context, addr hostarch.Addr) platform.ExecImage {
	mm.mappingMu.RLock()
	vseg := mm.vmas.FindSegment(addr)
	if !vseg.Ok() {
		mm.mappingMu.RUnlock()
		return platform.ExecImage{Kind: platform.MappingUnmapped}
	}
	vma := vseg.ValuePtr()
	if vma.mappable == nil {
		mm.mappingMu.RUnlock()
		return platform.ExecImage{Kind: platform.MappingAnonymous}
	}
	fd, ok := vma.id.(*vfs.FileDescription)
	if !ok {
		mm.mappingMu.RUnlock()
		return platform.ExecImage{Kind: platform.MappingSpecial}
	}
	// The reference keeps the description alive after the lock goes away.
	fd.IncRef()
	offset := vma.off + uint64(addr-vseg.Start())
	mm.mappingMu.RUnlock()
	return platform.ExecImage{
		Kind:    platform.MappingFile,
		Device:  fd.DeviceID(),
		Inode:   fd.InodeID(),
		Offset:  offset,
		File:    &fileReaderAt{ctx: ctx, fd: fd},
		Release: func() { fd.DecRef(ctx) },
	}
}

// HasMappingIn reports whether any virtual memory area overlaps ar.
//
// +checklocksexclude:mm.mappingMu
func (mm *MemoryManager) HasMappingIn(ar hostarch.AddrRange) bool {
	mm.mappingMu.RLock()
	defer mm.mappingMu.RUnlock()
	seg := mm.vmas.LowerBoundSegment(ar.Start)
	return seg.Ok() && seg.Start() < ar.End
}

// PopulateSubBlock implements platform.SubBlockPopulator.PopulateSubBlock.
//
// +checklocksexclude:mm.mappingMu
// +checklocksexclude:mm.activeMu
func (mm *MemoryManager) PopulateSubBlock(ctx context.Context, addr hostarch.Addr) bool {
	addr = hostarch.UntaggedUserAddr(addr)
	ar, ok := addr.RoundDown().ToRange(uint64(hostarch.PageSize))
	if !ok {
		return false
	}
	mm.mappingMu.RLock()
	vseg := mm.vmas.FindSegment(ar.Start)
	if !vseg.Ok() {
		mm.mappingMu.RUnlock()
		return false
	}
	vma := vseg.ValuePtr()
	if !vma.effectivePerms.Read && !vma.effectivePerms.Execute {
		mm.mappingMu.RUnlock()
		return false
	}
	at := hostarch.Read
	if !vma.effectivePerms.Read {
		at = hostarch.Execute
	} else if vma.mappable != nil && vma.private && vma.effectivePerms.Write && !vma.effectivePerms.Execute {
		at = vma.effectivePerms
	}
	mm.activeMu.Lock()
	pseg, _, err := mm.getPMAsLocked(ctx, vseg, ar, at, false /* callerIndirectCommit */, false /* forPin */)
	if err != nil {
		mm.activeMu.Unlock()
		mm.mappingMu.RUnlock()
		return false
	}
	const hostBlockSize = 0x4000
	blockStart := ar.Start &^ hostarch.Addr(hostBlockSize-1)
	blockAR := hostarch.AddrRange{Start: blockStart, End: blockStart + hostBlockSize}
	oldFRs, coalesced := mm.coalescePrivateBlockLocked(ctx, blockAR)
	mm.mappingMu.RUnlock()
	mm.activeMu.DowngradeLock()
	if coalesced {
		err = mm.mapASLocked(ctx, mm.pmas.LowerBoundSegment(blockAR.Start), blockAR, memmap.PlatformEffectPopulate)
	} else {
		err = mm.mapASLocked(ctx, pseg, ar, memmap.PlatformEffectPopulate)
	}
	mm.activeMu.RUnlock()
	for _, oldFR := range oldFRs {
		mm.mf.DecRef(oldFR)
	}
	return err == nil
}

// coalescePrivateBlockLocked moves the pages of a 16KB host block into a single
// 16KB-aligned MemoryFile range so the platform can map the block directly.
// Each page of the block must be backed by a private non-CoW writable
// MemoryFile PMA.
//
// A page of the block can also have no virtual memory area, when the address
// space implements platform.HostBlockOwner. The page of the new range for it
// is a spare page, and the address space receives its reference.
//
// +checklocksread:mm.mappingMu
// +checklocks:mm.activeMu
func (mm *MemoryManager) coalescePrivateBlockLocked(ctx context.Context, blockAR hostarch.AddrRange) ([]memmap.FileRange, bool) {
	const hostBlockSize = 0x4000
	owner, canOwn := mm.as.(platform.HostBlockOwner)
	// present has a bit for each page that a PMA backs.
	var present uint8
	alreadyAligned := true
	var firstOff uint64
	for seg := mm.pmas.LowerBoundSegment(blockAR.Start); seg.Ok() && seg.Start() < blockAR.End; seg = seg.NextSegment() {
		pma := seg.ValuePtr()
		if pma.file != mm.mf || !pma.private || pma.needCOW || !pma.effectivePerms.Read || !pma.effectivePerms.Write || pma.effectivePerms.Execute {
			return nil, false
		}
		sub := seg.Range().Intersect(blockAR)
		for p := sub.Start; p < sub.End; p += hostarch.PageSize {
			i := uint64(p-blockAR.Start) / hostarch.PageSize
			off := pma.off + uint64(p-seg.Start())
			if present == 0 {
				firstOff = off - i*hostarch.PageSize
				alreadyAligned = off >= i*hostarch.PageSize && firstOff%hostBlockSize == 0
			} else if off != firstOff+i*hostarch.PageSize {
				alreadyAligned = false
			}
			present |= 1 << i
		}
		if _, err := seg.getInternalMappingsLocked(sub); err != nil {
			return nil, false
		}
	}
	const allPages = 1<<(hostBlockSize/hostarch.PageSize) - 1
	if present == 0 {
		return nil, false
	}
	spare := allPages &^ present
	if spare != 0 {
		// A spare page must not hide a page that the guest can map later
		// without a new virtual memory area or an mprotect. So a page without
		// a PMA must have no area, or an area without access, such as the
		// guard page of musl malloc. ReleaseHostBlocks covers both changes.
		if !canOwn {
			return nil, false
		}
		for i := uint64(0); i < hostBlockSize/hostarch.PageSize; i++ {
			if spare&(1<<i) == 0 {
				continue
			}
			if vseg := mm.vmas.FindSegment(blockAR.Start + hostarch.Addr(i*hostarch.PageSize)); vseg.Ok() && vseg.ValuePtr().effectivePerms.Any() {
				return nil, false
			}
		}
	}
	if alreadyAligned && spare == 0 {
		return nil, true
	}
	fr, err := mm.mf.AllocateAligned(hostBlockSize, hostBlockSize, pgalloc.AllocOpts{
		Kind:    usage.Anonymous,
		MemCgID: pgalloc.MemoryCgroupIDFromContext(ctx),
		Mode:    pgalloc.AllocateAndWritePopulate,
	})
	if err != nil {
		return nil, false
	}
	dsts, err := mm.mf.MapInternal(fr, hostarch.Write)
	if err != nil {
		mm.mf.DecRef(fr)
		return nil, false
	}
	// Another thread can store into the old pages through the platform
	// until it unmaps them, so the copy comes after the unmap. A failed copy
	// leaves the old pages, and the next fault maps them again.
	mm.unmapASLocked(blockAR)
	for seg := mm.pmas.LowerBoundSegment(blockAR.Start); seg.Ok() && seg.Start() < blockAR.End; seg = seg.NextSegment() {
		subAR := seg.Range().Intersect(blockAR)
		srcs, err := mm.internalMappingsLocked(seg, subAR)
		if err != nil {
			mm.mf.DecRef(fr)
			return nil, false
		}
		subDsts := dsts.DropFirst64(uint64(subAR.Start - blockAR.Start)).TakeFirst64(uint64(subAR.Length()))
		if _, err := safemem.CopySeq(subDsts, srcs); err != nil {
			mm.mf.DecRef(fr)
			return nil, false
		}
	}
	if spare != 0 {
		owner.AdoptHostBlock(blockAR.Start, mm.mf, fr, spare)
	}
	var oldFRs []memmap.FileRange
	for seg := mm.pmas.LowerBoundSegment(blockAR.Start); seg.Ok() && seg.Start() < blockAR.End; seg = seg.NextSegment() {
		seg = mm.pmas.Isolate(seg, blockAR)
		oldFRs = append(oldFRs, seg.fileRange())
		pma := seg.ValuePtr()
		pma.off = fr.Start + uint64(seg.Start()-blockAR.Start)
		pma.internalMappings = safemem.BlockSeq{}
		if prev := seg.PrevSegment(); prev.Ok() {
			if merged := mm.pmas.Merge(prev, seg); merged.Ok() {
				seg = merged
			}
		}
		if seg.End() == blockAR.End {
			if next := seg.NextSegment(); next.Ok() {
				if merged := mm.pmas.Merge(seg, next); merged.Ok() {
					seg = merged
				}
			}
			break
		}
	}
	return oldFRs, true
}

// fileReaderAt reads a file description at absolute offsets.
type fileReaderAt struct {
	ctx context.Context
	fd  *vfs.FileDescription
}

// ReadAt implements io.ReaderAt.
func (r *fileReaderAt) ReadAt(p []byte, off int64) (int, error) {
	total := 0
	for total < len(p) {
		n, err := r.fd.PRead(r.ctx, usermem.BytesIOSequence(p[total:]), off+int64(total), vfs.ReadOptions{})
		total += int(n)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, io.EOF
			}
			return total, err
		}
		if n == 0 {
			return total, io.EOF
		}
	}
	return total, nil
}
