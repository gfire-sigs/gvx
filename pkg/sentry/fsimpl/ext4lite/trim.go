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

package ext4lite

import (
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/usermem"
)

const (
	// onlinePunchMinBlocks is the minimum contiguous free run (64 KiB = 16
	// blocks) that automatic post-flush reclaim punches immediately.
	onlinePunchMinBlocks = 16

	// ioctlFITRIM is Linux _IOWR('X', 121, struct fstrim_range).
	ioctlFITRIM    = 0xC0185879
	fstrimRangeLen = 24
)

func (v *volume) hasPendingHomeWrites() bool {
	t, ok := v.hf.(*trackedFile)
	if !ok {
		return false
	}
	t.pmu.Lock()
	n := len(t.pending)
	t.pmu.Unlock()
	return n > 0
}

// reclaimAfterFlushLocked punches newly released contiguous free runs after a
// flush commits to JBD2 and writes home metadata. The caller holds flushMu.
func (v *volume) reclaimAfterFlushLocked() {
	if v.readOnly || isPunchDisabled(v.hf) || v.hasPendingHomeWrites() {
		return
	}
	v.mu.Lock()
	var groups []uint32
	for gi, g := range v.groups {
		if g.reclaimPending != nil {
			groups = append(groups, uint32(gi))
		}
	}
	v.mu.Unlock()

	for _, gi := range groups {
		v.reclaimGroupPendingLocked(gi)
	}
}

func (v *volume) reclaimGroupPendingLocked(gi uint32) {
	v.mu.Lock()
	if gi >= uint32(len(v.groups)) {
		v.mu.Unlock()
		return
	}
	g := v.groups[gi]
	if g.reclaimPending == nil {
		v.mu.Unlock()
		return
	}
	pending := *g.reclaimPending
	g.reclaimPending = nil

	type freeSpan struct{ r0, r1 uint32 }
	var spans []freeSpan
	mask := g.allocMask()
	for off := metaBlocksOf(gi); off < blocksPerGroup; {
		off = g.blocks.firstFree(off, mask)
		if off >= blocksPerGroup {
			break
		}
		n := g.blocks.freeRun(off, blocksPerGroup-off, mask)
		if n >= onlinePunchMinBlocks && pending.anySet(off, n) && !allMarkedPunched(g.punched, off, n) {
			spans = append(spans, freeSpan{r0: off, r1: off + n})
		}
		off += max(n, 1)
	}
	v.mu.Unlock()

	for _, sp := range spans {
		_, _ = v.execPunchRunLocked(gi, sp.r0, sp.r1, false, true)
	}
}

func allMarkedPunched(p *bitmap, off, n uint32) bool {
	if p == nil {
		return false
	}
	for i := off; i < off+n; i++ {
		if !p.test(i) {
			return false
		}
	}
	return true
}

// punchAllFreeBestEffortLocked punches all unpunched free unheld runs of at
// least minBlocks across every block group. The caller holds flushMu.
func (v *volume) punchAllFreeBestEffortLocked(minBlocks uint32) {
	if v.readOnly || isPunchDisabled(v.hf) || v.hasPendingHomeWrites() {
		return
	}
	v.mu.Lock()
	totalBlocks := v.blocksCountLocked()
	v.mu.Unlock()
	_, _ = v.punchFreeRangeLocked(0, totalBlocks, max(minBlocks, 1), false, true)
}

// punchFreeRangeLocked scans free unheld runs inside [firstBlk, endBlk) of at
// least minBlocks and punches them on the host file. When skipAlreadyPunched is
// false (explicit FITRIM), already-punched runs are also included in the trim
// pass and returned byte count. The caller holds flushMu.
func (v *volume) punchFreeRangeLocked(firstBlk, endBlk uint64, minBlocks uint32, strict, skipAlreadyPunched bool) (uint64, error) {
	if firstBlk >= endBlk {
		return 0, nil
	}
	startGroup := uint32(firstBlk / blocksPerGroup)
	endGroup := uint32((endBlk - 1) / blocksPerGroup)
	var trimmed uint64

	for gi := startGroup; gi <= endGroup; gi++ {
		v.mu.Lock()
		if gi >= uint32(len(v.groups)) {
			v.mu.Unlock()
			break
		}
		g := v.groups[gi]
		if skipAlreadyPunched {
			g.reclaimPending = nil
		}
		gStart := groupStart(gi)
		loOff := metaBlocksOf(gi)
		if firstBlk > gStart+uint64(loOff) {
			loOff = uint32(firstBlk - gStart)
		}
		hiOff := uint32(blocksPerGroup)
		if endBlk < gStart+blocksPerGroup {
			hiOff = uint32(endBlk - gStart)
		}

		type freeSpan struct{ r0, r1 uint32 }
		var spans []freeSpan
		mask := g.allocMask()
		for off := loOff; off < hiOff; {
			off = g.blocks.firstFree(off, mask)
			if off >= hiOff {
				break
			}
			n := g.blocks.freeRun(off, hiOff-off, mask)
			if n >= minBlocks && (!skipAlreadyPunched || !allMarkedPunched(g.punched, off, n)) {
				spans = append(spans, freeSpan{r0: off, r1: off + n})
			}
			off += max(n, 1)
		}
		v.mu.Unlock()

		for _, sp := range spans {
			got, err := v.execPunchRunLocked(gi, sp.r0, sp.r1, strict, skipAlreadyPunched)
			if err != nil {
				return trimmed, err
			}
			trimmed += got
		}
	}
	return trimmed, nil
}

// execPunchRunLocked pins the host-page-aligned subrange of [r0, r1) in group
// gi inside g.punching, runs hostFile.PunchHole outside v.mu, and records the
// punched blocks in g.punched. The caller holds flushMu.
func (v *volume) execPunchRunLocked(gi, r0, r1 uint32, strict, skipIfAllPunched bool) (uint64, error) {
	if isPunchDisabled(v.hf) {
		return 0, nil
	}
	gran := punchGranularityOf(v.hf)
	byteStart := int64(groupStart(gi)+uint64(r0)) * blockSize
	byteEnd := int64(groupStart(gi)+uint64(r1)) * blockSize
	lo := (byteStart + gran - 1) / gran * gran
	hi := byteEnd / gran * gran
	if lo >= hi {
		return 0, nil
	}
	p0 := uint32(uint64(lo/blockSize) - groupStart(gi))
	p1 := uint32(uint64(hi/blockSize) - groupStart(gi))
	pCount := p1 - p0

	v.mu.Lock()
	if gi >= uint32(len(v.groups)) {
		v.mu.Unlock()
		return 0, nil
	}
	g := v.groups[gi]
	if skipIfAllPunched && allMarkedPunched(g.punched, p0, pCount) {
		v.mu.Unlock()
		return 0, nil
	}
	for i := p0; i < p1; i++ {
		if g.blocks.test(i) || g.isBlocked(i) {
			v.mu.Unlock()
			return 0, nil
		}
	}
	lazyBitmap(&g.punching).setRange(p0, pCount)
	g.punchingCount += pCount
	v.punchingTotal += uint64(pCount)
	v.mu.Unlock()

	err := v.hf.PunchHole(lo, hi-lo)

	v.mu.Lock()
	g.punching.clearRange(p0, pCount)
	g.punchingCount -= pCount
	v.punchingTotal -= uint64(pCount)
	if g.punchingCount == 0 {
		g.punching = nil
	}
	punchedOK := err == nil && !isPunchDisabled(v.hf)
	if punchedOK {
		lazyBitmap(&g.punched).setRange(p0, pCount)
	}
	if v.punchCond != nil {
		v.punchCond.Broadcast()
	}
	v.mu.Unlock()

	if err != nil && strict {
		return 0, hostError(err)
	}
	if !punchedOK {
		return 0, nil
	}
	return uint64(hi - lo), nil
}

// Trim discards free unheld blocks in [start, start+length) whose contiguous
// runs are at least minlen bytes long, returning the discarded byte count.
func (vol *Volume) Trim(start, length, minlen uint64) (uint64, error) {
	v := vol.v
	if v.readOnly {
		return 0, linuxerr.EROFS
	}
	if v.isClosed() {
		return 0, errVolumeClosed
	}
	if length < blockSize || minlen > groupBytes {
		return 0, linuxerr.EINVAL
	}
	if h := vol.dataSync.Load(); h != nil {
		if err := h.fn(); err != nil {
			return 0, err
		}
	}

	v.flushMu.Lock()
	defer v.flushMu.Unlock()

	v.mu.Lock()
	if v.closed {
		v.mu.Unlock()
		return 0, errVolumeClosed
	}
	totalBytes := v.blocksCountLocked() * blockSize
	v.mu.Unlock()

	if start >= totalBytes {
		return 0, linuxerr.EINVAL
	}
	if err := v.flushLocked(); err != nil {
		return 0, err
	}

	v.mu.Lock()
	totalBytes = v.blocksCountLocked() * blockSize
	v.mu.Unlock()
	if start >= totalBytes {
		return 0, linuxerr.EINVAL
	}

	endByte := totalBytes
	if rem := totalBytes - start; length < rem {
		endByte = start + length
	}
	firstBlk := start / blockSize
	endBlk := endByte / blockSize
	if firstBlk >= endBlk {
		return 0, nil
	}
	minBlocks := uint32(1)
	if minlen > blockSize {
		minBlocks = uint32((minlen + blockSize - 1) / blockSize)
	}
	return v.punchFreeRangeLocked(firstBlk, endBlk, minBlocks, true, false)
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl for regular files and
// directories, handling FITRIM and delegating all other commands.
func (fd *fileDescription) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	if uint32(args[1].Uint()) != ioctlFITRIM {
		return fd.FileDescriptionDefaultImpl.Ioctl(ctx, uio, sysno, args)
	}
	creds := auth.CredentialsFromContext(ctx)
	if creds == nil || !creds.HasRootCapability(linux.CAP_SYS_ADMIN) {
		return 0, linuxerr.EPERM
	}
	d := fd.dentry
	if d.fs.readOnly {
		return 0, linuxerr.EROFS
	}
	mnt := fd.vfsfd.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return 0, err
	}
	defer mnt.EndWrite()

	addr := args[2].Pointer()
	if addr == 0 {
		return 0, linuxerr.EFAULT
	}
	var raw [fstrimRangeLen]byte
	if _, err := uio.CopyIn(ctx, addr, raw[:], usermem.IOOpts{}); err != nil {
		return 0, err
	}
	start := le.Uint64(raw[0:8])
	length := le.Uint64(raw[8:16])
	minlen := le.Uint64(raw[16:24])

	trimmed, err := d.fs.vol.Trim(start, length, minlen)
	if err != nil {
		return 0, toLinuxErr(err)
	}
	le.PutUint64(raw[8:16], trimmed)
	if _, err := uio.CopyOut(ctx, addr, raw[:], usermem.IOOpts{}); err != nil {
		return 0, err
	}
	return 0, nil
}
