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
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

const testFITRIMIoctl = 0xC0185879

func invokeFITRIM(ctx *env, fd *vfs.FileDescription, start, length, minlen uint64) (uint64, error) {
	buf := make([]byte, 64)
	const addr = 16
	binary.LittleEndian.PutUint64(buf[addr+0:addr+8], start)
	binary.LittleEndian.PutUint64(buf[addr+8:addr+16], length)
	binary.LittleEndian.PutUint64(buf[addr+16:addr+24], minlen)
	bio := &usermem.BytesIO{Bytes: buf}
	_, err := fd.Ioctl(ctx.ctx, bio, 0, arch.SyscallArguments{
		{Value: 0},
		{Value: testFITRIMIoctl},
		{Value: addr},
	})
	if err != nil {
		return 0, err
	}
	if gotStart := binary.LittleEndian.Uint64(buf[addr+0 : addr+8]); gotStart != start {
		ctx.t.Fatalf("FITRIM mutated start from %d to %d", start, gotStart)
	}
	if gotMin := binary.LittleEndian.Uint64(buf[addr+16 : addr+24]); gotMin != minlen {
		ctx.t.Fatalf("FITRIM mutated minlen from %d to %d", minlen, gotMin)
	}
	return binary.LittleEndian.Uint64(buf[addr+8 : addr+16]), nil
}

// TestOnlineHolePunchReclaimsInteriorGroupsWithPinnedHighInode verifies:
//   - Property: Deleting interior file extents across multiple block groups while
//     a 1-byte sentinel inode remains pinned in group >= 4 reclaims physical host
//     blocks online (both via background flusher ticks and via FITRIM) and across
//     clean unmount, even though st_size stays pinned at >= 5 * 16 MiB.
//   - Seam: VFS2 OpenAt/PWrite/UnlinkAt/Sync/Ioctl(FITRIM)/Release + host Stat.
//   - Oracle: Independent byte-pattern payloads and OS stat block accounting.
//   - Distinct fault: Compaction that relies solely on trailing-group ftruncate
//     leaves 64+ MiB of deleted interior blocks permanently allocated on disk.
func TestOnlineHolePunchReclaimsInteriorGroupsWithPinnedHighInode(t *testing.T) {
	if platformTier == tierFallback {
		t.Skip("this operating system has no native hole-punch tier")
	}

	// Enable a fast background flusher so we also prove automatic online reclaim
	// on flusher ticks without explicit Sync or FITRIM.
	oldInterval := flushIntervalNanos.Swap(int64(25 * time.Millisecond))
	defer flushIntervalNanos.Store(oldInterval)
	flushedCh := make(chan struct{}, 16)
	hook := func() {
		select {
		case flushedCh <- struct{}{}:
		default:
		}
	}
	flushHook.Store(&hook)
	defer flushHook.Store(nil)

	path := filepath.Join(t.TempDir(), "pinned.ext4")
	e := openEnv(t, path, VolumeOptions{}, vfs.MountOptions{})

	// 1. Write 64 MiB of real non-zero data across 4 files (spanning groups 0..4).
	chunk := pattern(0x41, 1<<20)
	for fidx := range 4 {
		name := fmt.Sprintf("/bulk-%d", fidx)
		fd := e.mustOpen(name, linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY)
		for m := range 16 {
			if n, err := fd.PWrite(e.ctx, usermem.BytesIOSequence(chunk), int64(m)<<20, vfs.WriteOptions{}); err != nil || n != int64(len(chunk)) {
				t.Fatalf("PWrite(%s, %d MiB) = (%d, %v)", name, m, n, err)
			}
		}
		fd.DecRef(e.ctx)
	}

	// 2. Exhaust inodes in groups 0..3 so the 1-byte "/pin" file gets an inode
	// in group 4 (ino > 4*4096 = 16384), pinning groups 0..4 permanently.
	const tempDirs = 8
	const perDir = 2060 // 8 * 2060 = 16,480 > 4 * 4096
	for d := range tempDirs {
		dirPath := fmt.Sprintf("/fill-%d", d)
		if err := e.vfsObj.MkdirAt(e.ctx, e.creds, e.pop(dirPath), &vfs.MkdirOptions{Mode: 0o755}); err != nil {
			t.Fatalf("MkdirAt(%s): %v", dirPath, err)
		}
		for i := range perDir {
			p := fmt.Sprintf("%s/f-%d", dirPath, i)
			fd := e.mustOpen(p, linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY)
			fd.DecRef(e.ctx)
		}
	}
	e.writeFile("/pin", []byte("P"))
	pinStat := e.mustStat("/pin")
	if pinStat.Ino <= 4*inodesPerGroup {
		t.Fatalf("/pin allocated ino=%d, want > %d (group 4+)", pinStat.Ino, 4*inodesPerGroup)
	}
	e.writeFile("/survivor", pattern(0x7B, 128<<10))
	if err := e.fs.Sync(e.ctx); err != nil {
		t.Fatalf("Sync after populate: %v", err)
	}

	allocPeak, sizePeak, ok := hostAllocatedBytes(t, path)
	if !ok {
		t.Skip("hostAllocatedBytes unsupported on this platform")
	}
	if sizePeak < 5*groupBytes {
		t.Fatalf("host logical size = %d, want >= %d (5 groups)", sizePeak, 5*groupBytes)
	}
	if allocPeak < 64<<20 {
		t.Fatalf("peak allocated bytes = %d, want >= 64 MiB before delete", allocPeak)
	}

	// 3. Delete all 64 MiB bulk files and the temporary inode-filler files while
	// keeping "/pin" (in group 4+) and "/survivor" alive and mounted online.
	for d := range tempDirs {
		dirPath := fmt.Sprintf("/fill-%d", d)
		for i := range perDir {
			p := fmt.Sprintf("%s/f-%d", dirPath, i)
			if err := e.vfsObj.UnlinkAt(e.ctx, e.creds, e.pop(p)); err != nil {
				t.Fatalf("UnlinkAt(%s): %v", p, err)
			}
		}
		if err := e.vfsObj.RmdirAt(e.ctx, e.creds, e.pop(dirPath)); err != nil {
			t.Fatalf("Rmdir(%s): %v", dirPath, err)
		}
	}
	for fidx := range 4 {
		name := fmt.Sprintf("/bulk-%d", fidx)
		if err := e.vfsObj.UnlinkAt(e.ctx, e.creds, e.pop(name)); err != nil {
			t.Fatalf("UnlinkAt(%s): %v", name, err)
		}
	}

	// Drain any queued notification, then wait for two ticks: the first may
	// belong to a flush that started before the final UnlinkAt, whereas the
	// second is guaranteed to start and finish after all unlinks completed.
	for len(flushedCh) > 0 {
		<-flushedCh
	}
	for range 2 {
		select {
		case <-flushedCh:
		case <-time.After(5 * time.Second):
			t.Fatal("background flusher did not tick within 5s")
		}
	}

	allocOnline, sizeOnline, _ := hostAllocatedBytes(t, path)
	if sizeOnline < 5*groupBytes {
		t.Fatalf("online st_size shrank to %d, want >= %d while mounted with group 4+ inode", sizeOnline, 5*groupBytes)
	}
	if reclaimed := allocPeak - allocOnline; reclaimed < 48<<20 {
		t.Fatalf("online auto-shrink reclaimed only %d bytes (peak=%d, now=%d), want >= 48 MiB", reclaimed, allocPeak, allocOnline)
	}

	// Also invoke guest FITRIM on "/" to reclaim any sub-threshold fragments.
	rootFD := e.mustOpen("/", linux.O_RDONLY|linux.O_DIRECTORY)
	trimmed, err := invokeFITRIM(e, rootFD, 0, math.MaxUint64, 0)
	rootFD.DecRef(e.ctx)
	if err != nil {
		t.Fatalf("FITRIM on /: %v", err)
	}
	if trimmed < 48<<20 {
		t.Fatalf("FITRIM reported %d trimmed bytes, want >= 48 MiB", trimmed)
	}

	// Verify surviving files online, unmount cleanly, and verify st_size stays
	// pinned by "/pin"'s group 4+ inode while st_blocks stays low.
	if got := e.readFile("/pin"); !bytes.Equal(got, []byte("P")) {
		t.Fatalf("/pin online = %q, want \"P\"", got)
	}
	wantSurvivor := pattern(0x7B, 128<<10)
	if got := e.readFile("/survivor"); !bytes.Equal(got, wantSurvivor) {
		t.Fatal("/survivor payload corrupted online after hole punch")
	}

	e.unmount()

	allocAfterClose, sizeAfterClose, _ := hostAllocatedBytes(t, path)
	if sizeAfterClose < 5*groupBytes {
		t.Fatalf("after unmount st_size = %d, want >= %d (pinned by group 4+ inode)", sizeAfterClose, 5*groupBytes)
	}
	if reclaimed := allocPeak - allocAfterClose; reclaimed < 52<<20 {
		t.Fatalf("after unmount reclaimed %d bytes (peak=%d, close=%d), want >= 52 MiB", reclaimed, allocPeak, allocAfterClose)
	}

	// Remount and verify intact contents + e2fsck if installed.
	e2 := openEnv(t, path, VolumeOptions{}, vfs.MountOptions{})
	if got := e2.readFile("/pin"); !bytes.Equal(got, []byte("P")) {
		t.Fatalf("/pin after remount = %q, want \"P\"", got)
	}
	if got := e2.readFile("/survivor"); !bytes.Equal(got, wantSurvivor) {
		t.Fatal("/survivor corrupted after remount")
	}
	e2.unmount()
	verifyImageWithOracle(t, path)
	t.Run("e2fsck", func(t *testing.T) { runE2fsck(t, path) })
}

func verifyImageWithOracle(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	pages := newAuPages()
	pages.writeAt(raw, 0)
	res := auFsck(pages, true)
	if !res.OK() {
		t.Fatalf("auFsck(%s) failed:\n%s", path, res)
	}
}

// TestHeldBlocksNeverPunchedBeforeJournalCommitAndCrashRecovers verifies:
//   - Property: Blocks freed by unlink/truncate/punch stay in heldBlocks until
//     JBD2 commit completes; ZERO PunchHole calls target uncommitted freed blocks,
//     and crash recovery before commit preserves 100% of pre-delete file bytes.
//   - Also verifies dirty-mount recovery compaction + hole punching when a
//     sandbox is SIGKILLed after committing or leaving open orphans.
func TestHeldBlocksNeverPunchedBeforeJournalCommitAndCrashRecovers(t *testing.T) {
	auNoFlusher(t)

	// Part A: Intercept nativePunch on a real OS file to prove heldBlocks are
	// NEVER punched prior to JBD2 commit, and crash before commit preserves data.
	var punchCount atomic.Int64
	oldPunch := nativePunch
	nativePunch = func(f *os.File, off, n int64) (int64, int64, error) {
		punchCount.Add(1)
		return oldPunch(f, off, n)
	}
	defer func() { nativePunch = oldPunch }()

	path := filepath.Join(t.TempDir(), "crash-held.ext4")
	e := openEnv(t, path, VolumeOptions{}, vfs.MountOptions{})
	wantPayload := pattern(0x93, 2<<20) // 2 MiB non-zero payload
	e.writeFile("/precious", wantPayload)
	if err := e.fs.Sync(e.ctx); err != nil {
		t.Fatalf("initial Sync: %v", err)
	}
	punchCount.Store(0)

	// Unlink "/precious" WITHOUT calling Sync: blocks are now free in bitmap
	// AND held in heldBlocks.
	if err := e.vfsObj.UnlinkAt(e.ctx, e.creds, e.pop("/precious")); err != nil {
		t.Fatalf("UnlinkAt(/precious): %v", err)
	}
	if got := punchCount.Load(); got != 0 {
		t.Fatalf("nativePunch called %d times before JBD2 commit, want 0 (heldBlocks violation!)", got)
	}

	// Copy the live host file bytes right now to simulate power loss / SIGKILL
	// before JBD2 commit. Read through e.fs.v.hf because Windows LockFileEx
	// enforces mandatory locks against external os.ReadFile handles.
	crashCopy := filepath.Join(t.TempDir(), "crash-copy.ext4")
	hfSize, err := e.fs.v.hf.Size()
	if err != nil {
		t.Fatalf("hf.Size(crash snapshot): %v", err)
	}
	rawCrash := make([]byte, hfSize)
	if _, err := e.fs.v.hf.ReadAt(rawCrash, 0); err != nil {
		t.Fatalf("hf.ReadAt(crash snapshot): %v", err)
	}
	if err := os.WriteFile(crashCopy, rawCrash, 0o600); err != nil {
		t.Fatalf("WriteFile(crashCopy): %v", err)
	}

	// Now commit on the original mount: nativePunch MUST run after JBD2 commit!
	if err := e.fs.Sync(e.ctx); err != nil {
		t.Fatalf("Sync after unlink: %v", err)
	}
	if platformTier != tierFallback && punchCount.Load() == 0 {
		t.Fatal("nativePunch was not called after JBD2 commit of 2 MiB deletion")
	}
	e.unmount()

	// Mount crashCopy: "/precious" MUST still exist with 100% intact non-zero bytes!
	recoveredEnv := openEnv(t, crashCopy, VolumeOptions{}, vfs.MountOptions{})
	if got := recoveredEnv.readFile("/precious"); !bytes.Equal(got, wantPayload) {
		t.Fatal("/precious corrupted or zeroed after pre-commit crash recovery")
	}
	recoveredEnv.unmount()

	// Part B: Dirty-mount recovery compaction after simulated SIGKILL (abandon).
	if platformTier == tierFallback {
		return
	}
	dirtyPath := filepath.Join(t.TempDir(), "dirty-kill.ext4")
	v, err := tryOpenVolume(dirtyPath, volumeOptions{})
	if err == nil {
		_ = v.close()
	}
	fDirty, err := os.OpenFile(dirtyPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	volDirty, err := OpenVolume(fDirty, VolumeOptions{})
	if err != nil {
		t.Fatalf("OpenVolume(dirty): %v", err)
	}
	root := mustRoot(t, volDirty.v)
	chunk := pattern(0x5E, 1<<20)
	big1 := createChild(t, volDirty.v, root, "big1", modeRegular|0o644)
	big2 := createChild(t, volDirty.v, root, "big2", modeRegular|0o644)
	keep := createChild(t, volDirty.v, root, "keep", modeRegular|0o644)
	for i := range 24 {
		writeAll(t, big1, int64(i)<<20, chunk)
		writeAll(t, big2, int64(i)<<20, chunk)
	}
	keepWant := pattern(0x2D, 64<<10)
	writeAll(t, keep, 0, keepWant)
	if err := volDirty.Sync(); err != nil {
		t.Fatalf("volDirty.Sync: %v", err)
	}
	unlink(t, volDirty.v, root, "big1", big1)
	unlink(t, volDirty.v, root, "big2", big2)
	if err := volDirty.Sync(); err != nil {
		t.Fatalf("volDirty.Sync after unlink: %v", err)
	}
	// Simulate SIGKILL: close raw host file WITHOUT running clean shutdown/Truncate!
	abandon(volDirty.v)

	_, sizeBeforeRecover, _ := hostAllocatedBytes(t, dirtyPath)
	if sizeBeforeRecover < 4*groupBytes {
		t.Fatalf("dirty image size before recovery = %d, want >= %d", sizeBeforeRecover, 4*groupBytes)
	}

	// Reopen RW: openVolume MUST replay journal and compact + truncate + punch!
	fRecover, err := os.OpenFile(dirtyPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	volRecover, err := OpenVolume(fRecover, VolumeOptions{})
	if err != nil {
		t.Fatalf("OpenVolume(recover): %v", err)
	}
	allocAfterRecover, sizeAfterRecover, _ := hostAllocatedBytes(t, dirtyPath)
	if sizeAfterRecover != groupBytes {
		t.Fatalf("dirty-mount recovery st_size = %d, want %d (1 group)", sizeAfterRecover, groupBytes)
	}
	if allocAfterRecover > groupBytes {
		t.Fatalf("dirty-mount recovery st_blocks*512 = %d, want <= %d", allocAfterRecover, groupBytes)
	}
	keepRec := lookupNode(t, volRecover.v, mustRoot(t, volRecover.v), "keep")
	if got := readAll(t, keepRec); !bytes.Equal(got, keepWant) {
		t.Fatal("keep file corrupted across dirty-mount recovery compaction")
	}
	if err := volRecover.Close(); err != nil {
		t.Fatalf("volRecover.Close: %v", err)
	}
}

// TestReallocationOfPunchedBlocksEnforcesHostENOSPCWithoutCorruption verifies:
//   - Property: Reallocating punched blocks when the host filesystem is full
//     returns ENOSPC cleanly BEFORE marking blocks allocated in bitmaps, leaving
//     existing files intact and fsck clean on both tierNative and tierFallback.
func TestReallocationOfPunchedBlocksEnforcesHostENOSPCWithoutCorruption(t *testing.T) {
	auNoFlusher(t)

	// Subtest 1: Real OS host file on platformTier with fault-injected ENOSPC
	// on nativeAllocateRange during reallocation of punched blocks.
	if platformTier != tierFallback {
		t.Run("native_os_file", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "enospc-punch.ext4")
			e := openEnv(t, path, VolumeOptions{}, vfs.MountOptions{})
			keepBytes := pattern(0x33, 128<<10)
			e.writeFile("/keep", keepBytes)
			e.writeFile("/temp", pattern(0x77, 4<<20))
			if err := e.fs.Sync(e.ctx); err != nil {
				t.Fatalf("Sync: %v", err)
			}
			if err := e.vfsObj.UnlinkAt(e.ctx, e.creds, e.pop("/temp")); err != nil {
				t.Fatalf("UnlinkAt(/temp): %v", err)
			}
			if err := e.fs.Sync(e.ctx); err != nil {
				t.Fatalf("Sync after unlink: %v", err)
			}

			// Simulate host disk filling up completely before reallocating punched blocks.
			var failAlloc atomic.Bool
			failAlloc.Store(true)
			oldAlloc := nativeAllocateRange
			nativeAllocateRange = func(f *os.File, off, n int64) error {
				if failAlloc.Load() {
					return errHostDiskFull
				}
				return oldAlloc(f, off, n)
			}
			defer func() { nativeAllocateRange = oldAlloc }()

			freeBefore := e.fs.v.freeBlocksTotal
			fd := e.mustOpen("/new", linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY)
			_, werr := fd.PWrite(e.ctx, usermem.BytesIOSequence(pattern(0x88, 2<<20)), 0, vfs.WriteOptions{})
			fd.DecRef(e.ctx)
			if !errors.Is(werr, linuxerr.ENOSPC) {
				t.Fatalf("PWrite into punched blocks under host ENOSPC = %v, want ENOSPC", werr)
			}
			if err := e.vfsObj.UnlinkAt(e.ctx, e.creds, e.pop("/new")); err != nil {
				t.Fatalf("UnlinkAt(/new): %v", err)
			}
			if err := e.fs.Sync(e.ctx); err != nil {
				t.Fatalf("Sync after failed write: %v", err)
			}
			if got := e.fs.v.freeBlocksTotal; got != freeBefore {
				t.Fatalf("freeBlocksTotal after failed reallocation + cleanup = %d, want %d (bitmap leak!)", got, freeBefore)
			}
			if got := e.readFile("/keep"); !bytes.Equal(got, keepBytes) {
				t.Fatal("/keep corrupted after ENOSPC on punched block reallocation")
			}

			// Restore host disk space and verify reallocation now succeeds cleanly!
			failAlloc.Store(false)
			newPayload := pattern(0x99, 2<<20)
			e.writeFile("/recovered", newPayload)
			if err := e.fs.Sync(e.ctx); err != nil {
				t.Fatalf("Sync(/recovered): %v", err)
			}
			if got := e.readFile("/recovered"); !bytes.Equal(got, newPayload) {
				t.Fatal("/recovered payload mismatch after space restored")
			}
			e.unmount()
			verifyImageWithOracle(t, path)
			t.Run("e2fsck", func(t *testing.T) { runE2fsck(t, path) })
		})
	}

	// Subtest 2: Both tierNative and tierFallback on auFile with host capacity cap,
	// verifying auFsck oracle cleanliness across ENOSPC on punched blocks.
	for _, tier := range []storageTier{tierNative, tierFallback} {
		t.Run("aufile_"+tier.String(), func(t *testing.T) {
			f := newAuFile(nil)
			f.tier = tier
			d := auMount(t, f, newAuModel())
			d.create("/keep", 64<<10)
			d.create("/victim", 4<<20)
			d.syncAll()
			d.unlink("/victim")
			d.syncAll()

			// Cap host available bytes to current allocated bytes so zero room
			// remains to re-materialize punched blocks!
			f.mu.Lock()
			f.avail = int64(len(f.cur.pages)) * auPage
			f.mu.Unlock()

			fd, err := d.e.open("/failwrite", linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY, 0o644)
			if err != nil {
				t.Fatalf("open(/failwrite): %v", err)
			}
			_, werr := fd.PWrite(d.e.ctx, usermem.BytesIOSequence(pattern(0xAB, 2<<20)), 0, vfsWriteOpts)
			fd.DecRef(d.e.ctx)
			if !errors.Is(werr, linuxerr.ENOSPC) {
				t.Fatalf("tier %v: PWrite under exhausted host space = %v, want ENOSPC", tier, werr)
			}
			if err := d.e.vfsObj.UnlinkAt(d.e.ctx, d.e.creds, d.e.pop("/failwrite")); err != nil {
				t.Fatalf("UnlinkAt(/failwrite): %v", err)
			}
			d.syncAll()
			d.verifyLive("after punched reallocation ENOSPC")

			// Restore host capacity and write 3 MiB into previously punched space.
			f.mu.Lock()
			f.avail = -1
			f.mu.Unlock()
			d.create("/refill", 3<<20)
			d.syncAll()
			d.verifyLive("after refill")
			d.e.unmount()

			res := auFsck(f.snapshot(), true)
			if !res.OK() {
				t.Fatalf("tier %v: auFsck failed:\n%s", tier, res)
			}
		})
	}
}

// TestVFSFITRIMIoctlSemanticsAndBoundaries verifies Linux FITRIM ioctl behavior:
//   - Directory FD and regular FD support, flushing uncommitted frees, range
//     filtering (start, len, minlen), UINT64_MAX len clamping, EPERM without
//     CAP_SYS_ADMIN, EROFS on read-only mount/volume, EINVAL on out-of-range
//     start/len/minlen, and EFAULT on invalid user pointers.
func TestVFSFITRIMIoctlSemanticsAndBoundaries(t *testing.T) {
	auNoFlusher(t)
	path := filepath.Join(t.TempDir(), "fitrim.ext4")
	e := openEnv(t, path, VolumeOptions{}, vfs.MountOptions{})

	// Write 8 MiB, sync, delete WITHOUT sync so FITRIM must flush + trim.
	e.writeFile("/trimme", pattern(0x51, 8<<20))
	if err := e.fs.Sync(e.ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if err := e.vfsObj.UnlinkAt(e.ctx, e.creds, e.pop("/trimme")); err != nil {
		t.Fatalf("UnlinkAt: %v", err)
	}

	dirFD := e.mustOpen("/", linux.O_RDONLY|linux.O_DIRECTORY)

	// 1. Short user buffer returns EFAULT.
	bio := &usermem.BytesIO{Bytes: make([]byte, 64)}
	if _, err := dirFD.Ioctl(e.ctx, bio, 0, arch.SyscallArguments{
		{Value: 0},
		{Value: testFITRIMIoctl},
		{Value: 56}, // 56 + 24 > 64 triggers EFAULT
	}); !linuxerr.Equals(linuxerr.EFAULT, err) {
		t.Fatalf("FITRIM short user buffer = %v, want EFAULT", err)
	}

	// 2. Caller without CAP_SYS_ADMIN returns EPERM.
	unpriv := auth.NewUserCredentials(1000, 1000, nil, nil, e.creds.UserNamespace)
	unprivEnv := *e
	unprivEnv.ctx = credsContext{Context: e.ctx, creds: unpriv}
	if _, err := invokeFITRIM(&unprivEnv, dirFD, 0, math.MaxUint64, 0); !linuxerr.Equals(linuxerr.EPERM, err) {
		t.Fatalf("FITRIM without CAP_SYS_ADMIN = %v, want EPERM", err)
	}

	// 3. Invalid ranges return EINVAL.
	if _, err := invokeFITRIM(e, dirFD, 0, blockSize-1, 0); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Fatalf("FITRIM len < blockSize = %v, want EINVAL", err)
	}
	if _, err := invokeFITRIM(e, dirFD, uint64(groupBytes), blockSize, 0); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Fatalf("FITRIM start >= volume size = %v, want EINVAL", err)
	}
	if _, err := invokeFITRIM(e, dirFD, 0, math.MaxUint64, groupBytes+blockSize); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Fatalf("FITRIM minlen > groupBytes = %v, want EINVAL", err)
	}

	// 4. minlen = 16 MiB exceeds any single group data area and trims 0 bytes.
	trimmedHugeMin, err := invokeFITRIM(e, dirFD, 0, math.MaxUint64, groupBytes)
	if err != nil {
		t.Fatalf("FITRIM with 16 MiB minlen: %v", err)
	}
	if trimmedHugeMin != 0 {
		t.Fatalf("FITRIM with 16 MiB minlen trimmed %d bytes, want 0", trimmedHugeMin)
	}

	// 5. Subrange [0, 4 MiB) covers only Group 0 metadata + root dir + the 4 MiB
	//    JBD2 journal (blocks 0..1284), so FITRIM must trim 0 bytes there;
	//    subrange [0, 8 MiB) covers ~2.98 MiB of free data blocks behind the
	//    journal; and full trim on regularFD trims >= 8 MiB!
	e.writeFile("/reg", []byte("ok"))
	regFD := e.mustOpen("/reg", linux.O_RDONLY)

	if platformTier != tierFallback {
		metaJournalTrimmed, err := invokeFITRIM(e, dirFD, 0, 4<<20, 16<<10)
		if err != nil {
			t.Fatalf("FITRIM metadata/journal subrange: %v", err)
		}
		if metaJournalTrimmed != 0 {
			t.Fatalf("FITRIM [0, 4 MiB) trimmed %d bytes of metadata/journal, want 0", metaJournalTrimmed)
		}

		subTrimmed, err := invokeFITRIM(e, dirFD, 0, 8<<20, 16<<10)
		if err != nil {
			t.Fatalf("FITRIM subrange [0, 8 MiB): %v", err)
		}
		if subTrimmed == 0 || subTrimmed > 4<<20 {
			t.Fatalf("FITRIM [0, 8 MiB) trimmed %d bytes, want in (0, 4 MiB]", subTrimmed)
		}

		fullTrimmed, err := invokeFITRIM(e, regFD, 0, math.MaxUint64, 0)
		if err != nil {
			t.Fatalf("FITRIM full on regularFD: %v", err)
		}
		if fullTrimmed < 8<<20 {
			t.Fatalf("FITRIM full trimmed %d bytes, want >= 8 MiB", fullTrimmed)
		}
	}
	regFD.DecRef(e.ctx)
	dirFD.DecRef(e.ctx)
	e.unmount()

	// 6. Read-only mount or volume returns EROFS.
	roEnv := openEnv(t, path, VolumeOptions{ReadOnly: true}, vfs.MountOptions{ReadOnly: true})
	roDirFD := roEnv.mustOpen("/", linux.O_RDONLY|linux.O_DIRECTORY)
	if _, err := invokeFITRIM(roEnv, roDirFD, 0, math.MaxUint64, 0); !linuxerr.Equals(linuxerr.EROFS, err) {
		roDirFD.DecRef(roEnv.ctx)
		t.Fatalf("FITRIM on RO mount = %v, want EROFS", err)
	}
	roDirFD.DecRef(roEnv.ctx)
	roEnv.unmount()
}

// TestCheckpointRestorePreservesPunchedVolumeAndGuardsReallocation verifies:
//   - Property: Checkpoint & Restore preserves volumeIdentity and sparse host
//     blocks after hole punching, conservatively restores punched tracking so
//     post-restore host disk exhaustion still yields ENOSPC cleanly, and
//     continues reading/writing without corruption once space is available.
func TestCheckpointRestorePreservesPunchedVolumeAndGuardsReallocation(t *testing.T) {
	if platformTier == tierFallback {
		t.Skip("this operating system has no native hole-punch tier")
	}
	auNoFlusher(t)

	path := filepath.Join(t.TempDir(), "ckpt-punch.ext4")
	const uid = "ckpt-punch-vol"
	e := newNamedEnv(t, path, uid, VolumeOptions{})

	// Populate 32 MiB + a survivor file + an open FD, then delete 32 MiB and FITRIM.
	keepData := pattern(0x64, 96<<10)
	e.writeFile("/survivor", keepData)
	e.writeFile("/ephemeral", pattern(0x22, 32<<20))
	if err := e.fs.Sync(e.ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if err := e.vfsObj.UnlinkAt(e.ctx, e.creds, e.pop("/ephemeral")); err != nil {
		t.Fatalf("UnlinkAt(/ephemeral): %v", err)
	}
	rootFD := e.mustOpen("/", linux.O_RDONLY|linux.O_DIRECTORY)
	if _, err := invokeFITRIM(e, rootFD, 0, math.MaxUint64, 0); err != nil {
		rootFD.DecRef(e.ctx)
		t.Fatalf("FITRIM before save: %v", err)
	}
	rootFD.DecRef(e.ctx)

	openFD := e.mustOpen("/survivor", linux.O_RDWR)
	bundle := &checkpointBundle{
		vfsObj: e.vfsObj,
		mntns:  e.mntns,
		root:   e.root,
		creds:  e.creds,
		fds:    []*vfs.FileDescription{openFD},
	}
	saved := saveBundle(t, e.ctx, bundle)
	openFD.DecRef(e.ctx)
	e.unmount()

	allocSaved, _, _ := hostAllocatedBytes(t, path)
	if allocSaved > 8<<20 {
		t.Fatalf("checkpointed image allocated %d bytes after punching 32 MiB, want <= 8 MiB", allocSaved)
	}

	// Reopen backing volume for restore with DeferOrphanCleanup: true.
	rf, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	rvol, err := OpenVolume(rf, VolumeOptions{DeferOrphanCleanup: true})
	if err != nil {
		t.Fatalf("OpenVolume(restore): %v", err)
	}
	vmap, err := BuildRestoreVolumeMap([]RestoreVolumeMount{{UniqueID: uid, Volume: rvol}})
	if err != nil {
		t.Fatal(err)
	}
	re, rbundle, err := restoreBundle(t, saved, vmap)
	if err != nil {
		t.Fatalf("CompleteRestore: %v", err)
	}

	// Read from the restored open FD!
	gotBuf := make([]byte, len(keepData))
	if n, err := rbundle.fds[0].PRead(re.ctx, usermem.BytesIOSequence(gotBuf), 0, vfs.ReadOptions{}); err != nil || int(n) != len(keepData) || !bytes.Equal(gotBuf, keepData) {
		t.Fatalf("PRead on restored FD = (%d, %v), payload match=%v", n, err, bytes.Equal(gotBuf, keepData))
	}

	// Verify conservative punched-block ENOSPC protection survived Restore!
	var failAlloc atomic.Bool
	failAlloc.Store(true)
	oldAlloc := nativeAllocateRange
	nativeAllocateRange = func(f *os.File, off, n int64) error {
		if failAlloc.Load() {
			return errHostDiskFull
		}
		return oldAlloc(f, off, n)
	}
	defer func() { nativeAllocateRange = oldAlloc }()

	failFD := re.mustOpen("/post-restore-fail", linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY)
	_, werr := failFD.PWrite(re.ctx, usermem.BytesIOSequence(pattern(0x44, 1<<20)), 0, vfs.WriteOptions{})
	failFD.DecRef(re.ctx)
	if !errors.Is(werr, linuxerr.ENOSPC) {
		t.Fatalf("post-restore PWrite under simulated host ENOSPC = %v, want ENOSPC", werr)
	}
	_ = re.vfsObj.UnlinkAt(re.ctx, re.creds, re.pop("/post-restore-fail"))

	// Re-enable host space and verify post-restore writes/reads succeed cleanly!
	failAlloc.Store(false)
	postData := pattern(0xBE, 2<<20)
	re.writeFile("/post-restore-ok", postData)
	if err := re.fs.Sync(re.ctx); err != nil {
		t.Fatalf("post-restore Sync: %v", err)
	}
	if got := re.readFile("/post-restore-ok"); !bytes.Equal(got, postData) {
		t.Fatal("/post-restore-ok mismatch")
	}
}

// TestVolumeLockHelperProcess runs inside a child OS process for cross-process
// LOCK_SH / LOCK_EX verification.
func TestVolumeLockHelperProcess(t *testing.T) {
	mode := os.Getenv("EXT4LITE_LOCK_HELPER_MODE")
	path := os.Getenv("EXT4LITE_LOCK_HELPER_PATH")
	if mode == "" || path == "" {
		return
	}
	switch mode {
	case "hold-ro":
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(os.Stdout, "ERR:%v\n", err)
			os.Exit(1)
		}
		vol, err := OpenVolume(f, VolumeOptions{ReadOnly: true})
		if err != nil {
			fmt.Fprintf(os.Stdout, "ERR:%v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "LOCKED")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		_ = vol.Close()
		os.Exit(0)
	case "try-rw":
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			fmt.Fprintf(os.Stdout, "ERR:%v\n", err)
			os.Exit(1)
		}
		vol, err := OpenVolume(f, VolumeOptions{ReadOnly: false})
		if err != nil {
			if errors.Is(err, ErrVolumeInUse) {
				fmt.Fprintln(os.Stdout, "IN_USE")
				os.Exit(0)
			}
			fmt.Fprintf(os.Stdout, "ERR:%v\n", err)
			os.Exit(1)
		}
		_ = vol.Close()
		fmt.Fprintln(os.Stdout, "ACQUIRED_RW")
		os.Exit(0)
	case "try-ro":
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(os.Stdout, "ERR:%v\n", err)
			os.Exit(1)
		}
		vol, err := OpenVolume(f, VolumeOptions{ReadOnly: true})
		if err != nil {
			if errors.Is(err, ErrVolumeInUse) {
				fmt.Fprintln(os.Stdout, "IN_USE")
				os.Exit(0)
			}
			fmt.Fprintf(os.Stdout, "ERR:%v\n", err)
			os.Exit(1)
		}
		_ = vol.Close()
		fmt.Fprintln(os.Stdout, "ACQUIRED_RO")
		os.Exit(0)
	}
}

// TestVolumeSharedAndExclusiveLockMatrix verifies Phase 2 multi-reader LOCK_SH,
// LOCK_EX exclusion, RemoveVolumeFile protection under LOCK_SH, ProbeVolumeLock
// modes, cross-process enforcement, and concurrent probe race freedom.
func TestVolumeSharedAndExclusiveLockMatrix(t *testing.T) {
	if platformTier == tierFallback {
		t.Skip("this operating system has no advisory file lock")
	}

	if VolumeLockNone.String() != "none" || VolumeLockShared.String() != "shared" || VolumeLockExclusive.String() != "exclusive" {
		t.Fatalf("VolumeLockMode.String() = (%q, %q, %q), want (\"none\", \"shared\", \"exclusive\")",
			VolumeLockNone.String(), VolumeLockShared.String(), VolumeLockExclusive.String())
	}

	path := filepath.Join(t.TempDir(), "shared.ext4")
	// Format and cleanly unmount a valid base volume.
	initEnv := openEnv(t, path, VolumeOptions{}, vfs.MountOptions{})
	initEnv.writeFile("/hello", []byte("shared-base"))
	initEnv.unmount()

	// 1. Idle state: VolumeLockNone, InUse == false.
	if mode, err := ProbeVolumeLock(path); err != nil || mode != VolumeLockNone {
		t.Fatalf("idle ProbeVolumeLock = (%v, %v), want (none, nil)", mode, err)
	}
	if inUse, err := ProbeVolumeInUse(path); err != nil || inUse {
		t.Fatalf("idle ProbeVolumeInUse = (%v, %v), want (false, nil)", inUse, err)
	}

	// 2. Open N=4 in-process RO handles (using O_RDONLY!) + 1 child OS process RO handle.
	const numRO = 4
	roVols := make([]*Volume, numRO)
	for i := range numRO {
		rf, err := os.Open(path)
		if err != nil {
			t.Fatalf("os.Open(%d): %v", i, err)
		}
		vol, err := OpenVolume(rf, VolumeOptions{ReadOnly: true})
		if err != nil {
			t.Fatalf("OpenVolume(ReadOnly: true) #%d failed: %v", i, err)
		}
		roVols[i] = vol
	}
	defer func() {
		for _, vol := range roVols {
			if vol != nil {
				_ = vol.Close()
			}
		}
	}()

	// Start child process holding ReadOnly: true as well.
	childCmd := exec.Command(os.Args[0], "-test.run=^TestVolumeLockHelperProcess$")
	childCmd.Env = append(os.Environ(),
		"EXT4LITE_LOCK_HELPER_MODE=hold-ro",
		"EXT4LITE_LOCK_HELPER_PATH="+path,
	)
	childStdin, err := childCmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	childStdout, err := childCmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := childCmd.Start(); err != nil {
		t.Fatalf("start child helper: %v", err)
	}
	defer func() {
		_ = childStdin.Close()
		_ = childCmd.Wait()
	}()
	line, err := bufio.NewReader(childStdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "LOCKED" {
		t.Fatalf("child hold-ro output = %q (err=%v), want LOCKED", line, err)
	}

	// 3. While RO readers hold LOCK_SH:
	//    - ProbeVolumeLock == VolumeLockShared
	//    - ProbeVolumeInUse == true
	//    - OpenVolume(ReadOnly: false) fails with ErrVolumeInUse (both in-process & subprocess)
	//    - RemoveVolumeFile fails with ErrVolumeInUse and preserves file!
	if mode, err := ProbeVolumeLock(path); err != nil || mode != VolumeLockShared {
		t.Fatalf("shared ProbeVolumeLock = (%v, %v), want (shared, nil)", mode, err)
	}
	if inUse, err := ProbeVolumeInUse(path); err != nil || !inUse {
		t.Fatalf("shared ProbeVolumeInUse = (%v, %v), want (true, nil)", inUse, err)
	}
	rwF, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVolume(rwF, VolumeOptions{ReadOnly: false}); !errors.Is(err, ErrVolumeInUse) {
		t.Fatalf("OpenVolume(RW) while RO open = %v, want ErrVolumeInUse", err)
	}
	tryRWCmd := exec.Command(os.Args[0], "-test.run=^TestVolumeLockHelperProcess$")
	tryRWCmd.Env = append(os.Environ(),
		"EXT4LITE_LOCK_HELPER_MODE=try-rw",
		"EXT4LITE_LOCK_HELPER_PATH="+path,
	)
	var tryRWStderr bytes.Buffer
	tryRWCmd.Stderr = &tryRWStderr
	if out, err := tryRWCmd.Output(); err != nil || strings.TrimSpace(string(out)) != "IN_USE" {
		t.Fatalf("child try-rw while RO open = (%q, %v; stderr=%q), want IN_USE", string(out), err, tryRWStderr.String())
	}
	if err := RemoveVolumeFile(path); !errors.Is(err, ErrVolumeInUse) {
		t.Fatalf("RemoveVolumeFile while RO open = %v, want ErrVolumeInUse", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("volume file disappeared after rejected RemoveVolumeFile: %v", err)
	}

	// 4. Close in-process RO handles while child RO holds LOCK_SH; mode stays shared.
	for i, vol := range roVols {
		if err := vol.Close(); err != nil {
			t.Fatalf("roVols[%d].Close: %v", i, err)
		}
		roVols[i] = nil
	}
	if mode, err := ProbeVolumeLock(path); err != nil || mode != VolumeLockShared {
		t.Fatalf("ProbeVolumeLock with child RO still open = (%v, %v), want (shared, nil)", mode, err)
	}

	// Release child RO handle and verify mode returns to VolumeLockNone.
	_, _ = fmt.Fprintln(childStdin, "done")
	_ = childStdin.Close()
	if err := childCmd.Wait(); err != nil {
		t.Fatalf("child hold-ro exit: %v", err)
	}
	if mode, err := ProbeVolumeLock(path); err != nil || mode != VolumeLockNone {
		t.Fatalf("ProbeVolumeLock after all RO closed = (%v, %v), want (none, nil)", mode, err)
	}

	// 5. Open RW handle for VolumeLockExclusive; block RO, RW, and RemoveVolumeFile.
	rwF2, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	rwVol, err := OpenVolume(rwF2, VolumeOptions{ReadOnly: false})
	if err != nil {
		t.Fatalf("OpenVolume(RW) after RO close: %v", err)
	}
	defer func() {
		if rwVol != nil {
			_ = rwVol.Close()
		}
	}()

	if mode, err := ProbeVolumeLock(path); err != nil || mode != VolumeLockExclusive {
		t.Fatalf("exclusive ProbeVolumeLock = (%v, %v), want (exclusive, nil)", mode, err)
	}
	if inUse, err := ProbeVolumeInUse(path); err != nil || !inUse {
		t.Fatalf("exclusive ProbeVolumeInUse = (%v, %v), want (true, nil)", inUse, err)
	}
	roAttempt, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVolume(roAttempt, VolumeOptions{ReadOnly: true}); !errors.Is(err, ErrVolumeInUse) {
		t.Fatalf("OpenVolume(RO) while RW open = %v, want ErrVolumeInUse", err)
	}
	tryROCmd := exec.Command(os.Args[0], "-test.run=^TestVolumeLockHelperProcess$")
	tryROCmd.Env = append(os.Environ(),
		"EXT4LITE_LOCK_HELPER_MODE=try-ro",
		"EXT4LITE_LOCK_HELPER_PATH="+path,
	)
	var tryROStderr bytes.Buffer
	tryROCmd.Stderr = &tryROStderr
	if out, err := tryROCmd.Output(); err != nil || strings.TrimSpace(string(out)) != "IN_USE" {
		t.Fatalf("child try-ro while RW open = (%q, %v; stderr=%q), want IN_USE", string(out), err, tryROStderr.String())
	}
	if err := RemoveVolumeFile(path); !errors.Is(err, ErrVolumeInUse) {
		t.Fatalf("RemoveVolumeFile while RW open = %v, want ErrVolumeInUse", err)
	}
	if err := rwVol.Close(); err != nil {
		t.Fatalf("rwVol.Close: %v", err)
	}
	rwVol = nil

	// 6. Concurrent ProbeVolumeLock + OpenVolume(ReadOnly: true) contention hammer:
	//    8 probe goroutines on an unlocked volume must NEVER report false InUse,
	//    and 8 concurrent RO open/close + probe goroutines on a second volume must
	//    NEVER fail OpenVolume(RO) with ErrVolumeInUse or report VolumeLockExclusive!
	idlePath := filepath.Join(t.TempDir(), "idle-probe.ext4")
	idleEnv := openEnv(t, idlePath, VolumeOptions{}, vfs.MountOptions{})
	idleEnv.unmount()

	var wg sync.WaitGroup
	errCh := make(chan error, 32)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				mode, err := ProbeVolumeLock(idlePath)
				if err != nil || mode != VolumeLockNone {
					errCh <- fmt.Errorf("concurrent idle ProbeVolumeLock = (%v, %v), want (none, nil)", mode, err)
					return
				}
			}
		}()
	}
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 40 {
				f, err := os.Open(path)
				if err != nil {
					errCh <- fmt.Errorf("os.Open: %v", err)
					return
				}
				v, err := OpenVolume(f, VolumeOptions{ReadOnly: true})
				if err != nil {
					errCh <- fmt.Errorf("concurrent OpenVolume(RO) failed: %v", err)
					return
				}
				mode, perr := ProbeVolumeLock(path)
				_ = v.Close()
				if perr != nil || mode != VolumeLockShared {
					errCh <- fmt.Errorf("ProbeVolumeLock while holding RO = (%v, %v), want (shared, nil)", mode, perr)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	// Finally, RemoveVolumeFile succeeds when unlocked!
	if err := RemoveVolumeFile(path); err != nil {
		t.Fatalf("RemoveVolumeFile after all handles closed: %v", err)
	}
}

// TestPunchHoleUnsupportedGracefulNoOp verifies that exotic host filesystems
// returning EOPNOTSUPP, ENOSYS, or EINVAL disable future PunchHole syscalls on
// that handle without failing Sync, FITRIM, or unmount.
func TestPunchHoleUnsupportedGracefulNoOp(t *testing.T) {
	if platformTier == tierFallback {
		t.Skip("this operating system has no native tier")
	}
	auNoFlusher(t)

	for _, uerr := range testUnsupportedErrors {
		t.Run(uerr.Error(), func(t *testing.T) {
			var calls atomic.Int64
			oldPunch := nativePunch
			nativePunch = func(f *os.File, off, n int64) (int64, int64, error) {
				calls.Add(1)
				return 0, 0, uerr
			}
			defer func() { nativePunch = oldPunch }()

			path := filepath.Join(t.TempDir(), "no-punch.ext4")
			e := openEnv(t, path, VolumeOptions{}, vfs.MountOptions{})
			e.writeFile("/a", pattern(0x11, 2<<20))
			if err := e.fs.Sync(e.ctx); err != nil {
				t.Fatalf("Sync write: %v", err)
			}
			if err := e.vfsObj.UnlinkAt(e.ctx, e.creds, e.pop("/a")); err != nil {
				t.Fatalf("UnlinkAt(/a): %v", err)
			}
			if err := e.fs.Sync(e.ctx); err != nil {
				t.Fatalf("Sync after unlink on unsupported punch FS failed: %v", err)
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("nativePunch calls after first unsupported error = %d, want 1", got)
			}

			// Subsequent deletions and FITRIM must skip nativePunch cleanly.
			e.writeFile("/b", pattern(0x22, 2<<20))
			_ = e.fs.Sync(e.ctx)
			_ = e.vfsObj.UnlinkAt(e.ctx, e.creds, e.pop("/b"))
			if err := e.fs.Sync(e.ctx); err != nil {
				t.Fatalf("second Sync failed: %v", err)
			}
			rootFD := e.mustOpen("/", linux.O_RDONLY|linux.O_DIRECTORY)
			trimmed, err := invokeFITRIM(e, rootFD, 0, math.MaxUint64, 0)
			rootFD.DecRef(e.ctx)
			if err != nil || trimmed != 0 {
				t.Fatalf("FITRIM on punch-disabled handle = (%d, %v), want (0, nil)", trimmed, err)
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("nativePunch called %d times after disable, want 1", got)
			}
			e.unmount()
		})
	}
}
