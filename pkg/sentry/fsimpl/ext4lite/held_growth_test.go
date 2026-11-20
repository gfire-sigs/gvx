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
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// fillGroupZeroAndHoldOneBlock fills group 0 of a new volume, syncs, and frees
// one block that the disk records. That block waits for the next flush, so the
// volume has no allocatable block. hostBytes is the room of the host file, and
// -1 gives no limit. It returns the driver and creates the empty file /out.
func fillGroupZeroAndHoldOneBlock(t *testing.T, hostBytes int64) *auDrv {
	t.Helper()
	auNoFlusher(t)
	f := newAuFile(nil)
	f.avail = hostBytes
	d := auMount(t, f, newAuModel())
	d.create("/small", blockSize)
	d.create("/out", 0)
	v := d.e.fs.v
	v.mu.Lock()
	free := int(v.groups[0].desc.freeBlocks)
	v.mu.Unlock()
	d.create("/fill", free*blockSize)
	d.syncAll()
	if v.numGroups() != 1 {
		t.Fatalf("the volume has %d groups, want 1 full group", v.numGroups())
	}
	d.unlink("/small")
	if !v.hasHeld() {
		t.Fatal("the freed block of /small is not held")
	}
	return d
}

type blockingPunchFile struct {
	*auFile
	onPunch func(off, length int64)
}

func (b *blockingPunchFile) PunchHole(off, length int64) error {
	if b.onPunch != nil {
		b.onPunch(off, length)
	}
	return b.auFile.PunchHole(off, length)
}

// TestHeldSpaceDoesNotFailMappedWriteBack writes a new file through a writable
// mapping and ends the mapping, as a linker writes its output. The end of the
// mapping writes the pages back, and that write-back cannot flush the volume
// first. The volume can grow, so the close must succeed, and the file and the
// image must hold the stored bytes.
func TestHeldSpaceDoesNotFailMappedWriteBack(t *testing.T) {
	d := fillGroupZeroAndHoldOneBlock(t, -1)
	const size = 16 * blockSize
	d.truncate("/out", size)
	want := auFill(7, 0, size)

	fd := d.e.mustOpen("/out", linux.O_RDWR)
	mp := d.e.mapFile(fd, size, true)
	mp.store(0, want)
	mp.remove()
	if err := fd.OnClose(d.e.ctx); err != nil {
		t.Errorf("close after the end of the mapping fails with %v while the volume can grow", err)
	}
	wantBytes(t, "/out after the write-back", d.e.readAll(fd), want)
	fd.DecRef(d.e.ctx)

	d.m.nodes["/out"].data = want
	d.syncAll()
	d.e.unmount()
	final := auFsck(d.f.snapshot(), true)
	if !final.OK() {
		t.Errorf("image after the growth:\n%s", final)
	}
	for _, msg := range auCompareImage(final, d.m) {
		t.Errorf("image after the growth: %s", msg)
	}
}

// TestParallelChurnDoesNotFailWithENOSPC runs writers that create files and
// unlink older ones while another goroutine syncs in a loop. The unlinks of
// synced files keep freed blocks waiting for a flush most of the time, and the
// files that stay make the volume grow. The host has room, so no operation may
// fail.
func TestParallelChurnDoesNotFailWithENOSPC(t *testing.T) {
	d := newAuDrv(t)
	e := d.e
	const (
		workers = 8
		rounds  = 150
		size    = 64 << 10
	)
	stop := make(chan struct{})
	var syncer sync.WaitGroup
	syncer.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = e.fs.syncAll()
		}
	})
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			for i := range rounds {
				p := fmt.Sprintf("/w%d-%d", w, i)
				fd, err := e.open(p, linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY, 0o644)
				if err != nil {
					errs[w] = fmt.Errorf("create %s: %w", p, err)
					return
				}
				_, err = fd.PWrite(e.ctx, usermem.BytesIOSequence(auFill(uint32(w*rounds+i), 0, size)), 0, vfsWriteOpts)
				fd.DecRef(e.ctx)
				if err != nil {
					errs[w] = fmt.Errorf("write %s: %w", p, err)
					return
				}
				if i%2 == 1 {
					old := fmt.Sprintf("/w%d-%d", w, i-1)
					if err := e.unlink(old); err != nil {
						errs[w] = fmt.Errorf("unlink %s: %w", old, err)
						return
					}
				}
			}
		})
	}
	wg.Wait()
	close(stop)
	syncer.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Errorf("an operation failed while the host has room: %v", err)
	}
}

// TestSequentialUnlinkAndRewriteReusesHeldSpaceWithoutGrowth verifies that
// unlinking a synced file and writing a replacement of the same size without a
// flush between flushes and reuses the existing groups instead of doubling the
// volume size.
func TestSequentialUnlinkAndRewriteReusesHeldSpaceWithoutGrowth(t *testing.T) {
	d := newAuDrv(t)
	const fileSize = 64 << 20
	d.create("/f0", fileSize)
	d.syncAll()
	wantGroups := d.e.fs.v.numGroups()

	d.unlink("/f0")
	d.create("/f1", fileSize)
	if got := d.e.fs.v.numGroups(); got != wantGroups {
		t.Fatalf("groups after unlinked rewrite = %d, want %d (volume grew instead of flushing held space)", got, wantGroups)
	}
	for round := 2; round <= 7; round++ {
		d.syncAll()
		d.unlink(fmt.Sprintf("/f%d", round-1))
		d.create(fmt.Sprintf("/f%d", round), fileSize)
		if got := d.e.fs.v.numGroups(); got != wantGroups {
			t.Fatalf("round %d: groups = %d, want %d", round, got, wantGroups)
		}
	}

	d.syncAll()
	d.e.unmount()
	final := auFsck(d.f.snapshot(), true)
	if !final.OK() {
		t.Errorf("image after sequential churn:\n%s", final)
	}
	for _, msg := range auCompareImage(final, d.m) {
		t.Errorf("image after sequential churn: %s", msg)
	}
}

// TestAllocWaitsForInFlightHolePunchWithoutGrowth pauses an automatic post-flush
// hole punch while the volume has no other free blocks and verifies that both
// direct writes and mapped write-backs wait for the punch to finish and reuse
// the punched blocks without growing the volume.
func TestAllocWaitsForInFlightHolePunchWithoutGrowth(t *testing.T) {
	for _, mode := range []string{"pwrite", "mapped_writeback"} {
		t.Run(mode, func(t *testing.T) {
			auNoFlusher(t)
			base := newAuFile(nil)
			punchStarted := make(chan struct{})
			releasePunch := make(chan struct{})
			var armed sync.Once
			var trigger atomic.Bool
			bf := &blockingPunchFile{
				auFile: base,
				onPunch: func(_, _ int64) {
					if !trigger.Load() {
						return
					}
					armed.Do(func() { close(punchStarted) })
					<-releasePunch
				},
			}
			v, err := mountHostFile(bf, VolumeOptions{})
			if err != nil {
				t.Fatalf("mountHostFile: %v", err)
			}
			v.now = fakeClock()
			e := mountVolume(t, &Volume{v: v}, "audit.ext4", vfs.MountOptions{})
			d := &auDrv{t: t, e: e, f: base, m: newAuModel()}

			const punchBlocks = 16
			const punchBytes = punchBlocks * blockSize
			d.create("/punch", punchBytes)
			d.create("/out", 0)
			if mode == "mapped_writeback" {
				// Extend /out as a sparse hole before filling group 0 so mapped
				// stores allocate blocks during FlushLocked inside mp.remove().
				d.truncate("/out", punchBytes)
			}
			v.mu.Lock()
			free := int(v.groups[0].desc.freeBlocks)
			v.mu.Unlock()
			d.create("/fill", free*blockSize)
			d.syncAll()
			if got := v.numGroups(); got != 1 {
				t.Fatalf("groups after fill = %d, want 1", got)
			}
			d.unlink("/punch")

			trigger.Store(true)
			syncErr := make(chan error, 1)
			go func() {
				syncErr <- e.fs.syncAll()
			}()

			select {
			case <-punchStarted:
			case <-time.After(10 * time.Second):
				close(releasePunch)
				<-syncErr
				t.Fatal("reclaimAfterFlushLocked did not start PunchHole within 10s")
			}

			want := auFill(11, 0, punchBytes)
			writeDone := make(chan error, 1)
			var mp *mapping
			var fd *vfs.FileDescription
			if mode == "pwrite" {
				fd = e.mustOpen("/out", linux.O_RDWR)
				go func() {
					_, err := fd.PWrite(e.ctx, usermem.BytesIOSequence(want), 0, vfsWriteOpts)
					writeDone <- err
				}()
			} else {
				fd = e.mustOpen("/out", linux.O_RDWR)
				mp = e.mapFile(fd, punchBytes, true)
				mp.store(0, want)
				go func() {
					mp.remove()
					writeDone <- fd.OnClose(e.ctx)
				}()
			}

			select {
			case err := <-writeDone:
				close(releasePunch)
				<-syncErr
				t.Fatalf("write completed prematurely while hole punch was paused (err=%v, groups=%d), want it to wait", err, v.numGroups())
			case <-time.After(30 * time.Millisecond):
			}

			close(releasePunch)
			if err := <-syncErr; err != nil {
				t.Fatalf("syncAll: %v", err)
			}
			if err := <-writeDone; err != nil {
				t.Fatalf("write after punch release: %v", err)
			}
			if got := v.numGroups(); got != 1 {
				t.Fatalf("groups after waiting for punch = %d, want 1", got)
			}
			wantBytes(t, "/out after punch wait", e.readAll(fd), want)
			fd.DecRef(e.ctx)
			d.m.nodes["/out"].data = want

			d.syncAll()
			d.e.unmount()
			final := auFsck(d.f.snapshot(), true)
			if !final.OK() {
				t.Errorf("image after punch wait:\n%s", final)
			}
			for _, msg := range auCompareImage(final, d.m) {
				t.Errorf("image after punch wait: %s", msg)
			}
		})
	}
}

// TestHeldSpaceServesWriteOnFullHost fills group 0 on a host without room for
// a second group and frees one block that the disk records. A write of one
// block cannot grow the volume, so it must flush and use the freed block.
func TestHeldSpaceServesWriteOnFullHost(t *testing.T) {
	d := fillGroupZeroAndHoldOneBlock(t, 16<<20)
	fd := d.e.mustOpen("/out", linux.O_WRONLY)
	defer fd.DecRef(d.e.ctx)
	if _, err := fd.PWrite(d.e.ctx, usermem.BytesIOSequence(auFill(8, 0, blockSize)), 0, vfsWriteOpts); err != nil {
		t.Errorf("a write of the size of the held block fails with %v", err)
	}
	if n := d.e.fs.v.numGroups(); n != 1 {
		t.Errorf("the volume has %d groups on a host without room, want 1", n)
	}
}

// TestHeldSpaceServesWriteWhenGrowthFailsOtherwise fills group 0 and frees one
// block that the disk records. The host then rejects every growth with an error
// that does not mean "disk full", as a quota or a file size limit does. A write
// of one block must flush and use the freed block, because the flush releases
// space without the host.
func TestHeldSpaceServesWriteWhenGrowthFailsOtherwise(t *testing.T) {
	d := fillGroupZeroAndHoldOneBlock(t, -1)
	errQuota := errors.New("host: file size limit reached")
	d.f.mu.Lock()
	d.f.fail = func(kind auOpKind, _ int) error {
		if kind == auEnsure {
			return errQuota
		}
		return nil
	}
	d.f.mu.Unlock()

	fd := d.e.mustOpen("/out", linux.O_WRONLY)
	defer fd.DecRef(d.e.ctx)
	if _, err := fd.PWrite(d.e.ctx, usermem.BytesIOSequence(auFill(9, 0, blockSize)), 0, vfsWriteOpts); err != nil {
		t.Errorf("a write of the size of the held block fails with %v", err)
	}
	if n := d.e.fs.v.numGroups(); n != 1 {
		t.Errorf("the volume has %d groups after the failed growth, want 1", n)
	}
}

// TestHeldSpaceServesMappedFsyncOnFullHost fills group 0 on a full host, holds
// one freed block, dirties a writable mapping of /out, and verifies fsync
// flushes held space and persists the mapped bytes without growing the volume.
func TestHeldSpaceServesMappedFsyncOnFullHost(t *testing.T) {
	auNoFlusher(t)
	f := newAuFile(nil)
	f.avail = 16 << 20
	d := auMount(t, f, newAuModel())
	d.create("/small", blockSize)
	d.create("/out", 0)
	d.truncate("/out", blockSize)
	v := d.e.fs.v
	v.mu.Lock()
	free := int(v.groups[0].desc.freeBlocks)
	v.mu.Unlock()
	d.create("/fill", free*blockSize)
	d.syncAll()
	if v.numGroups() != 1 {
		t.Fatalf("the volume has %d groups, want 1 full group", v.numGroups())
	}
	d.unlink("/small")

	want := auFill(12, 0, blockSize)
	fd := d.e.mustOpen("/out", linux.O_RDWR)
	mp := d.e.mapFile(fd, blockSize, true)
	mp.store(0, want)
	if err := fd.Sync(d.e.ctx); err != nil {
		t.Fatalf("fsync with held space fails with %v", err)
	}
	mp.remove()
	if err := fd.OnClose(d.e.ctx); err != nil {
		t.Fatalf("OnClose: %v", err)
	}
	if n := v.numGroups(); n != 1 {
		t.Fatalf("groups after fsync on full host = %d, want 1", n)
	}
	wantBytes(t, "/out after mapped fsync", d.e.readAll(fd), want)
	fd.DecRef(d.e.ctx)
}

// TestFsyncAfterFailedUnmapWriteBackReportsENOSPC verifies that fsync still
// reports ENOSPC when an earlier RemoveMapping write-back failed and discarded
// dirty chunks before fsync ran.
func TestFsyncAfterFailedUnmapWriteBackReportsENOSPC(t *testing.T) {
	d := fillGroupZeroAndHoldOneBlock(t, 16<<20)
	const size = 4 * blockSize
	d.truncate("/out", size)
	fd := d.e.mustOpen("/out", linux.O_RDWR)
	defer fd.DecRef(d.e.ctx)

	mp := d.e.mapFile(fd, size, true)
	mp.store(0, auFill(13, 0, size))
	// Ending the only mapping flushes dirty chunks, fails with ENOSPC while
	// holding 1 block vs 4 needed, drops chunks, and records errSpaceHeld in WBErr.
	mp.remove()

	if err := fd.Sync(d.e.ctx); !errors.Is(err, linuxerr.ENOSPC) {
		t.Fatalf("fsync after failed unmap write-back = %v, want ENOSPC", err)
	}
}

// fillGroupZeroWithSharedCapAndHoldOneBlock mounts a 16 MiB-capped volume
// where /out has one data block plus security.capability and user.keep in an
// xattr block shared with /g, and group 0 has zero unheld free blocks and one
// held block.
func fillGroupZeroWithSharedCapAndHoldOneBlock(t *testing.T) *env {
	t.Helper()
	auNoFlusher(t)
	d0 := newAuDrv(t)
	d0.create("/out", blockSize)
	d0.create("/g", 0)
	capV2 := "\x01\x00\x00\x02" + "\x02\x00\x00\x00" + "\x00\x00\x00\x00" + "\x00\x00\x00\x00" + "\x00\x00\x00\x00"
	if err := auSetXattr(d0.e, "/out", linux.XATTR_SECURITY_CAPABILITY, capV2); err != nil {
		t.Fatalf("set security.capability: %v", err)
	}
	if err := auSetXattr(d0.e, "/out", "user.keep", "v"); err != nil {
		t.Fatalf("set user.keep: %v", err)
	}
	d0.e.unmount()
	base := d0.f.snapshot()
	tree := auFsck(base, true).Tree
	outRaw := auRawInode(base, tree["/out"].ino)
	acl := uint64(auLE.Uint32(outRaw[0x68:])) | uint64(auLE.Uint16(outRaw[0x76:]))<<32
	gRaw := auRawInode(base, tree["/g"].ino)
	auLE.PutUint32(gRaw[0x68:], uint32(acl))
	auLE.PutUint16(gRaw[0x76:], uint16(acl>>32))
	auLE.PutUint32(gRaw[0x1C:], auLE.Uint32(gRaw[0x1C:])+8)
	auWriteRawInode(base, tree["/g"].ino, gRaw)
	base.writeAt([]byte{2, 0, 0, 0}, int64(acl)*auBlock+4)

	e, fl := auMountImage(t, base)
	fl.mu.Lock()
	fl.avail = 16 << 20
	fl.mu.Unlock()

	e.writeFile("/held", auFill(1, 0, blockSize))
	v := e.fs.v
	v.mu.Lock()
	free := int(v.groups[0].desc.freeBlocks)
	v.mu.Unlock()
	if free > 0 {
		e.writeFile("/fill", auFill(2, 0, free*blockSize))
	}
	auFlush(t, e)
	if got := v.numGroups(); got != 1 {
		t.Fatalf("groups after fill = %d, want 1", got)
	}
	if err := e.unlink("/held"); err != nil {
		t.Fatalf("unlink /held: %v", err)
	}
	if !v.hasHeld() {
		t.Fatal("/held block is not held before PWrite")
	}
	return e
}

// TestPWriteClearsCapabilityUnderHeldSpace verifies that overwriting an existing
// file whose security.capability shares an xattr block allocates a CoW xattr
// block after flushing held space without failing or leaving capability intact.
func TestPWriteClearsCapabilityUnderHeldSpace(t *testing.T) {
	e := fillGroupZeroWithSharedCapAndHoldOneBlock(t)
	fd := e.mustOpen("/out", linux.O_WRONLY)
	defer fd.DecRef(e.ctx)
	if _, err := fd.PWrite(e.ctx, usermem.BytesIOSequence(auFill(15, 0, blockSize)), 0, vfsWriteOpts); err != nil {
		t.Fatalf("PWrite over existing block with shared xattr under held space: %v", err)
	}
	if _, err := auGetXattr(e, "/out", linux.XATTR_SECURITY_CAPABILITY); !errors.Is(err, linuxerr.ENODATA) {
		t.Fatalf("security.capability after PWrite = %v, want ENODATA", err)
	}
	if got, err := auGetXattr(e, "/out", "user.keep"); err != nil || got != "v" {
		t.Fatalf("user.keep after PWrite = (%q, %v), want (%q, nil)", got, err, "v")
	}
	if got := e.fs.v.numGroups(); got != 1 {
		t.Fatalf("groups after PWrite clearing capability = %d, want 1", got)
	}
}

// TestPWritePartialWriteClearsCapabilityUnderHeldSpace verifies that when the
// first pass of a multi-block PWrite overwrites an existing block and fails CoW
// capability removal with errSpaceHeld, the retry removes security.capability
// first even when writing the tail fails with ENOSPC.
func TestPWritePartialWriteClearsCapabilityUnderHeldSpace(t *testing.T) {
	e := fillGroupZeroWithSharedCapAndHoldOneBlock(t)
	fd := e.mustOpen("/out", linux.O_WRONLY)
	defer fd.DecRef(e.ctx)
	n, err := fd.PWrite(e.ctx, usermem.BytesIOSequence(auFill(16, 0, 2*blockSize)), 0, vfsWriteOpts)
	if n != blockSize || !errors.Is(err, linuxerr.ENOSPC) {
		t.Fatalf("partial PWrite = (%d, %v), want (%d, ENOSPC)", n, err, blockSize)
	}
	if _, err := auGetXattr(e, "/out", linux.XATTR_SECURITY_CAPABILITY); !errors.Is(err, linuxerr.ENODATA) {
		t.Fatalf("security.capability after partial PWrite = %v, want ENODATA", err)
	}
	if got, err := auGetXattr(e, "/out", "user.keep"); err != nil || got != "v" {
		t.Fatalf("user.keep after partial PWrite = (%q, %v), want (%q, nil)", got, err, "v")
	}
}

// TestRenameGrowsDirectoryUnderHeldSpace verifies that RenameAt allocating a
// new directory block under held space preserves errSpaceHeld across runSteps,
// retries cleanly, and succeeds while keeping consistency.
func TestRenameGrowsDirectoryUnderHeldSpace(t *testing.T) {
	auNoFlusher(t)
	f := newAuFile(nil)
	d := auMount(t, f, newAuModel())
	e := d.e
	d.mkdir("/src")
	d.mkdir("/dst")

	// Fill /dst's initial 4 KB directory block almost to capacity with long
	// filenames so one more entry requires a new directory block.
	prefix := strings.Repeat("d", 190)
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("/dst/%s_%02d", prefix, i)
		d.create(name, 0)
	}
	srcName := "/src/" + strings.Repeat("s", 190)
	d.create(srcName, 0)
	d.create("/held", blockSize)

	v := e.fs.v
	v.mu.Lock()
	free := int(v.groups[0].desc.freeBlocks)
	v.mu.Unlock()
	if free > 0 {
		d.create("/fill", free*blockSize)
	}
	d.syncAll()
	d.unlink("/held")
	if !v.hasHeld() {
		t.Fatal("/held block is not held before RenameAt")
	}

	dstName := "/dst/" + strings.Repeat("r", 190)
	if err := e.rename(srcName, dstName); err != nil {
		t.Fatalf("RenameAt needing new dir block under held space: %v", err)
	}
	if got := v.numGroups(); got != 1 {
		t.Fatalf("groups after RenameAt reusing held block = %d, want 1", got)
	}
	d.syncAll()
	d.e.unmount()
	final := auFsck(d.f.snapshot(), true)
	if !final.OK() {
		t.Fatalf("fsck after RenameAt:\n%s", final)
	}
}
