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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
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
