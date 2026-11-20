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
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
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
