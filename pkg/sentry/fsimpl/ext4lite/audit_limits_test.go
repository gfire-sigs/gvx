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
	"math/rand/v2"
	"slices"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/usermem"
)

// TestAuditNoSpace fills a volume whose host has little room. The guest must
// see ENOSPC and nothing else. The image must stay consistent, every byte that
// the guest wrote before the error must stay readable, and the space must come
// back after the guest deletes the files.
func TestAuditNoSpace(t *testing.T) {
	auNoFlusher(t)
	f := newAuFile(nil)
	f.avail = 40 << 20 // the host volume has room for two groups
	d := auMount(t, f, newAuModel())

	const chunk = 1 << 20
	var names []string
	var failure error
	var partial int
	for i := 0; failure == nil; i++ {
		if i > 200 {
			t.Fatal("the volume accepted 200 MiB on a host with 40 MiB")
		}
		p := fmt.Sprintf("/f%03d", i)
		fd, err := d.e.open(p, linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY, 0o644)
		if err != nil {
			failure = err
			break
		}
		d.m.nextID++
		id := d.m.nextID
		node := &auMNode{id: id}
		d.m.nodes[p] = node
		d.m.note(p, id)
		names = append(names, p)
		for off := 0; off < 4*chunk; off += chunk {
			n, err := fd.PWrite(d.e.ctx, usermem.BytesIOSequence(auFill(id, uint64(off), chunk)), int64(off), vfsWriteOpts)
			node.data = append(node.data, auFill(id, uint64(off), int(n))...)
			if err != nil {
				failure, partial = err, int(n)
				break
			}
		}
		fd.DecRef(d.e.ctx)
	}
	if !errors.Is(failure, linuxerr.ENOSPC) {
		t.Fatalf("the error of a full volume is %v, want ENOSPC", failure)
	}
	t.Logf("%d files, the last one partial with %d bytes of its failing write", len(names), partial)
	d.verifyLive("after ENOSPC")
	d.syncAll()

	// A crash at this point must keep what the guest wrote.
	res, err := auRecover(t, d.f.snapshot())
	if err != nil {
		t.Fatalf("mount after ENOSPC and a sync: %v", err)
	}
	if !res.OK() {
		t.Errorf("image after ENOSPC:\n%s", res)
	}
	for _, msg := range auCompareImage(res, d.m) {
		t.Errorf("after ENOSPC: %s", msg)
	}

	// Deleting returns the space.
	for _, p := range names[1:] {
		d.unlink(p)
	}
	d.syncAll()
	d.create("/again", 3<<20)
	d.verifyLive("after the delete")
	d.e.unmount()
	final := auFsck(f.snapshot(), true)
	if !final.OK() {
		t.Errorf("final image:\n%s", final)
	}
	for _, msg := range auCompareImage(final, d.m) {
		t.Errorf("final image: %s", msg)
	}
}

// TestAuditNoInodes fills the inodes of a volume that cannot grow.
// The error must be ENOSPC, as for blocks.
func TestAuditNoInodes(t *testing.T) {
	auNoFlusher(t)
	f := newAuFile(nil)
	f.avail = 16 << 20 // no room for a second group
	d := auMount(t, f, newAuModel())
	var failure error
	n := 0
	for ; n < 5000 && failure == nil; n++ {
		fd, err := d.e.open(fmt.Sprintf("/i%05d", n), linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY, 0o644)
		if err != nil {
			failure = err
			break
		}
		fd.DecRef(d.e.ctx)
	}
	if !errors.Is(failure, linuxerr.ENOSPC) {
		t.Fatalf("error after %d files is %v, want ENOSPC", n, failure)
	}
	// Group 0 has 4096 inodes, and the first 10 are reserved.
	if n != 4086 {
		t.Errorf("the volume held %d files before ENOSPC, want 4086", n)
	}
	d.e.unmount()
	if res := auFsck(f.snapshot(), true); !res.OK() {
		t.Errorf("image:\n%s", res)
	}
}

// auWorker runs random operations in its own directory with no help from the
// driver, which stops the test from a failing goroutine. It returns the files
// that it expects.
func auWorker(e *env, w int, rng *rand.Rand, n int) (map[string][]byte, error) {
	dir := fmt.Sprintf("/w%d", w)
	if err := e.mkdir(dir); err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	ids := map[string]uint32{}
	var seq uint32
	for range n {
		var names []string
		for p := range files {
			names = append(names, p)
		}
		slices.Sort(names)
		switch r := rng.IntN(10); {
		case r < 3 || len(names) == 0:
			seq++
			p := fmt.Sprintf("%s/f%d", dir, seq)
			id := uint32(w)*1_000_000 + seq
			size := auSizes[rng.IntN(len(auSizes))]
			fd, err := e.open(p, linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY, 0o644)
			if err != nil {
				return nil, fmt.Errorf("create %s: %w", p, err)
			}
			if size > 0 {
				if _, err := fd.PWrite(e.ctx, usermem.BytesIOSequence(auFill(id, 0, size)), 0, vfsWriteOpts); err != nil {
					return nil, fmt.Errorf("write %s: %w", p, err)
				}
			}
			fd.DecRef(e.ctx)
			files[p], ids[p] = auFill(id, 0, size), id
		case r < 6:
			p := names[rng.IntN(len(names))]
			off := rng.IntN(len(files[p]) + 5000)
			n := 1 + rng.IntN(9000)
			fd, err := e.open(p, linux.O_WRONLY, 0)
			if err != nil {
				return nil, fmt.Errorf("open %s: %w", p, err)
			}
			if _, err := fd.PWrite(e.ctx, usermem.BytesIOSequence(auFill(ids[p], uint64(off), n)), int64(off), vfsWriteOpts); err != nil {
				return nil, fmt.Errorf("pwrite %s: %w", p, err)
			}
			if fd.Sync(e.ctx) != nil {
				return nil, fmt.Errorf("fsync %s", p)
			}
			fd.DecRef(e.ctx)
			if end := off + n; end > len(files[p]) {
				files[p] = append(files[p], make([]byte, end-len(files[p]))...)
			}
			copy(files[p][off:], auFill(ids[p], uint64(off), n))
		case r < 7:
			p := names[rng.IntN(len(names))]
			size := rng.IntN(len(files[p]) + 3000)
			if err := e.setStat(p, linux.Statx{Mask: linux.STATX_SIZE, Size: uint64(size)}); err != nil {
				return nil, fmt.Errorf("truncate %s: %w", p, err)
			}
			if size <= len(files[p]) {
				files[p] = files[p][:size]
			} else {
				files[p] = append(files[p], make([]byte, size-len(files[p]))...)
			}
		case r < 9:
			p := names[rng.IntN(len(names))]
			if err := e.unlink(p); err != nil {
				return nil, fmt.Errorf("unlink %s: %w", p, err)
			}
			delete(files, p)
			delete(ids, p)
		default:
			p := names[rng.IntN(len(names))]
			seq++
			q := fmt.Sprintf("%s/r%d", dir, seq)
			if err := e.rename(p, q); err != nil {
				return nil, fmt.Errorf("rename %s: %w", p, err)
			}
			files[q], ids[q] = files[p], ids[p]
			delete(files, p)
			delete(ids, p)
		}
	}
	return files, nil
}

// TestAuditConcurrentWorkers runs several writers in separate directories
// while the background flusher runs every millisecond and a second goroutine
// syncs in a loop. The final tree must equal the union of the private models,
// and the image must pass the oracle. Run it with -race.
func TestAuditConcurrentWorkers(t *testing.T) {
	old := flushIntervalNanos.Load()
	flushIntervalNanos.Store(int64(time.Millisecond))
	t.Cleanup(func() { flushIntervalNanos.Store(old) })
	f := newAuFile(nil)
	d := auMount(t, f, newAuModel())

	const workers = 6
	results := make([]map[string][]byte, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			results[w], errs[w] = auWorker(d.e, w, rand.New(rand.NewPCG(uint64(w), 11)), 500)
		})
	}
	stop := make(chan struct{})
	var syncErr error
	var syncWG sync.WaitGroup
	syncWG.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := d.e.fs.syncAll(); err != nil {
				syncErr = err
				return
			}
			time.Sleep(time.Millisecond)
		}
	})
	wg.Wait()
	close(stop)
	syncWG.Wait()
	if syncErr != nil {
		t.Fatalf("sync: %v", syncErr)
	}
	for w, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", w, err)
		}
	}
	for w, files := range results {
		dir := fmt.Sprintf("/w%d", w)
		d.m.nodes[dir] = &auMNode{id: uint32(w) + 1, dir: true}
		for p, data := range files {
			d.m.nodes[p] = &auMNode{id: uint32(w) + 1, data: data}
		}
	}
	d.verifyLive("after the run")
	d.e.unmount()
	res := auFsck(f.snapshot(), true)
	if !res.OK() {
		t.Fatalf("image:\n%s", res)
	}
	for _, msg := range auCompareImage(res, d.m) {
		t.Errorf("image: %s", msg)
	}
}
