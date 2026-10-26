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
	"fmt"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/usermem"
)

// auRaceWithFlush starts a flush and stops it while it copies the state. The
// flush copies the dirty nodes in the order of their inode numbers, so a lock on
// the node blocker holds it in the middle of the copy. The test then starts op
// and checks that op waits. The flush ends when the lock goes, and op runs after
// it. The function returns the error of the flush and the error of op.
func auRaceWithFlush(t *testing.T, d *auDrv, blocker *node, op func() error) (flushErr, opErr error) {
	t.Helper()
	v := d.e.fs.v
	blocker.mu.Lock()
	flushDone := make(chan struct{})
	go func() {
		defer close(flushDone)
		flushErr = d.e.fs.syncAll()
	}()
	// The flush has taken its list of dirty nodes when the set is empty.
	deadline := time.Now().Add(10 * time.Second)
	for {
		v.nodeMu.Lock()
		n := len(v.dirtyNodes)
		v.nodeMu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			blocker.mu.Unlock()
			t.Fatal("the flush did not take its list of dirty nodes")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)

	opDone := make(chan struct{})
	go func() {
		defer close(opDone)
		opErr = op()
	}()
	select {
	case <-opDone:
		blocker.mu.Unlock()
		<-flushDone
		t.Errorf("a guest operation ran while the flush copied the state")
		return flushErr, opErr
	case <-time.After(100 * time.Millisecond):
	}
	blocker.mu.Unlock()
	<-flushDone
	<-opDone
	return flushErr, opErr
}

func auNodeOf(t *testing.T, d *auDrv, path string) *node {
	t.Helper()
	st := d.e.mustStat(path)
	n, err := d.e.fs.v.getNode(uint32(st.Ino))
	if err != nil {
		t.Fatalf("getNode %s: %v", path, err)
	}
	t.Cleanup(func() { d.e.fs.v.putNode(n) })
	return n
}

// TestAuditFlushSnapshotIsACutBetweenOperations stops a flush in the middle of
// its copy and starts the creation of a file in a directory that the flush
// copies later. The creation must wait for the end of the copy. Otherwise the
// directory image names an inode that the plan does not hold, and a crash after
// the sync leaves a directory entry for an inode that the disk does not have.
func TestAuditFlushSnapshotIsACutBetweenOperations(t *testing.T) {
	d := newAuDrv(t)
	d.create("/blocker", 10) // inode 11, copied before the directory
	d.mkdir("/dir")          // inode 12
	blocker := auNodeOf(t, d, "/blocker")

	flushErr, opErr := auRaceWithFlush(t, d, blocker, func() error {
		fd, err := d.e.open("/dir/late", linux.O_CREAT|linux.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		fd.DecRef(d.e.ctx)
		return nil
	})
	if flushErr != nil || opErr != nil {
		t.Fatalf("flush: %v, create: %v", flushErr, opErr)
	}
	// The sync has returned. A SIGKILL now must leave a mountable image.
	res, err := auRecover(t, d.f.snapshot())
	if err != nil {
		t.Fatalf("the engine does not mount the image after a completed sync: %v", err)
	}
	if !res.OK() {
		t.Errorf("image:\n%s", res)
	}
}

// TestAuditFlushDoesNotCopyAFreedBlockOfAnEarlierNode stops a flush after it
// copied a file that owns two blocks. A truncate of that file and the creation
// of a new file must wait, because the new file would take the freed blocks
// while the plan still names them for the old file. After the sync, a crash must
// leave the old file with its own data.
func TestAuditFlushDoesNotCopyAFreedBlockOfAnEarlierNode(t *testing.T) {
	d := newAuDrv(t)
	d.create("/victim", 2*blockSize) // inode 11: in the plan before the stop
	d.create("/blocker", 10)         // inode 12: the flush stops here
	blocker := auNodeOf(t, d, "/blocker")

	flushErr, opErr := auRaceWithFlush(t, d, blocker, func() error {
		if err := d.e.setStat("/victim", linux.Statx{Mask: linux.STATX_SIZE}); err != nil {
			return err
		}
		fd, err := d.e.open("/thief", linux.O_CREAT|linux.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer fd.DecRef(d.e.ctx)
		_, err = fd.PWrite(d.e.ctx, usermem.BytesIOSequence(auFill(777, 0, 2*blockSize)), 0, vfsWriteOpts)
		return err
	})
	if flushErr != nil || opErr != nil {
		t.Fatalf("flush: %v, truncate and create: %v", flushErr, opErr)
	}
	res, err := auRecover(t, d.f.snapshot())
	if err != nil {
		t.Fatalf("the engine does not mount the image after a completed sync: %v", err)
	}
	if !res.OK() {
		t.Fatalf("image:\n%s", res)
	}
	if e := res.Tree["/victim"]; e == nil || !auOwnBytes(e.data, d.m.nodes["/victim"].id) {
		t.Errorf("/victim shows bytes of another file after the crash")
	}
}

// TestAuditFormatIsAtomic crashes at every host call of the first format of a
// volume file. A crash must leave a file that the next open either mounts or
// formats again. The format extends the file to one group first and writes the
// superblock last, so a crash between the two leaves a 16 MiB file of zeros
// that the next open refuses with EUCLEAN, and every later open fails the same
// way.
func TestAuditFormatIsAtomic(t *testing.T) {
	f := newAuFile(nil)
	base, end := f.beginWindow()
	if err := formatVolume(f, testNow); err != nil {
		t.Fatal(err)
	}
	w := end()
	_ = base
	var problems []string
	for n := 0; n <= len(w.ops); n++ {
		img := w.prefix(n)
		v, err := mountHostFile(newAuFile(img), VolumeOptions{})
		if err != nil {
			problems = append(problems, fmt.Sprintf("open after %d of %d host calls of the format fails: %v", n, len(w.ops), err))
			continue
		}
		if err := (&Volume{v: v}).Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	}
	if len(problems) > 3 {
		problems = append(problems[:3], fmt.Sprintf("... %d states in all", len(problems)))
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// TestAuditFlushFailureIsRetryable fails each host call of a flush in turn. A
// failure before the transaction is durable must reach the caller. A failure
// of a home write after the commit does not fail the sync, because a crash
// would replay the transaction; reads must still see the new blocks. A later
// sync must make the whole state durable, with no lost change and no
// inconsistency.
func TestAuditFlushFailureIsRetryable(t *testing.T) {
	workload := func(d *auDrv) {
		d.mkdir("/d")
		d.create("/d/a", 30_000)
		d.create("/d/b", 100)
		d.mkdir("/d/sub")
		d.rename("/d/b", "/d/sub/b2")
		d.create("/big", 5<<20)
		d.unlink("/d/a")
		d.create("/d/c", 9_000)
		d.symlink("target", "/d/ln")
		d.link("/big", "/d/biglink")
	}

	// Count the host calls of one flush.
	d0 := newAuDrv(t)
	workload(d0)
	before := d0.f.mark()
	d0.syncAll()
	calls := d0.f.mark() - before
	if calls < 5 {
		t.Fatalf("a flush made %d host calls, want at least 5", calls)
	}
	// The commit is durable at the first write that follows a flush call and
	// that lies outside the journal.
	jl := d0.e.fs.v.j.extents[0]
	jlo, jhi := int64(jl.pblk)*auBlock, int64(jl.pblk+uint64(jl.n))*auBlock
	d0.f.mu.Lock()
	durableAt := calls
	for i := before + 1; i < len(d0.f.log); i++ {
		op := d0.f.log[i]
		if op.kind == auWrite && d0.f.log[i-1].kind == auSync && (op.off < jlo || op.off >= jhi) {
			durableAt = i - before
			break
		}
	}
	d0.f.mu.Unlock()

	for target := range calls {
		t.Run(fmt.Sprint("call", target), func(t *testing.T) {
			d := newAuDrv(t)
			workload(d)
			d.f.mu.Lock()
			d.f.nCalls = 0
			d.f.fail = func(kind auOpKind, idx int) error {
				if idx == target {
					return errAuInjected
				}
				return nil
			}
			d.f.mu.Unlock()
			err := d.e.fs.syncAll()
			if target < durableAt && err == nil {
				t.Fatalf("sync succeeded although host call %d of %d failed before the commit", target, durableAt)
			}
			d.verifyLive("live tree right after the failed flush")
			d.f.mu.Lock()
			d.f.fail = nil
			d.f.mu.Unlock()
			d.syncAll()

			res, err := auRecover(t, d.f.snapshot())
			if err != nil {
				t.Fatalf("mount after the retry: %v", err)
			}
			if !res.OK() {
				t.Errorf("image after the retry:\n%s", res)
			}
			for _, msg := range auCompareImage(res, d.m) {
				t.Errorf("after the retry: %s", msg)
			}
			d.verifyLive("live tree after the failed flush")
		})
	}
}

// TestAuditSyncMakesStateDurable checks the basic promise at every kind of
// object. After a sync, a crash must lose nothing, whatever mix of operations
// came before.
func TestAuditSyncMakesStateDurable(t *testing.T) {
	d := newAuDrv(t)
	auRichWorkload(d)
	d.syncAll()
	res, err := auRecover(t, d.f.snapshot())
	if err != nil {
		t.Fatalf("mount after a crash that follows a sync: %v", err)
	}
	if !res.OK() {
		t.Errorf("repaired image:\n%s", res)
	}
	for _, msg := range auCompareImage(res, d.m) {
		t.Errorf("synced state: %s", msg)
	}
}

// TestAuditUnsyncedUnlinkOfOpenFile keeps an open descriptor on an unlinked
// file across a sync and a crash. The file must not come back, and its blocks
// must return to the pool at the next mount.
func TestAuditUnsyncedUnlinkOfOpenFile(t *testing.T) {
	d := newAuDrv(t)
	d.create("/ghost", 300_000)
	d.create("/stay", 1000)
	d.syncAll()
	fd := d.e.mustOpen("/ghost", linux.O_RDONLY)
	d.unlink("/ghost")
	d.syncAll()
	var wg sync.WaitGroup
	wg.Go(func() { ; _ = d.e.readAll(fd) })
	wg.Wait()

	res, err := auRecover(t, d.f.snapshot())
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	if !res.OK() {
		t.Errorf("repaired image:\n%s", res)
	}
	if res.Tree["/ghost"] != nil {
		t.Errorf("the unlinked file is back")
	}
	for _, msg := range auCompareImage(res, d.m) {
		t.Errorf("%s", msg)
	}
	fd.DecRef(d.e.ctx)
}
