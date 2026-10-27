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
	"bytes"
	"fmt"
	"sync"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

var vfsReadOpts = vfs.ReadOptions{}

// TestAuditCompactionKeepsFragmentedFile fragments the free space of group 0
// and keeps a 1500-block file in group 1. The unmount moves the file into the
// holes. The move needs 1500 extents, which a depth-2 tree holds. The unmount
// must leave an image that mounts and matches the model.
func TestAuditCompactionKeepsFragmentedFile(t *testing.T) {
	d := newAuDrv(t)
	var small []string
	for i := 0; d.e.fs.v.numGroups() < 2; i++ {
		if i > 6000 {
			t.Fatal("group 0 did not fill")
		}
		p := fmt.Sprintf("/s%04d", i)
		d.create(p, blockSize)
		small = append(small, p)
	}
	d.create("/big", 1500*blockSize)
	for i := 0; i < len(small); i += 2 {
		d.unlink(small[i])
	}
	d.e.unmount()

	var problems []string
	res, err := auRecover(t, d.f.snapshot())
	switch {
	case err != nil:
		problems = append(problems, "the volume does not mount after the unmount: "+err.Error())
	case !res.OK():
		problems = append(problems, res.Problems...)
	default:
		problems = append(problems, auCompareImage(res, d.m)...)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// TestAuditInterleavedAppendersKeepWorking appends 4 KiB at a time to two
// files in turn. Each write lands after a block of the other file, so each
// file gets one extent per write. The files outgrow a depth-1 tree, and the
// volume must keep them growing, as ext4 does.
func TestAuditInterleavedAppendersKeepWorking(t *testing.T) {
	d := newAuDrv(t)
	d.create("/a", 0)
	d.create("/b", 0)
	fa := d.e.mustOpen("/a", linux.O_WRONLY)
	fb := d.e.mustOpen("/b", linux.O_WRONLY)
	defer fa.DecRef(d.e.ctx)
	defer fb.DecRef(d.e.ctx)
	var problems []string
	for i := range 6000 {
		off := int64(i) * blockSize
		if _, err := fa.PWrite(d.e.ctx, usermem.BytesIOSequence(auFill(2, uint64(off), blockSize)), off, vfsWriteOpts); err != nil {
			problems = append(problems, fmt.Sprintf("append %d to /a fails with %v although the volume has free space", i, err))
			break
		}
		if _, err := fb.PWrite(d.e.ctx, usermem.BytesIOSequence(auFill(3, uint64(off), blockSize)), off, vfsWriteOpts); err != nil {
			problems = append(problems, fmt.Sprintf("append %d to /b fails with %v although the volume has free space", i, err))
			break
		}
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// TestAuditDepthTwoTreeSurvivesRemount appends to two files in turn, so that
// each holds more than 1360 extents and needs a depth-2 tree. The volume
// unmounts, mounts the image again, and reads both files back byte for byte.
func TestAuditDepthTwoTreeSurvivesRemount(t *testing.T) {
	const blocks = 1500
	d := newAuDrv(t)
	d.create("/a", 0)
	d.create("/b", 0)
	fa := d.e.mustOpen("/a", linux.O_WRONLY)
	fb := d.e.mustOpen("/b", linux.O_WRONLY)
	for i := range blocks {
		off := int64(i) * blockSize
		if _, err := fa.PWrite(d.e.ctx, usermem.BytesIOSequence(auFill(2, uint64(off), blockSize)), off, vfsWriteOpts); err != nil {
			t.Fatalf("append %d to /a: %v", i, err)
		}
		if _, err := fb.PWrite(d.e.ctx, usermem.BytesIOSequence(auFill(3, uint64(off), blockSize)), off, vfsWriteOpts); err != nil {
			t.Fatalf("append %d to /b: %v", i, err)
		}
	}
	fa.DecRef(d.e.ctx)
	fb.DecRef(d.e.ctx)
	d.e.unmount()

	img := d.f.snapshot()
	res, err := auRecover(t, img)
	if err != nil || !res.OK() {
		t.Fatalf("the image does not pass the oracle: err %v, problems %v", err, res.Problems)
	}
	d2 := auMount(t, newAuFile(img.clone()), newAuModel())
	defer d2.e.unmount()
	for _, c := range []struct {
		path string
		id   uint32
	}{{"/a", 2}, {"/b", 3}} {
		n := auNodeOf(t, d2, c.path)
		n.mu.RLock()
		exts, ixs := len(n.exts), len(n.ixs)
		n.mu.RUnlock()
		if exts <= rootExtents*leafExtents || ixs == 0 {
			t.Errorf("%s has %d extents in %d index blocks after the remount, want a depth-2 tree", c.path, exts, ixs)
		}
		want := auFill(c.id, 0, blocks*blockSize)
		if got := d2.e.readFile(c.path); !bytes.Equal(got, want) {
			t.Errorf("%s after the remount differs at byte %d", c.path, auFirstDiff(got, want))
		}
	}
}

// TestExtentCapacityIsENOSPC asks for one extent more than the configured tree
// cap holds. The call must fail with ENOSPC and leave the node unchanged.
func TestExtentCapacityIsENOSPC(t *testing.T) {
	oldCap := maxTreeExtents
	maxTreeExtents = 2048
	t.Cleanup(func() { maxTreeExtents = oldCap })
	d := newAuDrv(t)
	d.create("/f", 2*blockSize)
	n := auNodeOf(t, d, "/f")
	n.mu.Lock()
	before := append([]extent(nil), n.exts...)
	err := n.setExtentsLocked(make([]extent, maxTreeExtents+1))
	after := n.exts
	n.mu.Unlock()
	if !linuxerr.Equals(linuxerr.ENOSPC, err) {
		t.Errorf("a list of %d extents fails with %v, want ENOSPC", maxTreeExtents+1, err)
	}
	if !sameExtents(before, after) {
		t.Errorf("the failed update changed the extent list of the node")
	}
}

// TestAuditFailedWriteLeavesNoStaleBlocks fails the host write of a file after
// the engine mapped the blocks of the file. The blocks come from a deleted
// file that held 0xAA. The failed write must leave nothing mapped that a later
// extend can expose as data.
func TestAuditFailedWriteLeavesNoStaleBlocks(t *testing.T) {
	d := newAuDrv(t)
	d.e.writeFile("/old", bytes.Repeat([]byte{0xAA}, 2<<20))
	d.unlink("/old")
	d.syncAll()

	d.f.mu.Lock()
	d.f.failWrite = func(off int64, n int) error {
		if n >= 1<<20 {
			return errAuInjected
		}
		return nil
	}
	d.f.mu.Unlock()
	fd := d.e.mustOpen("/new", linux.O_CREAT|linux.O_WRONLY)
	defer fd.DecRef(d.e.ctx)
	if _, err := fd.PWrite(d.e.ctx, usermem.BytesIOSequence(bytes.Repeat([]byte{1}, 1<<20)), 0, vfsWriteOpts); err == nil {
		t.Fatal("the write succeeded although the host refused it")
	}
	d.f.mu.Lock()
	d.f.failWrite = nil
	d.f.mu.Unlock()

	d.must("extend", d.e.setStat("/new", linux.Statx{Mask: linux.STATX_SIZE, Size: 1 << 20}))
	var problems []string
	got := d.e.readFile("/new")
	if bad := bytes.Count(got, []byte{0xAA}); bad > 0 {
		problems = append(problems, fmt.Sprintf("/new shows %d bytes of a deleted file after a failed write and an extend", bad))
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// TestAuditShortWriteKeepsFilledPrefix fails a write after the host accepted
// its first 512 KiB. The first part overwrites mapped blocks, and the second
// part maps fresh blocks that the host refuses. The write must report the 512
// KiB that reached the host and keep no fresh block beyond the size.
func TestAuditShortWriteKeepsFilledPrefix(t *testing.T) {
	d := newAuDrv(t)
	d.e.writeFile("/old", bytes.Repeat([]byte{0xAA}, 2<<20))
	d.unlink("/old")
	d.syncAll()
	d.create("/p", 512<<10)
	// The block after /p belongs to /blk, so the fresh run does not join the
	// extent of /p. Otherwise the host sees one write for the whole range.
	d.create("/blk", blockSize)

	d.f.mu.Lock()
	d.f.failWrite = func(off int64, n int) error {
		if n >= 1<<20 {
			return errAuInjected
		}
		return nil
	}
	d.f.mu.Unlock()
	fd := d.e.mustOpen("/p", linux.O_RDWR)
	defer fd.DecRef(d.e.ctx)
	ones := bytes.Repeat([]byte{1}, 1536<<10)
	n, err := fd.PWrite(d.e.ctx, usermem.BytesIOSequence(ones), 0, vfsWriteOpts)
	d.f.mu.Lock()
	d.f.failWrite = nil
	d.f.mu.Unlock()
	if err == nil {
		t.Fatal("the write succeeded although the host refused its second part")
	}
	if n != 512<<10 {
		t.Errorf("the failed write reports %d bytes, want the 524288 that reached the host", n)
	}
	d.must("extend", d.e.setStat("/p", linux.Statx{Mask: linux.STATX_SIZE, Size: 1536 << 10}))
	got := d.e.readFile("/p")
	if len(got) != 1536<<10 {
		t.Fatalf("/p has %d bytes after the extend, want %d", len(got), 1536<<10)
	}
	if !bytes.Equal(got[:512<<10], ones[:512<<10]) {
		t.Errorf("the written prefix differs at byte %d", auFirstDiff(got[:512<<10], ones[:512<<10]))
	}
	if bad := bytes.Count(got[512<<10:], []byte{0xAA}); bad > 0 {
		t.Errorf("%d bytes of a deleted file show after the failed write and an extend", bad)
	}
	if !isZero(got[512<<10:]) {
		t.Errorf("the unwritten tail does not read as zeros")
	}
}

// TestAuditHeldSpaceDoesNotFailFallocate fills group 0, frees one block that
// the disk still records, and calls fallocate. Free space is held until the
// next flush, and the volume can grow by a group. The call must succeed or
// retry. Instead the allocator returns the internal hold error, which reaches
// the guest as ENOSPC, while a write on another file in the same state works.
func TestAuditHeldSpaceDoesNotFailFallocate(t *testing.T) {
	d := newAuDrv(t)
	d.create("/small", blockSize)
	d.create("/other", 0)
	v := d.e.fs.v
	v.mu.Lock()
	free := int(v.groups[0].desc.freeBlocks)
	v.mu.Unlock()
	d.create("/fill", free*blockSize)
	d.syncAll()
	if v.numGroups() != 1 {
		t.Fatalf("the volume has %d groups, want 1 full group", v.numGroups())
	}
	d.unlink("/small") // the block is held until the next flush

	fd := d.e.mustOpen("/other", linux.O_WRONLY)
	defer fd.DecRef(d.e.ctx)
	var problems []string
	if err := fd.Allocate(d.e.ctx, 0, 0, 4*blockSize); err != nil {
		problems = append(problems, fmt.Sprintf("fallocate fails with %v while the volume can grow", err))
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// TestAuditMappedFlushRacesTruncate truncates a file to zero while a read of
// the same file writes back the pages of a writable mapping. The write-back
// reads the size, the truncate runs, and the write-back then writes its pages
// at the old size. The file must end empty.
func TestAuditMappedFlushRacesTruncate(t *testing.T) {
	d := newAuDrv(t)
	e := d.e
	e.writeFile("/m", make([]byte, 64<<10))
	fd := e.mustOpen("/m", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	mp := e.mapFile(fd, 64<<10, true)
	defer mp.remove()

	extend := linux.Statx{Mask: linux.STATX_SIZE, Size: 64 << 10}
	shrink := linux.Statx{Mask: linux.STATX_SIZE, Size: 0}
	page := bytes.Repeat([]byte{0x5A}, 64<<10)
	var buf [1]byte
	bad := 0
	for range 1500 {
		if err := e.setStat("/m", extend); err != nil {
			t.Fatal(err)
		}
		mp.store(0, page)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = fd.PRead(e.ctx, usermem.BytesIOSequence(buf[:]), 0, vfsReadOpts)
		}()
		go func() {
			defer wg.Done()
			_ = e.setStat("/m", shrink)
		}()
		wg.Wait()
		if st := e.mustStat("/m"); st.Size != 0 {
			bad++
		}
	}
	if bad > 0 {
		t.Errorf("ftruncate(0) left a non-empty file in %d of 1500 races", bad)
	}
}

// TestAuditReadDoesNotTouchTimes reads a file that has a writable mapping.
// A read that changes no byte must not change the modification time.
func TestAuditReadDoesNotTouchTimes(t *testing.T) {
	d := newAuDrv(t)
	e := d.e
	e.writeFile("/m", make([]byte, 8192))
	fd := e.mustOpen("/m", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	mp := e.mapFile(fd, 8192, true)
	defer mp.remove()
	mp.store(0, []byte("dirty"))
	var buf [1]byte
	_, _ = fd.PRead(e.ctx, usermem.BytesIOSequence(buf[:]), 0, vfsReadOpts)
	first := e.mustStat("/m").Mtime
	for range 4 {
		_, _ = fd.PRead(e.ctx, usermem.BytesIOSequence(buf[:]), 0, vfsReadOpts)
	}
	if last := e.mustStat("/m").Mtime; last != first {
		t.Error("four reads changed the modification time of an unmodified file")
	}
}

// TestAuditExtentEndDoesNotWrap checks the bound of validExtent. A file has at
// most 2^32-1 blocks, so an extent that ends at 2^32 makes end() wrap to 0 and
// breaks the binary search of every lookup in that file.
func TestAuditExtentEndDoesNotWrap(t *testing.T) {
	d := newAuDrv(t)
	e := extent{lblk: 0xFFFFFFFF, n: 1, pblk: 400}
	if d.e.fs.v.validExtent(e) {
		t.Errorf("validExtent accepts an extent whose end() wraps to 0")
	}
}

// TestFtruncateSameSizeFreesBlocksBeyondEOF maps blocks beyond the end with a
// keep-size fallocate. A truncate to the current size must free them, as Linux
// does.
func TestFtruncateSameSizeFreesBlocksBeyondEOF(t *testing.T) {
	d := newAuDrv(t)
	d.create("/f", blockSize)
	fd := d.e.mustOpen("/f", linux.O_RDWR)
	defer fd.DecRef(d.e.ctx)
	if err := fd.Allocate(d.e.ctx, linux.FALLOC_FL_KEEP_SIZE, blockSize, 4*blockSize); err != nil {
		t.Fatal(err)
	}
	if st := d.e.mustStat("/f"); st.Blocks != 5*blockSize/512 {
		t.Fatalf("after KEEP_SIZE: %d sectors, want %d", st.Blocks, 5*blockSize/512)
	}
	d.must("truncate to the same size", d.e.setStat("/f", linux.Statx{Mask: linux.STATX_SIZE, Size: blockSize}))
	if st := d.e.mustStat("/f"); st.Size != blockSize || st.Blocks != blockSize/512 {
		t.Errorf("after the same-size truncate: size %d, %d sectors; want size %d and %d sectors", st.Size, st.Blocks, blockSize, blockSize/512)
	}
}

// TestFallocateChecksFileSizeLimit grows a file past RLIMIT_FSIZE. Like pwrite,
// the call fails whole. A keep-size call does not grow the file, so it passes.
func TestFallocateChecksFileSizeLimit(t *testing.T) {
	d := newAuDrv(t)
	d.create("/f", 0)
	fd := d.e.mustOpen("/f", linux.O_RDWR)
	defer fd.DecRef(d.e.ctx)
	old := testLimits.Get(limits.FileSize)
	if _, err := testLimits.Set(limits.FileSize, limits.Limit{Cur: 4 * blockSize, Max: old.Max}, true); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = testLimits.Set(limits.FileSize, old, true) }()

	if err := fd.Allocate(d.e.ctx, 0, 0, 8*blockSize); !linuxerr.Equals(linuxerr.EFBIG, err) {
		t.Errorf("fallocate past RLIMIT_FSIZE fails with %v, want EFBIG", err)
	}
	if st := d.e.mustStat("/f"); st.Size != 0 || st.Blocks != 0 {
		t.Errorf("the refused fallocate left size %d and %d sectors", st.Size, st.Blocks)
	}
	if err := fd.Allocate(d.e.ctx, linux.FALLOC_FL_KEEP_SIZE, 0, 8*blockSize); err != nil {
		t.Errorf("a keep-size fallocate past RLIMIT_FSIZE fails with %v, want success", err)
	}
}

// auMarkFirstExtentUninit rewrites the first extent of the root of path in img
// as an uninitialized extent with the same length. The blocks keep their
// bytes, so a read must return zeros while a flush must keep them.
func auMarkFirstExtentUninit(t *testing.T, img *auPages, path string) (lblk, n uint32, pblk uint64) {
	t.Helper()
	res := auFsck(img, true)
	ent := res.Tree[path]
	if ent == nil {
		t.Fatalf("%s is not in the image", path)
	}
	ioff := int64(4)*auBlock + int64(ent.ino-1)*auISize
	var raw [auISize]byte
	img.readAt(raw[:], ioff)
	ee := raw[0x28+12:]
	lblk = auLE.Uint32(ee[0:])
	n = uint32(auLE.Uint16(ee[4:]))
	pblk = uint64(auLE.Uint16(ee[6:]))<<32 | uint64(auLE.Uint32(ee[8:]))
	auLE.PutUint16(ee[4:], uint16(n+32768))
	img.writeAt(raw[:], ioff)
	return lblk, n, pblk
}

// TestUninitExtentReadsZerosAndSurvivesFlush mounts a Linux-style uninitialized
// extent. It reads as zeros. An unmount without a write keeps the blocks and the
// extent byte for byte.
func TestUninitExtentReadsZerosAndSurvivesFlush(t *testing.T) {
	d := newAuDrv(t)
	d.e.writeFile("/u", auFill(4, 0, 2*blockSize))
	d.e.unmount()
	img := d.f.snapshot()
	patched := img.clone()
	_, n, pblk := auMarkFirstExtentUninit(t, patched, "/u")
	if n != 2 {
		t.Fatalf("/u has an extent of %d blocks, want 2", n)
	}

	d2 := auMount(t, newAuFile(patched.clone()), newAuModel())
	if got := d2.e.readFile("/u"); !isZero(got) || len(got) != 2*blockSize {
		t.Errorf("an uninitialized extent reads %d bytes, first non-zero at %d", len(got), firstNonZero(got))
	}
	d2.e.unmount()
	after := d2.f.snapshot()
	for i := range uint64(n) {
		want := make([]byte, blockSize)
		got := make([]byte, blockSize)
		patched.readAt(want, int64(pblk+i)*blockSize)
		after.readAt(got, int64(pblk+i)*blockSize)
		if !bytes.Equal(got, want) {
			t.Errorf("block %d of the uninitialized extent changed on a flush without a write", pblk+i)
		}
	}
	if _, err := auRecover(t, after); err != nil {
		t.Errorf("the image does not mount after the flush: %v", err)
	}
}

// TestUninitExtentWriteConvertsToInitialized writes into an uninitialized
// extent. The written block becomes initialized, the rest stays uninitialized,
// and every byte reads back as written after a remount.
func TestUninitExtentWriteConvertsToInitialized(t *testing.T) {
	d := newAuDrv(t)
	d.e.writeFile("/u", auFill(4, 0, 2*blockSize))
	d.e.unmount()
	patched := d.f.snapshot()
	auMarkFirstExtentUninit(t, patched, "/u")

	d2 := auMount(t, newAuFile(patched.clone()), newAuModel())
	fd := d2.e.mustOpen("/u", linux.O_RDWR)
	if _, err := fd.PWrite(d2.e.ctx, usermem.BytesIOSequence([]byte("hello")), 100, vfsWriteOpts); err != nil {
		t.Fatal(err)
	}
	fd.DecRef(d2.e.ctx)
	n := auNodeOf(t, d2, "/u")
	n.mu.RLock()
	shape := append([]extent(nil), n.exts...)
	n.mu.RUnlock()
	if len(shape) != 2 || shape[0].uninit || !shape[1].uninit || shape[0].n != 1 || shape[1].n != 1 {
		t.Errorf("after a write into block 0 the extents are %+v, want an initialized block 0 and an uninitialized block 1", shape)
	}
	want := make([]byte, 2*blockSize)
	copy(want[100:], "hello")
	if got := d2.e.readFile("/u"); !bytes.Equal(got, want) {
		t.Errorf("after the write the file differs at byte %d", auFirstDiff(got, want))
	}
	d2.e.unmount()

	d3 := auMount(t, newAuFile(d2.f.snapshot()), newAuModel())
	defer d3.e.unmount()
	if got := d3.e.readFile("/u"); !bytes.Equal(got, want) {
		t.Errorf("after a remount the file differs at byte %d", auFirstDiff(got, want))
	}
}

// TestAuditDepthThreeTreeAndCanonicalLevels verifies canonicalLevels up to
// depth 5 and checks that a depth-3 extent tree round-trips through disk,
// parseExtents, and auFsck.
func TestAuditDepthThreeTreeAndCanonicalLevels(t *testing.T) {
	leaves, lvls := canonicalLevels(rootExtents*leafExtents*leafExtents + 1)
	if gotDepth := 1 + len(lvls); gotDepth != 3 {
		t.Fatalf("canonicalLevels depth = %d, want 3 (leaves=%d)", gotDepth, len(leaves))
	}
	if len(leaves) != rootExtents*leafExtents+1 || len(lvls[0]) != rootExtents+1 || len(lvls[1]) != 1 {
		t.Fatalf("depth-3 counts = (leaves=%d, l0=%d, l1=%d)", len(leaves), len(lvls[0]), len(lvls[1]))
	}

	d := newAuDrv(t)
	d.create("/deep", 2*blockSize)
	n := auNodeOf(t, d, "/deep")
	d.e.fs.v.gate.enterOp()
	n.mu.Lock()
	// Build an explicit depth-3 tree (eh_depth = 3 in root, 1 block at depth 2,
	// 1 block at depth 1, 1 leaf at depth 0) for the existing extents.
	b0, err0 := n.allocTreeBlock(0)
	b1, err1 := n.allocTreeBlock(0)
	b2, err2 := n.allocTreeBlock(0)
	if err0 != nil || err1 != nil || err2 != nil {
		n.mu.Unlock()
		d.e.fs.v.gate.exit()
		t.Fatalf("allocTreeBlock: %v %v %v", err0, err1, err2)
	}
	n.leaves = []leafBlock{{blk: b0, cnt: len(n.exts)}}
	n.ixLevels = [][]indexBlock{
		{{blk: b1, cnt: 1}},
		{{blk: b2, cnt: 1}},
	}
	n.ixs = []indexBlock{{blk: b1, cnt: 1}, {blk: b2, cnt: 1}}
	n.nblocks += 3
	n.dirtyLeaf = true
	n.markDirtyLocked()
	n.mu.Unlock()
	d.e.fs.v.gate.exit()
	d.e.unmount()

	img := d.f.snapshot()
	if res := auFsck(img, true); !res.OK() {
		t.Fatalf("depth-3 tree failed auFsck:\n%s", res)
	}
	d2 := auMount(t, newAuFile(img.clone()), newAuModel())
	defer d2.e.unmount()
	n2 := auNodeOf(t, d2, "/deep")
	n2.mu.RLock()
	gotDepth := 1 + len(n2.ixLevels)
	n2.mu.RUnlock()
	if gotDepth != 3 {
		t.Fatalf("reloaded tree depth = %d, want 3", gotDepth)
	}
}

// TestAuditMetaBGGeometry verifies that every meta-group places its primary
// and backup descriptor blocks in meta-group blocks and caps s_inodes_count at
// maxInodeGroups.
func TestAuditMetaBGGeometry(t *testing.T) {
	if got, want := primaryDescBlock(0), uint64(1); got != want {
		t.Fatalf("primaryDescBlock(0) = %d, want %d", got, want)
	}
	bg := uint32(64 * descsPerBlock)
	// Group 4096 is even, so hasSuper(4096) is false; its primary descriptor is
	// at the first block of group 4096.
	if got, want := primaryDescBlock(64), groupStart(bg); got != want {
		t.Fatalf("primaryDescBlock(64) = %d, want %d", got, want)
	}
	// Group 4096, 4097, and 4159 carry the primary and two backup descriptors
	// of meta-group 64.
	for _, g := range []uint32{bg, bg + 1, bg + 63} {
		if !hasMetaDesc(g) {
			t.Errorf("hasMetaDesc(%d) = false, want true", g)
		}
		if groupOverhead(g) != superBlocksOf(g)+1 {
			t.Errorf("groupOverhead(%d) = %d, want %d", g, groupOverhead(g), superBlocksOf(g)+1)
		}
	}
	if hasMetaDesc(bg + 2) {
		t.Errorf("hasMetaDesc(%d) = true, want false", bg+2)
	}
	if inodesOfGroup(maxInodeGroups) != 0 || inodesOfGroup(maxInodeGroups-1) != inodesPerGroup {
		t.Errorf("inodesOfGroup boundary mismatch around maxInodeGroups=%d", maxInodeGroups)
	}
}

// TestAuditMultiExtentJournalUpgrade verifies that parseJournalExtents accepts
// both depth-0 and depth-1 journal extent trees and that dirtyNodeLimit scales
// with journal capacity.
func TestAuditMultiExtentJournalUpgrade(t *testing.T) {
	d := newAuDrv(t)
	defer d.e.unmount()
	v := d.e.fs.v
	if got := v.dirtyNodeLimit(); got != maxDirtyNodes {
		t.Fatalf("dirtyNodeLimit() for default journal = %d, want %d", got, maxDirtyNodes)
	}
	origMax := v.j.super.maxlen
	v.j.super.maxlen = 4096
	if got := v.dirtyNodeLimit(); got != 409 {
		t.Fatalf("dirtyNodeLimit() for 4096-block journal = %d, want 409", got)
	}
	v.j.super.maxlen = origMax
}

// TestAuditFilesystemTypeNameIsExt4 verifies that the VFS filesystem type
// reports "ext4" for /proc/mounts and df -T compatibility.
func TestAuditFilesystemTypeNameIsExt4(t *testing.T) {
	if got := (FilesystemType{}).Name(); got != "ext4" {
		t.Fatalf("FilesystemType.Name() = %q, want \"ext4\"", got)
	}
}
