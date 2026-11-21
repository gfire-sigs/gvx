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
	"os"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// The tests in this file build images in which two on-disk records name the
// same bytes. Each case must end with EUCLEAN, without a panic and without
// work that grows faster than the image.

// errReadBudget is the error of a read beyond the budget of a budgetFile.
var errReadBudget = errors.New("test: the read budget is spent")

// budgetFile is a host file that counts the reads of the blocks [lo, hi). A
// read of that range fails after budget reads. A walk that reads one block
// again and again then stops early, so the test needs no timeout.
type budgetFile struct {
	hostFile
	lo, hi uint64
	budget int64
	reads  atomic.Int64
}

func (f *budgetFile) ReadAt(p []byte, off int64) (int, error) {
	if blk := uint64(off) / blockSize; blk >= f.lo && blk < f.hi {
		if f.reads.Add(1) > f.budget {
			return 0, errReadBudget
		}
	}
	return f.hostFile.ReadAt(p, off)
}

// TestCorruptExtentTreeSharedChild builds an extent tree of depth 5 from five
// blocks. Every entry of a level names the one block of the level below, so
// the tree names its leaf 4 * 340^4 times. The parser must reject the tree
// when it meets a block for the second time.
func TestCorruptExtentTreeSharedChild(t *testing.T) {
	v, path := newTestVolume(t, platformTier)
	root := mustRoot(t, v)
	f := createChild(t, v, root, "f", modeRegular|0o644)
	writeAll(t, f, 0, pattern(1, maxExtentDepth*blockSize))
	f.mu.RLock()
	ino, first := f.ino, f.exts[0]
	f.mu.RUnlock()
	if first.n < maxExtentDepth {
		t.Fatalf("the first extent of the file has %d blocks, want %d", first.n, maxExtentDepth)
	}
	if err := v.close(); err != nil {
		t.Fatal(err)
	}

	// The data blocks of the file become the tree blocks. Block first.pblk+i
	// has the depth 4-i, and the last block is the leaf.
	for i := range maxExtentDepth {
		depth := maxExtentDepth - 1 - i
		patchBlock(t, path, first.pblk+uint64(i), func(b []byte) {
			clear(b)
			encodeExtentHeader(b, leafExtents, leafExtents, depth)
			for j := range leafExtents {
				at := b[extHeaderSize+j*extEntrySize:]
				if depth == 0 {
					encodeExtent(at, extent{lblk: uint32(j), n: 1, pblk: first.pblk + maxExtentDepth})
				} else {
					encodeExtentIdx(at, uint32(j), first.pblk+uint64(i)+1)
				}
			}
		})
	}
	patchInode(t, path, ino, func(raw []byte) {
		tree := raw[inBlock : inBlock+iBlockSize]
		clear(tree)
		encodeExtentHeader(tree, rootExtents, rootExtents, maxExtentDepth)
		for j := range rootExtents {
			encodeExtentIdx(tree[extHeaderSize+j*extEntrySize:], uint32(j), first.pblk)
		}
	})

	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	hf, err := newHostFile(file)
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	// An honest walk reads each of the five blocks once.
	bf := &budgetFile{hostFile: hf, lo: first.pblk, hi: first.pblk + maxExtentDepth, budget: 8 * maxExtentDepth}
	v, err = openVolume(bf, volumeOptions{now: func() time.Time { return testNow }})
	if err != nil {
		hf.Close()
		t.Fatalf("open: %v", err)
	}
	defer abandon(v)
	_, err = v.getNode(ino)
	if got := bf.reads.Load(); got > bf.budget {
		t.Errorf("the walk read the five tree blocks more than %d times", bf.budget)
	}
	if !errors.Is(err, linuxerr.EUCLEAN) {
		t.Errorf("getNode = %v, want EUCLEAN", err)
	}
}

// TestCorruptXattrOverlappingValues makes two entries of a xattr block name
// the same 2500 value bytes. Each value lies inside the block, but both
// together need more than one block. The first read of the attributes must
// fail. A removal of the third attribute must not make the flush encode the
// two large values into one block.
func TestCorruptXattrOverlappingValues(t *testing.T) {
	v, path := newTestVolume(t, platformTier)
	root := mustRoot(t, v)
	f := createChild(t, v, root, "f", modeRegular|0o644)
	if err := f.setXattr("user.c", []byte("seed"), false, false); err != nil {
		t.Fatal(err)
	}
	f.mu.RLock()
	ino, acl := f.ino, f.fileACL
	f.mu.RUnlock()
	if acl == 0 {
		t.Fatal("the file has no xattr block")
	}
	if err := v.close(); err != nil {
		t.Fatal(err)
	}

	const big = 2500
	patchBlock(t, path, acl, func(b []byte) {
		clear(b)
		le.PutUint32(b[0:], xattrMagic)
		le.PutUint32(b[4:], 1)
		le.PutUint32(b[8:], 1)
		off := xattrHeaderSize
		for _, e := range []struct {
			name string
			size int
		}{{"a", big}, {"b", big}, {"c", 4}} {
			b[off] = byte(len(e.name))
			b[off+1] = xattrIndexUser
			le.PutUint16(b[off+2:], blockSize-big)
			le.PutUint32(b[off+8:], uint32(e.size))
			copy(b[off+xattrEntryHeader:], e.name)
			off += xattrEntryLen(len(e.name))
		}
	})

	v, err := openForCorruptTest(path)
	if err != nil {
		if !isDamage(err) {
			t.Errorf("open = %v, want EUCLEAN or EIO", err)
		}
		return
	}
	defer abandon(v)
	if msg := auGuarded(func() {
		n, err := v.getNode(ino)
		if err != nil {
			if !isDamage(err) {
				t.Errorf("getNode = %v, want EUCLEAN or EIO", err)
			}
			return
		}
		if _, err := n.listXattr(); !errors.Is(err, linuxerr.EUCLEAN) {
			t.Errorf("listXattr = %v, want EUCLEAN", err)
		}
		if err := n.removeXattr("user.c"); !errors.Is(err, linuxerr.EUCLEAN) {
			t.Errorf("removeXattr = %v, want EUCLEAN", err)
		}
		if err := v.sync(); err != nil {
			t.Errorf("sync = %v", err)
		}
	}); msg != "" {
		t.Errorf("panic: %s", msg)
	}
}

// auMountGuarded mounts the image and closes the volume when the mount passes.
// It returns the message of a panic and the error of the mount.
func auMountGuarded(img *auPages) (panicked string, err error) {
	panicked = auGuarded(func() {
		var v *volume
		if v, err = mountHostFile(newAuFile(img), VolumeOptions{}); err == nil {
			_ = (&Volume{v: v}).Close()
		}
	})
	return panicked, err
}

// auJournalInodeAt returns the byte offset of the journal inode in an image.
func auJournalInodeAt() int64 {
	blk, off := inodeLocation(journalIno)
	return int64(blk)*blockSize + int64(off)
}

// TestCorruptReplayShrinksBelowJournal puts the journal into group 1 of a
// volume of two groups. The log holds one transaction, whose superblock image
// gives the volume one group. After the replay, the journal lies beyond the
// end of the volume. The mount must fail. Without a new test of the journal,
// fsckLite indexes its bitmaps with a block of group 1.
func TestCorruptReplayShrinksBelowJournal(t *testing.T) {
	auNoFlusher(t)
	d := newAuDrv(t)
	d.create("/big", 20<<20)
	d.e.unmount()
	base := d.f.snapshot()
	res := auFsck(base, true)
	if res.Groups != 2 {
		t.Fatalf("the volume has %d groups, want 2", res.Groups)
	}
	j, _ := auReadJournal(base)
	if j == nil || len(j.exts) != 1 || j.start != 0 {
		t.Fatalf("the journal is not one empty run: %+v", j)
	}

	// Move the journal to a free run of group 1.
	var dest, run uint64
	for b := uint64(blocksPerGroup) + 300; b < 2*blocksPerGroup; b++ {
		if _, used := res.Blocks[b]; used {
			run = 0
			continue
		}
		if run++; run == uint64(j.blocks) {
			dest = b + 1 - run
			break
		}
	}
	if dest == 0 {
		t.Fatalf("group 1 has no free run of %d blocks", j.blocks)
	}
	moved := base.clone()
	buf := make([]byte, blockSize)
	for i := range uint64(j.blocks) {
		base.readAt(buf, int64(j.exts[0].pblk+i)*blockSize)
		moved.writeAt(buf, int64(dest+i)*blockSize)
	}
	var raw [inodeSize]byte
	moved.readAt(raw[:], auJournalInodeAt())
	encodeExtent(raw[inBlock+extHeaderSize:], extent{lblk: 0, n: j.blocks, pblk: dest})
	moved.writeAt(raw[:], auJournalInodeAt())
	if msg, err := auMountGuarded(moved.clone()); err != nil || msg != "" {
		t.Fatalf("the image with the journal in group 1 does not mount: %v %s", err, msg)
	}

	for _, errorFlag := range []bool{true, false} {
		img := moved.clone()
		b0 := make([]byte, blockSize)
		img.readAt(b0, 0)
		sb := b0[superOffset:]
		le.PutUint32(sb[sbBlocksCountLo:], blocksPerGroup)
		le.PutUint32(sb[sbInodesCount:], inodesPerGroup)
		if errorFlag {
			le.PutUint16(sb[sbState:], le.Uint16(sb[sbState:])|stateError)
		}
		txn := encodeTxn(j.sequence, j.uuid, []blockWrite{{0, b0}}, nil, 0)
		img.writeAt(txn.buf, int64(dest+uint64(j.first))*blockSize)
		var start [4]byte
		be.PutUint32(start[:], j.first)
		img.writeAt(start[:], int64(dest)*blockSize+jsbStart)

		msg, err := auMountGuarded(img)
		if msg != "" {
			t.Errorf("error flag %v: panic: %s", errorFlag, msg)
			continue
		}
		if !errors.Is(err, linuxerr.EUCLEAN) {
			t.Errorf("error flag %v: mount = %v, want EUCLEAN", errorFlag, err)
		}
	}
}

// TestCorruptJournalExtentsOverlap makes the journal inode name host blocks
// more than once. The journal file is then longer than the blocks that hold
// it, and a log block can lie on the extent leaf. The mount must fail.
func TestCorruptJournalExtentsOverlap(t *testing.T) {
	auNoFlusher(t)
	d := newAuDrv(t)
	d.create("/f", 5000)
	d.e.unmount()
	base := d.f.snapshot()
	j, _ := auReadJournal(base)
	if j == nil || len(j.exts) != 1 || j.blocks != journalBlocks {
		t.Fatalf("the journal is not one run of %d blocks: %+v", journalBlocks, j)
	}
	p := j.exts[0].pblk

	for _, c := range []struct {
		name string
		exts []extent
		// leaf is the offset of the extent leaf in the run. Zero keeps the
		// extents in the inode.
		leaf uint64
	}{
		{name: "one run mapped four times", exts: []extent{
			{lblk: 0, n: journalBlocks, pblk: p},
			{lblk: journalBlocks, n: journalBlocks, pblk: p},
			{lblk: 2 * journalBlocks, n: journalBlocks, pblk: p},
			{lblk: 3 * journalBlocks, n: journalBlocks, pblk: p},
		}},
		{name: "two runs share blocks", exts: []extent{
			{lblk: 0, n: journalBlocks / 2, pblk: p},
			{lblk: journalBlocks / 2, n: journalBlocks / 2, pblk: p + journalBlocks/4},
		}},
		{name: "the leaf lies inside the run", exts: []extent{
			{lblk: 0, n: journalBlocks, pblk: p},
		}, leaf: 5},
	} {
		img := base.clone()
		var raw [inodeSize]byte
		img.readAt(raw[:], auJournalInodeAt())
		tree := raw[inBlock : inBlock+iBlockSize]
		clear(tree)
		var blocks uint64
		for _, e := range c.exts {
			blocks += uint64(e.n)
		}
		if c.leaf == 0 {
			encodeExtentHeader(tree, len(c.exts), rootExtents, 0)
			for i, e := range c.exts {
				encodeExtent(tree[extHeaderSize+i*extEntrySize:], e)
			}
		} else {
			encodeExtentHeader(tree, 1, rootExtents, 1)
			encodeExtentIdx(tree[extHeaderSize:], 0, p+c.leaf)
			leaf := make([]byte, blockSize)
			encodeExtentHeader(leaf, len(c.exts), leafExtents, 0)
			for i, e := range c.exts {
				encodeExtent(leaf[extHeaderSize+i*extEntrySize:], e)
			}
			img.writeAt(leaf, int64(p+c.leaf)*blockSize)
		}
		le.PutUint32(raw[inSizeLo:], uint32(blocks*blockSize))
		le.PutUint32(raw[inSizeHi:], uint32(blocks*blockSize>>32))
		img.writeAt(raw[:], auJournalInodeAt())

		msg, err := auMountGuarded(img)
		if msg != "" {
			t.Errorf("%s: panic: %s", c.name, msg)
			continue
		}
		if !errors.Is(err, linuxerr.EUCLEAN) {
			t.Errorf("%s: mount = %v, want EUCLEAN", c.name, err)
		}
	}
}
