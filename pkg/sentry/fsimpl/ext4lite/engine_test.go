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
	"errors"
	"fmt"
	"os"
	"testing"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

func TestEmptyVolumeIsClean(t *testing.T) {
	v, path := newTestVolume(t, platformTier)
	if err := v.close(); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() != groupBytes {
		t.Fatalf("size = %v, %v; want %d", fi, err, groupBytes)
	}
	runE2fsck(t, path)
}

// TestStorageRepresentations covers the three representations of a file: the
// inline form, the extent root in the inode, and the extent leaf blocks.
func TestStorageRepresentations(t *testing.T) {
	v, path := newTestVolume(t, platformTier)
	root := mustRoot(t, v)

	inlineSizes := []int{0, 1, 59, 60, 61, 100, maxInline}
	for _, size := range inlineSizes {
		n := createChild(t, v, root, fmt.Sprintf("inline-%d", size), modeRegular|0o644)
		writeAll(t, n, 0, pattern(byte(size), size))
		n.mu.RLock()
		inline, blocks := n.flags&flagInlineData != 0, n.nblocks
		n.mu.RUnlock()
		if !inline || blocks != 0 {
			t.Errorf("size %d: inline = %v, blocks = %d; want an inline file with no block", size, inline, blocks)
		}
	}
	over := createChild(t, v, root, "over-inline", modeRegular|0o644)
	writeAll(t, over, 0, pattern(9, maxInline+1))
	over.mu.RLock()
	if over.flags&flagInlineData != 0 || over.nblocks != 1 {
		t.Errorf("a file of %d bytes: flags %#x, blocks %d; want one extent block", maxInline+1, over.flags, over.nblocks)
	}
	over.mu.RUnlock()

	// Interleave two files so that each file has many extents.
	a := createChild(t, v, root, "frag-a", modeRegular|0o644)
	b := createChild(t, v, root, "frag-b", modeRegular|0o644)
	const frags = 900
	for i := range frags {
		writeAll(t, a, int64(i)*blockSize, pattern(byte(i), blockSize))
		writeAll(t, b, int64(i)*blockSize, pattern(byte(i+1), blockSize))
	}
	a.mu.RLock()
	exts, leaves := len(a.exts), len(a.leaves)
	a.mu.RUnlock()
	if exts <= leafExtents || leaves < 2 {
		t.Fatalf("fragmented file has %d extents in %d leaves; want more than %d extents", exts, leaves, leafExtents)
	}

	// A file with a few extents keeps them in the inode.
	small := createChild(t, v, root, "four-extents", modeRegular|0o644)
	filler := createChild(t, v, root, "filler", modeRegular|0o644)
	for i := range 4 {
		writeAll(t, small, int64(i)*blockSize, pattern(byte(i), blockSize))
		writeAll(t, filler, int64(i)*blockSize, pattern(byte(i), blockSize))
	}
	small.mu.RLock()
	if len(small.exts) != 4 || len(small.leaves) != 0 {
		t.Errorf("small file has %d extents in %d leaves; want 4 in the inode", len(small.exts), len(small.leaves))
	}
	small.mu.RUnlock()

	if err := v.close(); err != nil {
		t.Fatal(err)
	}
	v = reopenVolume(t, path)
	root = mustRoot(t, v)
	for _, size := range inlineSizes {
		n := lookupNode(t, v, root, fmt.Sprintf("inline-%d", size))
		if got := readAll(t, n); !bytes.Equal(got, pattern(byte(size), size)) {
			t.Errorf("inline-%d differs after remount", size)
		}
	}
	a = lookupNode(t, v, root, "frag-a")
	got := readAll(t, a)
	for i := range frags {
		if !bytes.Equal(got[i*blockSize:(i+1)*blockSize], pattern(byte(i), blockSize)) {
			t.Fatalf("frag-a block %d differs after remount", i)
		}
	}
	if err := v.close(); err != nil {
		t.Fatal(err)
	}
	runE2fsck(t, path)
}

func TestSparseAndTruncate(t *testing.T) {
	v, path := newTestVolume(t, platformTier)
	root := mustRoot(t, v)
	f := createChild(t, v, root, "sparse", modeRegular|0o644)
	writeAll(t, f, 10*blockSize+100, []byte("tail"))
	writeAll(t, f, 0, []byte("head"))
	if off, ok := f.seekData(blockSize); !ok || off != 10*blockSize {
		t.Errorf("seekData(%d) = %d, %v; want %d", blockSize, off, ok, 10*blockSize)
	}
	if got := f.seekHole(0); got != blockSize {
		t.Errorf("seekHole(0) = %d, want %d", got, blockSize)
	}
	buf := make([]byte, 8)
	if _, err := f.readAt(buf, 5*blockSize); err != nil || !bytes.Equal(buf, make([]byte, 8)) {
		t.Errorf("hole read = %v, %v; want zeros", buf, err)
	}
	if err := f.truncate(100); err != nil {
		t.Fatal(err)
	}
	if err := f.truncate(2 * blockSize); err != nil {
		t.Fatal(err)
	}
	// The block that the shrink kept must read as zeros behind the cut.
	tail := make([]byte, 16)
	if _, err := f.readAt(tail, 100); err != nil || !bytes.Equal(tail, make([]byte, 16)) {
		t.Errorf("tail after regrow = %v, %v; want zeros", tail, err)
	}
	g := createChild(t, v, root, "punch", modeRegular|0o644)
	writeAll(t, g, 0, pattern(1, 8*blockSize))
	if err := g.punchHole(blockSize+10, 4*blockSize); err != nil {
		t.Fatal(err)
	}
	want := pattern(1, 8*blockSize)
	clear(want[blockSize+10 : 5*blockSize+10])
	if got := readAll(t, g); !bytes.Equal(got, want) {
		t.Error("content differs after the hole punch")
	}
	h := createChild(t, v, root, "falloc", modeRegular|0o644)
	if err := h.preallocate(0, 3*blockSize, false); err != nil {
		t.Fatal(err)
	}
	if h.size != 3*blockSize || !bytes.Equal(readAll(t, h), make([]byte, 3*blockSize)) {
		t.Errorf("preallocate left size %d or nonzero content", h.size)
	}
	if err := v.close(); err != nil {
		t.Fatal(err)
	}
	runE2fsck(t, path)
}

func TestDirectoryGrowthAndShrink(t *testing.T) {
	v, path := newTestVolume(t, platformTier)
	root := mustRoot(t, v)
	dir := createChild(t, v, root, "big", modeDir|0o755)
	const count = 700
	for i := range count {
		createChild(t, v, dir, fmt.Sprintf("entry-%04d-%s", i, "xxxxxxxxxxxxxxxxxxxx"), modeRegular|0o644)
	}
	dir.mu.RLock()
	size := dir.size
	dir.mu.RUnlock()
	if size <= blockSize {
		t.Fatalf("directory size %d; want more than one block", size)
	}
	if _, _, err := dir.lookup("entry-0699-xxxxxxxxxxxxxxxxxxxx"); err != nil {
		t.Fatal(err)
	}
	if err := dir.addEntry("entry-0001-xxxxxxxxxxxxxxxxxxxx", 12, ftRegular); !errors.Is(err, linuxerr.EEXIST) {
		t.Errorf("duplicate add = %v, want EEXIST", err)
	}
	if err := v.sync(); err != nil {
		t.Fatal(err)
	}
	for i := range count {
		name := fmt.Sprintf("entry-%04d-%s", i, "xxxxxxxxxxxxxxxxxxxx")
		ino, _, err := dir.lookup(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := dir.removeEntry(name); err != nil {
			t.Fatal(err)
		}
		n, err := v.getNode(ino)
		if err != nil {
			t.Fatal(err)
		}
		setLinks(n, 0)
		v.putNode(n)
	}
	dir.mu.RLock()
	size = dir.size
	dir.mu.RUnlock()
	if size != blockSize {
		t.Errorf("empty directory size %d; want one block", size)
	}
	if empty, err := dir.isEmptyDir(); err != nil || !empty {
		t.Errorf("isEmptyDir = %v, %v", empty, err)
	}
	if err := v.close(); err != nil {
		t.Fatal(err)
	}
	runE2fsck(t, path)
}

func TestSymlinkSpecialAndXattr(t *testing.T) {
	v, path := newTestVolume(t, platformTier)
	root := mustRoot(t, v)
	short := createChild(t, v, root, "short-link", modeSymlink|0o777)
	writeAll(t, short, 0, []byte("target/file"))
	long := createChild(t, v, root, "long-link", modeSymlink|0o777)
	target := bytes.Repeat([]byte("d/"), 100)
	writeAll(t, long, 0, target)
	for name, mode := range map[string]uint16{"fifo": modeFIFO | 0o600, "sock": modeSocket | 0o600, "null": modeChar | 0o666} {
		n := createChild(t, v, root, name, mode)
		if mode&modeTypeMask == modeChar {
			n.mu.Lock()
			n.rdev = 1<<8 | 3
			n.mu.Unlock()
		}
	}
	f := createChild(t, v, root, "xattr-file", modeRegular|0o644)
	writeAll(t, f, 0, []byte("x"))
	if err := root.addEntry("hard-link", f.ino, ftRegular); err != nil {
		t.Fatal(err)
	}
	setLinks(f, 2)
	if err := f.setXattr("user.alpha", []byte("one"), false, false); err != nil {
		t.Fatal(err)
	}
	if err := f.setXattr("user.beta", bytes.Repeat([]byte("b"), 1000), false, false); err != nil {
		t.Fatal(err)
	}
	if err := f.setXattr("security.selinux", []byte("ctx\x00"), false, false); err != nil {
		t.Fatal(err)
	}
	if err := f.setXattr("user.alpha", nil, true, false); !errors.Is(err, linuxerr.EEXIST) {
		t.Errorf("create of an existing attribute = %v, want EEXIST", err)
	}
	if err := f.setXattr("user.huge", make([]byte, 4096), false, false); !errors.Is(err, linuxerr.ENOSPC) {
		t.Errorf("a value that exceeds the block = %v, want ENOSPC", err)
	}
	if err := f.removeXattr("user.alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.getXattr("user.alpha"); !errors.Is(err, linuxerr.ENODATA) {
		t.Errorf("removed attribute = %v, want ENODATA", err)
	}
	if err := v.close(); err != nil {
		t.Fatal(err)
	}
	v = reopenVolume(t, path)
	root = mustRoot(t, v)
	f = lookupNode(t, v, root, "xattr-file")
	if got, err := f.getXattr("user.beta"); err != nil || len(got) != 1000 {
		t.Errorf("user.beta = %d bytes, %v", len(got), err)
	}
	names, _ := f.listXattr()
	if len(names) != 2 {
		t.Errorf("attributes after remount: %v", names)
	}
	null := lookupNode(t, v, root, "null")
	if null.rdev != 1<<8|3 {
		t.Errorf("rdev = %#x", null.rdev)
	}
	if err := v.close(); err != nil {
		t.Fatal(err)
	}
	runE2fsck(t, path)
}

func TestGrowthAcrossGroupsAndShrink(t *testing.T) {
	for _, tier := range []storageTier{platformTier, tierFallback} {
		t.Run(fmt.Sprint("tier", tier), func(t *testing.T) {
			v, path := newTestVolume(t, tier)
			root := mustRoot(t, v)
			big := createChild(t, v, root, "big", modeRegular|0o644)
			chunk := pattern(5, 1<<20)
			const mib = 40
			for i := range mib {
				writeAll(t, big, int64(i)<<20, chunk)
			}
			if got := v.numGroups(); got < 3 {
				t.Fatalf("groups = %d after %d MiB, want at least 3", got, mib)
			}
			if err := v.close(); err != nil {
				t.Fatal(err)
			}
			fi, _ := os.Stat(path)
			if fi.Size()%groupBytes != 0 {
				t.Errorf("host size %d is not a multiple of a group", fi.Size())
			}
			runE2fsck(t, path)

			v = reopenVolume(t, path)
			root = mustRoot(t, v)
			big = lookupNode(t, v, root, "big")
			if err := big.truncate(0); err != nil {
				t.Fatal(err)
			}
			if err := v.close(); err != nil {
				t.Fatal(err)
			}
			if fi, _ := os.Stat(path); fi.Size() != groupBytes {
				t.Errorf("host size after the shrink = %d, want %d", fi.Size(), groupBytes)
			}
			runE2fsck(t, path)
		})
	}
}

// TestFreedBlocksWaitForFlush checks the rule that keeps a crash safe: a block
// that the disk records as used does not return to the pool before a flush.
func TestFreedBlocksWaitForFlush(t *testing.T) {
	v, _ := newTestVolume(t, platformTier)
	root := mustRoot(t, v)
	a := createChild(t, v, root, "a", modeRegular|0o644)
	writeAll(t, a, 0, pattern(1, blockSize*2))
	if err := v.sync(); err != nil {
		t.Fatal(err)
	}
	a.mu.RLock()
	old := a.exts[0]
	a.mu.RUnlock()
	unlink(t, v, root, "a", a)

	b := createChild(t, v, root, "b", modeRegular|0o644)
	writeAll(t, b, 0, pattern(2, blockSize*2))
	b.mu.RLock()
	got := b.exts[0]
	b.mu.RUnlock()
	if got.pblk < old.pend() && got.pend() > old.pblk {
		t.Errorf("new file reuses blocks %d+%d of a file that the disk still records", old.pblk, old.n)
	}
	if err := v.sync(); err != nil {
		t.Fatal(err)
	}
	c := createChild(t, v, root, "c", modeRegular|0o644)
	writeAll(t, c, 0, pattern(3, blockSize*2))
	c.mu.RLock()
	got = c.exts[0]
	c.mu.RUnlock()
	if got.pblk != old.pblk {
		t.Errorf("after the flush the new file starts at %d, want the freed block %d", got.pblk, old.pblk)
	}
	if err := v.close(); err != nil {
		t.Fatal(err)
	}
}

// TestRandomOperationsMatchModel runs random writes, truncates, and hole
// punches on one file and compares the file with a plain byte slice.
func TestRandomOperationsMatchModel(t *testing.T) {
	v, path := newTestVolume(t, platformTier)
	root := mustRoot(t, v)
	f := createChild(t, v, root, "model", modeRegular|0o644)
	var model []byte
	seed := uint32(12345)
	next := func(n int) int {
		seed = seed*1664525 + 1013904223
		return int(seed>>8) % n
	}
	grow := func(size int) {
		if size > len(model) {
			model = append(model, make([]byte, size-len(model))...)
		}
	}
	for i := range 400 {
		switch op := next(10); {
		case op < 6:
			off, length := next(300000), 1+next(20000)
			data := pattern(byte(i), length)
			writeAll(t, f, int64(off), data)
			grow(off + length)
			copy(model[off:], data)
		case op < 8:
			size := next(300000)
			if err := f.truncate(uint64(size)); err != nil {
				t.Fatal(err)
			}
			if size < len(model) {
				model = model[:size]
			} else {
				grow(size)
			}
		default:
			off, length := next(300000), 1+next(50000)
			if err := f.punchHole(uint64(off), uint64(length)); err != nil {
				t.Fatal(err)
			}
			for j := off; j < min(off+length, len(model)); j++ {
				model[j] = 0
			}
		}
		if i%50 == 49 {
			if got := readAll(t, f); !bytes.Equal(got, model) {
				t.Fatalf("step %d: the file differs from the model", i)
			}
			if err := v.sync(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := v.close(); err != nil {
		t.Fatal(err)
	}
	v = reopenVolume(t, path)
	f = lookupNode(t, v, mustRoot(t, v), "model")
	if got := readAll(t, f); !bytes.Equal(got, model) {
		t.Fatal("the file differs from the model after a remount")
	}
	if err := v.close(); err != nil {
		t.Fatal(err)
	}
	runE2fsck(t, path)
}
