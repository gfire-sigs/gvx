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
	"os"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// The tests in this file damage a valid image on purpose. Each case must end
// with EUCLEAN or EIO, without a panic, without an endless loop, and without a
// write into a metadata block.

// corruptFixture holds the inode numbers and the block numbers of a small tree.
type corruptFixture struct {
	path string
	// file1 and file2 hold one block of data each.
	file1, file2 uint32
	dir, sub     uint32
	// dirBlock is the block of the directory dir.
	dirBlock uint64
}

func buildCorruptFixture(t *testing.T) corruptFixture {
	t.Helper()
	v, path := newTestVolume(t, tierNative)
	root := mustRoot(t, v)
	f1 := createChild(t, v, root, "file1", modeRegular|0o644)
	f2 := createChild(t, v, root, "file2", modeRegular|0o644)
	writeAll(t, f1, 0, pattern(1, 2*blockSize))
	writeAll(t, f2, 0, pattern(2, 2*blockSize))
	dir := createChild(t, v, root, "dir", modeDir|0o755)
	sub := createChild(t, v, dir, "sub", modeDir|0o755)
	createChild(t, v, dir, "inner", modeRegular|0o644)
	fx := corruptFixture{path: path, file1: f1.ino, file2: f2.ino, dir: dir.ino, sub: sub.ino}
	dir.mu.RLock()
	fx.dirBlock = dir.exts[0].pblk
	dir.mu.RUnlock()
	if err := v.close(); err != nil {
		t.Fatal(err)
	}
	return fx
}

// patchInode rewrites the raw inode ino in the image.
func patchInode(t *testing.T, path string, ino uint32, edit func(raw []byte)) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	blk, off := inodeLocation(ino)
	var buf [blockSize]byte
	if _, err := f.ReadAt(buf[:], int64(blk)*blockSize); err != nil {
		t.Fatal(err)
	}
	edit(buf[off : off+inodeSize])
	if _, err := f.WriteAt(buf[:], int64(blk)*blockSize); err != nil {
		t.Fatal(err)
	}
}

func patchBlock(t *testing.T, path string, blk uint64, edit func(b []byte)) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var buf [blockSize]byte
	if _, err := f.ReadAt(buf[:], int64(blk)*blockSize); err != nil {
		t.Fatal(err)
	}
	edit(buf[:])
	if _, err := f.WriteAt(buf[:], int64(blk)*blockSize); err != nil {
		t.Fatal(err)
	}
}

// setUncleanState clears the valid bit, so that the mount runs fsckLite.
func setUncleanState(t *testing.T, path string) {
	t.Helper()
	patchBlock(t, path, 0, func(b []byte) {
		le.PutUint16(b[superOffset+sbState:], 0)
	})
}

func imageBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// metadataBlocksUnchanged compares the metadata blocks of two images.
func metadataBlocksUnchanged(t *testing.T, before, after []byte) {
	t.Helper()
	for blk := uint64(1); blk < 323; blk++ {
		lo, hi := blk*blockSize, (blk+1)*blockSize
		if !bytes.Equal(before[lo:hi], after[lo:hi]) {
			t.Errorf("metadata block %d changed", blk)
		}
	}
}

func isDamage(err error) bool {
	return errors.Is(err, linuxerr.EUCLEAN) || errors.Is(err, linuxerr.EIO)
}

func openForCorruptTest(path string) (*volume, error) {
	return tryOpenVolume(path, volumeOptions{now: func() time.Time { return testNow }})
}

// TestCorruptExtentTargets points the extent of a file at blocks that hold
// metadata. The first access must fail, and the write must not reach the block.
func TestCorruptExtentTargets(t *testing.T) {
	// Block 0 holds the superblock. Block 1 holds the first descriptors.
	// Block 65 is the block bitmap and 67 is the start of the inode table.
	for _, target := range []uint64{0, 1, 65, 66, 67, 200, 322} {
		fx := buildCorruptFixture(t)
		patchInode(t, fx.path, fx.file1, func(raw []byte) {
			encodeExtent(raw[inBlock+extHeaderSize:], extent{lblk: 0, n: 1, pblk: target})
		})
		before := imageBytes(t, fx.path)
		for _, unclean := range []bool{false, true} {
			path := fx.path
			if unclean {
				setUncleanState(t, path)
			}
			v, err := openForCorruptTest(path)
			if err != nil {
				if !isDamage(err) {
					t.Errorf("target %d unclean=%v: open = %v, want EUCLEAN or EIO", target, unclean, err)
				}
				continue
			}
			root := mustRoot(t, v)
			ino, _, err := root.lookup("file1")
			if err != nil {
				t.Fatal(err)
			}
			n, err := v.getNode(ino)
			if err == nil {
				// A parse that passes must not let the write through.
				_, err = n.writeAt([]byte("overwrite"), 0)
				if err == nil {
					t.Errorf("target %d: a write into block %d succeeded", target, target)
				}
			}
			if !isDamage(err) {
				t.Errorf("target %d unclean=%v: access = %v, want EUCLEAN or EIO", target, unclean, err)
			}
			abandon(v)
		}
		after := imageBytes(t, fx.path)
		metadataBlocksUnchanged(t, before, after)
	}
}

func TestCorruptDirectoryRecLen(t *testing.T) {
	for _, recLen := range []uint16{0, 1, 7, 9, 4097, 65535} {
		fx := buildCorruptFixture(t)
		patchBlock(t, fx.path, fx.dirBlock, func(b []byte) {
			// The first record is ".". Its rec_len is at offset 4.
			le.PutUint16(b[4:], recLen)
		})
		v, err := openForCorruptTest(fx.path)
		if err != nil {
			if !isDamage(err) {
				t.Errorf("rec_len %d: open = %v", recLen, err)
			}
			continue
		}
		root := mustRoot(t, v)
		ino, _, err := root.lookup("dir")
		if err != nil {
			t.Fatalf("rec_len %d: %v", recLen, err)
		}
		dir, err := v.getNode(ino)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = dir.lookup("inner")
		if !isDamage(err) {
			t.Errorf("rec_len %d: lookup = %v, want EUCLEAN or EIO", recLen, err)
		}
		if _, err := dir.entries(); !isDamage(err) {
			t.Errorf("rec_len %d: entries = %v, want EUCLEAN or EIO", recLen, err)
		}
		if err := dir.addEntry("new", 12, ftRegular); !isDamage(err) {
			t.Errorf("rec_len %d: addEntry = %v, want EUCLEAN or EIO", recLen, err)
		}
		abandon(v)
	}
}

func TestCorruptDirectoryRecLenInRoot(t *testing.T) {
	fx := buildCorruptFixture(t)
	// The root block follows the metadata of group 0.
	v := reopenVolume(t, fx.path)
	root := mustRoot(t, v)
	root.mu.RLock()
	rootBlock := root.exts[0].pblk
	root.mu.RUnlock()
	if err := v.close(); err != nil {
		t.Fatal(err)
	}
	for _, recLen := range []uint16{0, 4097} {
		patchBlock(t, fx.path, rootBlock, func(b []byte) {
			// The second record is "..". It starts at offset 12.
			le.PutUint16(b[12+4:], recLen)
		})
		if _, err := openForCorruptTest(fx.path); !isDamage(err) {
			t.Errorf("rec_len %d in the root: open = %v, want EUCLEAN or EIO", recLen, err)
		}
		patchBlock(t, fx.path, rootBlock, func(b []byte) {
			le.PutUint16(b[12+4:], 12)
		})
	}
}

// TestCorruptDirectoryCycle makes a directory name its own parent as a child.
func TestCorruptDirectoryCycle(t *testing.T) {
	fx := buildCorruptFixture(t)
	// Replace the entry "inner" of dir by an entry that names dir itself.
	patchBlock(t, fx.path, fx.dirBlock, func(b []byte) {
		idx := bytes.Index(b, []byte("inner"))
		if idx < 8 {
			t.Fatal("entry inner not found")
		}
		le.PutUint32(b[idx-8:], fx.dir)
	})
	setUncleanState(t, fx.path)
	before := imageBytes(t, fx.path)
	if _, err := openForCorruptTest(fx.path); !isDamage(err) {
		t.Errorf("open of a cyclic graph = %v, want EUCLEAN", err)
	}
	after := imageBytes(t, fx.path)
	if !bytes.Equal(before, after) {
		t.Error("the failed mount changed the image")
	}
}

// TestCorruptDirectoryGrandparentCycle points a subdirectory at the root.
func TestCorruptDirectoryGrandparentCycle(t *testing.T) {
	fx := buildCorruptFixture(t)
	patchBlock(t, fx.path, fx.dirBlock, func(b []byte) {
		idx := bytes.Index(b, []byte("sub"))
		if idx < 8 {
			t.Fatal("entry sub not found")
		}
		le.PutUint32(b[idx-8:], rootIno)
	})
	setUncleanState(t, fx.path)
	if _, err := openForCorruptTest(fx.path); !isDamage(err) {
		t.Errorf("open = %v, want EUCLEAN", err)
	}
}

func TestCorruptCrossLinkedExtents(t *testing.T) {
	fx := buildCorruptFixture(t)
	var shared extent
	v := reopenVolume(t, fx.path)
	n1 := mustNode(t, v, fx.file1)
	n1.mu.RLock()
	shared = n1.exts[0]
	n1.mu.RUnlock()
	if err := v.close(); err != nil {
		t.Fatal(err)
	}
	patchInode(t, fx.path, fx.file2, func(raw []byte) {
		encodeExtent(raw[inBlock+extHeaderSize:], shared)
	})
	setUncleanState(t, fx.path)
	before := imageBytes(t, fx.path)
	if _, err := openForCorruptTest(fx.path); !isDamage(err) {
		t.Errorf("open with cross-linked extents = %v, want EUCLEAN", err)
	}
	if after := imageBytes(t, fx.path); !bytes.Equal(before, after) {
		t.Error("the failed mount changed the image")
	}
}

func mustNode(t testing.TB, v *volume, ino uint32) *node {
	t.Helper()
	n, err := v.getNode(ino)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestCorruptSuperblock rejects an image of another profile.
func TestCorruptSuperblock(t *testing.T) {
	for name, edit := range map[string]func(sb []byte){
		"magic":           func(sb []byte) { le.PutUint16(sb[sbMagic:], 0) },
		"block size":      func(sb []byte) { le.PutUint32(sb[sbLogBlockSize:], 0) },
		"inodes per grp":  func(sb []byte) { le.PutUint32(sb[sbInodesPerGroup:], 8192) },
		"huge block cnt":  func(sb []byte) { le.PutUint32(sb[sbBlocksCountHi:], 0x7FFFFFFF) },
		"zero blocks":     func(sb []byte) { le.PutUint32(sb[sbBlocksCountLo:], 0) },
		"unknown feature": func(sb []byte) { le.PutUint32(sb[sbFeatureIncompat:], featIncompat|0x2000) },
	} {
		fx := buildCorruptFixture(t)
		patchBlock(t, fx.path, 0, func(b []byte) { edit(b[superOffset:]) })
		if _, err := openForCorruptTest(fx.path); !isDamage(err) {
			t.Errorf("%s: open = %v, want EUCLEAN", name, err)
		}
	}
}

// TestCorruptGroupDescriptor rejects a descriptor that moves the metadata.
func TestCorruptGroupDescriptor(t *testing.T) {
	fx := buildCorruptFixture(t)
	patchBlock(t, fx.path, 1, func(b []byte) {
		le.PutUint32(b[gdInodeTableLo:], 5)
	})
	if _, err := openForCorruptTest(fx.path); !isDamage(err) {
		t.Errorf("open = %v, want EUCLEAN", err)
	}
}

// TestCorruptExtentLeaf damages an extent leaf block.
func TestCorruptExtentLeaf(t *testing.T) {
	v, path := newTestVolume(t, tierNative)
	root := mustRoot(t, v)
	a := createChild(t, v, root, "a", modeRegular|0o644)
	b := createChild(t, v, root, "b", modeRegular|0o644)
	for i := range 8 {
		writeAll(t, a, int64(i)*blockSize, pattern(1, blockSize))
		writeAll(t, b, int64(i)*blockSize, pattern(2, blockSize))
	}
	a.mu.RLock()
	leaf := a.leaves[0]
	ino := a.ino
	a.mu.RUnlock()
	if err := v.close(); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(b []byte){
		"magic":       func(b []byte) { le.PutUint16(b[0:], 0) },
		"entry count": func(b []byte) { le.PutUint16(b[2:], 5000) },
		"depth":       func(b []byte) { le.PutUint16(b[6:], 3) },
		"target":      func(b []byte) { encodeExtent(b[extHeaderSize:], extent{lblk: 0, n: 1, pblk: 67}) },
	} {
		orig := imageBytes(t, path)
		patchBlock(t, path, leaf, edit)
		v, err := openForCorruptTest(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := v.getNode(ino); !isDamage(err) {
			t.Errorf("%s: getNode = %v, want EUCLEAN", name, err)
		}
		abandon(v)
		if err := os.WriteFile(path, orig, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
