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
	"strings"
	"testing"
)

// TestAuditFormatConformance formats a volume and checks the raw image with
// the independent oracle.
func TestAuditFormatConformance(t *testing.T) {
	auNoFlusher(t)
	f := newAuFile(nil)
	if err := formatVolume(f, testNow); err != nil {
		t.Fatal(err)
	}
	res := auFsck(f.snapshot(), true)
	if !res.OK() {
		t.Fatalf("a new volume fails the oracle:\n%s", res)
	}
	if got := res.paths(); len(got) != 1 || got[0] != "/" {
		t.Fatalf("a new volume holds %v, want only the root", got)
	}
}

// TestAuditOracleDetects mutates a valid image and requires the oracle to name
// each damage. A checker that accepts everything would make the rest of the
// suite pass without meaning.
func TestAuditOracleDetects(t *testing.T) {
	auNoFlusher(t)
	d := newAuDrv(t)
	d.create("/victim", 5000)
	d.create("/other", 5000)
	d.e.unmount()
	good := d.f.snapshot()
	if res := auFsck(good, true); !res.OK() {
		t.Fatalf("the base image fails the oracle:\n%s", res)
	}
	tree := auFsck(good, true).Tree
	victim := tree["/victim"].ino
	inodeOff := func(ino uint32) int64 {
		const group0Table = 65 + 2
		return int64(group0Table)*auBlock + int64(ino-1)*auISize
	}
	patch := func(img *auPages, off int64, b ...byte) { img.writeAt(b, off) }
	cases := []struct {
		name string
		hit  string
		mut  func(img *auPages)
	}{
		{"link count", "link count", func(img *auPages) { patch(img, inodeOff(victim)+0x1A, 7) }},
		{"dtime on a live inode", "dtime", func(img *auPages) { patch(img, inodeOff(victim)+0x14, 1) }},
		{"inode flags", "flags", func(img *auPages) { patch(img, inodeOff(victim)+0x20, 0, 0, 0, 0) }},
		{"extent magic", "extent header magic", func(img *auPages) { patch(img, inodeOff(victim)+0x28, 0, 0) }},
		{"i_blocks", "i_blocks", func(img *auPages) { patch(img, inodeOff(victim)+0x1C, 0xFF) }},
		{"free block counter", "superblock free counts", func(img *auPages) {
			var b [4]byte
			img.readAt(b[:], 1024+0x0C)
			b[0]++
			patch(img, 1024+0x0C, b[:]...)
		}},
		{"shared block", "owned by inodes", func(img *auPages) {
			// Copy the i_block of /other over the i_block of /victim.
			var b [60]byte
			img.readAt(b[:], inodeOff(tree["/other"].ino)+0x28)
			patch(img, inodeOff(victim)+0x28, b[:]...)
		}},
		{"free bit set", "bitmap says used", func(img *auPages) {
			// Block 4095 is free in a volume this small.
			var b [1]byte
			img.readAt(b[:], 65*auBlock+511)
			b[0] |= 0x80
			patch(img, 65*auBlock+511, b[:]...)
		}},
		{"inode bitmap bit", "bitmap says used=false", func(img *auPages) {
			var b [1]byte
			img.readAt(b[:], 66*auBlock+int64((victim-1)/8))
			b[0] &^= 1 << ((victim - 1) % 8)
			patch(img, 66*auBlock+int64((victim-1)/8), b[:]...)
		}},
		{"superblock magic", "magic", func(img *auPages) { patch(img, 1024+0x38, 0, 0) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			img := good.clone()
			tc.mut(img)
			res := auFsck(img, true)
			if res.OK() {
				t.Fatalf("the oracle accepts the damaged image")
			}
			if !strings.Contains(res.String(), tc.hit) {
				t.Fatalf("the oracle reports %q, want a message with %q", res, tc.hit)
			}
		})
	}
}

// auRichWorkload builds a tree that exercises every storage form: inline
// data at its limits, one block, several extents, an extent tree with leaf
// blocks, holes, long and short symlinks, hard links, a large directory, and a
// deep path.
func auRichWorkload(d *auDrv) {
	d.mkdir("/sizes")
	for _, n := range []int{0, 1, 59, 60, 61, 127, 128, 129, 4095, 4096, 4097, 100_000} {
		d.create(fmt.Sprintf("/sizes/f%d", n), n)
	}
	// Interleaved appends give each file many small extents, which needs an
	// extent tree with leaf blocks.
	d.create("/frag-a", 0)
	d.create("/frag-b", 0)
	for i := range 40 {
		d.pwrite("/frag-a", i*blockSize, blockSize)
		d.pwrite("/frag-b", i*blockSize, blockSize)
	}
	d.create("/sparse", 10)
	d.pwrite("/sparse", 3*blockSize+7, 100)
	d.pwrite("/sparse", 50*blockSize, 4096)
	d.truncate("/sparse", 60*blockSize+5)
	d.symlink("short-target", "/sym-short")
	d.symlink(strings.Repeat("t", 200), "/sym-long")
	d.create("/h1", 5000)
	d.link("/h1", "/h2")
	d.mkdir("/deep")
	p := "/deep"
	for i := range 12 {
		p = auJoin(p, fmt.Sprintf("d%d", i))
		d.mkdir(p)
	}
	d.create(auJoin(p, "leaf"), 300)
	d.mkdir("/big")
	for i := range 400 {
		d.create(fmt.Sprintf("/big/entry-with-a-long-name-%04d", i), i%3*100)
	}
	for i := 0; i < 400; i += 3 {
		d.unlink(fmt.Sprintf("/big/entry-with-a-long-name-%04d", i))
	}
	d.rename("/big/entry-with-a-long-name-0001", "/deep/moved")
	d.rename("/sizes", "/sizes2")
	d.truncate("/sizes2/f100000", 33)
	d.truncate("/sizes2/f129", 4)
	d.pwrite("/sizes2/f4096", 10, 5000)
}

// TestAuditCleanImageConformance writes a rich tree, unmounts, and checks the
// image with the oracle and against the model. A second mount must read the
// same tree.
func TestAuditCleanImageConformance(t *testing.T) {
	d := newAuDrv(t)
	auRichWorkload(d)
	d.verifyLive("live tree")
	d.e.unmount()

	res := auFsck(d.f.snapshot(), true)
	if !res.OK() {
		t.Fatalf("the image fails the oracle:\n%s", res)
	}
	for _, msg := range auCompareImage(res, d.m) {
		t.Errorf("image against model: %s", msg)
	}

	d2 := auMount(t, newAuFile(d.f.snapshot()), d.m)
	d2.verifyLive("remounted tree")
}
