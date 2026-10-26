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
	"testing"
)

// auFsckImage returns the unclean image of a volume of an older release. Its
// tree holds /etc/passwd, /etc/hosts, /one, /two, and /link. The valid bit is
// clear, so the mount runs fsckLite.
func auFsckImage(t *testing.T) (*auPages, *auResult) {
	t.Helper()
	d := newAuDrv(t)
	d.mkdir("/etc")
	d.create("/etc/passwd", 700)
	d.create("/etc/hosts", 90)
	d.create("/one", 200_000)
	d.create("/two", 200_000)
	d.symlink("etc/passwd", "/link")
	d.e.unmount()
	legacy := auDowngrade(t, d.f.snapshot())
	var sb [2]byte
	legacy.readAt(sb[:], 1024+0x3A)
	auLE.PutUint16(sb[:], auLE.Uint16(sb[:])&^1)
	legacy.writeAt(sb[:], 1024+0x3A)
	return legacy, auFsck(legacy, false)
}

// auInodeAt returns the byte offset of an inode in group 0.
func auInodeAt(ino uint32) int64 {
	return int64(67)*auBlock + int64(ino-1)*auISize
}

// auMountLegacy mounts the image without a journal upgrade and returns the
// oracle result of the image after the clean unmount, with the repair notes.
func auMountLegacy(t *testing.T, img *auPages) (*auResult, []string) {
	t.Helper()
	disableJournalUpgrade.Store(true)
	t.Cleanup(func() { disableJournalUpgrade.Store(false) })
	f := newAuFile(img.clone())
	v, err := mountHostFile(f, VolumeOptions{})
	if err != nil {
		t.Fatalf("the engine does not mount the damaged image: %v", err)
	}
	notes := v.repairNotes
	if err := (&Volume{v: v}).Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	res := auFsck(f.snapshot(), true)
	if !res.OK() {
		t.Fatalf("image after the repair:\n%s", res)
	}
	return res, notes
}

// TestAuditFsckDropsAnEntryForAZeroedInode mimics a crash between the write of a
// deleted inode and the write of its directory. The entry names an inode with no
// link. The mount drops the entry and keeps every other file.
func TestAuditFsckDropsAnEntryForAZeroedInode(t *testing.T) {
	img, res := auFsckImage(t)
	img.writeAt(make([]byte, auISize), auInodeAt(res.Tree["/etc/passwd"].ino))
	got, notes := auMountLegacy(t, img)
	if got.Tree["/etc/passwd"] != nil {
		t.Errorf("the entry of the zeroed inode is still there")
	}
	for _, p := range []string{"/etc", "/etc/hosts", "/one", "/two", "/link"} {
		if got.Tree[p] == nil {
			t.Errorf("%s was lost with the damaged entry", p)
		}
	}
	if len(notes) == 0 {
		t.Errorf("the repair left no note")
	}
}

// TestAuditFsckReplacesAnEmptyDirectoryBlock mimics a crash after the write of
// a new directory and before the write of its first block. The directory
// becomes empty and keeps . and .. again.
func TestAuditFsckReplacesAnEmptyDirectoryBlock(t *testing.T) {
	img, res := auFsckImage(t)
	var dirBlock uint64
	for blk, owner := range res.Blocks {
		if owner == res.Tree["/etc"].ino {
			dirBlock = blk
		}
	}
	img.writeAt(make([]byte, auBlock), int64(dirBlock)*auBlock)
	got, _ := auMountLegacy(t, img)
	if got.Tree["/etc"] == nil {
		t.Fatalf("the directory with the damaged block is gone")
	}
	if got.Tree["/etc/passwd"] != nil || got.Tree["/etc/hosts"] != nil {
		t.Errorf("the entries of a block that did not parse came back")
	}
	for _, p := range []string{"/one", "/two", "/link"} {
		if got.Tree[p] == nil {
			t.Errorf("%s was lost with the damaged directory", p)
		}
	}
}

// TestAuditFsckDropsTheSecondOwnerOfABlock gives /two the data blocks of /one.
// The first file that the walk reaches keeps the blocks. The mount drops the
// other.
func TestAuditFsckDropsTheSecondOwnerOfABlock(t *testing.T) {
	img, res := auFsckImage(t)
	var raw [60]byte
	img.readAt(raw[:], auInodeAt(res.Tree["/one"].ino)+0x28)
	img.writeAt(raw[:], auInodeAt(res.Tree["/two"].ino)+0x28)
	got, _ := auMountLegacy(t, img)
	kept := 0
	for _, p := range []string{"/one", "/two"} {
		if got.Tree[p] != nil {
			kept++
		}
	}
	if kept != 1 {
		t.Errorf("%d of the two files that share blocks survive, want 1", kept)
	}
	if got.Tree["/etc/passwd"] == nil || got.Tree["/link"] == nil {
		t.Errorf("unrelated files were lost")
	}
}

// TestAuditFsckDropsAnEntryOutOfRange points an entry of the root at an inode
// number beyond the volume.
func TestAuditFsckDropsAnEntryOutOfRange(t *testing.T) {
	img, res := auFsckImage(t)
	var rootBlock uint64
	for blk, owner := range res.Blocks {
		if owner == 2 {
			rootBlock = blk
		}
	}
	var blk [auBlock]byte
	img.readAt(blk[:], int64(rootBlock)*auBlock)
	at := bytes.Index(blk[:], []byte("one"))
	if at < 8 {
		t.Fatal("no entry named one in the root block")
	}
	auLE.PutUint32(blk[at-8:], 0x7FFFFFF0)
	img.writeAt(blk[:], int64(rootBlock)*auBlock)
	got, _ := auMountLegacy(t, img)
	if got.Tree["/one"] != nil {
		t.Errorf("the entry with the impossible inode number is still there")
	}
	if got.Tree["/two"] == nil || got.Tree["/etc/hosts"] == nil {
		t.Errorf("neighbours of the damaged entry were lost")
	}
}

// TestAuditFsckKeepsADirectoryThatTwoEntriesName adds a second name for a
// directory. The walk keeps the first name and drops the second, and the link
// counts come out right.
func TestAuditFsckKeepsADirectoryThatTwoEntriesName(t *testing.T) {
	img, res := auFsckImage(t)
	var rootBlock uint64
	for blk, owner := range res.Blocks {
		if owner == 2 {
			rootBlock = blk
		}
	}
	var blk [auBlock]byte
	img.readAt(blk[:], int64(rootBlock)*auBlock)
	// The entry "two" now names the inode of /etc.
	at := bytes.Index(blk[:], []byte("two"))
	auLE.PutUint32(blk[at-8:], res.Tree["/etc"].ino)
	blk[at-8+7] = 2
	img.writeAt(blk[:], int64(rootBlock)*auBlock)
	got, _ := auMountLegacy(t, img)
	if got.Tree["/etc"] == nil || got.Tree["/etc/hosts"] == nil {
		t.Errorf("the first name of the directory was lost")
	}
	if got.Tree["/two"] != nil {
		t.Errorf("the second name of the directory is still there")
	}
}
