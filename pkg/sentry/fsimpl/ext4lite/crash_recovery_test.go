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
	"path/filepath"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// cloneImage copies the bytes of the image while a volume has it open. The
// copy is what a power failure at this instant would leave on the host. It
// reads through the handle of the volume, because on Windows the lock of the
// volume stops every other handle from reading the file.
func cloneImage(t testing.TB, v *volume) string {
	t.Helper()
	size, err := v.hf.Size()
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, size)
	if _, err := v.hf.ReadAt(data, 0); err != nil {
		t.Fatal(err)
	}
	clone := filepath.Join(t.TempDir(), "clone.ext4")
	if err := os.WriteFile(clone, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return clone
}

// TestCrashRecovery clones the image in the middle of a workload. The workload
// has a file that was committed with a sync, a file that a guest unlinked
// while it kept the file open, and allocations that no sync covered. The
// remount must keep every committed file, reclaim the rest, and leave the
// volume consistent.
func TestCrashRecovery(t *testing.T) {
	v, _ := newTestVolume(t, platformTier)
	root := mustRoot(t, v)

	// A database and its write-ahead log, both committed.
	db := createChild(t, v, root, "app.db", modeRegular|0o644)
	wal := createChild(t, v, root, "app.db-wal", modeRegular|0o644)
	dir := createChild(t, v, root, "data", modeDir|0o755)
	cfg := createChild(t, v, dir, "config", modeRegular|0o600)
	if err := cfg.setXattr("user.tag", []byte("kept"), false, false); err != nil {
		t.Fatal(err)
	}
	writeAll(t, cfg, 0, []byte("committed config"))
	for i := range 64 {
		writeAll(t, db, int64(i)*blockSize, pattern(byte(i), blockSize))
		writeAll(t, wal, int64(i)*512, pattern(byte(i+100), 512))
	}
	if err := v.sync(); err != nil {
		t.Fatal(err)
	}
	wantDB, wantWAL := readAll(t, db), readAll(t, wal)

	// A file that a guest unlinked and still holds open.
	ghost := createChild(t, v, root, "ghost", modeRegular|0o644)
	writeAll(t, ghost, 0, pattern(7, 1<<20))
	if err := v.sync(); err != nil {
		t.Fatal(err)
	}
	unlinkKeepRef(t, root, "ghost", ghost)
	if err := v.sync(); err != nil {
		t.Fatal(err)
	}

	// Work that no sync covers: new files, a grown file, a removed file.
	for i := range 20 {
		n := createChild(t, v, dir, fmt.Sprintf("fresh-%d", i), modeRegular|0o644)
		writeAll(t, n, 0, pattern(byte(i), 50000))
	}
	writeAll(t, db, 64*blockSize, pattern(200, blockSize))

	clone := cloneImage(t, v)
	abandon(v)

	rv, err := tryOpenVolume(clone, volumeOptions{now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatalf("remount after the crash: %v", err)
	}
	rroot := mustRoot(t, rv)
	for name, want := range map[string][]byte{"app.db": wantDB, "app.db-wal": wantWAL} {
		n := lookupNode(t, rv, rroot, name)
		got := readAll(t, n)
		if len(got) < len(want) || !bytes.Equal(got[:len(want)], want) {
			t.Errorf("%s lost committed content", name)
		}
	}
	if _, _, err := rroot.lookup("ghost"); !errors.Is(err, linuxerr.ENOENT) {
		t.Errorf("lookup of the unlinked file = %v, want ENOENT", err)
	}
	if _, _, err := rroot.lookup("lost+found"); !errors.Is(err, linuxerr.ENOENT) {
		t.Errorf("lookup of lost+found = %v, want ENOENT", err)
	}
	rdir := lookupNode(t, rv, rroot, "data")
	rcfg := lookupNode(t, rv, rdir, "config")
	if got := readAll(t, rcfg); string(got) != "committed config" {
		t.Errorf("config = %q", got)
	}
	if got, err := rcfg.getXattr("user.tag"); err != nil || string(got) != "kept" {
		t.Errorf("xattr = %q, %v", got, err)
	}

	// The unreachable inodes and their blocks are free again: the used
	// counts equal what the tree reaches.
	used := usedInodes(rv)
	reachable := countReachable(t, rv)
	if used != reachable+firstIno-1-1 {
		t.Errorf("%d inodes in use, %d reachable plus %d reserved", used, reachable, firstIno-1)
	}
	if err := rv.close(); err != nil {
		t.Fatal(err)
	}
	runE2fsck(t, clone)
}

// unlinkKeepRef removes the entry and leaves the reference, as an unlink of
// an open file does.
func unlinkKeepRef(t testing.TB, dir *node, name string, n *node) {
	t.Helper()
	if err := dir.removeEntry(name); err != nil {
		t.Fatal(err)
	}
	setLinks(n, 0)
}

func usedInodes(v *volume) uint32 {
	v.mu.Lock()
	defer v.mu.Unlock()
	var used uint32
	for _, g := range v.groups {
		used += g.inodes.count()
	}
	return used
}

// countReachable counts the inodes from the root, the root included, that a
// walk of the directory tree reaches. Hard links count once.
func countReachable(t testing.TB, v *volume) uint32 {
	t.Helper()
	seen := map[uint32]bool{rootIno: true}
	stack := []uint32{rootIno}
	for len(stack) > 0 {
		ino := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		n, err := v.getNode(ino)
		if err != nil {
			t.Fatal(err)
		}
		if n.isDir() {
			ents, err := n.entriesFrom(0)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range ents {
				if e.name == "." || e.name == ".." || seen[e.ino] {
					continue
				}
				seen[e.ino] = true
				stack = append(stack, e.ino)
			}
		}
		v.putNode(n)
	}
	return uint32(len(seen))
}

// TestCrashBeforeAnySync mounts the image that a crash left right after the
// first write. Nothing was committed, so the volume must come back empty.
func TestCrashBeforeAnySync(t *testing.T) {
	v, _ := newTestVolume(t, platformTier)
	root := mustRoot(t, v)
	n := createChild(t, v, root, "never-synced", modeRegular|0o644)
	writeAll(t, n, 0, pattern(1, 3*blockSize))
	clone := cloneImage(t, v)
	abandon(v)

	rv, err := tryOpenVolume(clone, volumeOptions{now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	ents, err := mustRoot(t, rv).entriesFrom(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 2 {
		t.Errorf("root lists %d entries, want only . and ..", len(ents))
	}
	if err := rv.close(); err != nil {
		t.Fatal(err)
	}
	runE2fsck(t, clone)
}

// TestCrashRecoveryDatabaseWorkload runs a workload shaped like SQLite in WAL
// mode on the VFS layer. The writer appends frames to the log and syncs the
// log after each transaction. It checkpoints pages into the database file and
// syncs that file. It keeps a rollback file that it has unlinked but not
// closed, and it ends with writes that no sync covers. The test clones the
// image in that state. The remount must keep every byte that a sync covered,
// free the unlinked file, and leave no lost+found directory.
func TestCrashRecoveryDatabaseWorkload(t *testing.T) {
	e := newEnv(t)
	const page, frame = blockSize, blockSize + 24
	db := e.mustOpen("app.db", linux.O_CREAT|linux.O_RDWR)
	wal := e.mustOpen("app.db-wal", linux.O_CREAT|linux.O_RDWR)
	rollback := e.mustOpen("app.db-journal", linux.O_CREAT|linux.O_RDWR)
	// The descriptors outlive the crash clone. The deferred release also runs
	// when the test ends early, so the volume closes and Windows can delete
	// the image.
	defer func() {
		for _, fd := range []*vfs.FileDescription{db, wal, rollback} {
			fd.DecRef(e.ctx)
		}
	}()
	e.write(rollback, pattern(9, 100000))
	if err := e.unlink("app.db-journal"); err != nil {
		t.Fatal(err)
	}
	e.mustMkdir("attachments")

	var committedDB, committedWAL []byte
	sync := func(fd *vfs.FileDescription) {
		t.Helper()
		if err := fd.Sync(e.ctx); err != nil {
			t.Fatalf("fsync: %v", err)
		}
	}
	for tx := range 30 {
		data := pattern(byte(tx), frame)
		e.pwrite(wal, data, int64(tx)*frame)
		sync(wal)
		committedWAL = append(committedWAL, data...)
		if tx%10 == 9 {
			for p := range 10 {
				data := pattern(byte(100+tx+p), page)
				e.pwrite(db, data, int64(tx/10*10+p)*page)
				committedDB = append(committedDB[:min(len(committedDB), (tx/10*10+p)*page)], data...)
			}
			sync(db)
		}
	}
	// Work that no sync covers. It extends the files and adds new files.
	for tx := 30; tx < 45; tx++ {
		e.pwrite(wal, pattern(byte(tx), frame), int64(tx)*frame)
	}
	e.pwrite(db, pattern(77, 10*page), 40*page)
	for i := range 12 {
		e.writeFile(fmt.Sprintf("attachments/new-%d", i), pattern(byte(i), 30000))
	}

	clone := cloneImage(t, e.fs.v)
	raw, err := os.ReadFile(clone)
	if err != nil {
		t.Fatal(err)
	}
	if state := le.Uint16(raw[superOffset+sbState:]); state&stateValid != 0 {
		t.Fatalf("the clone has s_state %#x, want the valid bit clear during the workload", state)
	}

	r := openEnv(t, clone, VolumeOptions{}, vfs.MountOptions{})
	gotWAL := r.readFile("app.db-wal")
	if len(gotWAL) < len(committedWAL) || !bytes.Equal(gotWAL[:len(committedWAL)], committedWAL) {
		t.Errorf("the log lost committed frames: %d bytes after the crash, %d committed", len(gotWAL), len(committedWAL))
	}
	gotDB := r.readFile("app.db")
	if len(gotDB) < len(committedDB) || !bytes.Equal(gotDB[:len(committedDB)], committedDB) {
		t.Errorf("the database lost committed pages: %d bytes after the crash, %d committed", len(gotDB), len(committedDB))
	}
	names := r.readdir("")
	for _, name := range names {
		if name == "lost+found" || name == "app.db-journal" {
			t.Errorf("the root lists %q after the recovery", name)
		}
	}
	if used, reachable := usedInodes(r.fs.v), countReachable(t, r.fs.v); used != reachable+firstIno-2 {
		t.Errorf("%d inodes in use, %d reachable: the recovery left unreachable inodes", used, reachable)
	}
	r.unmount()
	runE2fsck(t, clone)
}
