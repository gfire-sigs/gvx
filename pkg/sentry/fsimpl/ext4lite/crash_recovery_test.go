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

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// cloneImage copies the bytes of the image while a volume has it open. The
// copy is what a power failure at this instant would leave on the host.
func cloneImage(t testing.TB, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
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
	v, path := newTestVolume(t, tierNative)
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

	clone := cloneImage(t, path)
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
			ents, err := n.entries()
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
	v, path := newTestVolume(t, tierNative)
	root := mustRoot(t, v)
	n := createChild(t, v, root, "never-synced", modeRegular|0o644)
	writeAll(t, n, 0, pattern(1, 3*blockSize))
	clone := cloneImage(t, path)
	abandon(v)

	rv, err := tryOpenVolume(clone, volumeOptions{now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	ents, err := mustRoot(t, rv).entries()
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
