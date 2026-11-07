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

//go:build !windows

package hostfs

import (
	"fmt"
	"os"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// openFDCount returns the number of descriptors of the process. The listing
// opens one descriptor itself, which the callers compare like for like.
func openFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Skipf("cannot list the descriptors of the process: %v", err)
	}
	return len(entries)
}

// hostCtime returns the change time of a host file in nanoseconds.
func hostCtime(t *testing.T, path string) int64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	return time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)).UnixNano()
}

// changeCtime changes the permission bits of a host file until the change
// time moves. A coarse host clock can keep the old value for a few
// milliseconds.
func changeCtime(t *testing.T, path string) {
	t.Helper()
	before := hostCtime(t, path)
	mode := os.FileMode(0o600)
	deadline := time.Now().Add(5 * time.Second)
	for hostCtime(t, path) == before {
		if time.Now().After(deadline) {
			t.Fatal("the change time of the host file does not move")
		}
		if mode == 0o600 {
			mode = 0o640
		} else {
			mode = 0o600
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHostWatcherReportsHostChmod(t *testing.T) {
	w := newWatchEnv(t)
	w.mustMkdir("d")
	w.writeFile("d/f", []byte("x"))
	w.add("d", hostEventMask)
	w.add("d/f", hostEventMask)
	w.settle()

	changeCtime(t, w.host("d/f"))
	w.sync()
	// The directory watch reports the name and the file watch reports itself.
	w.expect("after a host chmod", "ATTRIB f", "ATTRIB ")
}

func TestHostWatcherReportsHostHardLinkAsCreation(t *testing.T) {
	w := newWatchEnv(t)
	w.mustMkdir("d")
	w.writeFile("d/f", []byte("x"))
	w.add("d", hostEventMask)
	w.settle()

	if err := os.Link(w.host("d/f"), w.host("d/g")); err != nil {
		t.Fatal(err)
	}
	w.sync()
	// The new link count moves the change time of the old name. Linux tells
	// the watcher of the directory only about the new name.
	w.expect("after a host hard link", "CREATE g")
}

func TestHostWatcherReleasesDescriptors(t *testing.T) {
	w := newWatchEnv(t)
	w.mustMkdir("d")
	w.writeFile("d/f", []byte("x"))
	// Warm the pins that lookups use, so that only the descriptors of the
	// watcher show in the count.
	w.readdir("d")
	w.readFile("d/f")
	before := openFDCount(t)

	wd := w.add("d", hostEventMask)
	wf := w.add("d/f", hostEventMask)
	w.settle()
	w.rm(wd)
	w.rm(wf)
	w.ws.watch.waitTeardown()
	if got := openFDCount(t); got > before {
		t.Fatalf("descriptors after the last watch ended = %d, want %d", got, before)
	}
}

func TestHostWatcherWatchedFilesShareTheDirectoryDescriptor(t *testing.T) {
	// The revalidator reads a watched file through the pinned descriptor of
	// its directory, so a watched file costs no descriptor of its own.
	w := newWatchEnv(t)
	w.mustMkdir("d")
	const files = 40
	for i := range files {
		w.writeFile(fmt.Sprintf("d/f%02d", i), []byte("x"))
	}
	w.readdir("d")
	before := openFDCount(t)
	for i := range files {
		w.add(fmt.Sprintf("d/f%02d", i), linux.IN_MODIFY)
	}
	if got := w.ws.watch.watchedCount(); got != files {
		t.Fatalf("watched objects = %d, want %d", got, files)
	}
	if got := openFDCount(t); got != before {
		t.Fatalf("descriptors with %d watched files = %d, want %d", files, got, before)
	}
}

// TestTwoWorkspacesStayBelowTheDescriptorLimit lowers the descriptor limit of
// the process so that the cap of one workspace is the room of the whole process.
// The first workspace watches up to the cap. The second one must get ENOSPC for
// its next watch, and the process must still open files. Without a budget that
// the workspaces share, the second workspace pins descriptors until every open
// of the process fails with EMFILE.
func TestTwoWorkspacesStayBelowTheDescriptorLimit(t *testing.T) {
	var old unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &old); err != nil {
		t.Skipf("getrlimit: %v", err)
	}
	const dirs = minWatchedDentries
	// The room of the process is the cap, and a second set of directories
	// needs about the same number of descriptors again.
	lowered := unix.Rlimit{Cur: uint64(openFDCount(t) + dirs + dirs/2), Max: old.Max}
	if lowered.Cur >= old.Cur {
		t.Skipf("the descriptor limit %d is too low to lower it further", old.Cur)
	}
	oldLimit := processWatches.limit.Load()
	t.Cleanup(func() {
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &old); err != nil {
			t.Errorf("restore the descriptor limit: %v", err)
		}
		processWatches.limit.Store(oldLimit)
	})
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &lowered); err != nil {
		t.Fatalf("lower the descriptor limit: %v", err)
	}
	// The cap and the budget follow the lowered limit, as OpenWorkspace sets them.
	a, b := newWatchEnv(t), newWatchEnv(t)
	limit := hostWatchLimit()
	processWatches.limit.Store(int64(limit))
	for _, w := range []*watchEnv{a, b} {
		for i := range limit {
			if err := os.Mkdir(w.host(fmt.Sprintf("d%d", i)), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}

	for i := range limit {
		if err := a.admit(fmt.Sprintf("d%d", i)); err != nil {
			t.Fatalf("admit %d of the first workspace = %v", i, err)
		}
	}
	for i := range limit {
		err := b.admit(fmt.Sprintf("d%d", i))
		if err == nil {
			continue
		}
		if !linuxerr.Equals(linuxerr.ENOSPC, err) {
			t.Errorf("admit %d of the second workspace = %v, want ENOSPC or no error", i, err)
		}
		break
	}
	if got := a.ws.watch.watchedCount() + b.ws.watch.watchedCount(); got > limit {
		t.Errorf("the two workspaces watch %d objects, want at most %d", got, limit)
	}
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open after the watches of two workspaces = %v", err)
	}
	f.Close()
}
