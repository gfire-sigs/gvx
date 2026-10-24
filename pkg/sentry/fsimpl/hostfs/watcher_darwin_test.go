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

//go:build darwin

package hostfs

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/hostlockdown"
)

// The tests in this file run the real kqueue backend. A scan starts on its own
// when the kernel reports a change, so the tests wait for the events with a
// deadline and never call rescanAll to produce them.

func TestKqueueBackendReportsHostChanges(t *testing.T) {
	w := nativeWatchEnv(t)
	w.mustMkdir("d")
	w.writeFile("d/seed", []byte("seed"))
	w.add("d", hostEventMask)
	be, ok := w.ws.watch.currentBackend().(*kqBackend)
	if !ok {
		t.Fatalf("backend = %T, want *kqBackend", w.ws.watch.currentBackend())
	}
	w.drain()
	c := &collector{w: w}

	hostWrite(t, w.host("d/new"), "1")
	c.await(t, "CREATE new")
	// The creation event arrives after the backend registered the new file, so
	// the write that follows reaches the guest at once.
	hostWrite(t, w.host("d/new"), "12")
	c.await(t, "MODIFY new")
	// A scan can see a half-written file. This pass reads the final state, so
	// the rename below pairs with the name that the snapshot holds.
	w.sync()

	hostWrite(t, w.host("d/seed"), "seed and more")
	c.await(t, "MODIFY seed")

	if err := os.Rename(w.host("d/new"), w.host("d/moved")); err != nil {
		t.Fatal(err)
	}
	c.await(t, "MOVED_FROM new")
	c.await(t, "MOVED_TO moved")
	var from, to uint32
	for _, ev := range c.got {
		switch maskName(ev.mask) + " " + ev.name {
		case "MOVED_FROM new":
			from = ev.cookie
		case "MOVED_TO moved":
			to = ev.cookie
		}
	}
	if from == 0 || from != to {
		t.Fatalf("cookies of the move = %d and %d, want one shared non-zero cookie", from, to)
	}

	if err := os.Remove(w.host("d/moved")); err != nil {
		t.Fatal(err)
	}
	c.await(t, "DELETE moved")
	if got := be.kqueueRegistrations(); got < 2 {
		t.Fatalf("registrations = %d, want the directory and the seed file", got)
	}
}

func TestKqueueBackendWatchesAFileOnItsOwn(t *testing.T) {
	w := nativeWatchEnv(t)
	w.writeFile("f", []byte("data"))
	w.add("f", hostEventMask)
	w.drain()
	c := &collector{w: w}

	hostWrite(t, w.host("f"), "data and more data")
	c.await(t, "MODIFY ")
	if err := os.Remove(w.host("f")); err != nil {
		t.Fatal(err)
	}
	c.await(t, "DELETE_SELF ")
	c.await(t, "IGNORED ")
	waitFor(t, "the watch to end", func() bool { return w.ws.watch.watchedCount() == 0 })
}

func TestKqueueBackendInvalidatesTheMappingOnAHostWrite(t *testing.T) {
	w := nativeWatchEnv(t)
	old := bytes.Repeat([]byte("o"), hostarch.PageSize)
	w.writeFile("m", old)
	fd := w.mustOpen("m", linux.O_RDONLY)
	defer fd.DecRef(w.env.ctx)
	m, ms, ar := w.mapFile(fd, hostarch.PageSize, false)
	defer m.RemoveMapping(w.env.ctx, ms, ar, 0, false)
	if got := readMappedPage(t, w.env, m); !bytes.Equal(got, old) {
		t.Fatalf("first mapped read = %q, want the old bytes", got[:8])
	}

	w.add("m", hostEventMask)
	w.drain()
	c := &collector{w: w}
	fresh := bytes.Repeat([]byte("N"), hostarch.PageSize)
	// The write keeps the size, as an editor that saves in place does.
	f, err := os.OpenFile(w.host("m"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(fresh, 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(3 * time.Second)
	if err := os.Chtimes(w.host("m"), later, later); err != nil {
		t.Fatal(err)
	}
	// The event comes after the invalidation. Once it arrives, the mapping
	// shows the new bytes.
	c.await(t, "MODIFY ")
	waitFor(t, "the last host change", func() bool {
		return bytes.Equal(readMappedPage(t, w.env, m), fresh)
	})
}

func TestKqueueBackendFallsBackToTheTimerAboveTheBound(t *testing.T) {
	e := newEnv(t)
	e.ws.watch.setPollInterval(20 * time.Millisecond)
	w := newWatchEnvOn(t, e)
	w.mustMkdir("d")
	total := kqueueMaxChildren + 20
	for i := range total {
		hostWrite(t, w.host(fmt.Sprintf("d/f%04d", i)), "x")
	}
	w.add("d", hostEventMask)
	be := w.ws.watch.currentBackend().(*kqBackend)
	w.drain()
	c := &collector{w: w}

	// Names sort by number, so the last file has no registration.
	last := fmt.Sprintf("f%04d", total-1)
	be.mu.Lock()
	for _, r := range be.regs {
		if r.name == last {
			be.mu.Unlock()
			t.Fatalf("the file %q has a registration above the bound", last)
		}
	}
	nregs := len(be.regs)
	be.mu.Unlock()
	if nregs > kqueueMaxChildren+1 {
		t.Fatalf("registrations = %d, want at most %d", nregs, kqueueMaxChildren+1)
	}
	hostWrite(t, w.host("d/"+last), "changed by the host")
	c.await(t, "MODIFY "+last)
}

func TestKqueueBackendReleasesEverything(t *testing.T) {
	w := nativeWatchEnv(t)
	w.mustMkdir("d")
	w.writeFile("d/f", []byte("x"))
	w.readdir("d")
	w.readFile("d/f")
	before := openFDCount(t)

	wd := w.add("d", hostEventMask)
	wf := w.add("d/f", hostEventMask)
	be := w.ws.watch.currentBackend().(*kqBackend)
	kq := be.kq
	waitFor(t, "registrations", func() bool { return be.kqueueRegistrations() >= 3 })
	w.rm(wd)
	w.rm(wf)
	w.ws.watch.waitTeardown()

	if !be.idle() {
		t.Fatal("the backend holds registrations after the last watch ended")
	}
	if _, err := unix.FcntlInt(uintptr(kq), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("the kqueue descriptor is still open: %v", err)
	}
	if got := openFDCount(t); got > before {
		t.Fatalf("descriptors after the last watch ended = %d, want %d", got, before)
	}
}

func TestKqueueBackendFollowsAGuestRenameOfAWatchedDirectory(t *testing.T) {
	w := nativeWatchEnv(t)
	w.mustMkdir("old")
	w.add("old", hostEventMask)
	w.drain()
	if err := w.rename("old", "new"); err != nil {
		t.Fatal(err)
	}
	w.drain()
	c := &collector{w: w}
	// The descriptor follows the directory to its new name.
	hostWrite(t, w.host("new/x"), "1")
	c.await(t, "CREATE x")
}

// The host lockdown denies new file opens outside the workspace and gives no
// other call to the watcher. The next test re-executes the test binary as a
// locked child, because the lockdown cannot be undone.

const lockedChildEnv = "GVX_HOSTFS_WATCH_LOCKED_CHILD"

func TestHostWatcherWorksAfterTheHostLockdown(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHostWatcherLockedChild$", "-test.v")
	cmd.Env = append(os.Environ(), lockedChildEnv+"="+dir, "GORACE=atexit_sleep_ms=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("locked child failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Fatalf("locked child did not pass:\n%s", out)
	}
}

// TestHostWatcherLockedChild is the body of the locked child. It does nothing
// in the normal test run.
func TestHostWatcherLockedChild(t *testing.T) {
	dir := os.Getenv(lockedChildEnv)
	if dir == "" {
		t.Skip("runs only as the locked child of TestHostWatcherWorksAfterTheHostLockdown")
	}
	ws, err := openWorkspace(dir, false, workspaceOptions{coalesce: defaultMetaCoalesce})
	if err != nil {
		t.Fatal(err)
	}
	e := mountEnv(t, ws, dir)
	t.Cleanup(func() {
		e.root.DecRef(e.ctx)
		_ = ws.Close()
	})
	e.mustMkdir("d")
	e.writeFile("d/seed", []byte("seed"))
	e.readdir("d")
	e.readFile("d/seed")
	w := newWatchEnvOn(t, e)

	if _, err := hostlockdown.Apply(hostlockdown.Options{Mounts: []hostlockdown.HostMount{{Path: dir}}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// The watches start after the lockdown: the kqueue, the descriptors below
	// the pinned directory, and the scans all run under the Seatbelt profile.
	w.add("d", hostEventMask)
	w.add("d/seed", hostEventMask)
	w.drain()
	if _, ok := e.ws.watch.currentBackend().(*kqBackend); !ok {
		t.Fatalf("backend = %T, want *kqBackend", e.ws.watch.currentBackend())
	}
	c := &collector{w: w}
	hostWrite(t, filepath.Join(dir, "d", "made"), "1")
	c.await(t, "CREATE made")
	hostWrite(t, filepath.Join(dir, "d", "seed"), "seed and more")
	c.await(t, "MODIFY seed")
	c.await(t, "MODIFY ")
	if err := os.Rename(filepath.Join(dir, "d", "made"), filepath.Join(dir, "d", "renamed")); err != nil {
		t.Fatal(err)
	}
	c.await(t, "MOVED_TO renamed")
	if err := os.Remove(filepath.Join(dir, "d", "renamed")); err != nil {
		t.Fatal(err)
	}
	c.await(t, "DELETE renamed")
}
