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

package hostfs

import (
	"bytes"
	"encoding/binary"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/uniqueid"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// hostEventMask selects the events that the host watcher produces.
const hostEventMask = linux.IN_CREATE | linux.IN_DELETE | linux.IN_MODIFY | linux.IN_ATTRIB |
	linux.IN_MOVED_FROM | linux.IN_MOVED_TO | linux.IN_DELETE_SELF | linux.IN_MOVE_SELF

// idContext supplies the unique identifier that vfs.NewInotifyFD takes from
// its context.
type idContext struct {
	gvcontext.Context
	next *atomic.Uint64
}

func (c idContext) Value(key any) any {
	if key == uniqueid.CtxGlobalUniqueID {
		return c.next.Add(1)
	}
	return c.Context.Value(key)
}

// inotifyEvent is one decoded linux.inotify_event.
type inotifyEvent struct {
	wd     int32
	mask   uint32
	cookie uint32
	name   string
}

// watchEnv is a hostfs mount with one inotify instance.
type watchEnv struct {
	*env
	ctx gvcontext.Context
	in  *vfs.FileDescription
	ino *vfs.Inotify
}

// pollFactory returns a backend factory for the revalidator. With a long
// interval the revalidator never runs on its own, so a test drives every scan
// through rescanAll and sees a deterministic event sequence.
func pollFactory(hw *hostWatcher) (watchBackend, error) {
	return newPollBackend(hw), nil
}

// newWatchEnv mounts a workspace with the revalidator backend and a long
// interval. See pollFactory.
func newWatchEnv(t *testing.T) *watchEnv {
	t.Helper()
	e := newEnv(t)
	e.ws.watch.factory = pollFactory
	e.ws.watch.setPollInterval(time.Hour)
	return newWatchEnvOn(t, e)
}

// newWatchEnvOn adds an inotify instance to a mount.
func newWatchEnvOn(t *testing.T, e *env) *watchEnv {
	t.Helper()
	ctx := idContext{Context: e.ctx, next: new(atomic.Uint64)}
	in, err := vfs.NewInotifyFD(ctx, e.vfsObj, linux.O_NONBLOCK)
	if err != nil {
		t.Fatalf("NewInotifyFD: %v", err)
	}
	t.Cleanup(func() { in.DecRef(ctx) })
	return &watchEnv{env: e, ctx: ctx, in: in, ino: in.Impl().(*vfs.Inotify)}
}

// add registers a guest watch on the path and returns its descriptor.
func (w *watchEnv) add(p string, mask uint32) int32 {
	w.t.Helper()
	vd, err := w.vfsObj.GetDentryAt(w.ctx, w.creds, w.fpop(p), &vfs.GetDentryOptions{})
	if err != nil {
		w.t.Fatalf("GetDentryAt %q: %v", p, err)
	}
	defer vd.DecRef(w.ctx)
	return w.ino.AddWatch(vd.Dentry(), mask)
}

func (w *watchEnv) rm(wd int32) {
	w.t.Helper()
	if err := w.ino.RmWatch(w.ctx, wd); err != nil {
		w.t.Fatalf("RmWatch(%d): %v", wd, err)
	}
}

// drain reads every queued event.
func (w *watchEnv) drain() []inotifyEvent {
	w.t.Helper()
	var out []inotifyEvent
	buf := make([]byte, 64<<10)
	for {
		n, err := w.in.Read(w.ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
		if linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
			return out
		}
		if err != nil {
			w.t.Fatalf("read inotify: %v", err)
		}
		for rest := buf[:n]; len(rest) > 0; {
			nameLen := int(binary.LittleEndian.Uint32(rest[12:]))
			ev := inotifyEvent{
				wd:     int32(binary.LittleEndian.Uint32(rest)),
				mask:   binary.LittleEndian.Uint32(rest[4:]),
				cookie: binary.LittleEndian.Uint32(rest[8:]),
				name:   string(bytes.TrimRight(rest[16:16+nameLen], "\x00")),
			}
			out = append(out, ev)
			rest = rest[16+nameLen:]
		}
	}
}

// sync runs one scan of every watched object and returns after the scans
// delivered their events. It is the barrier that tests use instead of a
// sleep.
func (w *watchEnv) sync() {
	w.ws.watch.rescanAll()
}

// settle drains the events that earlier steps left.
func (w *watchEnv) settle() {
	w.t.Helper()
	w.sync()
	w.drain()
}

// eventNames renders events as "mask name" with the mask names of the host events.
func eventNames(evs []inotifyEvent) []string {
	out := make([]string, 0, len(evs))
	for _, ev := range evs {
		out = append(out, maskName(ev.mask)+" "+ev.name)
	}
	return out
}

func maskName(m uint32) string {
	var s string
	switch {
	case m&linux.IN_CREATE != 0:
		s = "CREATE"
	case m&linux.IN_DELETE_SELF != 0:
		s = "DELETE_SELF"
	case m&linux.IN_DELETE != 0:
		s = "DELETE"
	case m&linux.IN_MODIFY != 0:
		s = "MODIFY"
	case m&linux.IN_ATTRIB != 0:
		s = "ATTRIB"
	case m&linux.IN_MOVED_FROM != 0:
		s = "MOVED_FROM"
	case m&linux.IN_MOVED_TO != 0:
		s = "MOVED_TO"
	case m&linux.IN_MOVE_SELF != 0:
		s = "MOVE_SELF"
	case m&linux.IN_IGNORED != 0:
		s = "IGNORED"
	default:
		s = "?"
	}
	if m&linux.IN_ISDIR != 0 {
		s += "|ISDIR"
	}
	return s
}

func (w *watchEnv) expect(what string, want ...string) {
	w.t.Helper()
	got := eventNames(w.drain())
	if !slices.Equal(got, want) {
		w.t.Fatalf("%s: events = %q, want %q", what, got, want)
	}
}

func (w *watchEnv) expectNone(what string) {
	w.t.Helper()
	w.expect(what)
}

// hostWrite replaces the content of a host file. The caller passes a size
// that differs from the old size, so that the host watcher sees a change on
// a host with a coarse clock.
func hostWrite(t *testing.T, path string, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("host write %q: %v", path, err)
	}
}

// waitFor polls until cond holds. It fails at the deadline.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (hw *hostWatcher) waitTeardown() {
	hw.teardown.Wait()
}

func (hw *hostWatcher) currentBackend() watchBackend {
	hw.mu.Lock()
	defer hw.mu.Unlock()
	return hw.backend
}

func TestHostWatcherDirectoryEvents(t *testing.T) {
	w := newWatchEnv(t)
	w.mustMkdir("d")
	wd := w.add("d", hostEventMask)
	w.settle()

	hostWrite(t, w.host("d/a.txt"), "one")
	w.sync()
	evs := w.drain()
	if got, want := eventNames(evs), []string{"CREATE a.txt"}; !slices.Equal(got, want) {
		t.Fatalf("after host create: events = %q, want %q", got, want)
	}
	if evs[0].wd != wd {
		t.Fatalf("event wd = %d, want %d", evs[0].wd, wd)
	}

	hostWrite(t, w.host("d/a.txt"), "one two")
	w.sync()
	w.expect("after host write", "MODIFY a.txt")

	if err := os.Rename(w.host("d/a.txt"), w.host("d/b.txt")); err != nil {
		t.Fatal(err)
	}
	w.sync()
	moved := w.drain()
	if got, want := eventNames(moved), []string{"MOVED_FROM a.txt", "MOVED_TO b.txt"}; !slices.Equal(got, want) {
		t.Fatalf("after host rename: events = %q, want %q", got, want)
	}
	if moved[0].cookie == 0 || moved[0].cookie != moved[1].cookie {
		t.Fatalf("cookies of the move = %d and %d, want one shared non-zero cookie", moved[0].cookie, moved[1].cookie)
	}

	if err := os.Remove(w.host("d/b.txt")); err != nil {
		t.Fatal(err)
	}
	w.sync()
	w.expect("after host delete", "DELETE b.txt")

	if err := os.Mkdir(w.host("d/sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	w.sync()
	w.expect("after host mkdir", "CREATE|ISDIR sub")

	if got := w.ws.watch.delivered.Load(); got != 6 {
		t.Fatalf("delivered notifications = %d, want 6", got)
	}
	w.sync()
	w.expectNone("a scan without a change")
}

func TestHostWatcherFileEvents(t *testing.T) {
	w := newWatchEnv(t)
	w.writeFile("f", []byte("data"))
	w.add("f", hostEventMask)
	w.settle()

	hostWrite(t, w.host("f"), "longer data")
	w.sync()
	w.expect("after host write", "MODIFY ")

	// An atomic save replaces the file by renaming a new one over it. The
	// watched inode is gone, as on Linux.
	hostWrite(t, w.host("f.tmp"), "saved by an editor")
	if err := os.Rename(w.host("f.tmp"), w.host("f")); err != nil {
		t.Fatal(err)
	}
	w.sync()
	w.expect("after atomic save", "DELETE_SELF ", "IGNORED ")
	if got := w.ws.watch.watchedCount(); got != 0 {
		t.Fatalf("watched objects after the file went away = %d, want 0", got)
	}
	if got := string(w.readFile("f")); got != "saved by an editor" {
		t.Fatalf("guest read after atomic save = %q", got)
	}
}

func TestHostWatcherReplacedNameInDirectory(t *testing.T) {
	w := newWatchEnv(t)
	w.mustMkdir("d")
	w.writeFile("d/doc", []byte("old"))
	w.add("d", hostEventMask)
	w.settle()

	hostWrite(t, w.host("d/doc.tmp"), "brand new content")
	if err := os.Rename(w.host("d/doc.tmp"), w.host("d/doc")); err != nil {
		t.Fatal(err)
	}
	w.sync()
	w.expect("after atomic save", "DELETE doc", "CREATE doc")
	if got := string(w.readFile("d/doc")); got != "brand new content" {
		t.Fatalf("guest read after atomic save = %q", got)
	}
}

func TestHostWatcherDropsStaleLookupResults(t *testing.T) {
	w := newWatchEnv(t)
	w.mustMkdir("d")
	w.add("d", hostEventMask)
	w.settle()

	// A failed lookup leaves a negative entry that lives for a second.
	if _, err := w.stat("d/late"); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Fatalf("stat of a missing name = %v, want ENOENT", err)
	}
	hostWrite(t, w.host("d/late"), "here")
	w.sync()
	w.expect("after host create", "CREATE late")
	if st, err := w.stat("d/late"); err != nil || st.Size != 4 {
		t.Fatalf("stat after the event = (%v, %v), want a 4-byte file", st.Size, err)
	}

	hostWrite(t, w.host("d/late"), "here is more")
	w.sync()
	w.expect("after host write", "MODIFY late")
	if st := w.mustStat("d/late"); st.Size != 12 {
		t.Fatalf("size after the event = %d, want 12", st.Size)
	}

	if err := os.Remove(w.host("d/late")); err != nil {
		t.Fatal(err)
	}
	w.sync()
	w.expect("after host delete", "DELETE late")
	if _, err := w.stat("d/late"); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Fatalf("stat after the delete event = %v, want ENOENT", err)
	}
}

func TestHostWatcherHidesInternalNames(t *testing.T) {
	w := newWatchEnv(t)
	w.add(".", hostEventMask)
	w.settle()

	// The metadata file changes whenever the guest changes a mode.
	w.writeFile("visible", []byte("x"))
	w.drain()
	if err := w.ws.Sync(); err != nil {
		t.Fatal(err)
	}
	w.sync()
	w.expectNone("after a metadata flush")
}

// coherencyCase runs the cache check once with a watch on the file and once
// with a watch on its directory.
func TestHostWatcherKeepsMappedPagesCoherent(t *testing.T) {
	for _, watchDir := range []bool{false, true} {
		name := "file watch"
		if watchDir {
			name = "directory watch"
		}
		t.Run(name, func(t *testing.T) {
			forEachChunkMode(t, func(t *testing.T, e *env) {
				e.ws.watch.factory = pollFactory
				e.ws.watch.setPollInterval(time.Hour)
				testMappedPagesFollowHostWrites(t, newWatchEnvOn(t, e), watchDir)
			})
		})
	}
}

// readMappedPage translates the first page of a mapping and returns a copy of
// its bytes.
func readMappedPage(t *testing.T, e *env, m memmap.Mappable) []byte {
	t.Helper()
	ts, err := m.Translate(e.ctx, memmap.MappableRange{Start: 0, End: hostarch.PageSize},
		memmap.MappableRange{Start: 0, End: hostarch.PageSize}, hostarch.Read)
	if err != nil || len(ts) == 0 {
		t.Fatalf("Translate = (%v, %v)", ts, err)
	}
	bs, err := ts[0].File.MapInternal(memmap.FileRange{Start: ts[0].Offset, End: ts[0].Offset + hostarch.PageSize}, hostarch.Read)
	if err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	return bytes.Clone(bs.Head().ToSlice())
}

func testMappedPagesFollowHostWrites(t *testing.T, w *watchEnv, watchDir bool) {
	w.mustMkdir("d")
	old := bytes.Repeat([]byte("o"), hostarch.PageSize)
	w.writeFile("d/m", old)
	fd := w.mustOpen("d/m", linux.O_RDONLY)
	defer fd.DecRef(w.env.ctx)
	m, ms, ar := w.mapFile(fd, hostarch.PageSize, false)
	defer m.RemoveMapping(w.env.ctx, ms, ar, 0, false)

	read := func() []byte {
		t.Helper()
		return readMappedPage(t, w.env, m)
	}
	if got := read(); !bytes.Equal(got, old) {
		t.Fatalf("first mapped read = %q, want the old bytes", got[:8])
	}

	if watchDir {
		w.add("d", hostEventMask)
	} else {
		w.add("d/m", hostEventMask)
	}
	w.settle()

	// The new bytes have the same length. A later modification time is the
	// only sign of the change, as with an editor that saves in place.
	fresh := bytes.Repeat([]byte("N"), hostarch.PageSize)
	hostWrite(t, w.host("d/m"), string(fresh))
	later := time.Now().Add(3 * time.Second)
	if err := os.Chtimes(w.host("d/m"), later, later); err != nil {
		t.Fatal(err)
	}
	ms.mu.Lock()
	before := len(ms.invalidated)
	ms.mu.Unlock()
	w.sync()

	// The event is in the queue. A guest that wakes for it must see the new
	// bytes in the page cache, in a read, and in the mapping.
	evs := eventNames(w.drain())
	want := []string{"MODIFY m"}
	if !watchDir {
		want = []string{"MODIFY "}
	}
	if !slices.Equal(evs, want) {
		t.Fatalf("events = %q, want %q", evs, want)
	}
	ms.mu.Lock()
	after := len(ms.invalidated)
	ms.mu.Unlock()
	if after == before {
		t.Fatal("the host change did not invalidate the mapping")
	}
	if got := read(); !bytes.Equal(got, fresh) {
		t.Fatalf("mapped read after the event = %q, want the new bytes", got[:8])
	}
	buf := make([]byte, hostarch.PageSize)
	if n, err := fd.PRead(w.env.ctx, usermem.BytesIOSequence(buf), 0, vfs.ReadOptions{}); err != nil || int(n) != len(buf) || !bytes.Equal(buf, fresh) {
		t.Fatalf("pread after the event = (%d, %v), want the new bytes", n, err)
	}
}

func TestHostWatcherKeepsGuestModifiedChunks(t *testing.T) {
	w := newWatchEnv(t)
	w.writeFile("m", bytes.Repeat([]byte("a"), 2*hostarch.PageSize))
	fd := w.mustOpen("m", linux.O_RDWR)
	defer fd.DecRef(w.env.ctx)
	m, ms, ar := w.mapFile(fd, 2*hostarch.PageSize, true)
	ts, err := m.Translate(w.env.ctx, memmap.MappableRange{Start: 0, End: hostarch.PageSize},
		memmap.MappableRange{Start: 0, End: 2 * hostarch.PageSize}, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	bs, err := ts[0].File.MapInternal(memmap.FileRange{Start: ts[0].Offset, End: ts[0].Offset + 5}, hostarch.ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	copy(bs.Head().ToSlice(), "guest")

	w.add("m", hostEventMask)
	w.settle()
	hostWrite(t, w.host("m"), string(bytes.Repeat([]byte("h"), 2*hostarch.PageSize+1)))
	w.sync()
	w.expect("after host write", "MODIFY ")

	// The guest page is dirty, so the cache keeps it. The unmap writes it back.
	m.RemoveMapping(w.env.ctx, ms, ar, 0, true)
	raw, err := os.ReadFile(w.host("m"))
	if err != nil || string(raw[:5]) != "guest" {
		t.Fatalf("host content after write-back = (%q, %v), want the guest bytes", raw[:5], err)
	}
	w.sync()
	w.expectNone("echo of the write-back")
}

func TestHostWatcherSuppressesGuestEchoes(t *testing.T) {
	w := newWatchEnv(t)
	w.mustMkdir("d")
	w.add("d", hostEventMask)
	w.writeFile("d/seed", []byte("seed"))
	w.add("d/seed", hostEventMask)
	w.settle()
	hw := &w.ws.watch

	// Prove first that the bridge is live, so that the checks below mean
	// something.
	hostWrite(t, w.host("d/probe"), "p")
	w.sync()
	w.expect("probe", "CREATE probe")
	w.settle()
	base := hw.delivered.Load()

	step := func(what string, op func()) {
		t.Helper()
		op()
		// The guest events arrive without a scan. The scan that follows
		// must add nothing.
		w.drain()
		w.sync()
		w.expectNone("echo of " + what)
		if got := hw.delivered.Load(); got != base {
			t.Fatalf("%s: the watcher delivered %d notifications for a guest mutation", what, got-base)
		}
	}
	step("create and first write", func() { w.writeFile("d/g", []byte("guest")) })
	step("second write", func() {
		fd := w.mustOpen("d/g", linux.O_WRONLY|linux.O_APPEND)
		defer fd.DecRef(w.env.ctx)
		if _, err := fd.Write(w.env.ctx, usermem.BytesIOSequence([]byte(" more")), vfs.WriteOptions{}); err != nil {
			t.Fatal(err)
		}
	})
	step("write to the watched file", func() {
		fd := w.mustOpen("d/seed", linux.O_WRONLY|linux.O_APPEND)
		defer fd.DecRef(w.env.ctx)
		if _, err := fd.Write(w.env.ctx, usermem.BytesIOSequence([]byte("++")), vfs.WriteOptions{}); err != nil {
			t.Fatal(err)
		}
	})
	step("truncate", func() {
		if err := w.setStat("d/g", linux.Statx{Mask: linux.STATX_SIZE, Size: 3}); err != nil {
			t.Fatal(err)
		}
	})
	step("timestamps", func() {
		ts := linux.StatxTimestamp{Sec: time.Now().Add(-time.Hour).Unix()}
		if err := w.setStat("d/g", linux.Statx{Mask: linux.STATX_MTIME | linux.STATX_ATIME, Mtime: ts, Atime: ts}); err != nil {
			t.Fatal(err)
		}
	})
	step("rename", func() {
		if err := w.rename("d/g", "d/h"); err != nil {
			t.Fatal(err)
		}
	})
	step("rename over a name", func() {
		w.writeFile("d/over", []byte("x"))
		w.drain()
		if err := w.rename("d/h", "d/over"); err != nil {
			t.Fatal(err)
		}
	})
	step("hard link", func() {
		if err := w.link("d/over", "d/link"); err != nil {
			t.Fatal(err)
		}
	})
	step("unlink", func() {
		if err := w.unlink("d/link"); err != nil {
			t.Fatal(err)
		}
	})
	step("mkdir and rmdir", func() {
		w.mustMkdir("d/sub")
		w.drain()
		w.sync()
		if err := w.vfsObj.RmdirAt(w.env.ctx, w.creds, w.pop("d/sub")); err != nil {
			t.Fatal(err)
		}
	})
	step("mapped write and write-back", func() {
		fd := w.mustOpen("d/over", linux.O_RDWR)
		defer fd.DecRef(w.env.ctx)
		m, ms, ar := w.mapFile(fd, hostarch.PageSize, true)
		ts, err := m.Translate(w.env.ctx, memmap.MappableRange{Start: 0, End: hostarch.PageSize},
			memmap.MappableRange{Start: 0, End: hostarch.PageSize}, hostarch.ReadWrite)
		if err != nil {
			t.Fatal(err)
		}
		bs, err := ts[0].File.MapInternal(memmap.FileRange{Start: ts[0].Offset, End: ts[0].Offset + 1}, hostarch.ReadWrite)
		if err != nil {
			t.Fatal(err)
		}
		bs.Head().ToSlice()[0] = 'M'
		m.RemoveMapping(w.env.ctx, ms, ar, 0, true)
	})
}

func TestHostWatcherRacesWithGuestWrites(t *testing.T) {
	w := newWatchEnv(t)
	w.mustMkdir("d")
	w.writeFile("d/f", nil)
	w.add("d", hostEventMask)
	w.add("d/f", hostEventMask)
	w.settle()
	hw := &w.ws.watch
	base := hw.delivered.Load()

	fd := w.mustOpen("d/f", linux.O_WRONLY)
	defer fd.DecRef(w.env.ctx)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					hw.rescanAll()
				}
			}
		}()
	}
	for i := range 300 {
		if _, err := fd.PWrite(w.env.ctx, usermem.BytesIOSequence([]byte("0123456789")), int64(i*10), vfs.WriteOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	hw.rescanAll()
	if got := hw.delivered.Load(); got != base {
		t.Fatalf("the watcher delivered %d notifications for guest writes only", got-base)
	}
}

func TestHostWatcherCapRefusesTheExtraWatch(t *testing.T) {
	w := newWatchEnv(t)
	hw := &w.ws.watch
	hw.setLimit(2)
	for _, d := range []string{"a", "b", "c"} {
		w.mustMkdir(d)
	}
	wa := w.add("a", hostEventMask)
	w.add("b", hostEventMask)
	w.settle()

	vd, err := w.vfsObj.GetDentryAt(w.ctx, w.creds, w.fpop("c"), &vfs.GetDentryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer vd.DecRef(w.ctx)
	if err := w.ws.watchDentry(vd.Dentry().Impl().(*dentry)); !linuxerr.Equals(linuxerr.ENOSPC, err) {
		t.Fatalf("watchDentry above the cap = %v, want ENOSPC", err)
	}
	if got := hw.watchedCount(); got != 2 {
		t.Fatalf("watched objects = %d, want 2", got)
	}

	// The VFS cannot fail the add. The guest watch on the third directory works
	// for guest events and gets no host events.
	w.add("c", hostEventMask)
	hostWrite(t, w.host("c/x"), "x")
	hostWrite(t, w.host("a/x"), "x")
	w.sync()
	w.expect("host change in a refused directory and an accepted one", "CREATE x")
	w.writeFile("c/y", []byte("y"))
	w.expect("guest change in the refused directory", "CREATE y", "MODIFY y")

	// Ending a watch frees a slot.
	w.rm(wa)
	w.add("c", hostEventMask)
	if got := hw.watchedCount(); got != 2 {
		t.Fatalf("watched objects after the swap = %d, want 2", got)
	}
}

func TestHostWatcherDetachesAtZeroWatches(t *testing.T) {
	w := newWatchEnv(t)
	hw := &w.ws.watch
	w.mustMkdir("d")
	w.writeFile("d/f", []byte("x"))
	wd := w.add("d", hostEventMask)
	wf := w.add("d/f", hostEventMask)
	if got := hw.watchedCount(); got != 2 {
		t.Fatalf("watched objects = %d, want 2", got)
	}
	be := hw.currentBackend().(*pollBackend)
	if be.idle() {
		t.Fatal("backend is idle while it holds two watches")
	}

	// A second guest watch on the same file shares the host watch.
	second, err := vfs.NewInotifyFD(w.ctx, w.vfsObj, linux.O_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	vd, err := w.vfsObj.GetDentryAt(w.ctx, w.creds, w.fpop("d/f"), &vfs.GetDentryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second.Impl().(*vfs.Inotify).AddWatch(vd.Dentry(), linux.IN_MODIFY)
	vd.DecRef(w.ctx)
	if got := hw.watchedCount(); got != 2 {
		t.Fatalf("watched objects with a second guest watch = %d, want 2", got)
	}

	w.rm(wf)
	if got := hw.watchedCount(); got != 2 {
		t.Fatalf("the host watch ended while another guest watch remains: %d watched", got)
	}
	w.rm(wd)
	if got := hw.watchedCount(); got != 1 {
		t.Fatalf("watched objects after the directory watch ended = %d, want 1", got)
	}
	second.DecRef(w.ctx)
	if got := hw.watchedCount(); got != 0 {
		t.Fatalf("watched objects at zero guest watches = %d, want 0", got)
	}
	hw.waitTeardown()
	if hw.currentBackend() != nil {
		t.Fatal("the backend lives on without a watch")
	}
	if !be.idle() {
		t.Fatal("the revalidator goroutine or its entries are left")
	}
	if got := be.running.Load(); got != 0 {
		t.Fatalf("revalidator goroutines = %d, want 0", got)
	}
	w.ws.pinMu.Lock()
	for rel, p := range w.ws.pins {
		if p.refs != 0 {
			t.Errorf("pin %q keeps %d references after the last watch", rel, p.refs)
		}
	}
	w.ws.pinMu.Unlock()
	w.drain()
	hostWrite(t, w.host("d/f"), "again")
	w.sync()
	w.expectNone("host write after the watches ended")
}

func TestHostWatcherStopsAtWorkspaceClose(t *testing.T) {
	w := newWatchEnv(t)
	w.mustMkdir("d")
	w.add("d", hostEventMask)
	be := w.ws.watch.currentBackend().(*pollBackend)
	w.ws.watchShutdown()
	if !be.idle() {
		t.Fatal("the revalidator is left after the shutdown")
	}
	if got := w.ws.watch.watchedCount(); got != 0 {
		t.Fatalf("watched objects after the shutdown = %d, want 0", got)
	}
}

func TestHostWatcherPollBackendRunsOnItsOwn(t *testing.T) {
	e := newEnv(t)
	e.ws.watch.factory = pollFactory
	e.ws.watch.setPollInterval(5 * time.Millisecond)
	w := newWatchEnvOn(t, e)
	w.mustMkdir("d")
	w.add("d", hostEventMask)

	var got []inotifyEvent
	collect := func(pred func([]inotifyEvent) bool) func() bool {
		return func() bool {
			got = append(got, w.drain()...)
			return pred(got)
		}
	}
	hostWrite(t, w.host("d/n"), "1")
	waitFor(t, "IN_CREATE from the revalidator", collect(func(evs []inotifyEvent) bool {
		return slices.Contains(eventNames(evs), "CREATE n")
	}))
	hostWrite(t, w.host("d/n"), "12")
	waitFor(t, "IN_MODIFY from the revalidator", collect(func(evs []inotifyEvent) bool {
		return slices.Contains(eventNames(evs), "MODIFY n")
	}))
	if err := os.Remove(w.host("d/n")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "IN_DELETE from the revalidator", collect(func(evs []inotifyEvent) bool {
		return slices.Contains(eventNames(evs), "DELETE n")
	}))
}

// nativeWatchEnv mounts a workspace with the backend of the host platform: the
// revalidator on Linux, kqueue on macOS, and ReadDirectoryChangesW on Windows.
// The revalidator runs at a short interval.
func nativeWatchEnv(t *testing.T) *watchEnv {
	t.Helper()
	e := newEnv(t)
	e.ws.watch.setPollInterval(10 * time.Millisecond)
	return newWatchEnvOn(t, e)
}

// collector accumulates events until a test sees what it waits for.
type collector struct {
	w   *watchEnv
	got []inotifyEvent
}

func (c *collector) has(want string) bool {
	c.got = append(c.got, c.w.drain()...)
	return slices.Contains(eventNames(c.got), want)
}

func (c *collector) await(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !c.has(want) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for event %q, collected %q", want, eventNames(c.got))
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// cookieOf returns the cookie of the first collected event that matches.
func (c *collector) cookieOf(want string) uint32 {
	for _, ev := range c.got {
		if maskName(ev.mask)+" "+ev.name == want {
			return ev.cookie
		}
	}
	return 0
}

// The native tests let the backend find the changes on its own. They wait for
// each event with a deadline. A call of sync serves as a barrier only: it
// reads the state of the host, and it does not replace the wait for an event.

func TestNativeBackendReportsHostChanges(t *testing.T) {
	w := nativeWatchEnv(t)
	w.mustMkdir("d")
	w.writeFile("d/seed", []byte("seed"))
	w.add("d", hostEventMask)
	w.drain()
	c := &collector{w: w}

	hostWrite(t, w.host("d/new"), "1")
	c.await(t, "CREATE new")
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
	if from, to := c.cookieOf("MOVED_FROM new"), c.cookieOf("MOVED_TO moved"); from == 0 || from != to {
		t.Fatalf("cookies of the move = %d and %d, want one shared non-zero cookie", from, to)
	}

	if err := os.Remove(w.host("d/moved")); err != nil {
		t.Fatal(err)
	}
	c.await(t, "DELETE moved")
	if err := os.Mkdir(w.host("d/sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	c.await(t, "CREATE|ISDIR sub")
}

func TestNativeBackendWatchesAFile(t *testing.T) {
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

func TestNativeBackendReleasesItsResources(t *testing.T) {
	w := nativeWatchEnv(t)
	hw := &w.ws.watch
	w.mustMkdir("d")
	w.writeFile("d/f", []byte("x"))
	wd := w.add("d", hostEventMask)
	wf := w.add("d/f", hostEventMask)
	be := hw.currentBackend()
	if be == nil || be.idle() {
		t.Fatalf("backend = %v, want a busy backend", be)
	}
	w.rm(wd)
	w.rm(wf)
	hw.waitTeardown()
	if hw.currentBackend() != nil {
		t.Fatal("the backend lives on without a watch")
	}
	if !be.idle() {
		t.Fatal("the backend holds a goroutine, a descriptor, or a handle after the last watch ended")
	}
}
