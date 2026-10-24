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
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/socket/unix/transport"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// fakeEndpoint stands for the endpoint that bind(2) stores. Only its identity
// matters to the filesystem.
type fakeEndpoint struct {
	transport.BoundEndpoint
}

// crashClone copies the image while the volume of e stays open and mounts the
// copy. The copy is what a power failure at this instant leaves on the host.
func crashClone(t *testing.T, e *env) *env {
	t.Helper()
	return openEnv(t, cloneImage(t, e.fs.v), VolumeOptions{}, vfs.MountOptions{})
}

// TestOSyncWriteIsDurable checks the order of a synchronous write. After the
// write returns, a crash clone holds the data and the directory entries that
// lead to it, although the test never called fsync or sync. The control case
// shows that the plain write leaves the entries in memory.
func TestOSyncWriteIsDurable(t *testing.T) {
	for _, flag := range []uint32{linux.O_SYNC, linux.O_DSYNC} {
		t.Run(fmt.Sprintf("flag %#x", flag), func(t *testing.T) {
			e := newEnv(t)
			e.mustMkdir("db")
			e.mustMkdir("db/wal")
			fd := e.mustOpen("db/wal/log", linux.O_CREAT|linux.O_WRONLY|flag)
			defer fd.DecRef(e.ctx)
			records := pattern(9, 40000)
			e.write(fd, records[:10000])
			e.write(fd, records[10000:])

			c := crashClone(t, e)
			wantBytes(t, "durable content", c.readFile("db/wal/log"), records)
			if got := c.readdir("db/wal"); len(got) != 1 || got[0] != "log" {
				t.Fatalf("durable directory lists %v", got)
			}
		})
	}

	t.Run("plain write", func(t *testing.T) {
		e := newEnv(t)
		e.mustMkdir("db")
		e.writeFile("db/log", pattern(9, 40000))
		c := crashClone(t, e)
		if _, err := c.stat("db"); !linuxerr.Equals(linuxerr.ENOENT, err) {
			t.Fatalf("stat of an unsynced directory in the crash clone = %v, want ENOENT", err)
		}
	})
}

// TestOSyncRewriteIsDurable covers the write that changes no metadata except
// the times: the overwrite of a synced block must still reach the host file
// before the call returns.
func TestOSyncRewriteIsDurable(t *testing.T) {
	e := newEnv(t)
	e.writeFile("f", pattern(1, 3*blockSize))
	if err := e.fs.Sync(e.ctx); err != nil {
		t.Fatal(err)
	}
	fd := e.mustOpen("f", linux.O_WRONLY|linux.O_DSYNC)
	defer fd.DecRef(e.ctx)
	e.pwrite(fd, []byte("rewritten"), blockSize+5)
	want := pattern(1, 3*blockSize)
	copy(want[blockSize+5:], "rewritten")
	c := crashClone(t, e)
	wantBytes(t, "content in the crash clone", c.readFile("f"), want)
}

func TestFsyncFdatasyncAndSyncFS(t *testing.T) {
	for _, c := range []struct {
		name string
		sync func(e *env, fd *vfs.FileDescription) error
	}{
		{"fsync", func(e *env, fd *vfs.FileDescription) error { return fd.Sync(e.ctx) }},
		{"fdatasync", func(e *env, fd *vfs.FileDescription) error { return fd.SyncData(e.ctx) }},
		{"syncfs", func(e *env, fd *vfs.FileDescription) error { return fd.SyncFS(e.ctx) }},
		{"sync", func(e *env, fd *vfs.FileDescription) error { return e.vfsObj.SyncAllFilesystems(e.ctx) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			e.mustMkdir("d")
			fd := e.mustOpen("d/f", linux.O_CREAT|linux.O_RDWR)
			defer fd.DecRef(e.ctx)
			data := pattern(4, 200000)
			e.write(fd, data)
			if err := c.sync(e, fd); err != nil {
				t.Fatal(err)
			}
			cl := crashClone(t, e)
			wantBytes(t, "content in the crash clone", cl.readFile("d/f"), data)
		})
	}
}

func TestDirectoryFsync(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("d")
	e.writeFile("d/f", []byte("x"))
	dir := e.mustOpen("d", linux.O_RDONLY|linux.O_DIRECTORY)
	defer dir.DecRef(e.ctx)
	if err := dir.Sync(e.ctx); err != nil {
		t.Fatal(err)
	}
	c := crashClone(t, e)
	if got := c.readdir("d"); len(got) != 1 || got[0] != "f" {
		t.Fatalf("directory in the crash clone lists %v", got)
	}
}

func TestPersistenceAcrossRelease(t *testing.T) {
	e := newEnv(t)
	files := map[string][]byte{
		"empty":        nil,
		"inline":       pattern(1, 100),
		"inline-edge":  pattern(2, maxInline),
		"extent-edge":  pattern(3, maxInline+1),
		"block":        pattern(4, blockSize),
		"multi-extent": pattern(5, 1<<20+123),
		"deep/a/b/c/d": pattern(6, 5000),
	}
	e.mustMkdir("deep")
	e.mustMkdir("deep/a")
	e.mustMkdir("deep/a/b")
	e.mustMkdir("deep/a/b/c")
	for name, data := range files {
		e.writeFile(name, data)
	}
	// A file that grows from many small appends, which fragments its extents.
	fd := e.mustOpen("appended", linux.O_CREAT|linux.O_WRONLY|linux.O_APPEND)
	var appended []byte
	for i := range 300 {
		piece := pattern(byte(i), 700)
		e.write(fd, piece)
		appended = append(appended, piece...)
		if i%50 == 0 {
			e.writeFile(fmt.Sprintf("spacer%d", i), pattern(byte(i), 9000))
		}
	}
	fd.DecRef(e.ctx)
	files["appended"] = appended
	if err := e.link("block", "deep/hardlink"); err != nil {
		t.Fatal(err)
	}
	if err := e.symlink("deep/a/b/c/d", "link"); err != nil {
		t.Fatal(err)
	}
	if err := e.vfsObj.SetXattrAt(e.ctx, e.creds, e.fpop("block"), &vfs.SetXattrOptions{Name: "user.k", Value: "v"}); err != nil {
		t.Fatal(err)
	}
	if err := e.setStat("block", linux.Statx{Mask: linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID, Mode: 0o640, UID: 11, GID: 22}); err != nil {
		t.Fatal(err)
	}

	check := func(e *env, round int) {
		t.Helper()
		for name, data := range files {
			wantBytes(t, fmt.Sprintf("round %d: %s", round, name), e.readFile(name), data)
		}
		wantBytes(t, "hard link", e.readFile("deep/hardlink"), files["block"])
		wantBytes(t, "through the symlink", e.readFile("link"), files["deep/a/b/c/d"])
		st := e.mustStat("block")
		if st.Nlink != 2 || st.Mode&0o7777 != 0o640 || st.UID != 11 || st.GID != 22 {
			t.Fatalf("round %d: attributes of block = nlink %d mode %#o uid %d gid %d", round, st.Nlink, st.Mode, st.UID, st.GID)
		}
		got, err := e.vfsObj.GetXattrAt(e.ctx, e.creds, e.fpop("block"), &vfs.GetXattrOptions{Name: "user.k", Size: 10})
		if err != nil || got != "v" {
			t.Fatalf("round %d: xattr = (%q, %v)", round, got, err)
		}
	}
	check(e, 0)
	e = e.remount()
	check(e, 1)
	// Delete half, remount again, and verify that the rest stays intact.
	for _, name := range []string{"multi-extent", "spacer0", "spacer100", "empty"} {
		if err := e.unlink(name); err != nil {
			t.Fatal(err)
		}
		delete(files, name)
	}
	e = e.remount()
	check(e, 2)
	if _, err := e.stat("multi-extent"); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Fatalf("stat of a deleted file after remount = %v, want ENOENT", err)
	}
	e.unmount()
	runE2fsck(t, e.path)
}

// TestUnlinkedOpenFileDoesNotSurviveRelease unlinks a file, closes it, and
// remounts. The inode and the blocks must be gone.
func TestUnlinkedFileIsFreedAtRelease(t *testing.T) {
	e := newEnv(t)
	free := func(e *env) uint64 {
		e.fs.v.mu.Lock()
		defer e.fs.v.mu.Unlock()
		return e.fs.v.freeBlocksTotal
	}
	baseline := free(e)
	e.writeFile("gone", pattern(3, 2<<20))
	if err := e.unlink("gone"); err != nil {
		t.Fatal(err)
	}
	e = e.remount()
	if got := free(e); got != baseline {
		t.Fatalf("free blocks after remount = %d, want %d", got, baseline)
	}
	if got := e.readdir("/"); len(got) != 0 {
		t.Fatalf("root lists %v after remount", got)
	}
}

func TestReleaseShrinksHostFile(t *testing.T) {
	e := newEnv(t)
	const fileSize = 8 << 20
	for i := range 6 {
		e.writeFile(fmt.Sprintf("big%d", i), pattern(byte(i), fileSize))
	}
	e.writeFile("keep", []byte("small survivor"))
	if err := e.fs.Sync(e.ctx); err != nil {
		t.Fatal(err)
	}
	grown, err := os.Stat(e.path)
	if err != nil {
		t.Fatal(err)
	}
	if grown.Size() < 3*groupBytes {
		t.Fatalf("host file has %d bytes after 48 MiB of data, want at least 3 groups", grown.Size())
	}
	for i := range 6 {
		if err := e.unlink(fmt.Sprintf("big%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	e.unmount()
	shrunk, err := os.Stat(e.path)
	if err != nil {
		t.Fatal(err)
	}
	if shrunk.Size() != groupBytes {
		t.Fatalf("host file has %d bytes after the unmount, want one group of %d bytes (was %d)", shrunk.Size(), groupBytes, grown.Size())
	}
	e2 := openEnv(t, e.path, VolumeOptions{}, vfs.MountOptions{})
	wantBytes(t, "survivor", e2.readFile("keep"), []byte("small survivor"))
}

func TestConcurrentOperations(t *testing.T) {
	e := newEnv(t)
	const workers = 8
	for w := range workers {
		e.mustMkdir(fmt.Sprintf("w%d", w))
	}
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dir := fmt.Sprintf("w%d", w)
			for i := range 40 {
				name := fmt.Sprintf("%s/f%02d", dir, i)
				data := pattern(byte(w*40+i), 300+i*173)
				fd, err := e.open(name, linux.O_CREAT|linux.O_RDWR, 0o644)
				if err != nil {
					errs <- fmt.Errorf("create %s: %w", name, err)
					return
				}
				if n, err := fd.PWrite(e.ctx, usermem.BytesIOSequence(data), 0, vfs.WriteOptions{}); err != nil || int(n) != len(data) {
					errs <- fmt.Errorf("write %s: %d, %v", name, n, err)
					return
				}
				fd.DecRef(e.ctx)
				moved := fmt.Sprintf("%s/g%02d", dir, i)
				if err := e.rename(name, moved); err != nil {
					errs <- fmt.Errorf("rename %s: %w", name, err)
					return
				}
				if i%3 == 0 {
					if err := e.link(moved, fmt.Sprintf("w%d/link%02d", (w+1)%workers, i)); err != nil {
						errs <- fmt.Errorf("link %s: %w", moved, err)
						return
					}
				}
				if i%5 == 0 {
					if err := e.unlink(moved); err != nil {
						errs <- fmt.Errorf("unlink %s: %w", moved, err)
						return
					}
				}
				if _, err := e.stat(dir); err != nil {
					errs <- fmt.Errorf("stat %s: %w", dir, err)
					return
				}
			}
		}()
	}
	// Readers list the directories while the workers change them.
	var stop atomic.Bool
	var readers sync.WaitGroup
	for range 2 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for !stop.Load() {
				for w := range workers {
					fd, err := e.open(fmt.Sprintf("w%d", w), linux.O_RDONLY|linux.O_DIRECTORY, 0)
					if err != nil {
						errs <- err
						return
					}
					_ = fd.IterDirents(e.ctx, vfs.IterDirentsCallbackFunc(func(vfs.Dirent) error { return nil }))
					fd.DecRef(e.ctx)
				}
			}
		}()
	}
	// A syncer flushes the volume in the middle of the work.
	var syncer sync.WaitGroup
	syncer.Add(1)
	go func() {
		defer syncer.Done()
		for !stop.Load() {
			if err := e.fs.Sync(e.ctx); err != nil {
				errs <- err
				return
			}
		}
	}()
	wg.Wait()
	stop.Store(true)
	readers.Wait()
	syncer.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	// Verify the final state.
	for w := range workers {
		dir := fmt.Sprintf("w%d", w)
		for i := range 40 {
			moved := fmt.Sprintf("%s/g%02d", dir, i)
			_, err := e.stat(moved)
			if i%5 == 0 {
				wantErrno(t, "stat of the unlinked "+moved, err, linuxerr.ENOENT)
				continue
			}
			if err != nil {
				t.Fatalf("stat %s: %v", moved, err)
			}
			wantBytes(t, moved, e.readFile(moved), pattern(byte(w*40+i), 300+i*173))
		}
	}
	e = e.remount()
	for w := range workers {
		for i := 1; i < 40; i += 5 {
			wantBytes(t, "after remount", e.readFile(fmt.Sprintf("w%d/g%02d", w, i)), pattern(byte(w*40+i), 300+i*173))
		}
	}
}
