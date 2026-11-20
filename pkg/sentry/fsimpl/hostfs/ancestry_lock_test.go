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
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// ancestryWaitTimeout bounds the wait for a call that must not need fs.mu.
const ancestryWaitTimeout = 10 * time.Second

func (e *env) filesystem() *filesystem {
	return e.root.Mount().Filesystem().Impl().(*filesystem)
}

// heldMuCall runs call on a new goroutine while the test holds fs.mu, as a
// rename or an unlink does while it waits for the mount lock of the VFS. It
// fails the test when call does not return within ancestryWaitTimeout.
func heldMuCall(t *testing.T, fs *filesystem, what string, call func()) {
	t.Helper()
	fs.mu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		call()
	}()
	select {
	case <-done:
		fs.mu.Unlock()
	case <-time.After(ancestryWaitTimeout):
		fs.mu.Unlock()
		<-done
		t.Fatalf("%s waited for fs.mu, but the VFS lock order puts its locks after the mount lock, and a rename holds fs.mu while it waits for that lock", what)
	}
}

// raceAncestry calls write count times on a new goroutine while the test
// goroutine reads the ancestry and the workspace path of vd without fs.mu.
// Each path that the reader sees must be in want.
func raceAncestry(t *testing.T, e *env, vd vfs.VirtualDentry, count int, write func(i int) error, want ...string) {
	t.Helper()
	fs := e.filesystem()
	d := vd.Dentry().Impl().(*dentry)
	done := make(chan error, 1)
	go func() {
		for i := range count {
			if err := write(i); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	probe := func() string {
		if !fs.IsDescendant(e.root, vd) {
			return "IsDescendant(/, moved directory) = false, want true"
		}
		path, err := e.vfsObj.PathnameWithDeleted(e.ctx, e.root, vd)
		if err != nil || !slices.Contains(want, path) {
			return fmt.Sprintf("PathnameWithDeleted(moved directory) = %q, %v, want one of %q", path, err, want)
		}
		if rel := d.path(); !slices.Contains(want, "/"+rel) {
			return fmt.Sprintf("workspace path of the moved directory = %q, want one of %q without the leading slash", rel, want)
		}
		return ""
	}
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("writer: %v", err)
			}
			return
		default:
		}
		if msg := probe(); msg != "" {
			// The writer still uses the environment that the cleanup of the
			// test closes. Wait for it before the test stops.
			if err := <-done; err != nil {
				t.Errorf("writer: %v", err)
			}
			t.Fatal(msg)
		}
	}
}

func (e *env) dentryAt(p string) vfs.VirtualDentry {
	e.t.Helper()
	vd, err := e.vfsObj.GetDentryAt(e.ctx, e.creds, e.fpop(p), &vfs.GetDentryOptions{})
	if err != nil {
		e.t.Fatalf("GetDentryAt(%s): %v", p, err)
	}
	e.t.Cleanup(func() { vd.DecRef(e.ctx) })
	return vd
}

// TestAncestryReadersDoNotTakeFilesystemMu verifies the lock order of
// pkg/sentry/vfs/vfs.go for IsDescendant, PrependPath, and InotifyWithParent.
// That order puts their locks last. For example, the VFS calls IsDescendant
// with its mount lock held, and a rename or an unlink holds fs.mu while it
// waits for that lock in Prepare*Dentry. So none of the methods may take
// fs.mu.
func TestAncestryReadersDoNotTakeFilesystemMu(t *testing.T) {
	e := newEnv(t)
	fs := e.filesystem()
	e.mustMkdir("a")
	e.mustMkdir("a/b")
	vd := e.dentryAt("a/b")

	var descendant bool
	heldMuCall(t, fs, "IsDescendant", func() {
		descendant = fs.IsDescendant(e.root, vd)
	})
	if !descendant {
		t.Errorf("IsDescendant(/, /a/b) = false, want true")
	}

	var path string
	var err error
	heldMuCall(t, fs, "PrependPath through VirtualFilesystem.PathnameWithDeleted", func() {
		path, err = e.vfsObj.PathnameWithDeleted(e.ctx, e.root, vd)
	})
	if err != nil || path != "/a/b" {
		t.Errorf("PathnameWithDeleted(/a/b) = %q, %v, want %q, nil", path, err, "/a/b")
	}

	d := vd.Dentry().Impl().(*dentry)
	heldMuCall(t, fs, "InotifyWithParent", func() {
		d.InotifyWithParent(e.ctx, linux.IN_ATTRIB, 0, vfs.InodeEvent)
	})
}

// TestAncestryReadersRaceWithRenames changes the place of a directory while
// readers that do not hold fs.mu walk its ancestry and read its workspace
// path. Each reader must see one of the two places. Under the race detector
// the test also fails when a writer of these fields does not hold
// fs.ancestryMu. The subtests cover the writers moveLocked,
// exchangeDentriesLocked, and the dead flag of detachLocked.
func TestAncestryReadersRaceWithRenames(t *testing.T) {
	e := newEnv(t)
	for _, d := range []string{"a", "c", "x", "y", "a/b", "x/m", "y/n"} {
		e.mustMkdir(d)
	}
	t.Run("move", func(t *testing.T) {
		raceAncestry(t, e, e.dentryAt("a/b"), 100, func(i int) error {
			if i%2 == 0 {
				return e.rename("a/b", "c/b")
			}
			return e.rename("c/b", "a/b")
		}, "/a/b", "/c/b")
	})
	t.Run("exchange", func(t *testing.T) {
		exchange := &vfs.RenameOptions{Flags: linux.RENAME_EXCHANGE}
		raceAncestry(t, e, e.dentryAt("x/m"), 100, func(int) error {
			return e.vfsObj.RenameAt(e.ctx, e.creds, e.pop("x/m"), e.pop("y/n"), exchange)
		}, "/x/m", "/y/n")
	})
	t.Run("unlink", func(t *testing.T) {
		// detachLocked sets the dead flag that PrependPath reads.
		for range 20 {
			e.writeFile("f", nil)
			vd := e.dentryAt("f")
			stop := make(chan struct{})
			read := make(chan error, 1)
			go func() {
				for {
					select {
					case <-stop:
						read <- nil
						return
					default:
					}
					if _, err := e.vfsObj.PathnameWithDeleted(e.ctx, e.root, vd); err != nil {
						read <- err
						return
					}
				}
			}()
			if err := e.unlink("f"); err != nil {
				close(stop)
				t.Fatalf("unlink: %v", err)
			}
			close(stop)
			if err := <-read; err != nil {
				t.Fatalf("PathnameWithDeleted(unlinked file): %v", err)
			}
		}
	})
}

// TestMountPropagationDoesNotDeadlockWithRename runs the two operations of the
// deadlock against each other. A bind mount on a shared mount with a peer
// propagates under the VFS mount lock and calls IsDescendant on the peer. A
// rename holds fs.mu and waits for that mount lock in PrepareRenameDentry.
func TestMountPropagationDoesNotDeadlockWithRename(t *testing.T) {
	e := newEnv(t)
	for _, d := range []string{"peer", "src", "dst", "r", "r/x"} {
		e.mustMkdir(d)
	}
	if err := e.vfsObj.SetMountPropagation(e.root.Mount(), linux.MS_SHARED, false); err != nil {
		t.Fatalf("SetMountPropagation(MS_SHARED): %v", err)
	}
	if err := e.vfsObj.BindAt(e.ctx, e.creds, e.pop("."), e.pop("peer"), false); err != nil {
		t.Fatalf("BindAt(/, /peer): %v", err)
	}
	deadlocked := false
	t.Cleanup(func() {
		if !deadlocked {
			_ = e.vfsObj.UmountAt(e.ctx, e.creds, e.pop("peer"), &vfs.UmountOptions{Flags: linux.MNT_DETACH})
		}
	})

	const runFor = 2 * time.Second
	var mounts, renames atomic.Int64
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	stop := time.Now().Add(runFor)
	wg.Add(2)
	go func() {
		defer wg.Done()
		for time.Now().Before(stop) {
			if err := e.vfsObj.BindAt(e.ctx, e.creds, e.pop("src"), e.pop("dst"), false); err != nil {
				errs <- fmt.Errorf("bind /src at /dst: %w", err)
				return
			}
			// A lazy unmount also removes the propagated copy below /peer.
			if err := e.vfsObj.UmountAt(e.ctx, e.creds, e.pop("dst"), &vfs.UmountOptions{Flags: linux.MNT_DETACH}); err != nil {
				errs <- fmt.Errorf("unmount /dst: %w", err)
				return
			}
			mounts.Add(1)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; time.Now().Before(stop); i++ {
			from, to := "r/x", "r/y"
			if i%2 == 1 {
				from, to = to, from
			}
			if err := e.rename(from, to); err != nil {
				errs <- fmt.Errorf("rename %s to %s: %w", from, to, err)
				return
			}
			renames.Add(1)
		}
	}()
	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(runFor + ancestryWaitTimeout):
		deadlocked = true
		t.Fatalf("bind mounts and renames deadlocked after %d mounts and %d renames", mounts.Load(), renames.Load())
	}
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if mounts.Load() == 0 || renames.Load() == 0 {
		t.Fatalf("got %d mounts and %d renames, want both above zero", mounts.Load(), renames.Load())
	}
}
