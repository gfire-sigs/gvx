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
	"runtime"
	"strings"
	"testing"
	"time"
)

// waitUntil polls cond until it is true. It fails the test after 10 seconds.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout while waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// goroutineIn reports whether a goroutine has a frame whose text contains
// frame.
func goroutineIn(frame string) bool {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Contains(string(buf[:n]), frame)
		}
		buf = make([]byte, 2*len(buf))
	}
}

// TestReadlinkDoesNotTakeMountLockUnderFilesystemMutex checks the lock order
// of the VFS mount lock and fs.mu. A mount operation holds the mount lock and
// calls IsDescendant, which takes fs.mu. ReadlinkAt must therefore not take
// the mount lock, which Mount.Options takes, while it holds fs.mu. Otherwise
// the readlink waits for the mount operation, the mount operation waits for
// the readlink, and every other call that needs fs.mu waits behind them,
// including the background flush.
func TestReadlinkDoesNotTakeMountLockUnderFilesystemMutex(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("a")
	e.mustMkdir("b")
	if err := e.symlink("target", "l"); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// The mount at b makes the mount operation below call IsDescendant of
	// this filesystem.
	if err := e.vfsObj.BindAt(e.ctx, e.creds, e.pop("a"), e.pop("b"), false); err != nil {
		t.Fatalf("BindAt: %v", err)
	}

	// Hold the lock of the root node. ReadlinkAt takes fs.mu and then waits
	// for this lock when it checks the search permission of the root.
	rootNode := e.fs.root.inode.n
	rootNode.mu.Lock()
	unlocked := false
	unlockRoot := func() {
		if !unlocked {
			unlocked = true
			rootNode.mu.Unlock()
		}
	}
	defer unlockRoot()

	readlinkDone := make(chan error, 1)
	go func() {
		_, err := e.vfsObj.ReadlinkAt(e.ctx, e.creds, e.pop("l"))
		readlinkDone <- err
	}()
	waitUntil(t, "readlink to hold fs.mu", func() bool {
		if e.fs.mu.TryLock() {
			e.fs.mu.Unlock()
			return false
		}
		return true
	})

	// The mount operation takes the mount lock and then waits for fs.mu.
	cloneDone := make(chan error, 1)
	go func() {
		cloneDone <- e.vfsObj.CheckClonePrivateMount(e.ctx, e.creds, e.root)
	}()
	waitUntil(t, "the mount operation to wait for fs.mu", func() bool {
		return goroutineIn("ext4lite.(*filesystem).IsDescendant")
	})

	unlockRoot()
	for _, c := range []struct {
		name string
		done chan error
	}{
		{"ReadlinkAt", readlinkDone},
		{"CheckClonePrivateMount", cloneDone},
	} {
		select {
		case err := <-c.done:
			if err != nil {
				t.Errorf("%s = %v", c.name, err)
			}
		case <-time.After(10 * time.Second):
			// The unmount would wait for fs.mu behind the stuck calls.
			e.done = true
			t.Fatalf("%s did not end: ReadlinkAt holds fs.mu and waits for the mount lock, and the mount operation holds the mount lock and waits for fs.mu", c.name)
		}
	}
}
