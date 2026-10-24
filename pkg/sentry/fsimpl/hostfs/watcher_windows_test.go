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

//go:build windows

package hostfs

import (
	"fmt"
	"os"
	"testing"
)

// These tests run the ReadDirectoryChangesW backend. NTFS refuses to rename or
// remove a directory that has an open handle below it, so the tests also prove
// that the backend lets go of its handles for such an operation.

func TestWindowsBackendIsTheCompletionPortBackend(t *testing.T) {
	w := nativeWatchEnv(t)
	w.mustMkdir("d")
	w.add("d", hostEventMask)
	if _, ok := w.ws.watch.currentBackend().(*winBackend); !ok {
		t.Fatalf("backend = %T, want *winBackend", w.ws.watch.currentBackend())
	}
}

func TestWindowsBackendLetsAWatchedDirectoryBeRenamed(t *testing.T) {
	w := nativeWatchEnv(t)
	w.mustMkdir("old")
	w.writeFile("old/f", []byte("data"))
	w.add("old", hostEventMask)
	w.add("old/f", hostEventMask)
	w.drain()
	c := &collector{w: w}

	if err := w.rename("old", "new"); err != nil {
		t.Fatalf("rename of a watched directory = %v, want success", err)
	}
	w.drain()

	// The backend reopens its handles at the new path and scans the directory
	// again, so this change reaches the guest.
	hostWrite(t, w.host("new/g"), "1")
	c.await(t, "CREATE g")
	hostWrite(t, w.host("new/f"), "data and more")
	c.await(t, "MODIFY f")
	c.await(t, "MODIFY ")
}

func TestWindowsBackendLetsAParentOfAWatchedDirectoryBeRenamed(t *testing.T) {
	w := nativeWatchEnv(t)
	w.mustMkdir("p")
	w.mustMkdir("p/q")
	w.add("p/q", hostEventMask)
	w.drain()
	c := &collector{w: w}

	if err := w.rename("p", "r"); err != nil {
		t.Fatalf("rename of the parent of a watched directory = %v, want success", err)
	}
	hostWrite(t, w.host("r/q/x"), "1")
	c.await(t, "CREATE x")
}

func TestWindowsBackendLetsAWatchedDirectoryBeRemoved(t *testing.T) {
	w := nativeWatchEnv(t)
	w.mustMkdir("gone")
	w.add("gone", hostEventMask)
	w.drain()
	c := &collector{w: w}

	if err := w.vfsObj.RmdirAt(w.env.ctx, w.creds, w.pop("gone")); err != nil {
		t.Fatalf("rmdir of a watched directory = %v, want success", err)
	}
	c.await(t, "DELETE_SELF ")
	waitFor(t, "the watch to end", func() bool { return w.ws.watch.watchedCount() == 0 })
}

func TestWindowsBackendScansAfterABufferOverflow(t *testing.T) {
	w := nativeWatchEnv(t)
	w.mustMkdir("d")
	w.add("d", hostEventMask)
	w.drain()
	c := &collector{w: w}

	// Thousands of creations in a burst can fill the 64 KiB buffer. The scan
	// that follows an overflow reads the whole directory, so the last name
	// still arrives.
	const files = 3000
	for i := range files {
		if err := os.WriteFile(w.host(fmt.Sprintf("d/file-with-a-long-name-%05d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c.await(t, fmt.Sprintf("CREATE file-with-a-long-name-%05d", files-1))
}

func TestWindowsBackendCloseWaitsForOutstandingCalls(t *testing.T) {
	w := nativeWatchEnv(t)
	w.mustMkdir("a")
	w.mustMkdir("b")
	w.add("a", hostEventMask)
	w.add("b", hostEventMask)
	be := w.ws.watch.currentBackend()
	w.ws.watchShutdown()
	if !be.idle() {
		t.Fatal("the backend holds a handle after the shutdown")
	}
}
