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
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

var testNow = time.Unix(1700000000, 0)

func testStamp() tstamp { return tstamp{sec: testNow.Unix(), nsec: 123} }

// newTestFile returns a new empty host file in a temporary directory.
func newTestFile(t testing.TB) (*os.File, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vol.ext4")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	return f, path
}

// newTestVolume formats and opens a volume on the storage tier tier.
func newTestVolume(t testing.TB, tier storageTier) (*volume, string) {
	t.Helper()
	f, path := newTestFile(t)
	hf, err := newHostFileForTier(f, tier)
	if err != nil {
		t.Fatal(err)
	}
	if err := formatVolume(hf, testNow); err != nil {
		t.Fatalf("formatVolume: %v", err)
	}
	v, err := openVolume(hf, volumeOptions{now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatalf("openVolume: %v", err)
	}
	return v, path
}

// reopenVolume opens the image at path again with the native storage tier.
func reopenVolume(t testing.TB, path string) *volume {
	t.Helper()
	v, err := tryOpenVolume(path, volumeOptions{now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	return v
}

// tryOpenVolume opens the image at path and returns the error of the open.
func tryOpenVolume(path string, opts volumeOptions) (*volume, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	hf, err := newHostFile(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	v, err := openVolume(hf, opts)
	if err != nil {
		hf.Close()
		return nil, err
	}
	return v, nil
}

// abandon drops a volume without a clean shutdown, as a crash does. It
// releases the host file lock and nothing else.
func abandon(v *volume) {
	v.hf.Close()
}

func mustRoot(t testing.TB, v *volume) *node {
	t.Helper()
	root, err := v.getNode(rootIno)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func setLinks(n *node, links uint32) {
	n.mu.Lock()
	n.links = links
	n.markDirtyLocked()
	n.mu.Unlock()
}

// createChild makes a child of parent. A directory gets the link count 2.
func createChild(t testing.TB, v *volume, parent *node, name string, mode uint16) *node {
	t.Helper()
	n, err := v.newNode(mode, 1000, 1000, 0, testStamp())
	if err != nil {
		t.Fatalf("newNode %s: %v", name, err)
	}
	if mode&modeTypeMask == modeDir {
		if err := n.initDir(parent.ino); err != nil {
			t.Fatalf("initDir %s: %v", name, err)
		}
		setLinks(n, 2)
		parent.mu.Lock()
		parent.links++
		parent.markDirtyLocked()
		parent.mu.Unlock()
	} else {
		setLinks(n, 1)
	}
	if err := parent.addEntry(name, n.ino, n.fileType()); err != nil {
		t.Fatalf("addEntry %s: %v", name, err)
	}
	return n
}

func writeAll(t testing.TB, n *node, off int64, data []byte) {
	t.Helper()
	w, err := n.writeAt(data, off)
	if err != nil || w != len(data) {
		t.Fatalf("writeAt(%d bytes at %d) = %d, %v", len(data), off, w, err)
	}
}

func readAll(t testing.TB, n *node) []byte {
	t.Helper()
	buf := make([]byte, n.size)
	got, err := n.readAt(buf, 0)
	if err != nil && got != len(buf) {
		t.Fatalf("readAt: %d bytes, %v", got, err)
	}
	return buf
}

// pattern returns n deterministic bytes that differ for each seed.
func pattern(seed byte, n int) []byte {
	b := make([]byte, n)
	x := uint32(seed)*2654435761 + 1
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = byte(x >> 24)
	}
	return b
}

func lookupNode(t testing.TB, v *volume, dir *node, name string) *node {
	t.Helper()
	ino, _, err := dir.lookup(name)
	if err != nil {
		t.Fatalf("lookup %s: %v", name, err)
	}
	n, err := v.getNode(ino)
	if err != nil {
		t.Fatalf("getNode %s: %v", name, err)
	}
	return n
}

// runE2fsck runs e2fsck -fn on the image and fails the test when it reports
// a problem. It skips the test when e2fsck is not installed. The variable
// EXT4LITE_KEEP_IMAGES names a directory that receives a copy of the image.
func runE2fsck(t testing.TB, path string) {
	t.Helper()
	if dir := os.Getenv("EXT4LITE_KEEP_IMAGES"); dir != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Join(dir, sanitize(t.Name())+".img")
		if err := os.WriteFile(name, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bin, err := exec.LookPath("e2fsck")
	if err != nil {
		if os.Getenv("EXT4LITE_REQUIRE_E2FSCK") != "" {
			t.Fatal("e2fsck is not installed, and EXT4LITE_REQUIRE_E2FSCK is set")
		}
		t.Skip("e2fsck is not installed")
	}
	out, err := exec.Command(bin, "-fn", path).CombinedOutput()
	if err != nil {
		t.Fatalf("e2fsck -fn failed: %v\n%s", err, bytes.TrimSpace(out))
	}
}

func sanitize(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c == '/' || c == ' ' {
			b[i] = '_'
		}
	}
	return string(b)
}
