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
	"os"
	"path/filepath"
	"testing"
)

func TestPathAtOrBelow(t *testing.T) {
	for _, tc := range []struct {
		path, root string
		want       bool
	}{
		{`\ws`, `\ws`, true},
		{`\ws\a\b`, `\ws`, true},
		{`\WS\A`, `\ws`, true},
		{`\ws2`, `\ws`, false},
		{`\ws2\a`, `\ws`, false},
		{`\other\ws`, `\ws`, false},
		{`\$Recycle.Bin\S-1\$R1`, `\Users\me\ws`, false},
		{`\Users\me`, `\Users\me\ws`, false},
		{`\Users\me\ws\a`, `\Users\me\ws\`, true},
		{`\anything`, `\`, true},
		{`\`, `\`, true},
		{`\Ünï\a`, `\ünï`, true},
	} {
		if got := pathAtOrBelow(tc.path, tc.root); got != tc.want {
			t.Errorf("pathAtOrBelow(%q, %q) = %t, want %t", tc.path, tc.root, got, tc.want)
		}
	}
}

// existsFixture is a hostRoot over a temporary directory with the keys of two
// entries: the file "f" and the directory "d".
type existsFixture struct {
	host *hostRoot
	// dir is the real path of the workspace root. outside is a directory on
	// the same volume that lies outside the root.
	dir, outside string
	file, subdir fileKey
}

func newExistsFixture(t *testing.T) *existsFixture {
	t.Helper()
	h, dir := winTestHost(t)
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks() = %v", err)
	}
	if h.byIDErr != nil {
		t.Skipf("OpenFileById is not available: %v", h.byIDErr)
	}
	if h.volume == 0 || h.rootPath == "" {
		t.Fatalf("root location = (%#x, %q), want volume and path", h.volume, h.rootPath)
	}
	winTestWrite(t, h, "f", "data")
	if err := h.mkdir("d"); err != nil {
		t.Fatalf("mkdir(d) = %v", err)
	}
	fx := &existsFixture{host: h, dir: dir, outside: t.TempDir()}
	for name, key := range map[string]*fileKey{"f": &fx.file, "d": &fx.subdir} {
		info, err := h.lstat(name)
		if err != nil {
			t.Fatalf("lstat(%q) = %v", name, err)
		}
		if !info.fidOK {
			t.Skipf("volume does not report file ids for %q", name)
		}
		*key = info.fid
	}
	if fx.file.dev != h.volume {
		t.Fatalf("file key dev = %#x, want root volume %#x", fx.file.dev, h.volume)
	}
	return fx
}

func (fx *existsFixture) want(t *testing.T, key fileKey, want bool) {
	t.Helper()
	got, err := fx.host.existsByID(key)
	if err != nil || got != want {
		t.Errorf("existsByID(%+v) = (%t, %v), want (%t, nil)", key, got, err, want)
	}
}

func TestExistsByIDPresent(t *testing.T) {
	fx := newExistsFixture(t)
	fx.want(t, fx.file, true)
	fx.want(t, fx.subdir, true)
}

func TestExistsByIDDeleted(t *testing.T) {
	fx := newExistsFixture(t)
	if err := os.Remove(filepath.Join(fx.dir, "f")); err != nil {
		t.Fatalf("Remove() = %v", err)
	}
	if err := os.Remove(filepath.Join(fx.dir, "d")); err != nil {
		t.Fatalf("Remove() = %v", err)
	}
	fx.want(t, fx.file, false)
	fx.want(t, fx.subdir, false)
}

// A moved file still exists on the volume, so only the final path check can
// tell that it left the workspace.
func TestExistsByIDMovedOutsideRoot(t *testing.T) {
	fx := newExistsFixture(t)
	moved := filepath.Join(fx.outside, "f")
	if err := os.Rename(filepath.Join(fx.dir, "f"), moved); err != nil {
		t.Fatalf("Rename() = %v", err)
	}
	if _, err := os.Lstat(moved); err != nil {
		t.Fatalf("Lstat(moved) = %v", err)
	}
	fx.want(t, fx.file, false)

	if err := os.Rename(moved, filepath.Join(fx.dir, "f")); err != nil {
		t.Fatalf("Rename back = %v", err)
	}
	fx.want(t, fx.file, true)

	if err := os.Rename(filepath.Join(fx.dir, "d"), filepath.Join(fx.outside, "d")); err != nil {
		t.Fatalf("Rename(d) = %v", err)
	}
	fx.want(t, fx.subdir, false)
}

func TestExistsByIDMovedInsideRoot(t *testing.T) {
	fx := newExistsFixture(t)
	if err := os.Rename(filepath.Join(fx.dir, "f"), filepath.Join(fx.dir, "d", "f")); err != nil {
		t.Fatalf("Rename() = %v", err)
	}
	fx.want(t, fx.file, true)
}

// A sibling whose name starts like the root must not count as inside it.
func TestExistsByIDSiblingWithRootPrefix(t *testing.T) {
	fx := newExistsFixture(t)
	sibling := fx.dir + "2"
	if err := os.Mkdir(sibling, 0o700); err != nil {
		t.Fatalf("Mkdir() = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sibling) })
	if err := os.Rename(filepath.Join(fx.dir, "f"), filepath.Join(sibling, "f")); err != nil {
		t.Fatalf("Rename() = %v", err)
	}
	fx.want(t, fx.file, false)
}

func TestExistsByIDVolume(t *testing.T) {
	fx := newExistsFixture(t)
	other := fx.file
	other.dev = fx.host.volume ^ 1
	fx.want(t, other, false)

	same := fx.file
	same.dev = fx.host.volume
	fx.want(t, same, true)

	// The Workspace stores device 0 for the volume of the root.
	stored := fx.file
	stored.dev = 0
	fx.want(t, stored, true)
}
