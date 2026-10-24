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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// volumeHost models the name rules of a host volume on top of a real backend,
// so that every test host can act as a volume that folds case or as a volume
// that refuses the Windows names. It resolves each name against the stored
// directory entries, the way such a volume does.
type volumeHost struct {
	hostBackend

	// fold makes the volume treat names that differ in case as one name.
	fold bool
	// verified makes lstat fail with errNameMismatch for a name that differs
	// in case from the stored name, as the Windows backend does. Without it,
	// the volume silently resolves the stored entry, as APFS does.
	verified bool
	// win makes the volume refuse the Windows reserved names and characters.
	win bool

	mu   sync.Mutex
	dirs map[hostDirHandle]string
}

func newVolumeHost(inner hostBackend, fold, verified, win bool) *volumeHost {
	return &volumeHost{hostBackend: inner, fold: fold, verified: verified, win: win, dirs: make(map[hostDirHandle]string)}
}

func (v *volumeHost) caseInsensitive() bool { return v.fold }

func (v *volumeHost) caseVerified() bool { return v.verified }

// checkName rejects a name that a Windows volume refuses.
func (v *volumeHost) checkName(name string) error {
	if !v.win {
		return nil
	}
	bad := name == "" || !utf8.ValidString(name) || isReservedDeviceName(name)
	for i := 0; i < len(name) && !bad; i++ {
		bad = name[i] < 0x20 || strings.IndexByte(winForbiddenBytes, name[i]) >= 0
	}
	if last := name[len(name)-1:]; !bad && (last == "." || last == " ") {
		bad = true
	}
	if bad {
		return fmt.Errorf("volume: %w: %q", errInvalidHostName, name)
	}
	return nil
}

// stored returns the name under which the host directory dir stores name. The
// second result is false when the stored name differs from name.
func (v *volumeHost) stored(dir, name string) (string, bool, error) {
	if err := v.checkName(name); err != nil {
		return "", false, err
	}
	if !v.fold {
		return name, true, nil
	}
	entries, err := v.hostBackend.readDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return name, true, nil
		}
		return "", false, err
	}
	key := foldKey(name, false)
	variant := ""
	for _, e := range entries {
		if e.name == name {
			return name, true, nil
		}
		if variant == "" && foldKey(e.name, false) == key {
			variant = e.name
		}
	}
	if variant != "" {
		return variant, false, nil
	}
	return name, true, nil
}

// resolve returns the stored path of rel. The second result is false when the
// last component differs from its stored name.
func (v *volumeHost) resolve(rel string) (string, bool, error) {
	if rel == "." {
		return ".", true, nil
	}
	cur, exact := ".", true
	parts := strings.Split(rel, "/")
	for i, p := range parts {
		s, ex, err := v.stored(cur, p)
		if err != nil {
			return "", false, err
		}
		cur = joinRelPath(cur, s)
		if i == len(parts)-1 {
			exact = ex
		}
	}
	return cur, exact, nil
}

func mismatchError(rel string) error {
	return fmt.Errorf("volume: %q: %w: %w", rel, errNameMismatch, fs.ErrNotExist)
}

// lookupPath resolves a path for an operation on an existing entry.
func (v *volumeHost) lookupPath(rel string) (string, error) {
	p, exact, err := v.resolve(rel)
	if err != nil {
		return "", err
	}
	if v.verified && !exact {
		return "", mismatchError(rel)
	}
	return p, nil
}

// createPath resolves a path for the creation of a new entry. A stored entry
// under another case makes the creation fail, as it does on a folding volume.
func (v *volumeHost) createPath(rel string) (string, error) {
	p, exact, err := v.resolve(rel)
	if err != nil {
		return "", err
	}
	if !exact {
		return "", fmt.Errorf("volume: create %q: %w", rel, fs.ErrExist)
	}
	return p, nil
}

func (v *volumeHost) open(rel string, flags int, perm os.FileMode) (*os.File, error) {
	var p string
	var err error
	if flags&os.O_CREATE != 0 {
		p, err = v.createPath(rel)
	} else {
		p, err = v.lookupPath(rel)
	}
	if err != nil {
		return nil, err
	}
	return v.hostBackend.open(p, flags, perm)
}

func (v *volumeHost) openDir(rel string) (*os.File, error) {
	p, err := v.lookupPath(rel)
	if err != nil {
		return nil, err
	}
	return v.hostBackend.openDir(p)
}

func (v *volumeHost) lstat(rel string) (hostInfo, error) {
	p, err := v.lookupPath(rel)
	if err != nil {
		return hostInfo{}, err
	}
	return v.hostBackend.lstat(p)
}

func (v *volumeHost) mkdir(rel string) error {
	p, err := v.createPath(rel)
	if err != nil {
		return err
	}
	return v.hostBackend.mkdir(p)
}

func (v *volumeHost) unlink(rel string) error {
	p, err := v.lookupPath(rel)
	if err != nil {
		return err
	}
	return v.hostBackend.unlink(p)
}

func (v *volumeHost) rmdir(rel string) error {
	p, err := v.lookupPath(rel)
	if err != nil {
		return err
	}
	return v.hostBackend.rmdir(p)
}

func (v *volumeHost) rename(oldRel, newRel string) error {
	oldPath, err := v.lookupPath(oldRel)
	if err != nil {
		return err
	}
	newPath, exact, err := v.resolve(newRel)
	if err != nil {
		return err
	}
	if !exact && newPath != oldPath {
		// A rename onto another name that folds to the same name replaces it.
		if err := v.hostBackend.unlink(newPath); err != nil {
			return err
		}
	}
	if !exact {
		// The stored name becomes the requested name.
		dir, _ := splitParent(newPath)
		_, given := splitParent(newRel)
		newPath = joinRelPath(dir, given)
	}
	return v.hostBackend.rename(oldPath, newPath)
}

func (v *volumeHost) link(oldRel, newRel string) error {
	oldPath, err := v.lookupPath(oldRel)
	if err != nil {
		return err
	}
	newPath, err := v.createPath(newRel)
	if err != nil {
		return err
	}
	return v.hostBackend.link(oldPath, newPath)
}

func (v *volumeHost) readlink(rel string) (string, error) {
	p, err := v.lookupPath(rel)
	if err != nil {
		return "", err
	}
	return v.hostBackend.readlink(p)
}

func (v *volumeHost) readDir(rel string) ([]hostDirEntry, error) {
	p, err := v.lookupPath(rel)
	if err != nil {
		return nil, err
	}
	return v.hostBackend.readDir(p)
}

func (v *volumeHost) syncDir(rel string) error {
	p, err := v.lookupPath(rel)
	if err != nil {
		return err
	}
	return v.hostBackend.syncDir(p)
}

func (v *volumeHost) chtimes(rel string, atime, mtime *time.Time) error {
	p, err := v.lookupPath(rel)
	if err != nil {
		return err
	}
	return v.hostBackend.chtimes(p, atime, mtime)
}

// dirPath returns the stored path of a pinned directory handle.
func (v *volumeHost) dirPath(dir hostDirHandle) string {
	if dir == v.hostBackend.rootDir() {
		return "."
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.dirs[dir]
}

// storedIn resolves a name inside a pinned directory.
func (v *volumeHost) storedIn(dir hostDirHandle, name string, create bool) (string, string, error) {
	base := v.dirPath(dir)
	s, exact, err := v.stored(base, name)
	if err != nil {
		return "", "", err
	}
	if !exact && (create || v.verified) {
		if create {
			return "", "", fmt.Errorf("volume: create %q: %w", name, fs.ErrExist)
		}
		return "", "", mismatchError(name)
	}
	return base, s, nil
}

func (v *volumeHost) openDirAt(dir hostDirHandle, name string) (hostDirHandle, hostInfo, error) {
	base, s, err := v.storedIn(dir, name, false)
	if err != nil {
		return 0, hostInfo{}, err
	}
	h, info, err := v.hostBackend.openDirAt(dir, s)
	if err != nil {
		return h, info, err
	}
	v.mu.Lock()
	v.dirs[h] = joinRelPath(base, s)
	v.mu.Unlock()
	return h, info, nil
}

func (v *volumeHost) closeDir(dir hostDirHandle) error {
	v.mu.Lock()
	delete(v.dirs, dir)
	v.mu.Unlock()
	return v.hostBackend.closeDir(dir)
}

func (v *volumeHost) lstatAt(dir hostDirHandle, name string) (hostInfo, error) {
	_, s, err := v.storedIn(dir, name, false)
	if err != nil {
		return hostInfo{}, err
	}
	return v.hostBackend.lstatAt(dir, s)
}

func (v *volumeHost) openChildAt(dir hostDirHandle, name string, flags int, perm os.FileMode) (*os.File, error) {
	_, s, err := v.storedIn(dir, name, flags&os.O_CREATE != 0)
	if err != nil {
		return nil, err
	}
	return v.hostBackend.openChildAt(dir, s, flags, perm)
}

// volumeOptions builds the options of a workspace on a modeled volume.
func volumeOptions(caps WorkspaceCaps, fold, verified, win bool) workspaceOptions {
	return workspaceOptions{
		coalesce: defaultMetaCoalesce,
		caps:     &caps,
		wrapHost: func(b hostBackend) hostBackend { return newVolumeHost(b, fold, verified, win) },
	}
}

// openEnvAt opens a workspace in dir and mounts it. The returned function
// closes the mount and the workspace. It runs again at the end of the test, so
// a test can close early to reopen the directory.
func openEnvAt(t *testing.T, dir string, opts workspaceOptions) (*env, func()) {
	t.Helper()
	ws, err := openWorkspace(dir, false, opts)
	if err != nil {
		t.Fatalf("openWorkspace: %v", err)
	}
	e := mountEnv(t, ws, dir)
	var once sync.Once
	closeEnv := func() {
		once.Do(func() {
			e.root.DecRef(e.ctx)
			if err := ws.Close(); err != nil {
				t.Errorf("Workspace.Close: %v", err)
			}
		})
	}
	t.Cleanup(closeEnv)
	return e, closeEnv
}

// resolvedTempDir returns a temporary directory without symbolic links.
func resolvedTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	return dir
}

// hostNames lists the stored names in a host directory, without .gvx_meta.
func hostNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if e.Name() != MetaFileName {
			out = append(out, e.Name())
		}
	}
	return out
}

// Capability sets of the volumes that the tests model.
var (
	linuxCaps = WorkspaceCaps{CaseSensitive: true}
	// macCaps is the default APFS volume.
	macCaps = WorkspaceCaps{UnicodeNormalized: true}
	// winCaps is the default NTFS volume.
	winCaps = WorkspaceCaps{RestrictsWinNames: true, LocksOpenDirMove: true}
	// winCSCaps is an NTFS directory with the case-sensitive flag.
	winCSCaps = WorkspaceCaps{CaseSensitive: true, RestrictsWinNames: true, LocksOpenDirMove: true}
	// apfsCSCaps is a case-sensitive APFS volume.
	apfsCSCaps = WorkspaceCaps{CaseSensitive: true, UnicodeNormalized: true}
)
