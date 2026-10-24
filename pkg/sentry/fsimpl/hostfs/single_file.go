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
	"os"
	"path/filepath"
	"strings"
	"time"
)

// This file implements the single-file mode of GVXIP-001 section 4.3. A guest
// can bind one host file instead of a directory. OpenWorkspace then pins the
// PARENT directory of the file and remembers the name of the file. The root
// dentry of the mounted filesystem is the regular file.
//
// The rules of the mode:
//
//   - No other name of the parent is visible. The root is a file, so the VFS
//     never looks up a child, and every Workspace method refuses a path other
//     than ".".
//   - hostfs writes no .gvx_meta, because the parent directory belongs to the
//     user. The mode, the owner, and the extended attributes that the guest
//     sets live in memory and are lost at the next start. The host file keeps
//     its own mode and owner. A change of the times goes to the host file.
//   - The host name of the file is used as it is. The name codec and the
//     clutter filter never see it.
//   - The pinned name is not pinned to one inode. A host editor can replace the
//     file with an atomic rename. Every fresh open resolves the name again and
//     reaches the new file. A file description that is open keeps its handle,
//     and so it keeps the old file.
//   - A unlink or a rename of the mount point fails with EBUSY, because the
//     mount point lies in another filesystem.

// singleHost maps the guest path "." to the host name of the bound file. The
// root of the host backend is the parent directory, so every other call passes
// through unchanged. Workspace refuses every path other than ".".
type singleHost struct {
	hostBackend
	// bound is the same backend as hostBackend. It stats the bound file without
	// a query that needs a list right on the parent directory.
	bound interface {
		lstatBound(name string) (hostInfo, error)
	}
	// name is the host name of the file inside the pinned parent directory.
	name string
}

func (s *singleHost) lstat(rel string) (hostInfo, error) {
	if rel == "." {
		return s.bound.lstatBound(s.name)
	}
	return s.hostBackend.lstat(rel)
}

// open opens the bound file. The call never creates the file.
func (s *singleHost) open(rel string, flags int, perm os.FileMode) (*os.File, error) {
	if rel == "." {
		return s.hostBackend.open(s.name, flags&^(os.O_CREATE|os.O_EXCL), perm)
	}
	return s.hostBackend.open(rel, flags, perm)
}

func (s *singleHost) openDir(rel string) (*os.File, error) {
	if rel == "." {
		return nil, fmt.Errorf("hostfs: open %q: %w", rel, errNotDir)
	}
	return s.hostBackend.openDir(rel)
}

func (s *singleHost) readDir(rel string) ([]hostDirEntry, error) {
	if rel == "." {
		return nil, nil
	}
	return s.hostBackend.readDir(rel)
}

// syncDir does nothing for ".", because the parent directory is not part of
// the mount.
func (s *singleHost) syncDir(rel string) error {
	if rel == "." {
		return nil
	}
	return s.hostBackend.syncDir(rel)
}

func (s *singleHost) chtimes(rel string, atime, mtime *time.Time) error {
	if rel == "." {
		return s.hostBackend.chtimes(s.name, atime, mtime)
	}
	return s.hostBackend.chtimes(rel, atime, mtime)
}

// splitSingleFile resolves hostPath, which names a regular file, to the
// directory that holds the file and the stored name of the file. Links in the
// path resolve now, before the lockdown, as a bind mount of Docker does. On a
// volume that folds case, the stored name replaces a name with another case.
func splitSingleFile(hostPath string) (dir, name string, err error) {
	resolved, err := filepath.EvalSymlinks(hostPath)
	if err != nil {
		return "", "", fmt.Errorf("hostfs: resolve %q: %w", hostPath, err)
	}
	dir, name = filepath.Split(resolved)
	dir = filepath.Clean(dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", "", fmt.Errorf("hostfs: list the directory of %q: %w", resolved, err)
	}
	fold := ""
	for _, e := range entries {
		switch {
		case e.Name() == name:
			return dir, name, nil
		case fold == "" && strings.EqualFold(e.Name(), name):
			fold = e.Name()
		}
	}
	if fold != "" {
		return dir, fold, nil
	}
	return "", "", fmt.Errorf("hostfs: %q is not in its directory: %w", resolved, os.ErrNotExist)
}

// SingleFile reports that the workspace is a bind of one file. See
// single_file.go.
func (w *Workspace) SingleFile() bool {
	return w.single != ""
}

// openSingle opens the bound file again by its host name, for a file
// description that the guest opens. A read-only workspace refuses write access.
func (w *Workspace) openSingle(flags int) (*hostHandle, error) {
	if w.readOnly && flags&(os.O_WRONLY|os.O_RDWR|os.O_TRUNC) != 0 {
		return nil, ErrReadOnly
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return nil, os.ErrClosed
	}
	f, err := w.host.open(".", flags, 0)
	if err != nil {
		return nil, err
	}
	return w.wrapLocked(".", f, flags), nil
}
