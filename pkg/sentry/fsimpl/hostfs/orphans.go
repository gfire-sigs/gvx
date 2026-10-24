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
	"errors"
	"io/fs"
	"sort"
)

const (
	// pruneBatch is the number of .gvx_meta records that one flush checks
	// against the host. A flush resumes where the last one stopped, so every
	// record gets checked in turn, and a large table never stalls the guest.
	pruneBatch = 256

	// maxSweepDirs bounds the directories that OpenWorkspace sweeps for
	// internal files, besides the workspace root.
	maxSweepDirs = 1024
)

// isNotExist reports a host answer that proves the absence of an entry. A
// name that the host resolves to an entry with another case does not count.
func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist) && !errors.Is(err, errNameMismatch)
}

// pruneOrphansLocked removes up to limit records of .gvx_meta whose host
// object no longer exists: a record of a file or directory whose host entry is
// gone, and a virtual symlink whose parent directory is gone. A record
// survives every other host answer, because a transient host error must never
// delete state. It returns the number of removed records. Callers hold w.mu
// for writing.
func (w *Workspace) pruneOrphansLocked(limit int) int {
	if w.readOnly {
		return 0
	}
	if w.pruneCursor >= len(w.pruneKeys) {
		w.pruneKeys = w.pruneKeys[:0]
		for k := range w.meta {
			w.pruneKeys = append(w.pruneKeys, k)
		}
		w.pruneCursor = 0
	}
	removed := 0
	parentGone := make(map[string]bool)
	for checked := 0; checked < limit && w.pruneCursor < len(w.pruneKeys); checked++ {
		k := w.pruneKeys[w.pruneCursor]
		w.pruneCursor++
		m, ok := w.meta[k]
		if !ok {
			continue
		}
		if w.recordOrphanLocked(k, m, parentGone) {
			delete(w.meta, k)
			removed++
		}
	}
	if removed > 0 {
		w.markDirtyLocked()
	}
	return removed
}

// recordOrphanLocked reports whether the record of key k has lost its host
// object. parentGone caches the verdict for parent directories.
func (w *Workspace) recordOrphanLocked(k string, m POSIXAttr, parentGone map[string]bool) bool {
	if m.Symlink == "" {
		p, err := w.locateLocked(k)
		return err == nil && !p.found && !p.collided && isNotExist(p.err)
	}
	parent, _ := splitParent(k)
	if parent == "." {
		return false
	}
	gone, known := parentGone[parent]
	if !known {
		p, err := w.locateLocked(parent)
		gone = err == nil && !p.found && !p.collided && isNotExist(p.err)
		parentGone[parent] = gone
	}
	return gone
}

// sweepEphemeral unlinks the internal files that a killed process left
// behind: the unnamed temporary files "~gvx~tmp.*" and the swap files
// "~gvx~swap.*". It sweeps the workspace root and the directories that hold a
// .gvx_meta record, at most maxSweepDirs of them in path order. A directory
// that has no record and that is not the root keeps its leftovers until it gets
// one. The sweep removes regular files only. A directory under an internal
// name holds guest data, so it stays. OpenWorkspace calls it before the guest
// runs, so it takes no lock.
func (w *Workspace) sweepEphemeral() {
	seen := map[string]struct{}{}
	for k := range w.meta {
		parent, _ := splitParent(k)
		if parent != "." {
			seen[parent] = struct{}{}
		}
	}
	dirs := make([]string, 0, len(seen))
	for d := range seen {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	dirs = append([]string{"."}, dirs[:min(len(dirs), maxSweepDirs)]...)
	for _, dir := range dirs {
		hostDir, err := w.hostPath(dir)
		if err != nil {
			continue
		}
		entries, err := w.host.readDir(hostDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.kind == hostKindRegular && isEphemeralName(e.name) {
				_ = w.host.unlink(hostChild(hostDir, e.name))
			}
		}
	}
}
