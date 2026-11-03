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
// delete state. A call stops at the end of one cycle through the table. It
// returns the number of removed records. Callers hold w.mu for writing.
func (w *Workspace) pruneOrphansLocked(limit int) int {
	if w.readOnly {
		return 0
	}
	removed := 0
	parentGone := make(map[string]bool)
	for checked := 0; checked < limit && w.pruneNextLocked(parentGone, &removed); checked++ {
	}
	return removed
}

// pruneOrphans is pruneOrphansLocked for a caller that holds no lock. It takes
// w.mu for one record at a time, so a batch never stalls the guest for longer
// than one record check. The check and the removal of a record happen under
// one lock hold, so a record that the guest recreates meanwhile survives.
func (w *Workspace) pruneOrphans(limit int) {
	if w.readOnly {
		return
	}
	removed := 0
	for checked := 0; checked < limit; checked++ {
		w.mu.Lock()
		// A verdict about a parent directory holds only for this lock hold.
		more := !w.closed && w.pruneNextLocked(make(map[string]bool), &removed)
		w.mu.Unlock()
		if !more {
			return
		}
	}
}

// pruneNextLocked checks the next record of the prune cycle and removes it
// when its host object is gone. It adds one to removed for a removal. It
// reports whether the cycle has more records. A cycle reads the keys once and
// resumes where the last call stopped, so every record gets checked in turn,
// and a small table costs one check for each record at most. parentGone caches
// the verdict for parent directories. Callers hold w.mu for writing.
func (w *Workspace) pruneNextLocked(parentGone map[string]bool, removed *int) bool {
	if w.pruneCursor >= len(w.pruneKeys) {
		w.pruneKeys = w.pruneKeys[:0]
		for k := range w.meta {
			w.pruneKeys = append(w.pruneKeys, k)
		}
		w.pruneCursor = 0
		if len(w.pruneKeys) == 0 {
			return false
		}
	}
	k := w.pruneKeys[w.pruneCursor]
	w.pruneCursor++
	m, ok := w.meta[k]
	if ok && w.recordOrphanLocked(k, m, parentGone) {
		w.delMetaLocked(k)
		*removed++
	}
	return w.pruneCursor < len(w.pruneKeys)
}

// recordOrphanLocked reports whether the record of key k has lost its host
// object. parentGone caches the verdict for parent directories.
func (w *Workspace) recordOrphanLocked(k string, m POSIXAttr, parentGone map[string]bool) bool {
	if m.Symlink == "" {
		return w.entryGoneLocked(k)
	}
	parent, _ := splitParent(k)
	if parent == "." {
		return false
	}
	gone, known := parentGone[parent]
	if !known {
		gone = w.entryGoneLocked(parent)
		parentGone[parent] = gone
	}
	return gone
}

// entryGoneLocked reports whether the host proves that the guest path rel does
// not exist. The check goes through the pinned directory first. A cached pin
// can name a directory that a host process replaced, and its answer then
// misses a live entry. A deletion needs more than that answer, so a missing
// entry gets a second check by a walk from the workspace root. Callers hold
// w.mu.
func (w *Workspace) entryGoneLocked(rel string) bool {
	p, err := w.locateLocked(rel)
	if err != nil || p.found || p.collided || !isNotExist(p.err) {
		return false
	}
	p, err = w.locatePathLocked(rel)
	return err == nil && !p.found && !p.collided && isNotExist(p.err)
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
