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
	"sync"
	"time"
)

const (
	// maxSweepDirs bounds the directories that OpenWorkspace sweeps for
	// internal files, besides the workspace root.
	maxSweepDirs = 1024

	// orphanStartDelay is the time between OpenWorkspace and the first step of
	// the orphan collector. The guest starts first.
	orphanStartDelay = 30 * time.Second
	// orphanStepInterval is the pause between two steps of one pass. It caps
	// the host load of a pass.
	orphanStepInterval = 100 * time.Millisecond
	// orphanPassInterval is the pause between two passes. A record needs two
	// passes to die, so this is also the time that a host editor has to save
	// a file by rename before hostfs drops the record that the new file adopts.
	orphanPassInterval = 10 * time.Minute

	// orphanStepDirs is the number of directories that one walk step lists.
	orphanStepDirs = 4
	// orphanStepRecords is the number of records that one identity step asks
	// the host about.
	orphanStepRecords = 64
)

// isNotExist reports a host answer that proves the absence of an entry. A
// name that the host resolves to an entry with another case does not count.
func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist) && !errors.Is(err, errNameMismatch)
}

// orphanCollector removes the records whose host file is gone, in the
// background and in small steps. A host process that deletes a file or a
// directory leaves its records behind. Since records key on identity, a stale
// record never applies to another file, so the collector only reclaims memory
// and disk space. It never stops the guest: a step holds the Workspace lock for
// the listing of one directory or the check of one record.
//
// A pass finds the records that have no host file. A record dies when two
// passes in a row miss it, and a last check by the guest path confirms the
// verdict. A host error ends a pass without a verdict, so a transient error
// never deletes a record.
//
// A volume that opens a file by identity (Windows) asks the host about each
// record. Any other volume walks the tree through the pinned handles. The walk
// lists each directory once and stats only the entries whose inode number a
// record names.
type orphanCollector struct {
	// mu serializes steps. The goroutine and the tests both call them.
	mu sync.Mutex

	// stop and done end the background goroutine. They are nil without one.
	stop chan struct{}
	done chan struct{}

	// active reports that a pass is in progress.
	active bool
	// broken reports that a host error invalidated the pass.
	broken bool
	// queue holds the directories that the walk has to list.
	queue []string
	// seen holds the records that the walk proved alive.
	seen map[recKey]struct{}
	// keys and pos drive the identity pass over a copy of the table keys.
	keys []recKey
	pos  int
	// dead holds the records that the identity pass found without a file.
	dead []recKey
	// missed holds the records that the previous complete pass missed.
	missed map[recKey]struct{}
}

// startOrphanGC starts the background collector.
func (w *Workspace) startOrphanGC() {
	c := &w.orphans
	c.stop = make(chan struct{})
	c.done = make(chan struct{})
	go w.orphanLoop(c.stop, c.done)
}

// stopOrphanGC stops the background collector and waits for its step.
func (w *Workspace) stopOrphanGC() {
	c := &w.orphans
	if c.stop == nil {
		return
	}
	close(c.stop)
	<-c.done
	c.stop = nil
}

func (w *Workspace) orphanLoop(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	timer := time.NewTimer(orphanStartDelay)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
		}
		next := orphanPassInterval
		if w.orphanStep() {
			next = orphanStepInterval
		}
		timer.Reset(next)
	}
}

// orphanPass runs one pass to its end. Tests use it to drive the collector
// without a clock.
func (w *Workspace) orphanPass() {
	for w.orphanStep() {
	}
}

// orphanStep runs one step of the current pass. It reports whether the pass
// has more steps.
func (w *Workspace) orphanStep() bool {
	if w.readOnly || w.single != "" || w.pendingConversion() {
		return false
	}
	c := &w.orphans
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active {
		if w.meta.size() == 0 {
			return false
		}
		c.begin(w)
	}
	var more bool
	if w.useIDPass() {
		more = w.identityStepLocked(c)
	} else {
		more = w.walkStepLocked(c)
	}
	if !more {
		w.finishPassLocked(c)
	}
	return more
}

// useIDPass reports whether the host answers for each record by identity.
func (w *Workspace) useIDPass() bool {
	return !w.pathKeys && w.caps.ExistsByID
}

// pendingConversion reports that the file on disk still has the form that
// the loader converted. A session that changed nothing must leave the file
// alone, so the collector waits for the first flush of a change.
func (w *Workspace) pendingConversion() bool {
	w.flushMu.Lock()
	defer w.flushMu.Unlock()
	return w.journal.converted
}

func (c *orphanCollector) begin(w *Workspace) {
	c.active, c.broken = true, false
	c.queue = append(c.queue[:0], ".")
	c.seen = make(map[recKey]struct{})
	c.keys, c.pos, c.dead = nil, 0, nil
	if w.useIDPass() {
		c.keys = w.meta.keys()
	}
}

// walkStepLocked lists the next directories of the walk. It reports whether
// directories remain.
func (w *Workspace) walkStepLocked(c *orphanCollector) bool {
	for range orphanStepDirs {
		if len(c.queue) == 0 {
			break
		}
		rel := c.queue[len(c.queue)-1]
		c.queue = c.queue[:len(c.queue)-1]
		w.mu.RLock()
		if w.closed {
			c.broken = true
			c.queue = nil
		} else {
			w.visitDirLocked(c, rel)
		}
		w.mu.RUnlock()
	}
	return len(c.queue) > 0
}

// visitDirLocked lists the directory rel, marks the records that name its
// entries as alive, and queues its subdirectories. Callers hold w.mu.
func (w *Workspace) visitDirLocked(c *orphanCollector, rel string) {
	pin, err := w.acquirePin(rel)
	if err != nil {
		c.broken = true
		return
	}
	defer w.releasePin(pin)
	dirKey := w.dirKeyOf(pin, rel)
	c.seen[dirKey] = struct{}{}
	for _, name := range w.meta.kidsOf(dirKey) {
		c.seen[dirKey.withName(name)] = struct{}{}
	}
	entries, err := w.host.readDirAt(pin.h)
	if err != nil {
		c.broken = true
		return
	}
	for _, e := range entries {
		if e.kind != hostKindRegular && e.kind != hostKindDir {
			continue
		}
		if (rel == "." && isReservedPath(e.name)) || w.hiddenByName(e.name) {
			continue
		}
		child := joinRelPath(rel, w.codec.ToGuest(e.name))
		if e.kind == hostKindDir {
			c.queue = append(c.queue, child)
		}
		if w.pathKeys {
			if k := (recKey{kind: kindPath, path: child}); w.meta.has(k) {
				c.seen[k] = struct{}{}
			}
			continue
		}
		if e.ino != 0 && !w.meta.hasIno(e.ino) {
			continue
		}
		info, err := w.host.lstatAt(pin.h, e.name)
		if err != nil {
			if !isNotExist(err) {
				c.broken = true
			}
			continue
		}
		if w.keyed(info) {
			if k := w.keyOf(child, info); w.meta.has(k) {
				c.seen[k] = struct{}{}
			}
		}
	}
}

// identityStepLocked asks the host about the next records of the pass. It
// reports whether records remain.
func (w *Workspace) identityStepLocked(c *orphanCollector) bool {
	for range orphanStepRecords {
		if c.pos >= len(c.keys) {
			break
		}
		k := c.keys[c.pos]
		c.pos++
		w.mu.RLock()
		gone, err := w.recordGoneByIDLocked(k)
		w.mu.RUnlock()
		switch {
		case err != nil:
			c.broken = true
		case gone:
			c.dead = append(c.dead, k)
		}
	}
	return c.pos < len(c.keys)
}

// recordGoneByIDLocked asks the host whether the file that the record under k
// belongs to is gone. A virtual symbolic link belongs to its parent
// directory. A record that no longer exists is not gone. Callers hold w.mu.
func (w *Workspace) recordGoneByIDLocked(k recKey) (bool, error) {
	if !w.meta.has(k) {
		return false, nil
	}
	found, err := w.host.existsByID(w.rawID(k.id))
	return !found && err == nil, err
}

// finishPassLocked ends the pass. A complete pass confirms the records that
// the previous pass missed too, and it remembers the new misses.
func (w *Workspace) finishPassLocked(c *orphanCollector) {
	defer func() {
		c.active = false
		c.queue, c.seen, c.keys, c.dead = nil, nil, nil, nil
	}()
	if c.broken {
		return
	}
	var missing []recKey
	if w.useIDPass() {
		missing = c.dead
	} else {
		for _, k := range w.meta.keys() {
			if _, ok := c.seen[k]; !ok {
				missing = append(missing, k)
			}
		}
	}
	next := make(map[recKey]struct{}, len(missing))
	for _, k := range missing {
		if _, again := c.missed[k]; !again {
			next[k] = struct{}{}
			continue
		}
		w.mu.Lock()
		if !w.closed && w.orphanedLocked(k) {
			w.meta.del(k)
		} else {
			// A failed or inconclusive lookup keeps the record, and the next
			// pass asks again.
			next[k] = struct{}{}
		}
		w.mu.Unlock()
	}
	c.missed = next
}

// orphanedLocked confirms that the record under k has lost its host object.
// The walk and the identity pass both prove it twice. This last check goes
// through the guest path of the record, so a file that moved while the passes
// ran keeps its record. A host error, or an answer that shows the file, keeps
// the record. Callers hold w.mu for writing.
func (w *Workspace) orphanedLocked(k recKey) bool {
	r := w.meta.get(k)
	if r == nil {
		return false
	}
	if w.pathKeys {
		// A link lives in a directory, so the directory decides for it.
		return k.path != "." && w.entryGoneLocked(k.path)
	}
	// The hint names the file, or the directory that holds a virtual link.
	hint := r.hint
	if k.isName() {
		hint, _ = splitParent(hint)
	}
	if r.hint == "" {
		return true
	}
	var info hostInfo
	if hint == "." {
		var err error
		if info, err = w.host.lstat("."); err != nil {
			return false
		}
	} else {
		p, err := w.locatePathLocked(hint)
		if err != nil {
			return false
		}
		if !p.found {
			return !p.collided && isNotExist(p.err)
		}
		info = p.info
	}
	return w.keyed(info) && w.keyOf(hint, info).id != k.id
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
// "~gvx~swap.*". It sweeps the workspace root and the directories that the
// hints of .gvx_meta records name, at most maxSweepDirs of them in path order.
// A directory that has no record and that is not the root keeps its leftovers
// until it gets one. The sweep removes regular files only. A directory under
// an internal name holds guest data, so it stays. OpenWorkspace calls it before
// the guest runs, so it takes no lock.
func (w *Workspace) sweepEphemeral() {
	seen := map[string]struct{}{}
	for _, p := range w.meta.paths() {
		parent, _ := splitParent(p)
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
