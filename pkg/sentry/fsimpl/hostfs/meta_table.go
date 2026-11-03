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
	"strings"
	"sync"
	"sync/atomic"
)

// metaTable is the in-memory form of the .gvx_meta table. Its own lock
// protects every field, and no method calls out while it holds the lock, so
// the lock is a leaf in the lock order of Workspace. Records are immutable:
// a method that changes a record replaces its pointer.
//
// The table keeps four derived indexes, so no operation scans it:
//
//	kids   the names of the virtual symbolic links of each directory, which a
//	       listing reads in O(entries)
//	hints  the record that last held each guest path, for adoption
//	inos   the inode numbers that records mention, so a background walk stats
//	       only the host entries that can own a record
//	special the inode numbers of the placeholder files of sockets, FIFOs, and
//	       devices, so a listing stats only those entries
type metaTable struct {
	mu      sync.RWMutex
	recs    map[recKey]*rec
	kids    map[recKey]map[string]struct{}
	hints   map[string]recKey
	inos    map[uint64]int
	special map[uint64]int
	names   int
	bytes   int64
	dirty   map[recKey]struct{}
	// scans counts the operations that visit every record. A guest call never
	// needs one, and tests read the counter to prove it.
	scans atomic.Int64
	// kick wakes the background flusher when a record changes. It is nil
	// until the Workspace starts the flusher.
	kick chan struct{}
}

func newMetaTable() *metaTable {
	return &metaTable{
		recs:    make(map[recKey]*rec),
		kids:    make(map[recKey]map[string]struct{}),
		hints:   make(map[string]recKey),
		inos:    make(map[uint64]int),
		special: make(map[uint64]int),
		dirty:   make(map[recKey]struct{}),
	}
}

// get returns the record under k, or nil.
func (t *metaTable) get(k recKey) *rec {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.recs[k]
}

// put stores r under k and schedules the write.
func (t *metaTable) put(k recKey, r *rec) {
	t.mu.Lock()
	t.putLocked(k, r)
	t.markLocked(k)
	t.mu.Unlock()
	t.wake()
}

// load stores r under k without a write. The loader and the repair of a hint
// use it, because the file already holds the record.
func (t *metaTable) load(k recKey, r *rec) {
	t.mu.Lock()
	t.putLocked(k, r)
	t.mu.Unlock()
}

// del removes the record under k and schedules the removal. A key without a
// record needs no write.
func (t *metaTable) del(k recKey) {
	t.mu.Lock()
	_, had := t.recs[k]
	_, pending := t.dirty[k]
	if had {
		t.delLocked(k)
	}
	if had || pending {
		t.markLocked(k)
	}
	t.mu.Unlock()
	if had || pending {
		t.wake()
	}
}

func (t *metaTable) markLocked(k recKey) {
	t.dirty[k] = struct{}{}
}

func (t *metaTable) wake() {
	if t.kick == nil {
		return
	}
	select {
	case t.kick <- struct{}{}:
	default:
	}
}

func (t *metaTable) putLocked(k recKey, r *rec) {
	if old := t.recs[k]; old != nil {
		t.unindexLocked(k, old)
		t.bytes -= recSize(k, old)
	}
	t.recs[k] = r
	t.bytes += recSize(k, r)
	t.indexLocked(k, r)
}

func (t *metaTable) delLocked(k recKey) {
	old := t.recs[k]
	if old == nil {
		return
	}
	t.unindexLocked(k, old)
	t.bytes -= recSize(k, old)
	delete(t.recs, k)
}

func (t *metaTable) indexLocked(k recKey, r *rec) {
	switch k.kind {
	case kindInode:
		t.inos[k.id.ino]++
		if specialFileType(r.attr.Mode) != 0 {
			t.special[k.id.ino]++
		}
		if r.hint != "" {
			t.hints[r.hint] = k
		}
	case kindName:
		t.inos[k.id.ino]++
		t.addKidLocked(k)
	case kindPathName:
		t.addKidLocked(k)
	}
}

func (t *metaTable) unindexLocked(k recKey, r *rec) {
	switch k.kind {
	case kindInode:
		dec(t.inos, k.id.ino)
		if specialFileType(r.attr.Mode) != 0 {
			dec(t.special, k.id.ino)
		}
		if r.hint != "" && t.hints[r.hint] == k {
			delete(t.hints, r.hint)
		}
	case kindName:
		dec(t.inos, k.id.ino)
		t.dropKidLocked(k)
	case kindPathName:
		t.dropKidLocked(k)
	}
}

func dec(m map[uint64]int, ino uint64) {
	if m[ino] <= 1 {
		delete(m, ino)
		return
	}
	m[ino]--
}

func (t *metaTable) addKidLocked(k recKey) {
	dir := k.dir()
	set := t.kids[dir]
	if set == nil {
		set = make(map[string]struct{})
		t.kids[dir] = set
	}
	if _, ok := set[k.name]; !ok {
		t.names++
	}
	set[k.name] = struct{}{}
}

func (t *metaTable) dropKidLocked(k recKey) {
	dir := k.dir()
	set := t.kids[dir]
	if _, ok := set[k.name]; !ok {
		return
	}
	t.names--
	delete(set, k.name)
	if len(set) == 0 {
		delete(t.kids, dir)
	}
}

// setHint replaces the hint of the record under k without scheduling a write.
// The file keeps the old hint until a change of the record writes the new one.
// It does nothing when the record changed meanwhile.
func (t *metaTable) setHint(k recKey, from *rec, hint string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.recs[k] != from {
		return
	}
	t.putLocked(k, from.withHint(hint))
}

// kidsOf returns the names of the virtual symbolic links of the directory dir.
func (t *metaTable) kidsOf(dir recKey) []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	set := t.kids[dir]
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	return out
}

// hasNames reports whether the table holds any virtual symbolic link.
func (t *metaTable) hasNames() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.names > 0
}

// byHint returns the record that last held the guest path, and its key.
func (t *metaTable) byHint(path string) (recKey, *rec) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	k, ok := t.hints[path]
	if !ok {
		return recKey{}, nil
	}
	return k, t.recs[k]
}

// hasIno reports whether any record names the inode number ino.
func (t *metaTable) hasIno(ino uint64) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.inos[ino] > 0
}

// hasSpecialIno reports whether a socket, FIFO, or device record names the
// inode number ino.
func (t *metaTable) hasSpecialIno(ino uint64) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.special[ino] > 0
}

// size returns the number of records.
func (t *metaTable) size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.recs)
}

// memBytes returns the estimated memory of the records.
func (t *metaTable) memBytes() int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.bytes
}

// has reports whether a record exists under k.
func (t *metaTable) has(k recKey) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.recs[k]
	return ok
}

// pending returns the number of records that changed since the last flush.
func (t *metaTable) pending() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.dirty)
}

// paths returns the guest path of every record: the hint of a record on a
// volume with identities, and the key of a record on a volume with paths. A
// record without a path adds nothing.
func (t *metaTable) paths() []string {
	t.scans.Add(1)
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]string, 0, len(t.recs))
	for k, r := range t.recs {
		switch {
		case k.kind == kindPath:
			out = append(out, k.path)
		case k.kind == kindPathName:
			out = append(out, joinRelPath(k.path, k.name))
		case r.hint != "":
			out = append(out, r.hint)
		}
	}
	return out
}

// keys returns a copy of every key. A caller that walks a large table takes
// the copy once, so the walk holds no lock.
func (t *metaTable) keys() []recKey {
	t.scans.Add(1)
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]recKey, 0, len(t.recs))
	for k := range t.recs {
		out = append(out, k)
	}
	return out
}

// takeBatch hands out the pending changes as journal operations and resets the
// pending set. With full set it hands out a snapshot of every record instead,
// because a snapshot already holds each pending change. The copy holds only
// pointers: the caller encodes the operations after the call, outside the
// lock. The result dirty lists the keys that the caller must put back when its
// write fails.
func (t *metaTable) takeBatch(full bool) (ops []metaOp, dirty []recKey) {
	if full {
		t.scans.Add(1)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	dirty = make([]recKey, 0, len(t.dirty))
	for k := range t.dirty {
		dirty = append(dirty, k)
	}
	clear(t.dirty)
	if full {
		ops = make([]metaOp, 0, len(t.recs))
		for k, r := range t.recs {
			ops = append(ops, metaOp{key: k, r: r})
		}
		return ops, dirty
	}
	ops = make([]metaOp, 0, len(dirty))
	for _, k := range dirty {
		ops = append(ops, metaOp{key: k, r: t.recs[k]})
	}
	return ops, dirty
}

// restore puts the keys of a failed write back into the pending set.
func (t *metaTable) restore(keys []recKey) {
	t.mu.Lock()
	for _, k := range keys {
		t.dirty[k] = struct{}{}
	}
	t.mu.Unlock()
}

// moveTree re-keys every path record below the directory oldRel to the same
// place below newRel, and the virtual symbolic links that oldRel holds. The
// record of oldRel itself stays. Only a table that keys on paths calls it. The
// operation scans the whole table, which is the cost of path keys.
func (t *metaTable) moveTree(oldRel, newRel string) {
	t.scans.Add(1)
	prefix := oldRel + "/"
	rebase := func(p string) string { return newRel + strings.TrimPrefix(p, oldRel) }
	t.mu.Lock()
	var moved []recKey
	for k := range t.recs {
		switch {
		case k.kind == kindPath && strings.HasPrefix(k.path, prefix):
			moved = append(moved, k)
		case k.kind == kindPathName && (k.path == oldRel || strings.HasPrefix(k.path, prefix)):
			moved = append(moved, k)
		}
	}
	for _, k := range moved {
		r := t.recs[k]
		t.delLocked(k)
		t.markLocked(k)
		nk := k
		nk.path = rebase(k.path)
		if r.hint != "" {
			r = r.withHint(rebase(r.hint))
		}
		t.putLocked(nk, r)
		t.markLocked(nk)
	}
	t.mu.Unlock()
	if len(moved) > 0 {
		t.wake()
	}
}

// swapTree exchanges the path records at or below aRel and bRel. The two
// directories cannot nest. Only a table that keys on paths calls it.
func (t *metaTable) swapTree(aRel, bRel string) {
	t.scans.Add(1)
	aPrefix, bPrefix := aRel+"/", bRel+"/"
	t.mu.Lock()
	type move struct {
		from, to recKey
		r        *rec
	}
	var moves []move
	retarget := func(p string) (string, bool) {
		switch {
		case p == aRel:
			return bRel, true
		case p == bRel:
			return aRel, true
		case strings.HasPrefix(p, aPrefix):
			return bRel + p[len(aRel):], true
		case strings.HasPrefix(p, bPrefix):
			return aRel + p[len(bRel):], true
		}
		return "", false
	}
	for k, r := range t.recs {
		if !k.isPath() {
			continue
		}
		np, ok := retarget(k.path)
		if !ok {
			continue
		}
		nk := k
		nk.path = np
		if r.hint != "" {
			if h, ok := retarget(r.hint); ok {
				r = r.withHint(h)
			}
		}
		moves = append(moves, move{from: k, to: nk, r: r})
	}
	for _, m := range moves {
		t.delLocked(m.from)
		t.markLocked(m.from)
	}
	for _, m := range moves {
		t.putLocked(m.to, m.r)
		t.markLocked(m.to)
	}
	t.mu.Unlock()
	if len(moves) > 0 {
		t.wake()
	}
}
