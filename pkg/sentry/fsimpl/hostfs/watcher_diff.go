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
	"sort"

	"z.gfire.dev/gvx/pkg/abi/linux"
)

// This file holds the pure part of the host watcher: the state that one scan
// reads from the host and the diff that turns two scans into inotify events.
// It has no host calls and no locks, so the tests run it on every OS.

// nameStat is the state of one directory entry, or of one watched file or
// directory, at the time of a scan. Times are Unix nanoseconds.
type nameStat struct {
	kind  hostKind
	id    hostID
	size  int64
	mtime int64
	ctime int64
	nlink uint32
	// guest is the guest name of a directory entry, or empty for a watched
	// object.
	guest string
	// hidden marks an entry that never reaches the guest, such as the
	// metadata file or the clutter that a host shell writes.
	hidden bool
}

func nameStatOf(info hostInfo) nameStat {
	return nameStat{
		kind:  info.kind,
		id:    info.id,
		size:  info.size,
		mtime: info.mtime.UnixNano(),
		ctime: info.ctime.UnixNano(),
		nlink: info.nlink,
	}
}

// sameFile reports whether two states describe one host object.
func (s nameStat) sameFile(o nameStat) bool {
	return s.id == o.id && s.kind == o.kind
}

// contentChanged reports a change of the modification time or of the size.
func (s nameStat) contentChanged(o nameStat) bool {
	return s.mtime != o.mtime || s.size != o.size
}

// dirSnapshot maps the host name of each entry of a directory to its state.
type dirSnapshot map[string]nameStat

// changeKind is the kind of one change that a scan found.
type changeKind uint8

const (
	changeCreate changeKind = iota + 1
	changeDelete
	changeModify
	changeAttrib
	changeMovedFrom
	changeMovedTo
)

// watchChange is one difference between two scans of a directory.
type watchChange struct {
	// host is the host name of the entry. The dispatcher decodes it to the
	// guest name.
	host string
	kind changeKind
	// cur is the state of the entry after the change, or the state before
	// the change for changeDelete and changeMovedFrom.
	cur nameStat
	// old is the state before the change for changeModify and changeAttrib.
	old nameStat
	// pair is non-zero for a move. The two halves of one move share it.
	pair uint32
}

// mask returns the inotify event mask of the change.
func (c watchChange) mask() uint32 {
	var m uint32
	switch c.kind {
	case changeCreate:
		m = linux.IN_CREATE
	case changeDelete:
		m = linux.IN_DELETE
	case changeModify:
		m = linux.IN_MODIFY
	case changeAttrib:
		m = linux.IN_ATTRIB
	case changeMovedFrom:
		m = linux.IN_MOVED_FROM
	case changeMovedTo:
		m = linux.IN_MOVED_TO
	}
	if c.cur.kind == hostKindDir {
		m |= linux.IN_ISDIR
	}
	return m
}

func (s dirSnapshot) visible(name string) (nameStat, bool) {
	st, ok := s[name]
	if !ok || st.hidden {
		return nameStat{}, false
	}
	return st, true
}

// diffDir compares two scans of one directory. The result is deterministic:
// moves come first, then deletions, creations, and modifications, each group
// in the order of the names.
//
// A rename shows up as one vanished name and one new name with the same file
// identity, size, and modification time. diffDir reports the pair as a move.
// The identity alone is not enough, because a file system can reuse the
// inode number of a file that it just deleted.
//
// A name that holds another file than before reports a deletion and a
// creation, unless the new file arrived by a move.
func diffDir(old, cur dirSnapshot) []watchChange {
	names := make([]string, 0, len(old)+len(cur))
	for n := range old {
		names = append(names, n)
	}
	for n := range cur {
		if _, ok := old[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)

	type vanished struct {
		name string
		st   nameStat
		// replaced marks a name that still exists in the new scan, with
		// another file.
		replaced bool
	}
	type arrived struct {
		name     string
		st       nameStat
		replaced bool
	}
	var gone []vanished
	var came []arrived
	var edits []watchChange
	for _, n := range names {
		o, inOld := old.visible(n)
		c, inCur := cur.visible(n)
		switch {
		case inOld && !inCur:
			gone = append(gone, vanished{name: n, st: o})
		case !inOld && inCur:
			came = append(came, arrived{name: n, st: c})
		case inOld && inCur && !o.sameFile(c):
			gone = append(gone, vanished{name: n, st: o, replaced: true})
			came = append(came, arrived{name: n, st: c, replaced: true})
		case inOld && inCur:
			if ch, ok := diffEntry(n, o, c, true); ok {
				edits = append(edits, ch)
			}
		}
	}

	// Pair vanished names with new names by identity.
	fromPair := make([]uint32, len(gone))
	toPair := make([]uint32, len(came))
	var nextPair uint32
	for ai, a := range came {
		if a.st.id.ino == 0 {
			continue
		}
		for gi, g := range gone {
			if fromPair[gi] != 0 || g.name == a.name || !g.st.sameFile(a.st) || g.st.size != a.st.size || g.st.mtime != a.st.mtime {
				continue
			}
			nextPair++
			fromPair[gi] = nextPair
			toPair[ai] = nextPair
			break
		}
	}
	// A name that a move replaced reports the move and no deletion, as Linux
	// does.
	replacedByMove := make(map[string]bool)
	for ai, a := range came {
		if a.replaced && toPair[ai] != 0 {
			replacedByMove[a.name] = true
		}
	}

	var moves, deletes, creates []watchChange
	for gi, g := range gone {
		switch {
		case fromPair[gi] != 0:
			moves = append(moves, watchChange{host: g.name, kind: changeMovedFrom, cur: g.st, pair: fromPair[gi]})
		case g.replaced && replacedByMove[g.name]:
		default:
			deletes = append(deletes, watchChange{host: g.name, kind: changeDelete, cur: g.st})
		}
	}
	for ai, a := range came {
		if toPair[ai] != 0 {
			moves = append(moves, watchChange{host: a.name, kind: changeMovedTo, cur: a.st, pair: toPair[ai]})
			continue
		}
		creates = append(creates, watchChange{host: a.name, kind: changeCreate, cur: a.st})
	}
	sort.SliceStable(moves, func(i, j int) bool {
		if moves[i].pair != moves[j].pair {
			return moves[i].pair < moves[j].pair
		}
		return moves[i].kind == changeMovedFrom && moves[j].kind == changeMovedTo
	})

	out := make([]watchChange, 0, len(moves)+len(deletes)+len(creates)+len(edits))
	out = append(out, moves...)
	out = append(out, deletes...)
	out = append(out, creates...)
	out = append(out, edits...)
	return out
}

// diffEntry compares two states of one file or directory that kept its
// identity. A regular file reports IN_MODIFY for a new modification time or
// size and IN_ATTRIB for a new change time alone. A directory changes its
// times whenever an entry below it changes, and Linux reports none of that to
// the watcher of the parent. A directory therefore reports IN_ATTRIB only
// when the change time moved and the modification time did not.
//
// A change of the link count moves the change time too. Linux tells the
// watchers of the inode about it, but it tells the watcher of a parent
// directory nothing, because the creation or removal of the name is the
// event there. So child is true for an entry of a watched directory, and a
// new change time that comes with a new link count then reports nothing.
func diffEntry(name string, old, cur nameStat, child bool) (watchChange, bool) {
	if cur.kind == hostKindDir {
		if cur.ctime != old.ctime && cur.mtime == old.mtime {
			return watchChange{host: name, kind: changeAttrib, old: old, cur: cur}, true
		}
		return watchChange{}, false
	}
	switch {
	case old.contentChanged(cur):
		return watchChange{host: name, kind: changeModify, old: old, cur: cur}, true
	case old.ctime != cur.ctime:
		if child && old.nlink != cur.nlink {
			return watchChange{}, false
		}
		return watchChange{host: name, kind: changeAttrib, old: old, cur: cur}, true
	}
	return watchChange{}, false
}

// selfChange is what a scan finds about the watched object itself.
type selfChange struct {
	// gone reports that the host no longer holds the object.
	gone bool
	// kind is changeModify or changeAttrib, or zero when nothing changed.
	kind changeKind
}

// diffSelf compares two states of a watched object. A regular file reports a
// modification or an attribute change. A directory reports an attribute
// change only, by the rule of diffEntry.
func diffSelf(old, cur nameStat, exists bool) selfChange {
	if !exists || !old.sameFile(cur) {
		return selfChange{gone: true}
	}
	if ch, ok := diffEntry("", old, cur, false); ok {
		return selfChange{kind: ch.kind}
	}
	return selfChange{}
}
