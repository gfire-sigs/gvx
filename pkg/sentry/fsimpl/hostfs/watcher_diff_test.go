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
	"slices"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
)

func file(ino uint64, size, mtime, ctime int64) nameStat {
	return nameStat{kind: hostKindRegular, id: hostID{dev: 1, ino: ino}, size: size, mtime: mtime, ctime: ctime}
}

func folder(ino uint64, mtime, ctime int64) nameStat {
	return nameStat{kind: hostKindDir, id: hostID{dev: 1, ino: ino}, mtime: mtime, ctime: ctime}
}

func withLinks(st nameStat, n uint32) nameStat {
	st.nlink = n
	return st
}

// describe renders a change as "kind name" so that a table can state the
// expected sequence.
func describe(c watchChange) string {
	kind := map[changeKind]string{
		changeCreate:    "create",
		changeDelete:    "delete",
		changeModify:    "modify",
		changeAttrib:    "attrib",
		changeMovedFrom: "from",
		changeMovedTo:   "to",
	}[c.kind]
	s := fmt.Sprintf("%s %s", kind, c.host)
	if c.pair != 0 {
		s += fmt.Sprintf(" #%d", c.pair)
	}
	return s
}

func describeAll(cs []watchChange) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, describe(c))
	}
	return out
}

func TestDiffDir(t *testing.T) {
	tests := []struct {
		name     string
		old, cur dirSnapshot
		want     []string
	}{
		{
			name: "nothing changed",
			old:  dirSnapshot{"a": file(1, 3, 10, 10)},
			cur:  dirSnapshot{"a": file(1, 3, 10, 10)},
		},
		{
			name: "create and delete",
			old:  dirSnapshot{"gone": file(1, 3, 10, 10)},
			cur:  dirSnapshot{"new": file(2, 5, 20, 20)},
			want: []string{"delete gone", "create new"},
		},
		{
			name: "rename pairs by identity",
			old:  dirSnapshot{"a": file(7, 3, 10, 10)},
			cur:  dirSnapshot{"b": file(7, 3, 10, 11)},
			want: []string{"from a #1", "to b #1"},
		},
		{
			name: "reused inode number is not a rename",
			old:  dirSnapshot{"a": file(7, 3, 10, 10)},
			cur:  dirSnapshot{"b": file(7, 3, 99, 99)},
			want: []string{"delete a", "create b"},
		},
		{
			name: "two renames get two pairs",
			old:  dirSnapshot{"a": file(1, 1, 1, 1), "b": file(2, 2, 2, 2)},
			cur:  dirSnapshot{"c": file(1, 1, 1, 1), "d": file(2, 2, 2, 2)},
			want: []string{"from a #1", "to c #1", "from b #2", "to d #2"},
		},
		{
			name: "rename over an existing name reports the move only",
			old:  dirSnapshot{"tmp": file(8, 4, 30, 30), "doc": file(5, 2, 10, 10)},
			cur:  dirSnapshot{"doc": file(8, 4, 30, 31)},
			want: []string{"from tmp #1", "to doc #1"},
		},
		{
			name: "another file under the same name is a delete and a create",
			old:  dirSnapshot{"doc": file(5, 2, 10, 10)},
			cur:  dirSnapshot{"doc": file(9, 6, 40, 40)},
			want: []string{"delete doc", "create doc"},
		},
		{
			name: "new size and time is a modification",
			old:  dirSnapshot{"a": file(1, 3, 10, 10)},
			cur:  dirSnapshot{"a": file(1, 4, 20, 20)},
			want: []string{"modify a"},
		},
		{
			name: "new time alone is a modification",
			old:  dirSnapshot{"a": file(1, 3, 10, 10)},
			cur:  dirSnapshot{"a": file(1, 3, 20, 20)},
			want: []string{"modify a"},
		},
		{
			name: "new change time alone is an attribute change",
			old:  dirSnapshot{"a": file(1, 3, 10, 10)},
			cur:  dirSnapshot{"a": file(1, 3, 10, 20)},
			want: []string{"attrib a"},
		},
		{
			name: "a child directory ignores entry changes below it",
			old:  dirSnapshot{"d": folder(1, 10, 10)},
			cur:  dirSnapshot{"d": folder(1, 20, 20)},
		},
		{
			name: "a child directory reports an attribute change",
			old:  dirSnapshot{"d": folder(1, 10, 10)},
			cur:  dirSnapshot{"d": folder(1, 10, 20)},
			want: []string{"attrib d"},
		},
		{
			name: "hidden entries stay out",
			old:  dirSnapshot{},
			cur: dirSnapshot{
				".DS_Store": {kind: hostKindRegular, id: hostID{ino: 3}, hidden: true},
				"keep":      file(4, 1, 1, 1),
			},
			want: []string{"create keep"},
		},
		{
			name: "an entry that turns hidden looks deleted",
			old:  dirSnapshot{"x": file(4, 1, 1, 1)},
			cur:  dirSnapshot{"x": {kind: hostKindRegular, id: hostID{dev: 1, ino: 4}, hidden: true}},
			want: []string{"delete x"},
		},
		{
			name: "without an inode number there is no pairing",
			old:  dirSnapshot{"a": file(0, 3, 10, 10)},
			cur:  dirSnapshot{"b": file(0, 3, 10, 10)},
			want: []string{"delete a", "create b"},
		},
		{
			name: "a link count change is silent for a child",
			old:  dirSnapshot{"a": withLinks(file(1, 3, 10, 10), 1)},
			cur:  dirSnapshot{"a": withLinks(file(1, 3, 10, 20), 2)},
		},
		{
			name: "an attribute change that keeps the link count is reported",
			old:  dirSnapshot{"a": withLinks(file(1, 3, 10, 10), 2)},
			cur:  dirSnapshot{"a": withLinks(file(1, 3, 10, 20), 2)},
			want: []string{"attrib a"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := describeAll(diffDir(tc.old, tc.cur))
			if !slices.Equal(got, tc.want) {
				t.Fatalf("diffDir = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDiffDirIsDeterministic(t *testing.T) {
	old := dirSnapshot{}
	cur := dirSnapshot{}
	for i := range 40 {
		cur[fmt.Sprintf("f%02d", i)] = file(uint64(100+i), int64(i), 5, 5)
	}
	first := describeAll(diffDir(old, cur))
	for range 20 {
		if got := describeAll(diffDir(old, cur)); !slices.Equal(got, first) {
			t.Fatalf("diffDir order changed between runs:\n%q\n%q", first, got)
		}
	}
	if !slices.IsSorted(first) {
		t.Fatalf("creations are not in name order: %q", first)
	}
}

func TestChangeMaskCarriesTheDirectoryFlag(t *testing.T) {
	changes := diffDir(dirSnapshot{}, dirSnapshot{"d": folder(1, 1, 1), "f": file(2, 1, 1, 1)})
	var masks = map[string]uint32{}
	for _, c := range changes {
		masks[c.host] = c.mask()
	}
	if got, want := masks["d"], uint32(linux.IN_CREATE|linux.IN_ISDIR); got != want {
		t.Fatalf("mask of a new directory = %#x, want %#x", got, want)
	}
	if got, want := masks["f"], uint32(linux.IN_CREATE); got != want {
		t.Fatalf("mask of a new file = %#x, want %#x", got, want)
	}
}

func TestDiffSelf(t *testing.T) {
	base := file(1, 3, 10, 10)
	tests := []struct {
		name   string
		old    nameStat
		cur    nameStat
		exists bool
		want   selfChange
	}{
		{"unchanged", base, base, true, selfChange{}},
		{"modified", base, file(1, 4, 20, 20), true, selfChange{kind: changeModify}},
		{"attributes", base, file(1, 3, 10, 20), true, selfChange{kind: changeAttrib}},
		{"missing", base, nameStat{}, false, selfChange{gone: true}},
		{"replaced", base, file(2, 3, 10, 10), true, selfChange{gone: true}},
		{"directory entry change is silent", folder(1, 10, 10), folder(1, 20, 20), true, selfChange{}},
		{"directory attribute change", folder(1, 10, 10), folder(1, 10, 20), true, selfChange{kind: changeAttrib}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := diffSelf(tc.old, tc.cur, tc.exists); got != tc.want {
				t.Fatalf("diffSelf = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestAdoptTouchedHidesGuestChanges(t *testing.T) {
	old := dirSnapshot{
		"keep": {kind: hostKindRegular, id: hostID{ino: 1}, guest: "keep", size: 1},
		"out":  {kind: hostKindRegular, id: hostID{ino: 2}, guest: "out", size: 1},
	}
	cur := dirSnapshot{
		"keep": {kind: hostKindRegular, id: hostID{ino: 1}, guest: "keep", size: 2},
		"in":   {kind: hostKindRegular, id: hostID{ino: 3}, guest: "in", size: 1},
	}
	touched := map[string]struct{}{"out": {}, "in": {}}
	got := describeAll(diffDir(adoptTouched(old, cur, touched), cur))
	if want := []string{"modify keep"}; !slices.Equal(got, want) {
		t.Fatalf("diff after adopting the guest names = %q, want %q", got, want)
	}
	if _, ok := old["in"]; ok {
		t.Fatal("adoptTouched changed the snapshot of the caller")
	}
}

func TestJudgeChange(t *testing.T) {
	old := file(1, 3, 10, 10)
	modified := file(1, 5, 20, 20)
	same := func(st nameStat) func() (nameStat, bool) {
		return func() (nameStat, bool) { return st, true }
	}
	newInode := func(valid bool, st nameStat) *inode {
		ino := &inode{kind: hostKindRegular}
		if valid {
			ino.guest.valid = true
			ino.guest.mtime, ino.guest.ctime, ino.guest.size = st.mtime, st.ctime, st.size
		}
		return ino
	}
	tests := []struct {
		name     string
		ino      *inode
		cur      nameStat
		wantV    verdict
		wantKind changeKind
	}{
		{"no inode means a host change", nil, modified, verdictEmit, changeModify},
		{"no guest record means a host change", newInode(false, nameStat{}), modified, verdictEmit, changeModify},
		{"state of the guest write is suppressed", newInode(true, modified), modified, verdictSuppress, 0},
		{"host write after a guest write is reported", newInode(true, file(1, 4, 15, 15)), modified, verdictEmit, changeModify},
		{"host chmod after a guest write is an attribute change", newInode(true, file(1, 5, 20, 15)), modified, verdictEmit, changeAttrib},
		{"attribute change by the guest is suppressed", newInode(true, file(1, 3, 10, 20)), file(1, 3, 10, 20), verdictSuppress, 0},
		{"attribute change by the host is reported", newInode(true, file(1, 3, 10, 12)), file(1, 3, 10, 20), verdictEmit, changeAttrib},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, kind, _ := judgeChange(tc.ino, old, tc.cur, true, same(tc.cur))
			if v != tc.wantV || kind != tc.wantKind {
				t.Fatalf("judgeChange = (%v, %v), want (%v, %v)", v, kind, tc.wantV, tc.wantKind)
			}
		})
	}

	t.Run("a write in progress defers the decision", func(t *testing.T) {
		ino := newInode(true, modified)
		ino.guestBegin()
		if v, _, _ := judgeChange(ino, old, modified, true, same(modified)); v != verdictDefer {
			t.Fatalf("verdict during a guest write = %v, want defer", v)
		}
		ino.guestEnd(hostInfo{}, false)
		if v, _, _ := judgeChange(ino, old, modified, true, same(modified)); v != verdictSuppress {
			t.Fatalf("verdict after the write = %v, want suppress", v)
		}
	})

	t.Run("a write that finishes during the stat defers the decision", func(t *testing.T) {
		ino := newInode(true, modified)
		restat := func() (nameStat, bool) {
			ino.guestBegin()
			ino.guestEnd(hostInfo{}, false)
			return modified, true
		}
		if v, _, _ := judgeChange(ino, old, modified, true, restat); v != verdictDefer {
			t.Fatalf("verdict = %v, want defer", v)
		}
	})
}
