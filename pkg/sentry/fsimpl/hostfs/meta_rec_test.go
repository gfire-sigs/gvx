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
	"bytes"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
)

func sampleRecords() []metaOp {
	id := fileKey{dev: 0, ino: 1 << 40, ino2: 17, btime: 1_700_000_000_123_456_789}
	full := &rec{
		attr: POSIXAttr{
			Mode: linux.S_IFREG | 0o751, UID: 1000, GID: 2000, Rdev: 5<<32 | 6,
			Atime: -5, Mtime: 1_700_000_000_000_000_001, Ctime: 3,
			Xattrs: map[string][]byte{"user.b": []byte("two"), "user.a": []byte("one"), "user.empty": {}},
		},
		hint: "dir/file name",
	}
	link := &rec{attr: POSIXAttr{Mode: linux.S_IFLNK | 0o777, Symlink: "../target", Ctime: 9}, hint: "dir/link"}
	return []metaOp{
		{key: recKey{kind: kindInode, id: id}, r: full},
		{key: recKey{kind: kindName, id: id, name: "link"}, r: link},
		{key: recKey{kind: kindPath, path: "dir/file name"}, r: full},
		{key: recKey{kind: kindPathName, path: "dir", name: "link"}, r: link},
		{key: recKey{kind: kindInode, id: id}},
		{key: recKey{kind: kindName, id: id, name: "link"}},
		{key: recKey{kind: kindPath, path: "x"}},
		{key: recKey{kind: kindPathName, path: ".", name: "y"}},
	}
}

func TestRecordOperationsRoundTrip(t *testing.T) {
	var payload []byte
	ops := sampleRecords()
	for _, op := range ops {
		payload = appendOp(payload, op)
	}
	for i, want := range ops {
		got, rest, ok := readOp(payload)
		if !ok {
			t.Fatalf("operation %d did not decode", i)
		}
		payload = rest
		if got.key != want.key {
			t.Errorf("operation %d key = %+v, want %+v", i, got.key, want.key)
		}
		if (got.r == nil) != (want.r == nil) {
			t.Fatalf("operation %d is a delete = %v, want %v", i, got.r == nil, want.r == nil)
		}
		if want.r == nil {
			continue
		}
		g, w := got.r, want.r
		if g.hint != w.hint || g.attr.Mode != w.attr.Mode || g.attr.UID != w.attr.UID || g.attr.GID != w.attr.GID ||
			g.attr.Rdev != w.attr.Rdev || g.attr.Atime != w.attr.Atime || g.attr.Mtime != w.attr.Mtime ||
			g.attr.Ctime != w.attr.Ctime || g.attr.Symlink != w.attr.Symlink || len(g.attr.Xattrs) != len(w.attr.Xattrs) {
			t.Errorf("operation %d record = %+v, want %+v", i, g, w)
		}
		for name, v := range w.attr.Xattrs {
			if gv, ok := g.attr.Xattrs[name]; !ok || !bytes.Equal(gv, v) {
				t.Errorf("operation %d attribute %s = %q (present %v), want %q", i, name, gv, ok, v)
			}
		}
	}
	if len(payload) != 0 {
		t.Fatalf("%d bytes left after the last operation", len(payload))
	}
}

func TestRecordEncodingIgnoresMapOrder(t *testing.T) {
	a := &rec{attr: POSIXAttr{Xattrs: map[string][]byte{"user.a": []byte("1"), "user.b": []byte("2"), "user.c": []byte("3")}}}
	b := &rec{attr: POSIXAttr{Xattrs: map[string][]byte{"user.c": []byte("3"), "user.b": []byte("2"), "user.a": []byte("1")}}}
	for range 20 {
		if !bytes.Equal(appendBody(nil, a), appendBody(nil, b)) {
			t.Fatal("equal records encode to different bytes")
		}
	}
}

func TestTruncatedOperationsAreRejected(t *testing.T) {
	for i, op := range sampleRecords() {
		full := appendOp(nil, op)
		for cut := range len(full) {
			if _, _, ok := readOp(full[:cut]); ok {
				t.Errorf("operation %d decoded from %d of %d bytes", i, cut, len(full))
			}
		}
	}
}

func TestUnknownOperationsAreRejected(t *testing.T) {
	good := appendOp(nil, sampleRecords()[0])
	badCode := append([]byte{9}, good[1:]...)
	if _, _, ok := readOp(badCode); ok {
		t.Error("an unknown operation code decoded")
	}
	badKind := bytes.Clone(good)
	badKind[1] = 0x77
	if _, _, ok := readOp(badKind); ok {
		t.Error("an unknown key kind decoded")
	}
}

func TestRecordBodyIgnoresBytesAfterItsLastKnownField(t *testing.T) {
	r := &rec{attr: POSIXAttr{Mode: 0o100644, UID: 4}, hint: "h"}
	body := append(appendBody(nil, r), 1, 2, 3)
	got, ok := readBody(body)
	if !ok || got.attr.Mode != r.attr.Mode || got.attr.UID != 4 || got.hint != "h" {
		t.Fatalf("readBody with a later release's extra bytes = (%+v, %v), want the known fields", got, ok)
	}
}

func TestRecordSizeGrowsWithTheAttributes(t *testing.T) {
	k := recKey{kind: kindInode, id: fileKey{ino: 1}}
	plain := &rec{attr: POSIXAttr{Mode: 0o100644}, hint: "f"}
	longer := &rec{attr: POSIXAttr{Mode: 0o100644}, hint: "f/with/a/much/longer/path"}
	big := &rec{attr: POSIXAttr{Mode: 0o100644, Xattrs: map[string][]byte{"user.k": make([]byte, 4096)}}, hint: "f"}
	if !(recSize(k, plain) < recSize(k, longer) && recSize(k, longer) < recSize(k, big)) {
		t.Fatalf("record sizes %d, %d, %d do not grow with the hint and the attributes", recSize(k, plain), recSize(k, longer), recSize(k, big))
	}
}

func TestMetaTableKeepsItsIndexesInStepWithTheRecords(t *testing.T) {
	tab := newMetaTable()
	dir := recKey{kind: kindInode, id: fileKey{ino: 10, btime: 1}}
	file := recKey{kind: kindInode, id: fileKey{ino: 11, btime: 2}}
	special := recKey{kind: kindInode, id: fileKey{ino: 12, btime: 3}}
	link := dir.withName("l")
	tab.put(dir, &rec{attr: POSIXAttr{Mode: linux.S_IFDIR | 0o755}, hint: "d"})
	tab.put(file, &rec{attr: POSIXAttr{Mode: linux.S_IFREG | 0o644}, hint: "d/f"})
	tab.put(special, &rec{attr: POSIXAttr{Mode: linux.S_IFIFO | 0o600}, hint: "d/fifo"})
	tab.put(link, &rec{attr: POSIXAttr{Mode: linux.S_IFLNK | 0o777, Symlink: "t"}, hint: "d/l"})

	if names := tab.kidsOf(dir); len(names) != 1 || names[0] != "l" {
		t.Fatalf("kidsOf = %v, want [l]", names)
	}
	if !tab.hasSpecialIno(12) || tab.hasSpecialIno(11) {
		t.Fatal("the special inode index does not match the FIFO record")
	}
	if k, r := tab.byHint("d/f"); k != file || r == nil {
		t.Fatalf("byHint(d/f) = (%+v, %v), want the file record", k, r)
	}
	tab.put(file, &rec{attr: POSIXAttr{Mode: linux.S_IFREG | 0o600}, hint: "e/f"})
	if _, r := tab.byHint("d/f"); r != nil {
		t.Fatal("byHint still finds the old path after the hint changed")
	}
	tab.del(link)
	tab.del(special)
	if len(tab.kidsOf(dir)) != 0 || tab.hasNames() || tab.hasSpecialIno(12) || tab.hasIno(12) {
		t.Fatal("an index kept an entry of a deleted record")
	}
	if got, want := tab.size(), 2; got != want {
		t.Fatalf("size = %d, want %d", got, want)
	}
	if tab.memBytes() <= 0 {
		t.Fatal("memBytes is not positive for a table with records")
	}
	tab.del(dir)
	tab.del(file)
	if tab.size() != 0 || tab.memBytes() != 0 {
		t.Fatalf("an empty table has size %d and %d bytes", tab.size(), tab.memBytes())
	}
}
