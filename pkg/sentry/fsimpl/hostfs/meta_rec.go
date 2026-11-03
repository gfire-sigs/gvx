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
	"encoding/binary"
	"maps"
	"slices"
)

// recKind tells which table a .gvx_meta record belongs to and how its key is
// built. A volume with trustworthy file identities uses the first two kinds.
// A volume without them uses the path kinds, which behave as the journal of
// earlier releases did.
type recKind uint8

const (
	// kindInode is the record of one host file or directory. The key is the
	// identity of the file, so every hard link shares the record, and a host
	// process that renames the file keeps it.
	kindInode recKind = iota + 1
	// kindName is a virtual symbolic link. The host holds no object for it, so
	// the key is the identity of the parent directory and the name.
	kindName
	// kindPath is kindInode for an entry without a trustworthy identity: any
	// entry of a volume without identities, and an entry of a file system that
	// the guest mounts inside a workspace with identities. The key is the guest
	// path.
	kindPath
	// kindPathName is kindName in a directory without a trustworthy identity.
	// The key is the guest path of the parent directory and the name.
	kindPathName
)

// recKey is the key of one .gvx_meta record. It is comparable, so it keys the
// in-memory table directly. Only the fields of its kind are set.
type recKey struct {
	kind recKind
	// id is the file for kindInode and the parent directory for kindName.
	id fileKey
	// path is the guest path for kindPath and the guest path of the parent
	// directory for kindPathName.
	path string
	// name is the entry name for kindName and kindPathName.
	name string
}

// isName reports whether k keys a virtual symbolic link.
func (k recKey) isName() bool {
	return k.kind == kindName || k.kind == kindPathName
}

// isPath reports whether k keys on a guest path.
func (k recKey) isPath() bool {
	return k.kind == kindPath || k.kind == kindPathName
}

// dir returns the key of the directory that holds the name record k. The
// result is the kindInode or kindPath key of that directory.
func (k recKey) dir() recKey {
	if k.kind == kindPathName {
		return recKey{kind: kindPath, path: k.path}
	}
	return recKey{kind: kindInode, id: k.id}
}

// withName returns the key of the name record of name in the directory that
// the key k names.
func (k recKey) withName(name string) recKey {
	if k.kind == kindPath {
		return recKey{kind: kindPathName, path: k.path, name: name}
	}
	return recKey{kind: kindName, id: k.id, name: name}
}

// rec is one .gvx_meta record. A stored rec never changes: a mutation builds a
// new rec and replaces the pointer, so the snapshot of a compaction can encode
// records without a lock.
type rec struct {
	attr POSIXAttr
	// hint is the guest path at which the guest last saw the record: the path
	// of the file for kindInode, and the path of the link for kindName. It
	// never decides which file a record belongs to. It lets the loader adopt
	// the record of a file that a host editor replaced by a rename, and it
	// names the record for tools.
	hint string
	// parent and leaf are the identity of the directory that held the file and
	// the entry name, when the guest last saw it. A host editor that saves by
	// rename gives the new file the same parent and leaf, and a rename of an
	// ancestor directory changes neither. Adoption matches on them and not on
	// the path. They are zero on a volume with guest paths.
	parent fileKey
	leaf   string
}

// withHint returns a copy of r with the given hint.
func (r *rec) withHint(hint string) *rec {
	c := *r
	c.hint = hint
	return &c
}

// withLoc returns a copy of r with the given hint, parent directory, and leaf.
func (r *rec) withLoc(hint string, parent fileKey, leaf string) *rec {
	c := *r
	c.hint, c.parent, c.leaf = hint, parent, leaf
	return &c
}

// recOverhead is the estimated size in bytes of one record in memory without
// its strings: the rec, the key, the map entries, and the indexes.
const recOverhead = 320

// recSize returns the estimated memory in bytes of one record. The estimate
// drives the table cap, so it only needs to grow with the real size.
func recSize(k recKey, r *rec) int64 {
	n := recOverhead + len(k.path) + len(k.name) + len(r.hint) + len(r.leaf) + len(r.attr.Symlink)
	for name, v := range r.attr.Xattrs {
		n += len(name) + len(v) + 64
	}
	return int64(n)
}

// Journal operations. One frame holds a sequence of them.
const (
	opPut byte = 1
	opDel byte = 2
)

// metaOp is one journal operation: the record to store under key, or a delete
// when r is nil.
type metaOp struct {
	key recKey
	r   *rec
}

// appendKey encodes k at the end of buf.
func appendKey(buf []byte, k recKey) []byte {
	buf = append(buf, byte(k.kind))
	switch k.kind {
	case kindInode:
		buf = appendFileKey(buf, k.id)
	case kindName:
		buf = appendFileKey(buf, k.id)
		buf = appendString(buf, k.name)
	case kindPath:
		buf = appendString(buf, k.path)
	case kindPathName:
		buf = appendString(buf, k.path)
		buf = appendString(buf, k.name)
	}
	return buf
}

func appendFileKey(buf []byte, k fileKey) []byte {
	buf = binary.AppendUvarint(buf, k.dev)
	buf = binary.AppendUvarint(buf, k.ino)
	buf = binary.AppendUvarint(buf, k.ino2)
	return binary.AppendVarint(buf, k.btime)
}

func appendString(buf []byte, s string) []byte {
	buf = binary.AppendUvarint(buf, uint64(len(s)))
	return append(buf, s...)
}

// appendOp encodes op at the end of buf.
func appendOp(buf []byte, op metaOp) []byte {
	if op.r == nil {
		buf = append(buf, opDel)
		return appendKey(buf, op.key)
	}
	buf = append(buf, opPut)
	buf = appendKey(buf, op.key)
	body := appendBody(nil, op.r)
	buf = binary.AppendUvarint(buf, uint64(len(body)))
	return append(buf, body...)
}

// appendBody encodes the fields of r. The decoder ignores bytes after the
// last field that it knows, so a later release can append fields.
func appendBody(buf []byte, r *rec) []byte {
	a := &r.attr
	buf = binary.AppendUvarint(buf, uint64(a.Mode))
	buf = binary.AppendUvarint(buf, uint64(a.UID))
	buf = binary.AppendUvarint(buf, uint64(a.GID))
	buf = binary.AppendUvarint(buf, a.Rdev)
	buf = binary.AppendVarint(buf, a.Atime)
	buf = binary.AppendVarint(buf, a.Mtime)
	buf = binary.AppendVarint(buf, a.Ctime)
	buf = appendString(buf, a.Symlink)
	buf = appendString(buf, r.hint)
	buf = binary.AppendUvarint(buf, uint64(len(a.Xattrs)))
	// A sorted order keeps the encoding of equal records equal.
	for _, name := range slices.Sorted(maps.Keys(a.Xattrs)) {
		buf = appendString(buf, name)
		v := a.Xattrs[name]
		buf = binary.AppendUvarint(buf, uint64(len(v)))
		buf = append(buf, v...)
	}
	buf = appendFileKey(buf, r.parent)
	return appendString(buf, r.leaf)
}

// byteReader decodes the fields of a record. The first malformed field sets
// bad, and every later read returns a zero value.
type byteReader struct {
	b   []byte
	bad bool
}

func (r *byteReader) byte() byte {
	if r.bad || len(r.b) == 0 {
		r.bad = true
		return 0
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c
}

func (r *byteReader) uvarint() uint64 {
	if r.bad {
		return 0
	}
	v, n := binary.Uvarint(r.b)
	if n <= 0 {
		r.bad = true
		return 0
	}
	r.b = r.b[n:]
	return v
}

func (r *byteReader) varint() int64 {
	if r.bad {
		return 0
	}
	v, n := binary.Varint(r.b)
	if n <= 0 {
		r.bad = true
		return 0
	}
	r.b = r.b[n:]
	return v
}

// bytes returns a length-prefixed byte string. The result aliases the input.
func (r *byteReader) bytes() []byte {
	n := r.uvarint()
	if r.bad || n > uint64(len(r.b)) {
		r.bad = true
		return nil
	}
	v := r.b[:n:n]
	r.b = r.b[n:]
	return v
}

func (r *byteReader) str() string {
	return string(r.bytes())
}

// fileKey decodes an identity. A platform whose keys hold no birth time reads
// the birth time as zero. An earlier build keyed macOS records on the birth
// time, and the key of such a record must reach the key that a stat builds now.
func (r *byteReader) fileKey() fileKey {
	k := fileKey{dev: r.uvarint(), ino: r.uvarint(), ino2: r.uvarint(), btime: r.varint()}
	if !keysCarryBirthTime {
		k.btime = 0
	}
	return k
}

// readKey decodes one key. It returns false for a malformed key and for an
// unknown kind.
func readKey(r *byteReader) (recKey, bool) {
	k := recKey{kind: recKind(r.byte())}
	switch k.kind {
	case kindInode:
		k.id = r.fileKey()
	case kindName:
		k.id = r.fileKey()
		k.name = r.str()
	case kindPath:
		k.path = r.str()
	case kindPathName:
		k.path = r.str()
		k.name = r.str()
	default:
		return recKey{}, false
	}
	return k, !r.bad
}

// readBody decodes the body of one record.
func readBody(body []byte) (*rec, bool) {
	r := byteReader{b: body}
	out := &rec{}
	a := &out.attr
	a.Mode = uint32(r.uvarint())
	a.UID = uint32(r.uvarint())
	a.GID = uint32(r.uvarint())
	a.Rdev = r.uvarint()
	a.Atime = r.varint()
	a.Mtime = r.varint()
	a.Ctime = r.varint()
	a.Symlink = r.str()
	out.hint = r.str()
	n := r.uvarint()
	// Every xattr takes two bytes at least, which bounds the allocation.
	if n > uint64(len(r.b)) {
		return nil, false
	}
	if n > 0 {
		a.Xattrs = make(map[string][]byte, n)
		for range n {
			name := r.str()
			v := r.bytes()
			if r.bad {
				return nil, false
			}
			a.Xattrs[name] = slices.Clone(v)
		}
	}
	if len(r.b) > 0 {
		out.parent = r.fileKey()
		out.leaf = r.str()
	}
	return out, !r.bad
}

// readOp decodes the next operation of a frame payload. It returns the rest
// of the payload.
func readOp(payload []byte) (op metaOp, rest []byte, ok bool) {
	r := byteReader{b: payload}
	code := r.byte()
	key, kok := readKey(&r)
	if !kok || (code != opPut && code != opDel) {
		return metaOp{}, nil, false
	}
	if code == opDel {
		return metaOp{key: key}, r.b, true
	}
	body := r.bytes()
	if r.bad {
		return metaOp{}, nil, false
	}
	rc, bok := readBody(body)
	if !bok {
		return metaOp{}, nil, false
	}
	return metaOp{key: key, r: rc}, r.b, true
}
