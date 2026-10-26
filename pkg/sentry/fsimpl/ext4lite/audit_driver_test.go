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

package ext4lite

// The driver applies each operation to the engine through the VFS layer and
// to a plain in-memory model. The model is the oracle for what a file system
// must hold. The data of a file is a function of the file identity and the
// file offset, so a byte that reached the wrong file shows at once.

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

var vfsWriteOpts = vfs.WriteOptions{}

// auByte returns the byte that file id holds at offset off. It is never zero,
// so a zero byte always means a hole.
func auByte(id uint32, off uint64) byte {
	x := uint64(id)*0x9E3779B97F4A7C15 ^ off*0xBF58476D1CE4E5B9
	x ^= x >> 29
	x *= 0x94D049BB133111EB
	x ^= x >> 32
	return 1 + byte(x%255)
}

// auFill returns n bytes of file id from offset off.
func auFill(id uint32, off uint64, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = auByte(id, off+uint64(i))
	}
	return b
}

// auMNode is one object of the model.
type auMNode struct {
	id     uint32
	dir    bool
	sym    bool
	target string
	data   []byte
}

// auModel is the expected namespace. Hard links share an auMNode.
type auModel struct {
	nodes  map[string]*auMNode
	nextID uint32
	// ids records every identity that ever lived at a path.
	ids map[string]map[uint32]bool
}

func newAuModel() *auModel {
	m := &auModel{nodes: map[string]*auMNode{"/": {id: 1, dir: true}}, nextID: 1, ids: map[string]map[uint32]bool{}}
	return m
}

// clone copies the model, including the content of every file.
func (m *auModel) clone() *auModel {
	c := &auModel{nodes: make(map[string]*auMNode, len(m.nodes)), nextID: m.nextID, ids: map[string]map[uint32]bool{}}
	copied := map[*auMNode]*auMNode{}
	for p, n := range m.nodes {
		if cn, ok := copied[n]; ok {
			c.nodes[p] = cn
			continue
		}
		cn := &auMNode{id: n.id, dir: n.dir, sym: n.sym, target: n.target, data: slices.Clone(n.data)}
		copied[n] = cn
		c.nodes[p] = cn
	}
	for p, s := range m.ids {
		c.ids[p] = maps2(s)
	}
	return c
}

func maps2(s map[uint32]bool) map[uint32]bool {
	c := make(map[uint32]bool, len(s))
	maps.Copy(c, s)
	return c
}

func (m *auModel) note(p string, id uint32) {
	if m.ids[p] == nil {
		m.ids[p] = map[uint32]bool{}
	}
	m.ids[p][id] = true
}

func auJoin(dir, name string) string {
	if dir == "/" {
		return "/" + name
	}
	return dir + "/" + name
}

func auParent(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

// children returns the paths below dir, at any depth, sorted.
func (m *auModel) below(dir string) []string {
	pre := dir + "/"
	if dir == "/" {
		pre = "/"
	}
	var out []string
	for p := range m.nodes {
		if p != dir && strings.HasPrefix(p, pre) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// entries returns the names that dir holds directly.
func (m *auModel) entries(dir string) []string {
	var out []string
	for _, p := range m.below(dir) {
		if auParent(p) == dir {
			out = append(out, p[strings.LastIndexByte(p, '/')+1:])
		}
	}
	return out
}

// nlink returns the link count that the model expects for the object at p.
func (m *auModel) nlink(p string) int {
	n := m.nodes[p]
	if n.dir {
		c := 2
		for _, name := range m.entries(p) {
			if m.nodes[auJoin(p, name)].dir {
				c++
			}
		}
		return c
	}
	c := 0
	for _, o := range m.nodes {
		if o == n {
			c++
		}
	}
	return c
}

// auDrv runs operations on a mounted volume and on the model.
type auDrv struct {
	t  *testing.T
	e  *env
	f  *auFile
	m  *auModel
	rd int // number of operations done
}

// newAuDrv formats a volume in memory and mounts it.
func newAuDrv(t *testing.T) *auDrv {
	t.Helper()
	auNoFlusher(t)
	f := newAuFile(nil)
	return auMount(t, f, newAuModel())
}

// auMount mounts the image of f. The model m describes what the image holds.
func auMount(t *testing.T, f *auFile, m *auModel) *auDrv {
	t.Helper()
	v, err := mountHostFile(f, VolumeOptions{})
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	v.now = fakeClock()
	e := mountVolume(t, &Volume{v: v}, "audit.ext4", vfs.MountOptions{})
	return &auDrv{t: t, e: e, f: f, m: m}
}

func (d *auDrv) must(what string, err error) {
	d.t.Helper()
	if err != nil {
		d.t.Fatalf("%s: %v", what, err)
	}
}

func (d *auDrv) mkdir(p string) {
	d.t.Helper()
	d.must("mkdir "+p, d.e.mkdir(p))
	d.m.nextID++
	d.m.nodes[p] = &auMNode{id: d.m.nextID, dir: true}
	d.m.note(p, d.m.nextID)
}

// create makes a regular file with size bytes of its own data.
func (d *auDrv) create(p string, size int) {
	d.t.Helper()
	d.m.nextID++
	id := d.m.nextID
	fd := d.e.mustOpen(p, linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY)
	defer fd.DecRef(d.e.ctx)
	if size > 0 {
		d.e.write(fd, auFill(id, 0, size))
	}
	d.m.nodes[p] = &auMNode{id: id, data: auFill(id, 0, size)}
	d.m.note(p, id)
}

// pwrite writes n bytes of the file at offset off. A write past the end leaves
// a hole.
func (d *auDrv) pwrite(p string, off, n int) {
	d.t.Helper()
	node := d.m.nodes[p]
	fd := d.e.mustOpen(p, linux.O_WRONLY)
	defer fd.DecRef(d.e.ctx)
	d.e.pwrite(fd, auFill(node.id, uint64(off), n), int64(off))
	if end := off + n; end > len(node.data) {
		node.data = append(node.data, make([]byte, end-len(node.data))...)
	}
	copy(node.data[off:], auFill(node.id, uint64(off), n))
}

func (d *auDrv) truncate(p string, size int) {
	d.t.Helper()
	d.must("truncate "+p, d.e.setStat(p, linux.Statx{Mask: linux.STATX_SIZE, Size: uint64(size)}))
	node := d.m.nodes[p]
	if size <= len(node.data) {
		node.data = node.data[:size]
	} else {
		node.data = append(node.data, make([]byte, size-len(node.data))...)
	}
}

func (d *auDrv) unlink(p string) {
	d.t.Helper()
	d.must("unlink "+p, d.e.unlink(p))
	delete(d.m.nodes, p)
}

func (d *auDrv) rmdir(p string) {
	d.t.Helper()
	d.must("rmdir "+p, d.e.rmdir(p))
	delete(d.m.nodes, p)
}

// rename moves p to q. A directory takes its subtree along.
func (d *auDrv) rename(p, q string) {
	d.t.Helper()
	d.must(fmt.Sprintf("rename %s %s", p, q), d.e.rename(p, q))
	if p == q || d.m.nodes[p] == d.m.nodes[q] && d.m.nodes[q] != nil && !d.m.nodes[p].dir {
		// Renaming a name onto another name of the same file changes nothing.
		return
	}
	moves := []string{p}
	if d.m.nodes[p].dir {
		moves = append(moves, d.m.below(p)...)
	}
	moved := map[string]*auMNode{}
	for _, old := range moves {
		moved[q+strings.TrimPrefix(old, p)] = d.m.nodes[old]
		delete(d.m.nodes, old)
	}
	delete(d.m.nodes, q)
	for np, n := range moved {
		d.m.nodes[np] = n
		d.m.note(np, n.id)
	}
}

func (d *auDrv) link(p, q string) {
	d.t.Helper()
	d.must(fmt.Sprintf("link %s %s", p, q), d.e.link(p, q))
	d.m.nodes[q] = d.m.nodes[p]
	d.m.note(q, d.m.nodes[p].id)
}

func (d *auDrv) symlink(target, p string) {
	d.t.Helper()
	d.must("symlink "+p, d.e.symlink(target, p))
	d.m.nextID++
	d.m.nodes[p] = &auMNode{id: d.m.nextID, sym: true, target: target, data: []byte(target)}
	d.m.note(p, d.m.nextID)
}

// fsync syncs one file or directory, as the guest does.
func (d *auDrv) fsync(p string) {
	d.t.Helper()
	fd := d.e.mustOpen(p, linux.O_RDONLY)
	defer fd.DecRef(d.e.ctx)
	d.must("fsync "+p, fd.Sync(d.e.ctx))
}

// syncAll flushes the volume as sync(2) does.
func (d *auDrv) syncAll() {
	d.t.Helper()
	d.must("sync", d.e.fs.syncAll())
}

// verifyLive compares the mounted tree with the model through the VFS layer.
func (d *auDrv) verifyLive(what string) {
	d.t.Helper()
	for _, msg := range auCompareLive(d.e, d.m) {
		d.t.Errorf("%s: %s", what, msg)
	}
}

// auCompareLive lists the differences between a mounted tree and the model.
func auCompareLive(e *env, m *auModel) []string {
	var out []string
	var walk func(dir string)
	walk = func(dir string) {
		got := e.readdir(dir)
		want := m.entries(dir)
		sort.Strings(want)
		if !slices.Equal(got, want) {
			out = append(out, fmt.Sprintf("%s lists %v, want %v", dir, got, want))
			return
		}
		for _, name := range want {
			p := auJoin(dir, name)
			n := m.nodes[p]
			st, err := e.lstat(p)
			if err != nil {
				out = append(out, fmt.Sprintf("lstat %s: %v", p, err))
				continue
			}
			isDir := st.Mode&linux.S_IFMT == linux.S_IFDIR
			if isDir != n.dir {
				out = append(out, fmt.Sprintf("%s: directory=%v, want %v", p, isDir, n.dir))
				continue
			}
			if int(st.Nlink) != m.nlink(p) {
				out = append(out, fmt.Sprintf("%s: nlink %d, want %d", p, st.Nlink, m.nlink(p)))
			}
			switch {
			case n.dir:
				walk(p)
			case n.sym:
				fd, err := e.open(p, linux.O_PATH|linux.O_NOFOLLOW, 0)
				if err == nil {
					fd.DecRef(e.ctx)
				}
			default:
				if st.Size != uint64(len(n.data)) {
					out = append(out, fmt.Sprintf("%s: size %d, want %d", p, st.Size, len(n.data)))
					continue
				}
				if data := e.readFile(p); !slices.Equal(data, n.data) {
					out = append(out, fmt.Sprintf("%s: content differs at byte %d", p, auFirstDiff(data, n.data)))
				}
			}
		}
	}
	walk("/")
	return out
}

func auFirstDiff(a, b []byte) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

// auCompareImage lists the differences between the oracle tree of an image and
// the model.
func auCompareImage(res *auResult, m *auModel) []string {
	var out []string
	for p, n := range m.nodes {
		e := res.Tree[p]
		if e == nil {
			out = append(out, fmt.Sprintf("%s is missing from the image", p))
			continue
		}
		isDir := e.mode&0xF000 == 0x4000
		if isDir != n.dir {
			out = append(out, fmt.Sprintf("%s: directory=%v, want %v", p, isDir, n.dir))
			continue
		}
		if !n.dir && !slices.Equal(e.data, n.data) {
			out = append(out, fmt.Sprintf("%s: image content differs at byte %d (size %d, want %d)", p, auFirstDiff(e.data, n.data), len(e.data), len(n.data)))
		}
	}
	for p := range res.Tree {
		if m.nodes[p] == nil {
			out = append(out, fmt.Sprintf("%s is in the image, but not in the model", p))
		}
	}
	sort.Strings(out)
	return out
}

// auMountImage opens a crash image with the engine and returns the oracle view
// of the image after the clean unmount that follows. It returns an error when
// the engine refuses to mount.
func auRecover(t *testing.T, img *auPages) (res *auResult, mountErr error) {
	t.Helper()
	f := newAuFile(img.clone())
	v, err := mountHostFile(f, VolumeOptions{})
	if err != nil {
		return nil, err
	}
	vol := &Volume{v: v}
	if err := vol.Close(); err != nil {
		return nil, fmt.Errorf("close after recovery: %w", err)
	}
	return auFsck(f.snapshot(), true), nil
}
