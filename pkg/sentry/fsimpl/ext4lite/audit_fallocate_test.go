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

// Crash workloads for the fallocate range modes and for unnamed files. The
// harness of audit_crash_test.go crashes each workload after every host call and
// inside every sync epoch, and it mounts the image that the crash leaves.

import (
	"bytes"
	"fmt"
	"slices"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// fallocate applies one call to the file p and to its model. The offsets and
// lengths are block aligned, so the call changes only the extent list and the
// size, and the file passes through exactly the states that the model lists.
func (d *auDrv) fallocate(p string, mode uint64, off, n int) {
	d.t.Helper()
	fd := d.e.mustOpen(p, linux.O_RDWR)
	defer fd.DecRef(d.e.ctx)
	d.must(fmt.Sprintf("fallocate %s mode %#x %d+%d", p, mode, off, n), fd.Allocate(d.e.ctx, mode, uint64(off), uint64(n)))
	node := d.m.nodes[p]
	switch mode {
	case zeroKeep, zeroGrow, punchKS:
		if end := off + n; end > len(node.data) && mode == zeroGrow {
			node.data = append(node.data, make([]byte, end-len(node.data))...)
		}
		clear(node.data[min(off, len(node.data)):min(off+n, len(node.data))])
	case collapse:
		node.data = append(node.data[:off], node.data[off+n:]...)
		d.m.loose[node.id] = true
	case insert:
		node.data = append(node.data[:off], append(make([]byte, n), node.data[off:]...)...)
		d.m.loose[node.id] = true
	}
}

// auFallocateCase is a workload that zeroes, collapses, inserts, punches, and
// truncates one file. The file must pass through only the states that the
// workload lists, because every call is one transaction. The workload has no
// write, because a write to a mapped block reaches the disk before its
// transaction and so adds states that the list cannot hold.
func auFallocateCase() auCrashCase {
	var states [][]byte
	return auCrashCase{
		name: "fallocate-ranges",
		setup: func(d *auDrv) {
			d.create("/big", 40*blockSize)
			d.create("/other", 33_000)
		},
		body: func(d *auDrv) {
			record := func() { states = append(states, slices.Clone(d.m.nodes["/big"].data)) }
			states = nil
			record()
			d.fallocate("/big", zeroKeep, 3*blockSize, 6*blockSize)
			record()
			d.fallocate("/big", collapse, 10*blockSize, 5*blockSize)
			record()
			d.fsync("/big")
			d.fallocate("/big", insert, 5*blockSize, 3*blockSize)
			record()
			d.syncAll()
			d.fallocate("/big", zeroGrow, 30*blockSize, 20*blockSize)
			record()
			d.fallocate("/big", punchKS, 33*blockSize, 4*blockSize)
			record()
			d.truncate("/big", 5*blockSize)
			record()
		},
		check: func(res *auResult, durable, final *auModel) []string {
			e := res.Tree["/big"]
			if e == nil {
				return []string{"/big vanished"}
			}
			for _, s := range states {
				if bytes.Equal(e.data, s) {
					return nil
				}
			}
			return []string{fmt.Sprintf("/big holds none of the %d states that the workload passed through (size %d)", len(states), len(e.data))}
		},
	}
}

// auTmpfileCase is a workload with two unnamed files. The first file gets a
// name after its data is durable. The second file never gets a name, and the
// last close frees it. A crash anywhere must leave the first file whole or
// absent, and must leave no trace of the second file.
func auTmpfileCase() auCrashCase {
	return auCrashCase{
		name: "tmpfile-link-and-orphans",
		setup: func(d *auDrv) {
			d.mkdir("/d")
			d.create("/d/keep", 9_000)
		},
		body: func(d *auDrv) {
			open := func() *vfs.FileDescription {
				fd, err := d.e.openTmpfile("/d", linux.O_RDWR, 0o600)
				d.must("open with O_TMPFILE", err)
				return fd
			}
			linked, lost := open(), open()
			d.m.nextID++
			id := d.m.nextID
			data := auFill(id, 0, 120_000)
			d.e.write(linked, data)
			d.e.write(lost, auFill(id+1000, 0, 80_000))
			d.must("fsync of the unnamed file", linked.Sync(d.e.ctx))
			// The flush writes the orphan chain with both files.
			d.syncAll()
			d.must("link", d.e.linkDescription(linked, "/d/linked"))
			d.m.nodes["/d/linked"] = &auMNode{id: id, data: data}
			d.m.note("/d/linked", id)
			d.fsync("/d")
			lost.DecRef(d.e.ctx)
			d.syncAll()
			linked.DecRef(d.e.ctx)
		},
		check: func(res *auResult, durable, final *auModel) []string {
			var out []string
			if e := res.Tree["/d/linked"]; e != nil && !bytes.Equal(e.data, final.nodes["/d/linked"].data) {
				out = append(out, fmt.Sprintf("/d/linked is not whole: size %d, first difference at byte %d", len(e.data), auFirstDiff(e.data, final.nodes["/d/linked"].data)))
			}
			if n := len(res.Tree); n > len(durable.nodes)+1 {
				out = append(out, fmt.Sprintf("the image holds %d objects, want at most %d: an unnamed file left a trace", n, len(durable.nodes)+1))
			}
			return out
		},
	}
}
