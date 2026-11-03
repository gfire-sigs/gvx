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
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// benchDepth is the directory depth of the benchmark paths.
const benchDepth = 5

// benchDir returns a directory path with the given number of components.
func benchDir(depth int) string {
	p := ""
	for i := range depth {
		p = joinRelPath(p, "d"+strconv.Itoa(i))
	}
	return p
}

// mkdirChain creates every directory of dir.
func (e *env) mkdirChain(dir string) {
	e.t.Helper()
	cur := ""
	for _, part := range strings.Split(dir, "/") {
		cur = joinRelPath(cur, part)
		e.mustMkdir(cur)
	}
}

// benchCase is one measured hostfs operation. setup builds the fixture. op
// runs the operation for iteration i, and every i is unique within one case.
type benchCase struct {
	name  string
	setup func(e *env)
	op    func(e *env, i int)
}

// benchCases returns the operations that the guest workloads repeat most, on
// paths that have depth directory components.
func benchCases(depth int) []benchCase {
	deep := benchDir(depth)
	file := deep + "/f"
	payload := make([]byte, 100)
	return []benchCase{
		{
			name:  "create small file at depth 5",
			setup: func(e *env) { e.mkdirChain(deep) },
			op: func(e *env, i int) {
				fd := e.mustOpen(deep+"/n"+strconv.Itoa(i), linux.O_CREAT|linux.O_WRONLY)
				if _, err := fd.Write(e.ctx, usermem.BytesIOSequence(payload), vfs.WriteOptions{}); err != nil {
					e.t.Fatalf("write: %v", err)
				}
				fd.DecRef(e.ctx)
			},
		},
		{
			name: "stat warm at depth 5",
			setup: func(e *env) {
				e.mkdirChain(deep)
				e.writeFile(file, []byte("x"))
				e.mustStat(file)
			},
			op: func(e *env, _ int) { e.mustStat(file) },
		},
		{
			name: "readdir of 1000 entries",
			setup: func(e *env) {
				e.mustMkdir("big")
				for i := range 1000 {
					e.writeFile("big/e"+strconv.Itoa(i), nil)
				}
			},
			op: func(e *env, _ int) {
				if n := len(e.readdir("big")); n != 1000 {
					e.t.Fatalf("readdir returned %d entries, want 1000", n)
				}
			},
		},
		{
			name: "readdir and stat of 100 entries",
			setup: func(e *env) {
				e.mustMkdir("mid")
				for i := range 100 {
					e.writeFile("mid/e"+strconv.Itoa(i), nil)
				}
			},
			op: func(e *env, _ int) {
				for _, n := range e.readdir("mid") {
					e.mustStat("mid/" + n)
				}
			},
		},
		{
			name: "rename at depth 5",
			setup: func(e *env) {
				e.mkdirChain(deep)
				e.writeFile(deep+"/r0", []byte("x"))
			},
			op: func(e *env, i int) {
				from, to := deep+"/r"+strconv.Itoa(i), deep+"/r"+strconv.Itoa(i+1)
				if err := e.rename(from, to); err != nil {
					e.t.Fatalf("rename %q %q: %v", from, to, err)
				}
			},
		},
		{
			name: "chmod at depth 5",
			setup: func(e *env) {
				e.mkdirChain(deep)
				e.writeFile(file, []byte("x"))
			},
			op: func(e *env, i int) { e.chmod(file, uint16(0o600+i%8)) },
		},
		{
			name: "utimens at depth 5",
			setup: func(e *env) {
				e.mkdirChain(deep)
				e.writeFile(file, []byte("x"))
			},
			op: func(e *env, i int) {
				ts := linux.StatxTimestamp{Sec: int64(1_700_000_000 + i)}
				if err := e.setStat(file, linux.Statx{Mask: linux.STATX_MTIME | linux.STATX_ATIME, Mtime: ts, Atime: ts}); err != nil {
					e.t.Fatalf("utimens: %v", err)
				}
			},
		},
		{
			name: "hard link at depth 5",
			setup: func(e *env) {
				e.mkdirChain(deep)
				e.writeFile(file, []byte("x"))
			},
			op: func(e *env, i int) {
				if err := e.link(file, deep+"/l"+strconv.Itoa(i)); err != nil {
					e.t.Fatalf("link: %v", err)
				}
			},
		},
		{
			name:  "symlink at depth 5",
			setup: func(e *env) { e.mkdirChain(deep) },
			op: func(e *env, i int) {
				if err := e.symlink(deep+"/s"+strconv.Itoa(i), "target"); err != nil {
					e.t.Fatalf("symlink: %v", err)
				}
			},
		},
		{
			name: "append 4 KiB and fsync",
			setup: func(e *env) {
				e.mustMkdir("wal")
			},
			op: func(e *env, i int) {
				fd := e.mustOpen("wal/log", linux.O_CREAT|linux.O_WRONLY|linux.O_APPEND)
				defer fd.DecRef(e.ctx)
				if _, err := fd.Write(e.ctx, usermem.BytesIOSequence(make([]byte, 4096)), vfs.WriteOptions{}); err != nil {
					e.t.Fatalf("write: %v", err)
				}
				if err := fd.Sync(e.ctx); err != nil {
					e.t.Fatalf("fsync: %v", err)
				}
			},
		},
	}
}

// TestHostfsBench reports the time and the host calls of the operations in
// benchCases. It runs only when HOSTFS_BENCH is set, because the cases create
// many host files and the append case waits for the host flush call. The env
// helpers need a *testing.T, so the test runs each case through
// testing.Benchmark.
func TestHostfsBench(t *testing.T) {
	if os.Getenv("HOSTFS_BENCH") == "" {
		t.Skip("set HOSTFS_BENCH=1 to run the hostfs benchmarks")
	}
	for _, c := range benchCases(benchDepth) {
		// A counting env measures the host calls of one operation after a
		// warm-up run, so the counts match what a steady workload pays.
		ce, ch, _ := newCountEnv(t)
		c.setup(ce)
		c.op(ce, 0)
		ch.reset()
		c.op(ce, 1)
		calls, syscalls, dump := ch.total(), ch.syscalls(), ch.dump()

		e := newEnv(t)
		c.setup(e)
		seq := 0
		res := testing.Benchmark(func(b *testing.B) {
			for range b.N {
				c.op(e, seq)
				seq++
			}
		})
		t.Logf("%-34s %12v/op %3d host calls, about %3d system calls %s", c.name, time.Duration(res.NsPerOp()), calls, syscalls, dump)
	}
}

// benchFlushRecords is the table sizes that TestHostfsMetaFlushBench measures.
var benchFlushRecords = []int{10_000, 100_000}

// TestHostfsMetaFlushBench reports the cost of making one metadata change
// durable when the .gvx_meta table holds N records. Each iteration changes the
// mode of one file and calls Sync, the way an fsync of a guest file does. It
// runs only when HOSTFS_BENCH is set.
func TestHostfsMetaFlushBench(t *testing.T) {
	if os.Getenv("HOSTFS_BENCH") == "" {
		t.Skip("set HOSTFS_BENCH=1 to run the hostfs benchmarks")
	}
	for _, n := range benchFlushRecords {
		t.Run(fmt.Sprintf("%d records", n), func(t *testing.T) {
			// A long coalesce window keeps the background flusher out of the
			// measurement.
			ws, err := openWorkspace(t.TempDir(), false, workspaceOptions{coalesce: time.Hour})
			if err != nil {
				t.Fatalf("openWorkspace: %v", err)
			}
			t.Cleanup(func() {
				if err := ws.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
			})
			for i := range n {
				f, _, err := ws.createFile("f"+strconv.Itoa(i), 0o644, 0, 0)
				if err != nil {
					t.Fatalf("create file %d: %v", i, err)
				}
				_ = f.Close()
			}
			if err := ws.Sync(); err != nil {
				t.Fatalf("Sync: %v", err)
			}
			res := testing.Benchmark(func(b *testing.B) {
				for i := range b.N {
					if err := ws.Chmod("f0", uint32(0o600+i%8)); err != nil {
						b.Fatalf("Chmod: %v", err)
					}
					if err := ws.Sync(); err != nil {
						b.Fatalf("Sync: %v", err)
					}
				}
			})
			t.Logf("flush of one change with %d records: %v per flush", n, time.Duration(res.NsPerOp()))
		})
	}
}
