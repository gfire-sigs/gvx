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

import (
	"fmt"
	"os"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// TestDurableCommitCost measures the cost of one durable commit on a real
// host file. It shows what a guest database pays for each fsync. The test
// runs only when EXT4LITE_BENCH is set, because each iteration waits for the
// host flush call. The env helpers need a *testing.T, so the test runs the
// benchmark bodies through testing.Benchmark.
func TestDurableCommitCost(t *testing.T) {
	if os.Getenv("EXT4LITE_BENCH") == "" {
		t.Skip("set EXT4LITE_BENCH=1 to run the durable commit benchmark")
	}
	run := func(name string, body func(e *env, b *testing.B)) {
		e := newEnv(t)
		res := testing.Benchmark(func(b *testing.B) { body(e, b) })
		t.Logf("%-22s %8d commits, %v per commit", name, res.N, time.Duration(res.NsPerOp()))
	}

	run("append 4 KiB", func(e *env, b *testing.B) {
		fd := e.mustOpen("/wal", linux.O_CREAT|linux.O_WRONLY)
		defer fd.DecRef(e.ctx)
		buf := pattern(1, 4096)
		b.ResetTimer()
		for i := range b.N {
			if _, err := fd.PWrite(e.ctx, usermem.BytesIOSequence(buf), int64(i)*4096, vfs.WriteOptions{}); err != nil {
				b.Fatal(err)
			}
			if err := fd.Sync(e.ctx); err != nil {
				b.Fatal(err)
			}
		}
	})
	run("overwrite 4 KiB", func(e *env, b *testing.B) {
		e.writeFile("/db", make([]byte, 1<<20))
		fd := e.mustOpen("/db", linux.O_WRONLY)
		defer fd.DecRef(e.ctx)
		buf := pattern(2, 4096)
		b.ResetTimer()
		for i := range b.N {
			if _, err := fd.PWrite(e.ctx, usermem.BytesIOSequence(buf), int64(i%256)*4096, vfs.WriteOptions{}); err != nil {
				b.Fatal(err)
			}
			if err := fd.Sync(e.ctx); err != nil {
				b.Fatal(err)
			}
		}
	})
	run("create small file", func(e *env, b *testing.B) {
		buf := pattern(3, 100)
		b.ResetTimer()
		for i := range b.N {
			fd := e.mustOpen(fmt.Sprintf("/f%d", i), linux.O_CREAT|linux.O_WRONLY)
			if _, err := fd.PWrite(e.ctx, usermem.BytesIOSequence(buf), 0, vfs.WriteOptions{}); err != nil {
				b.Fatal(err)
			}
			if err := fd.Sync(e.ctx); err != nil {
				b.Fatal(err)
			}
			fd.DecRef(e.ctx)
		}
	})
}
