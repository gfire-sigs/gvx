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
	"slices"
	"strconv"
	"testing"
	"time"
)

// benchMetaRecords is the table sizes that TestHostfsMetaScaleBench measures.
var benchMetaRecords = []int{10_000, 100_000}

const (
	// benchListed is the number of entries of the directory that the listing
	// case reads.
	benchListed = 100
	// benchChildren is the number of children of the directory that the rename
	// case moves.
	benchChildren = 2000
)

// TestHostfsMetaScaleBench reports how the cost of single guest calls grows
// with the size of the .gvx_meta table: a listing of a small directory, the
// rename of a directory with benchChildren children, a change through a hard
// link, one flush, and the open of a workspace that holds the table. It runs
// only when HOSTFS_BENCH is set, and it prints one line for each table size.
func TestHostfsMetaScaleBench(t *testing.T) {
	if os.Getenv("HOSTFS_BENCH") == "" {
		t.Skip("set HOSTFS_BENCH=1 to run the hostfs benchmarks")
	}
	for _, n := range benchMetaRecords {
		t.Run(fmt.Sprintf("%d records", n), func(t *testing.T) { benchMetaScale(t, n) })
	}
}

// timeEach returns the median time of rounds calls of fn. A median keeps one
// slow call, such as the first call after a cache warm-up, out of the result.
func timeEach(rounds int, fn func(i int)) time.Duration {
	times := make([]time.Duration, rounds)
	for i := range rounds {
		start := time.Now()
		fn(i)
		times[i] = time.Since(start)
	}
	slices.Sort(times)
	return times[rounds/2]
}

func benchMetaScale(t *testing.T, records int) {
	dir := t.TempDir()
	ch := &countingHost{}
	open := func(wrap bool) *Workspace {
		opts := workspaceOptions{coalesce: time.Hour}
		if wrap {
			opts.wrapHost = func(b hostBackend) hostBackend {
				ch.hostBackend = b
				return ch
			}
		}
		ws, err := openWorkspace(dir, false, opts)
		if err != nil {
			t.Fatalf("openWorkspace: %v", err)
		}
		return ws
	}
	must := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	create := func(ws *Workspace, rel string) {
		f, _, err := ws.createFile(rel, 0o644, 0, 0)
		must("create "+rel, err)
		_ = f.Close()
	}

	ws := open(true)
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = ws.Close()
		}
	})
	must("mkdir bulk", ws.Mkdir("bulk", 0o755))
	for i := range records {
		if i%1000 == 0 {
			must("mkdir shard", ws.Mkdir("bulk/d"+strconv.Itoa(i/1000), 0o755))
		}
		create(ws, "bulk/d"+strconv.Itoa(i/1000)+"/f"+strconv.Itoa(i))
	}
	must("mkdir listed", ws.Mkdir("listed", 0o755))
	for i := range benchListed {
		create(ws, "listed/f"+strconv.Itoa(i))
	}
	must("mkdir big", ws.Mkdir("big", 0o755))
	for i := range benchChildren {
		create(ws, "big/f"+strconv.Itoa(i))
	}
	create(ws, "hl")
	for _, name := range []string{"hl1", "hl2", "hl3"} {
		must("link "+name, ws.link("hl", name))
	}
	must("first sync", ws.Sync())

	// A listing of a small directory. The first call warms the pinned handle.
	_, err := ws.listDir("listed")
	must("listDir", err)
	ch.reset()
	listing := timeEach(201, func(int) {
		if _, err := ws.listDir("listed"); err != nil {
			t.Fatal(err)
		}
	})
	listCalls := ch.total() / 201

	// The rename of a directory with benchChildren children, back and forth.
	renaming := timeEach(21, func(i int) {
		from, to := "big", "big2"
		if i%2 == 1 {
			from, to = to, from
		}
		must("rename", ws.Rename(from, to))
	})

	// A change through one name of a file with four names.
	linkChange := timeEach(21, func(i int) {
		must("chmod", ws.Chmod("hl1", uint32(0o600+i%8)))
	})

	// One change of a file with one name, and its flush.
	flush := timeEach(51, func(i int) {
		must("chmod", ws.Chmod("listed/f0", uint32(0o600+i%8)))
		must("sync", ws.Sync())
	})

	must("sync", ws.Sync())
	must("close", ws.Close())
	closed = true
	var startup time.Duration
	const opens = 3
	for range opens {
		start := time.Now()
		reopened := open(false)
		startup += time.Since(start)
		must("close", reopened.Close())
	}
	startup /= opens

	t.Logf("META-BENCH records=%d listdir=%v listdir_host_calls=%d rename_dir_%d_children=%v hardlink_chmod=%v flush=%v startup=%v",
		records, listing, listCalls, benchChildren, renaming, linkChange, flush, startup)
}
