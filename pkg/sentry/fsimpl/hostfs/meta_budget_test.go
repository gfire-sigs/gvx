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
	"path/filepath"
	"testing"
	"time"
)

// budgetFiles is the number of files that a host editor replaces in the
// budget tests. A cost that grows with this number for each file turns into a
// quadratic cost, which the bounds below reject.
const budgetFiles = 2000

// replacedDirWS opens a workspace with a counting host and a fixed clock. The
// directory "d" holds budgetFiles files with guest records. A host process then
// replaces every file by writing a temporary file and renaming it over the old
// one, as an editor saves. The returned counter holds no calls yet.
func replacedDirWS(t *testing.T) (*Workspace, *countingHost) {
	t.Helper()
	dir := resolvedTempDir(t)
	ch := &countingHost{}
	clock := &testClock{}
	clock.ns.Store(int64(time.Hour))
	ws := plainWS(t, dir, workspaceOptions{
		clock: clock.now,
		wrapHost: func(b hostBackend) hostBackend {
			ch.hostBackend = b
			return ch
		},
	})
	if ws.pathKeys {
		t.Skip("a volume with path keys has no adoption")
	}
	if err := ws.Mkdir("d", 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range budgetFiles {
		rel := fmt.Sprintf("d/f%04d", i)
		mustWriteFile(t, ws, rel, 0o751)
		if err := ws.Chown(rel, 7, 8); err != nil {
			t.Fatal(err)
		}
	}
	mustSync(t, ws)
	for i := range budgetFiles {
		name := filepath.Join(dir, "d", fmt.Sprintf("f%04d", i))
		if err := os.WriteFile(name+".tmp", []byte("saved"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(name+".tmp", name); err != nil {
			t.Fatal(err)
		}
	}
	ch.reset()
	return ws, ch
}

func TestStatOfManyReplacedFilesListsTheDirectoryOnce(t *testing.T) {
	ws, ch := replacedDirWS(t)
	for i := range budgetFiles {
		requireMode(t, ws, fmt.Sprintf("d/f%04d", i), 0o751, 7)
	}
	// The cache of the inode set serves every stat after the first.
	if n := ch.got("readDirAt") + ch.got("readDir"); n > 3 {
		t.Fatalf("%d stats of replaced files made %d directory listings %s, want at most 3", budgetFiles, n, ch.dump())
	}
	// Each stat makes its own lookup, and a listed inode number costs one more
	// lstatAt to confirm the candidate. The stats stay linear.
	if n := ch.got("lstatAt"); n > 2*budgetFiles+10 {
		t.Fatalf("%d stats of replaced files made %d lstatAt calls, want at most %d", budgetFiles, n, 2*budgetFiles+10)
	}
	t.Logf("calls for %d stats: readDirAt=%d readDir=%d lstatAt=%d", budgetFiles, ch.got("readDirAt"), ch.got("readDir"), ch.got("lstatAt"))
}

func TestCollectorBudgetFollowsRecordsAndDirectories(t *testing.T) {
	ws, ch := replacedDirWS(t)
	const dirs = 2 // the root and d

	// The first pass misses every record, and the confirming pass starts at
	// once. Each pass lists each directory once.
	for {
		confirming := ws.orphans.confirming
		before := ch.got("lstat") + ch.got("lstatAt")
		listed := ch.got("readDirAt")
		more := ws.orphanStep()
		if confirming {
			if n := ch.got("lstat") + ch.got("lstatAt") - before; n > orphanStepRecords {
				t.Fatalf("a confirm step made %d host lookups, want at most %d", n, orphanStepRecords)
			}
			if n := ch.got("readDirAt") - listed; n > 0 {
				t.Fatalf("a confirm step listed %d directories, want none", n)
			}
		}
		if !more {
			break
		}
	}
	if n := ch.got("readDirAt") + ch.got("readDir"); n > 2*dirs+2 {
		t.Fatalf("the collector made %d directory listings %s for %d directories and %d files, want at most %d", n, ch.dump(), dirs, budgetFiles, 2*dirs+2)
	}
	t.Logf("listings of the collector: readDirAt=%d readDir=%d", ch.got("readDirAt"), ch.got("readDir"))
	for i := range budgetFiles {
		requireMode(t, ws, fmt.Sprintf("d/f%04d", i), 0o751, 7)
	}
	if n := ws.meta.size(); n != budgetFiles+1 {
		t.Fatalf("the table holds %d records after the collector, want %d", n, budgetFiles+1)
	}
}
