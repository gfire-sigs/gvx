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

//go:build !windows

package hostfs

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
)

// TestPruneKeepsRecordsBehindAReplacedDirectory covers a host process that
// removes a directory and creates it again. The pinned handle of the old
// directory still answers "missing" for the names of the new one. The prune
// must not delete the record of a file that exists.
func TestPruneKeepsRecordsBehindAReplacedDirectory(t *testing.T) {
	e := newSlowFlushEnv(t, workspaceOptions{})
	e.mustMkdir("d")
	e.writeFile("d/f", []byte("old"))
	e.chmod("d/f", 0o751)
	e.writeFile("other", []byte("x"))
	if err := e.ws.Sync(); err != nil {
		t.Fatal(err)
	}
	// The stat opens the pin of d.
	e.mustStat("d/f")

	if err := os.RemoveAll(e.host("d")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(e.host("d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.host("d/f"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A change of another record makes the table dirty, so the flush prunes.
	e.chmod("other", 0o600)
	if err := e.ws.Sync(); err != nil {
		t.Fatal(err)
	}
	table := readMetaTable(t, filepath.Join(e.dir, MetaFileName))
	if got := table["d/f"].Mode & 0o7777; got != 0o751 {
		t.Fatalf("record of d/f on disk has mode %o, want 751: the prune deleted a live record", got)
	}
	if got := metaSnapshot(e.ws)["d/f"].Mode & linux.S_IFMT; got != linux.S_IFREG {
		t.Fatalf("record of d/f in memory has type %o, want a regular file", got)
	}
}

// TestPruneDropsRecordOfAFileThatAHostProcessRemoved checks that the second
// look by path still lets a real orphan go.
func TestPruneDropsRecordOfAFileThatAHostProcessRemoved(t *testing.T) {
	e := newSlowFlushEnv(t, workspaceOptions{})
	e.mustMkdir("d")
	e.writeFile("d/gone", []byte("x"))
	e.writeFile("keep", []byte("x"))
	if err := e.ws.Sync(); err != nil {
		t.Fatal(err)
	}
	e.mustStat("d/gone")
	if err := os.Remove(e.host("d/gone")); err != nil {
		t.Fatal(err)
	}
	e.chmod("keep", 0o600)
	if err := e.ws.Sync(); err != nil {
		t.Fatal(err)
	}
	table := readMetaTable(t, filepath.Join(e.dir, MetaFileName))
	if _, ok := table["d/gone"]; ok {
		t.Fatal("the record of a removed file survived the prune")
	}
	if _, ok := table["d"]; !ok {
		t.Fatal("the record of the live directory d is gone")
	}
}

// TestPruneOfASmallTableChecksEachRecordOnce proves that a flush does not
// loop over the table again: three records cost at most three lookups.
func TestPruneOfASmallTableChecksEachRecordOnce(t *testing.T) {
	ch := &countingHost{}
	e := newEnvOpts(t, workspaceOptions{
		coalesce: time.Hour,
		wrapHost: func(b hostBackend) hostBackend {
			ch.hostBackend = b
			return ch
		},
	})
	for _, name := range []string{"a", "b", "c"} {
		e.writeFile(name, []byte("x"))
	}
	if err := e.ws.Sync(); err != nil {
		t.Fatal(err)
	}
	e.chmod("a", 0o600)
	ch.reset()
	if err := e.ws.Sync(); err != nil {
		t.Fatal(err)
	}
	if n := ch.got("lstatAt"); n > 3 {
		t.Fatalf("a flush of a table with 3 records made %d lstatAt calls %s, want at most 3", n, ch.dump())
	}
	if n := ch.got("lstat"); n != 0 {
		t.Fatalf("a flush made %d path lstat calls %s for records that exist, want 0", n, ch.dump())
	}
}
