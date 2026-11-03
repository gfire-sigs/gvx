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
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
)

// readMetaTable decodes the .gvx_meta file at path.
func readMetaTable(t testing.TB, path string) map[string]POSIXAttr {
	t.Helper()
	table, err := ReadMeta(path)
	if err != nil {
		t.Fatalf("ReadMeta(%s): %v", path, err)
	}
	return table
}

// metaSnapshot returns a copy of the table that a workspace holds in memory.
func metaSnapshot(w *Workspace) map[string]POSIXAttr {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make(map[string]POSIXAttr, len(w.meta))
	for k, v := range w.meta {
		out[k] = v
	}
	return out
}

// requireSameTable fails when the tables differ in a key or in a record.
func requireSameTable(t testing.TB, what string, got, want map[string]POSIXAttr) {
	t.Helper()
	var problems []string
	for k, w := range want {
		g, ok := got[k]
		if !ok {
			problems = append(problems, fmt.Sprintf("missing %q", k))
			continue
		}
		gj, _ := json.Marshal(g)
		wj, _ := json.Marshal(w)
		if !bytes.Equal(gj, wj) {
			problems = append(problems, fmt.Sprintf("%q = %s, want %s", k, gj, wj))
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			problems = append(problems, fmt.Sprintf("unexpected %q", k))
		}
	}
	slices.Sort(problems)
	if len(problems) > 0 {
		t.Fatalf("%s differs (%d problems): %s", what, len(problems), strings.Join(problems[:min(len(problems), 8)], "; "))
	}
}

// journalWS opens a workspace whose flushes happen only at Sync and Close, so
// a test controls when records reach the disk.
func journalWS(t testing.TB, dir string, opts workspaceOptions) *Workspace {
	t.Helper()
	opts.coalesce = time.Hour
	ws, err := openWorkspace(dir, false, opts)
	if err != nil {
		t.Fatalf("openWorkspace: %v", err)
	}
	var once sync.Once
	t.Cleanup(func() {
		once.Do(func() {
			if err := ws.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
	})
	return ws
}

func mustSync(t testing.TB, ws *Workspace) {
	t.Helper()
	if err := ws.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
}

func mustWriteFile(t testing.TB, ws *Workspace, rel string, mode uint32) {
	t.Helper()
	if err := ws.WriteFile(rel, []byte("x"), mode); err != nil {
		t.Fatalf("WriteFile(%s): %v", rel, err)
	}
}

func fileSize(t testing.TB, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

func isJournal(t testing.TB, path string) bool {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.HasPrefix(raw, []byte(journalMagic))
}

func TestFlushAppendsInsteadOfRewritingTheTable(t *testing.T) {
	dir := t.TempDir()
	var compactions atomic.Int32
	ws := journalWS(t, dir, workspaceOptions{beforeMetaRename: func() error {
		compactions.Add(1)
		return nil
	}})
	for i := range 200 {
		mustWriteFile(t, ws, fmt.Sprintf("f%03d", i), 0o644)
	}
	mustSync(t, ws)
	path := filepath.Join(dir, MetaFileName)
	before := fileSize(t, path)

	if err := ws.Chmod("f007", 0o600); err != nil {
		t.Fatal(err)
	}
	mustSync(t, ws)
	grew := fileSize(t, path) - before
	if grew <= 0 || grew > 200 {
		t.Fatalf("one changed record grew the file by %d bytes, want a small positive append (file was %d bytes)", grew, before)
	}
	if n := compactions.Load(); n != 1 {
		t.Fatalf("%d table rewrites for the first flush and one change, want 1", n)
	}
	if got := readMetaTable(t, path)["f007"].Mode & 0o7777; got != 0o600 {
		t.Fatalf("record f007 on disk has mode %o, want 600", got)
	}
}

func TestSyncOfCleanTableTouchesNothing(t *testing.T) {
	ch := &countingHost{}
	dir := t.TempDir()
	ws := journalWS(t, dir, workspaceOptions{wrapHost: func(b hostBackend) hostBackend {
		ch.hostBackend = b
		return ch
	}})
	mustWriteFile(t, ws, "f", 0o644)
	mustSync(t, ws)

	ch.reset()
	path := filepath.Join(dir, MetaFileName)
	before := fileSize(t, path)
	mustSync(t, ws)
	mustSync(t, ws)
	if n := ch.total(); n != 0 {
		t.Fatalf("Sync of a clean table made %d host calls %s, want 0", n, ch.dump())
	}
	if after := fileSize(t, path); after != before {
		t.Fatalf("Sync of a clean table changed the file from %d to %d bytes", before, after)
	}
}

func TestFsyncedMetadataSurvivesWithoutClose(t *testing.T) {
	dir := t.TempDir()
	ws := journalWS(t, dir, workspaceOptions{})
	mustWriteFile(t, ws, "kept", 0o640)
	mustSync(t, ws)
	mustWriteFile(t, ws, "later", 0o600)
	if err := ws.Chown("kept", 5, 6); err != nil {
		t.Fatal(err)
	}
	mustSync(t, ws)
	// A mutation after the last Sync stays in memory: the process dies here.

	if err := ws.Chmod("kept", 0o777); err != nil {
		t.Fatal(err)
	}
	crashed, err := OpenWorkspace(dir, true)
	if err != nil {
		t.Fatalf("reopen after the crash: %v", err)
	}
	defer func() { _ = crashed.Close() }()
	if attr, _, err := crashed.Stat("kept"); err != nil || attr.Mode&0o7777 != 0o640 || attr.UID != 5 || attr.GID != 6 {
		t.Fatalf("kept after the crash = (%+v, %v), want mode 640 and owner 5:6 from the last Sync", attr, err)
	}
	if attr, _, err := crashed.Stat("later"); err != nil || attr.Mode&0o7777 != 0o600 {
		t.Fatalf("later after the crash = (%+v, %v), want mode 600", attr, err)
	}
}

// writeTable closes a workspace that holds the given files and returns the
// bytes of its .gvx_meta file.
func writeTable(t *testing.T, dir string, files ...string) []byte {
	t.Helper()
	ws, err := openWorkspace(dir, false, workspaceOptions{coalesce: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		mustWriteFile(t, ws, f, 0o644)
		mustSync(t, ws)
	}
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, MetaFileName))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestTornTailIsIgnoredAtEveryCutPoint(t *testing.T) {
	dir := t.TempDir()
	// Each file is one flush, so one frame. The first flush is the snapshot.
	full := writeTable(t, dir, "a", "b", "c")
	lastFrame := frameStart(t, full, 2)
	for cut := lastFrame; cut < len(full); cut += max(1, (len(full)-lastFrame)/12) {
		t.Run(fmt.Sprintf("cut at %d of %d", cut, len(full)), func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, MetaFileName), full[:cut], 0o600); err != nil {
				t.Fatal(err)
			}
			table := readMetaTable(t, filepath.Join(dir, MetaFileName))
			if _, ok := table["b"]; !ok {
				t.Fatalf("a torn last frame hid record b, which an earlier frame holds: %v", table)
			}
			if _, ok := table["c"]; ok {
				t.Fatalf("a torn last frame still applied record c")
			}
		})
	}
}

// frameStart returns the offset of the n-th frame (counting from zero after the
// header) of a journal file.
func frameStart(t *testing.T, raw []byte, n int) int {
	t.Helper()
	off := journalHeader
	for i := 0; ; i++ {
		if i == n {
			return off
		}
		if off+frameHeader > len(raw) {
			t.Fatalf("the journal has only %d frames, want more than %d", i, n)
		}
		off += frameHeader + int(binary.LittleEndian.Uint32(raw[off:]))
	}
}

func TestTornTailHealsOnTheNextWrite(t *testing.T) {
	dir := t.TempDir()
	full := writeTable(t, dir, "a", "b", "c")
	torn := append(slices.Clone(full[:len(full)-3]), 0xde, 0xad)
	path := filepath.Join(dir, MetaFileName)
	if err := os.WriteFile(path, torn, 0o600); err != nil {
		t.Fatal(err)
	}

	ws := journalWS(t, dir, workspaceOptions{})
	if _, _, err := ws.Stat("c"); err != nil {
		// The record of c lost its frame, but the file c exists on the host.
		t.Fatalf("Stat(c): %v", err)
	}
	mustWriteFile(t, ws, "d", 0o600)
	mustSync(t, ws)
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	img, err := parseMeta(raw)
	if err != nil {
		t.Fatal(err)
	}
	if img.torn {
		t.Fatalf("the file still has a torn tail after a write")
	}
	for _, name := range []string{"a", "b", "d"} {
		if _, ok := img.entries[name]; !ok {
			t.Errorf("record %s lost after the torn tail healed", name)
		}
	}
}

func TestChecksumFailureStopsTheReplay(t *testing.T) {
	dir := t.TempDir()
	full := writeTable(t, dir, "a", "b", "c")
	damaged := slices.Clone(full)
	damaged[frameStart(t, full, 1)+frameHeader] ^= 0xff
	path := filepath.Join(dir, MetaFileName)
	if err := os.WriteFile(path, damaged, 0o600); err != nil {
		t.Fatal(err)
	}
	table := readMetaTable(t, path)
	if _, ok := table["a"]; !ok {
		t.Fatal("the frame before the damage was lost")
	}
	if len(table) != 1 {
		t.Fatalf("replay continued past a failed checksum: %v", table)
	}
}

func TestUnknownJournalVersionIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, MetaFileName), []byte(journalMagic+"\x63"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ws, err := OpenWorkspace(dir, false); err == nil {
		_ = ws.Close()
		t.Fatal("OpenWorkspace accepted a journal of an unknown version")
	}
}

func TestLegacyJSONTableLoadsAndStaysUntouchedWithoutWrites(t *testing.T) {
	dir := resolvedTempDir(t)
	for _, f := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	legacy := `{"version":2,"entries":{"a":{"mode":33152,"uid":1,"gid":2},"b":{"mode":33188,"uid":3,"gid":4}}}`
	path := filepath.Join(dir, MetaFileName)
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	ws := journalWS(t, dir, workspaceOptions{})
	if attr, _, err := ws.Stat("a"); err != nil || attr.UID != 1 || attr.GID != 2 || attr.Mode&0o7777 != 0o600 {
		t.Fatalf("Stat(a) = (%+v, %v), want the legacy record", attr, err)
	}
	mustSync(t, ws)
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != legacy {
		t.Fatalf("a session without writes changed the legacy file: (%q, %v)", raw, err)
	}
}

func TestLegacyJSONTableConvertsOnTheFirstWrite(t *testing.T) {
	dir := resolvedTempDir(t)
	for _, f := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	legacy := `{"version":2,"entries":{"a":{"mode":33152,"uid":1,"gid":2,"xattrs":{"user.k":"dmFs"}},"b":{"mode":33188,"uid":3,"gid":4}}}`
	path := filepath.Join(dir, MetaFileName)
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	ws := journalWS(t, dir, workspaceOptions{})
	if err := ws.Chmod("b", 0o700); err != nil {
		t.Fatal(err)
	}
	mustSync(t, ws)
	if !isJournal(t, path) {
		t.Fatal("the first write left the legacy JSON form in place")
	}
	table := readMetaTable(t, path)
	if a := table["a"]; a.UID != 1 || a.GID != 2 || string(a.Xattrs["user.k"]) != "val" {
		t.Fatalf("record a after the conversion = %+v, want the legacy values", a)
	}
	if b := table["b"]; b.Mode&0o7777 != 0o700 || b.UID != 3 {
		t.Fatalf("record b after the conversion = %+v, want mode 700 owner 3", b)
	}
	reopened, err := OpenWorkspace(dir, true)
	if err != nil {
		t.Fatalf("reopen after the conversion: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if attr, _, err := reopened.Stat("a"); err != nil || attr.UID != 1 {
		t.Fatalf("Stat(a) after reopen = (%+v, %v)", attr, err)
	}
}

func TestLegacyKeysThatEscapeTheWorkspaceAreDropped(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"version":2,"entries":{"../outside":{"mode":33188},".gvx_meta":{"mode":33188},"ok":{"mode":33188}}}`
	path := filepath.Join(dir, MetaFileName)
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	table := readMetaTable(t, path)
	if len(table) != 1 {
		t.Fatalf("table = %v, want only ok", table)
	}
	if _, ok := table["ok"]; !ok {
		t.Fatalf("table = %v, want ok", table)
	}
}

func TestCompactionKeepsEveryRecord(t *testing.T) {
	dir := t.TempDir()
	var compactions atomic.Int32
	ws := journalWS(t, dir, workspaceOptions{
		journalSlack: 4,
		beforeMetaRename: func() error {
			compactions.Add(1)
			return nil
		},
	})
	if err := ws.Mkdir("d", 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range 6 {
		mustWriteFile(t, ws, fmt.Sprintf("d/f%d", i), 0o644)
	}
	if err := ws.Symlink("target", "link"); err != nil {
		t.Fatal(err)
	}
	mustSync(t, ws)
	path := filepath.Join(dir, MetaFileName)
	snapshot := fileSize(t, path)

	// Many small appends push the journal past its bound, so a later flush
	// compacts. Deletes and renames must survive that rewrite too.
	for i := range 20 {
		if err := ws.Chmod("d/f0", uint32(0o600+i%8)); err != nil {
			t.Fatal(err)
		}
		mustSync(t, ws)
	}
	if err := ws.Unlink("d/f1"); err != nil {
		t.Fatal(err)
	}
	if err := ws.Rename("d/f2", "d/renamed"); err != nil {
		t.Fatal(err)
	}
	if err := ws.Rename("d", "moved"); err != nil {
		t.Fatal(err)
	}
	mustSync(t, ws)

	if n := compactions.Load(); n < 2 {
		t.Fatalf("%d rewrites after 20 appends with slack 4, want a compaction after the first snapshot", n)
	}
	if got := fileSize(t, path); got > 3*snapshot {
		t.Fatalf("journal is %d bytes after compactions, want at most 3 times the %d-byte snapshot", got, snapshot)
	}
	requireSameTable(t, "table on disk", readMetaTable(t, path), metaSnapshot(ws))
	for _, gone := range []string{"d", "d/f1", "d/f2"} {
		if _, ok := readMetaTable(t, path)[gone]; ok {
			t.Errorf("record %s is on disk after it moved or died", gone)
		}
	}
	for _, kept := range []string{"moved", "moved/f0", "moved/renamed", "link"} {
		if _, ok := readMetaTable(t, path)[kept]; !ok {
			t.Errorf("record %s is missing from disk", kept)
		}
	}
}

func TestMutationsDuringACompactionAreNotLost(t *testing.T) {
	dir := t.TempDir()
	var ws *Workspace
	var snapshots, injected atomic.Int32
	opts := workspaceOptions{
		journalSlack: 1,
		beforeMetaRename: func() error {
			// The first compaction is the first flush. At the second, the
			// snapshot is complete and the rename has not happened: the guest
			// keeps writing.
			if snapshots.Add(1) != 2 {
				return nil
			}
			injected.Store(1)
			if err := ws.Chmod("a", 0o611); err != nil {
				return err
			}
			return ws.WriteFile("during", []byte("x"), 0o622)
		},
	}
	ws = journalWS(t, dir, opts)
	mustWriteFile(t, ws, "a", 0o644)
	mustSync(t, ws)
	for i := 0; injected.Load() == 0; i++ {
		if i > 20 {
			t.Fatal("no compaction ran after 20 appends with slack 1")
		}
		if err := ws.Chmod("a", uint32(0o640+i%8)); err != nil {
			t.Fatal(err)
		}
		mustSync(t, ws)
	}
	// The compaction rewrote the file from a snapshot that predates the
	// mutations of the hook. The next flush must carry them to disk.
	mustSync(t, ws)
	table := readMetaTable(t, filepath.Join(dir, MetaFileName))
	if got := table["during"].Mode & 0o7777; got != 0o622 {
		t.Fatalf("record created during the compaction has mode %o on disk, want 622", got)
	}
	if got := table["a"].Mode & 0o7777; got != 0o611 {
		t.Fatalf("record a changed during the compaction has mode %o on disk, want 611", got)
	}
}

func TestConcurrentMutationsAndCompactionsKeepTheTable(t *testing.T) {
	dir := t.TempDir()
	ws := journalWS(t, dir, workspaceOptions{journalSlack: 8})
	const writers, perWriter = 4, 40
	var wg sync.WaitGroup
	stop := make(chan struct{})
	syncDone := make(chan struct{})
	go func() {
		defer close(syncDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := ws.Sync(); err != nil {
				t.Errorf("Sync: %v", err)
				return
			}
		}
	}()
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perWriter {
				rel := fmt.Sprintf("w%d-%d", w, i)
				if err := ws.WriteFile(rel, []byte("x"), 0o644); err != nil {
					t.Errorf("WriteFile(%s): %v", rel, err)
					return
				}
				if i%3 == 0 {
					if err := ws.Chmod(rel, 0o600); err != nil {
						t.Errorf("Chmod(%s): %v", rel, err)
						return
					}
				}
				if i%5 == 0 {
					if err := ws.Unlink(rel); err != nil {
						t.Errorf("Unlink(%s): %v", rel, err)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	<-syncDone
	mustSync(t, ws)
	want := metaSnapshot(ws)
	requireSameTable(t, "table on disk", readMetaTable(t, filepath.Join(dir, MetaFileName)), want)
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWorkspace(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	requireSameTable(t, "table after reopen", metaSnapshot(reopened), want)
}

func TestReopenRestoresTheTableAfterRandomMutations(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	dir := resolvedTempDir(t)
	ws := journalWS(t, dir, workspaceOptions{journalSlack: 16})
	dirs := []string{"."}
	var files []string
	for step := range 400 {
		switch rng.IntN(8) {
		case 0:
			parent := dirs[rng.IntN(len(dirs))]
			name := joinRelPath(parent, fmt.Sprintf("d%d", step))
			if err := ws.Mkdir(name, 0o755); err != nil {
				t.Fatalf("Mkdir(%s): %v", name, err)
			}
			dirs = append(dirs, name)
		case 1, 2:
			parent := dirs[rng.IntN(len(dirs))]
			name := joinRelPath(parent, fmt.Sprintf("f%d", step))
			mustWriteFile(t, ws, name, 0o644)
			files = append(files, name)
		case 3:
			if len(files) > 0 {
				i := rng.IntN(len(files))
				if err := ws.Unlink(files[i]); err != nil {
					t.Fatalf("Unlink(%s): %v", files[i], err)
				}
				files = slices.Delete(files, i, i+1)
			}
		case 4:
			if len(files) > 0 {
				f := files[rng.IntN(len(files))]
				if err := ws.Chown(f, uint32(rng.IntN(100)), uint32(rng.IntN(100))); err != nil {
					t.Fatalf("Chown(%s): %v", f, err)
				}
			}
		case 5:
			parent := dirs[rng.IntN(len(dirs))]
			name := joinRelPath(parent, fmt.Sprintf("l%d", step))
			if err := ws.Symlink("t", name); err != nil {
				t.Fatalf("Symlink(%s): %v", name, err)
			}
		case 6:
			if len(files) > 0 {
				i := rng.IntN(len(files))
				to := joinRelPath(dirs[rng.IntN(len(dirs))], fmt.Sprintf("r%d", step))
				if err := ws.Rename(files[i], to); err != nil {
					t.Fatalf("Rename(%s, %s): %v", files[i], to, err)
				}
				files[i] = to
			}
		case 7:
			mustSync(t, ws)
		}
	}
	want := metaSnapshot(ws)
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWorkspace(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	requireSameTable(t, "table after reopen", metaSnapshot(reopened), want)
}

func TestRecordCapStillBoundsTheTable(t *testing.T) {
	dir := t.TempDir()
	ws := journalWS(t, dir, workspaceOptions{maxMeta: 3})
	for i := range 3 {
		mustWriteFile(t, ws, fmt.Sprintf("f%d", i), 0o644)
	}
	err := ws.WriteFile("f3", []byte("x"), 0o644)
	if !errors.Is(err, errMetaFull) {
		t.Fatalf("WriteFile beyond the cap = %v, want errMetaFull", err)
	}
}

func TestSnapshotKeepsDirectoryAndSymlinkRecords(t *testing.T) {
	dir := t.TempDir()
	ws := journalWS(t, dir, workspaceOptions{})
	if err := ws.Mkdir("d", 0o750); err != nil {
		t.Fatal(err)
	}
	if err := ws.Symlink("elsewhere", "s"); err != nil {
		t.Fatal(err)
	}
	mustSync(t, ws)
	table := readMetaTable(t, filepath.Join(dir, MetaFileName))
	if table["d"].Mode&linux.S_IFMT != linux.S_IFDIR || table["d"].Mode&0o7777 != 0o750 {
		t.Fatalf("record d = %+v, want a directory with mode 750", table["d"])
	}
	if table["s"].Symlink != "elsewhere" {
		t.Fatalf("record s = %+v, want the symlink target", table["s"])
	}
}
