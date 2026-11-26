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
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func assertNoMetaFilesInDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	for _, e := range entries {
		if isReservedPath(e.Name()) {
			t.Errorf("unexpected metadata file %q found in %q", e.Name(), dir)
		}
	}
}

func isCaseInsensitiveDir(t *testing.T, dir string) bool {
	t.Helper()
	probe := filepath.Join(dir, "caseProbe")
	if err := os.WriteFile(probe, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(probe)
	fi1, err1 := os.Stat(probe)
	fi2, err2 := os.Stat(filepath.Join(dir, "CASEPROBE"))
	return err1 == nil && err2 == nil && os.SameFile(fi1, fi2)
}

func TestExternalMetaDirKeepsWorkspaceCleanAndPersistsMetadata(t *testing.T) {
	wsDir := t.TempDir()
	metaDir := t.TempDir()

	ws, err := OpenWorkspaceWithOptions(wsDir, OpenOptions{MetaDir: metaDir})
	if err != nil {
		t.Fatalf("OpenWorkspaceWithOptions: %v", err)
	}
	if ws.MetaDir() == "" {
		t.Fatal("MetaDir() = empty, want resolved external directory")
	}
	e := mountEnv(t, ws, wsDir)
	e.writeFile("script.sh", []byte("#!/bin/sh\necho hi\n"))
	e.chmod("script.sh", 0o751)
	if err := ws.Chown("script.sh", 1001, 2002); err != nil {
		t.Fatalf("Chown: %v", err)
	}
	if err := e.symlink("link.sh", "script.sh"); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := ws.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	e.root.DecRef(e.ctx)
	if err := ws.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	assertNoMetaFilesInDir(t, wsDir)
	for _, name := range []string{MetaFileName, MetaLockFileName} {
		if _, err := os.Stat(filepath.Join(metaDir, name)); err != nil {
			t.Errorf("expected %s in MetaDir %q: %v", name, metaDir, err)
		}
	}

	// ReadMetaAt resolves identity-keyed records against wsDir.
	recs, err := ReadMetaAt(filepath.Join(metaDir, MetaFileName), wsDir)
	if err != nil {
		t.Fatalf("ReadMetaAt: %v", err)
	}
	attr, ok := recs["script.sh"]
	if !ok {
		t.Fatalf("ReadMetaAt missing script.sh: %+v", recs)
	}
	if attr.Mode&0o777 != 0o751 || attr.UID != 1001 || attr.GID != 2002 {
		t.Errorf("script.sh attr = %+v, want mode 0751 uid 1001 gid 2002", attr)
	}
	linkAttr, ok := recs["link.sh"]
	if !ok || linkAttr.Symlink != "script.sh" {
		t.Errorf("link.sh attr = %+v (ok=%v), want symlink target %q", linkAttr, ok, "script.sh")
	}

	// Reopen with the same MetaDir and verify persisted POSIX metadata.
	ws2, err := OpenWorkspaceWithOptions(wsDir, OpenOptions{MetaDir: metaDir})
	if err != nil {
		t.Fatalf("reopen OpenWorkspaceWithOptions: %v", err)
	}
	e2 := mountEnv(t, ws2, wsDir)
	t.Cleanup(func() {
		e2.root.DecRef(e2.ctx)
		if err := ws2.Close(); err != nil {
			t.Errorf("ws2.Close: %v", err)
		}
	})
	st, err := e2.stat("script.sh")
	if err != nil {
		t.Fatalf("stat script.sh: %v", err)
	}
	if st.Mode&0o777 != 0o751 || st.UID != 1001 || st.GID != 2002 {
		t.Errorf("reopened script.sh stat = mode %#o uid %d gid %d, want 0751 1001 2002", st.Mode&0o777, st.UID, st.GID)
	}
	target, err := e2.readlink("link.sh")
	if err != nil || target != "script.sh" {
		t.Errorf("reopened readlink(link.sh) = %q, %v; want %q", target, err, "script.sh")
	}
	assertNoMetaFilesInDir(t, wsDir)
}

func TestExternalMetaDirAllowsLiteralMetaFilesInWorkspace(t *testing.T) {
	wsDir := t.TempDir()
	metaDir := t.TempDir()

	ws, err := OpenWorkspaceWithOptions(wsDir, OpenOptions{MetaDir: metaDir})
	if err != nil {
		t.Fatalf("OpenWorkspaceWithOptions: %v", err)
	}
	e := mountEnv(t, ws, wsDir)
	t.Cleanup(func() {
		e.root.DecRef(e.ctx)
		if err := ws.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	payload := []byte("ordinary workspace file\n")
	e.writeFile(MetaFileName, payload)
	e.chmod(MetaFileName, 0o640)
	if err := ws.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	got := e.readFile(MetaFileName)
	if !bytes.Equal(got, payload) {
		t.Fatalf("read %s = %q, want %q", MetaFileName, got, payload)
	}
	st, err := e.stat(MetaFileName)
	if err != nil {
		t.Fatalf("stat %s: %v", MetaFileName, err)
	}
	if st.Mode&0o777 != 0o640 {
		t.Errorf("mode of workspace %s = %#o, want 0640", MetaFileName, st.Mode&0o777)
	}
	entries := e.readdir(".")
	found := false
	for _, name := range entries {
		if name == MetaFileName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("readdir(.) = %v, want %q visible with external MetaDir", entries, MetaFileName)
	}

	recs, err := ReadMetaAt(filepath.Join(metaDir, MetaFileName), wsDir)
	if err != nil {
		t.Fatalf("ReadMetaAt: %v", err)
	}
	if attr, ok := recs[MetaFileName]; !ok || attr.Mode&0o777 != 0o640 {
		t.Errorf("ReadMetaAt[%q] = %+v (ok=%v), want mode 0640", MetaFileName, attr, ok)
	}
}

func TestExternalMetaDirCompactsAndSweepsOnlyInMetaDir(t *testing.T) {
	wsDir := t.TempDir()
	metaDir := t.TempDir()

	// Seed a real torn journal tail in MetaDir so loadMeta sets hadFault and
	// compact without touching private Workspace fields.
	tornJournal := append([]byte(journalMagic), journalVersion, 0xff, 0xff)
	if err := os.WriteFile(filepath.Join(metaDir, MetaFileName), tornJournal, 0o600); err != nil {
		t.Fatalf("seed torn journal: %v", err)
	}
	staleTemp := filepath.Join(metaDir, ".gvx_meta.tmp.deadbeef")
	staleProbe := filepath.Join(metaDir, "~gvx~tmp.probe.deadbeef")
	wsSentinel := filepath.Join(wsDir, "~gvx~tmp.live.sentinel")
	for _, p := range []string{staleTemp, staleProbe, wsSentinel} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("seed %q: %v", p, err)
		}
	}

	ws, err := OpenWorkspaceWithOptions(wsDir, OpenOptions{MetaDir: metaDir, RestoreMode: true})
	if err != nil {
		t.Fatalf("OpenWorkspaceWithOptions: %v", err)
	}
	e := mountEnv(t, ws, wsDir)
	t.Cleanup(func() {
		e.root.DecRef(e.ctx)
		if err := ws.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	e.writeFile("a.txt", []byte("one"))
	e.chmod("a.txt", 0o700)
	if err := ws.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	assertNoMetaFilesInDir(t, wsDir)
	if _, err := os.Stat(staleTemp); !os.IsNotExist(err) {
		t.Errorf("stale meta temp %q still exists (err=%v)", staleTemp, err)
	}
	if _, err := os.Stat(staleProbe); !os.IsNotExist(err) {
		t.Errorf("stale probe temp %q still exists (err=%v)", staleProbe, err)
	}
	if _, err := os.Stat(wsSentinel); err != nil {
		t.Errorf("workspace ephemeral sentinel %q was unexpectedly deleted: %v", wsSentinel, err)
	}
}

func TestInWorkspaceCompactionSweepPreservesLiveEphemeralFiles(t *testing.T) {
	wsDir := t.TempDir()

	// Seed a real torn journal tail in the default in-workspace mode alongside
	// a stale meta temp and a live unlinked ephemeral backing file.
	tornJournal := append([]byte(journalMagic), journalVersion, 0xff, 0xff)
	if err := os.WriteFile(filepath.Join(wsDir, MetaFileName), tornJournal, 0o600); err != nil {
		t.Fatalf("seed torn journal: %v", err)
	}
	staleTemp := filepath.Join(wsDir, ".gvx_meta.tmp.deadbeef")
	liveEphemeral := filepath.Join(wsDir, "~gvx~tmp.live.unlinked")
	for _, p := range []string{staleTemp, liveEphemeral} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("seed %q: %v", p, err)
		}
	}

	ws, err := OpenWorkspaceWithOptions(wsDir, OpenOptions{RestoreMode: true})
	if err != nil {
		t.Fatalf("OpenWorkspaceWithOptions: %v", err)
	}
	e := mountEnv(t, ws, wsDir)
	t.Cleanup(func() {
		e.root.DecRef(e.ctx)
		if err := ws.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	e.writeFile("b.txt", []byte("two"))
	e.chmod("b.txt", 0o700)
	if err := ws.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if _, err := os.Stat(staleTemp); !os.IsNotExist(err) {
		t.Errorf("stale meta temp %q still exists (err=%v)", staleTemp, err)
	}
	if _, err := os.Stat(liveEphemeral); err != nil {
		t.Errorf("live workspace ephemeral file %q was deleted during compaction sweep: %v", liveEphemeral, err)
	}
}

func TestExternalMetaDirMultiWorkspaceSyncAndReadOnly(t *testing.T) {
	wsDir := t.TempDir()
	metaDir := t.TempDir()

	// Open RO BEFORE any writer creates .gvx_meta.lock to exercise
	// tryOpenMetaLockReadOnlyLocked once a writable peer joins.
	ro, err := OpenWorkspaceWithOptions(wsDir, OpenOptions{ReadOnly: true, MetaDir: metaDir})
	if err != nil {
		t.Fatalf("ro OpenWorkspaceWithOptions: %v", err)
	}
	if entries, err := os.ReadDir(metaDir); err != nil || len(entries) != 0 {
		_ = ro.Close()
		t.Fatalf("read-only open created files in empty MetaDir: %v (err=%v)", entries, err)
	}

	rw1, err := OpenWorkspaceWithOptions(wsDir, OpenOptions{MetaDir: metaDir})
	if err != nil {
		_ = ro.Close()
		t.Fatalf("rw1 OpenWorkspaceWithOptions: %v", err)
	}
	rw2, err := OpenWorkspaceWithOptions(wsDir, OpenOptions{MetaDir: metaDir})
	if err != nil {
		_ = rw1.Close()
		_ = ro.Close()
		t.Fatalf("rw2 OpenWorkspaceWithOptions: %v", err)
	}
	eRO := mountEnv(t, ro, wsDir)
	eRW1 := mountEnv(t, rw1, wsDir)
	eRW2 := mountEnv(t, rw2, wsDir)
	t.Cleanup(func() {
		eRW2.root.DecRef(eRW2.ctx)
		_ = rw2.Close()
		eRW1.root.DecRef(eRW1.ctx)
		_ = rw1.Close()
		eRO.root.DecRef(eRO.ctx)
		_ = ro.Close()
	})

	eRW1.writeFile("shared.txt", []byte("hello"))
	eRW1.chmod("shared.txt", 0o750)
	if err := rw1.Sync(); err != nil {
		t.Fatalf("rw1.Sync: %v", err)
	}

	// Both RO (which opened before .gvx_meta.lock existed) and RW2 observe RW1's commit.
	stRO, err := eRO.stat("shared.txt")
	if err != nil {
		t.Fatalf("ro stat: %v", err)
	}
	if stRO.Mode&0o777 != 0o750 {
		t.Errorf("ro observed mode %#o, want 0750 synced via external MetaDir lock", stRO.Mode&0o777)
	}
	stRW2, err := eRW2.stat("shared.txt")
	if err != nil {
		t.Fatalf("rw2 stat: %v", err)
	}
	if stRW2.Mode&0o777 != 0o750 {
		t.Errorf("rw2 observed mode %#o, want 0750", stRW2.Mode&0o777)
	}

	// RW2 writes a second file and syncs; RW1 observes it without losing shared.txt.
	eRW2.writeFile("peer.txt", []byte("world"))
	eRW2.chmod("peer.txt", 0o711)
	if err := rw2.Sync(); err != nil {
		t.Fatalf("rw2.Sync: %v", err)
	}
	stRW1, err := eRW1.stat("peer.txt")
	if err != nil {
		t.Fatalf("rw1 stat(peer.txt): %v", err)
	}
	if stRW1.Mode&0o777 != 0o711 {
		t.Errorf("rw1 observed peer.txt mode %#o, want 0711", stRW1.Mode&0o777)
	}
	assertNoMetaFilesInDir(t, wsDir)
}

func TestExternalMetaDirWithWrapHostDoesNotCorruptWorkspace(t *testing.T) {
	wsDir := t.TempDir()
	metaDir := t.TempDir()

	// Mimic single-instance wrapHost closures used across hostfs tests.
	type singleWrapper struct {
		hostBackend
		calls int
	}
	wrapper := &singleWrapper{}
	ws, err := openWorkspace(wsDir, false, workspaceOptions{
		metaDir: metaDir,
		wrapHost: func(b hostBackend) hostBackend {
			wrapper.calls++
			wrapper.hostBackend = b
			return wrapper
		},
	})
	if err != nil {
		t.Fatalf("openWorkspace: %v", err)
	}
	if wrapper.calls != 1 {
		_ = ws.Close()
		t.Fatalf("wrapHost called %d times, want 1", wrapper.calls)
	}
	if err := ws.WriteFile("hello.txt", []byte("data"), 0o644); err != nil {
		_ = ws.Close()
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ws.Sync(); err != nil {
		_ = ws.Close()
		t.Fatalf("Sync: %v", err)
	}
	if err := ws.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(filepath.Join(wsDir, "hello.txt")); err != nil {
		t.Errorf("workspace missing hello.txt: %v", err)
	}
	if _, err := os.Stat(filepath.Join(metaDir, MetaFileName)); err != nil {
		t.Errorf("metaDir missing %s: %v", MetaFileName, err)
	}
	assertNoMetaFilesInDir(t, wsDir)
}

func TestExternalMetaDirSameDirectoryNormalizesToDefault(t *testing.T) {
	wsDir := t.TempDir()
	ws, err := OpenWorkspaceWithOptions(wsDir, OpenOptions{MetaDir: wsDir})
	if err != nil {
		t.Fatalf("OpenWorkspaceWithOptions(same dir): %v", err)
	}
	defer ws.Close()
	if ws.MetaDir() != "" {
		t.Errorf("MetaDir() = %q, want empty when MetaDir equals workspace root", ws.MetaDir())
	}
	f, err := ws.OpenFile(MetaFileName, os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		_ = f.Close()
		t.Fatalf("OpenFile(%q) succeeded, want errReservedName", MetaFileName)
	}
	if !errors.Is(err, errReservedName) {
		t.Errorf("OpenFile(%q) err = %v, want errReservedName", MetaFileName, err)
	}
}

func TestExternalMetaDirValidationRejectsUnsafePaths(t *testing.T) {
	parent := t.TempDir()
	wsDir := filepath.Join(parent, "ws")
	childMeta := filepath.Join(wsDir, "meta")
	if err := os.MkdirAll(childMeta, 0o755); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(parent, "file.txt")
	if err := os.WriteFile(filePath, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	otherMeta := t.TempDir()

	fsRoot := string(filepath.Separator)
	if runtime.GOOS == "windows" {
		fsRoot = filepath.VolumeName(parent) + `\`
	}

	cases := []struct {
		name    string
		host    string
		metaDir string
		wantSub string
	}{
		{"single file with MetaDir", filePath, otherMeta, "single-file"},
		{"missing MetaDir", wsDir, filepath.Join(parent, "missing"), "MetaDir"},
		{"file as MetaDir", wsDir, filePath, "directory"},
		{"filesystem root MetaDir", wsDir, fsRoot, "root"},
		{"MetaDir inside workspace", wsDir, childMeta, "inside"},
		{"MetaDir ancestor of workspace", wsDir, parent, "ancestor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ws, err := OpenWorkspaceWithOptions(tc.host, OpenOptions{MetaDir: tc.metaDir})
			if err == nil {
				_ = ws.Close()
				t.Fatalf("OpenWorkspaceWithOptions(%q, MetaDir=%q) succeeded, want error", tc.host, tc.metaDir)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %q, want substring %q", err, tc.wantSub)
			}
		})
	}

	if runtime.GOOS != "windows" {
		linkDir := t.TempDir()
		linkChild := filepath.Join(linkDir, "link-to-child")
		linkAncestor := filepath.Join(linkDir, "link-to-ancestor")
		linkRoot := filepath.Join(linkDir, "link-to-root")
		for _, pair := range [][2]string{
			{childMeta, linkChild},
			{parent, linkAncestor},
			{fsRoot, linkRoot},
		} {
			if err := os.Symlink(pair[0], pair[1]); err != nil {
				t.Fatal(err)
			}
		}
		for name, link := range map[string]string{
			"symlinked child":    linkChild,
			"symlinked ancestor": linkAncestor,
			"symlinked root":     linkRoot,
		} {
			t.Run(name, func(t *testing.T) {
				ws, err := OpenWorkspaceWithOptions(wsDir, OpenOptions{MetaDir: link})
				if err == nil {
					_ = ws.Close()
					t.Fatalf("%s MetaDir succeeded, want error", name)
				}
			})
		}
	}

	// Verify case-variant paths on case-insensitive volumes (macOS APFS, Windows).
	if isCaseInsensitiveDir(t, parent) {
		wsUpper := filepath.Join(parent, "WS")
		childViaUpper := filepath.Join(wsUpper, "meta")
		t.Run("case-variant child", func(t *testing.T) {
			ws, err := OpenWorkspaceWithOptions(wsDir, OpenOptions{MetaDir: childViaUpper})
			if err == nil {
				_ = ws.Close()
				t.Fatal("case-variant descendant MetaDir succeeded, want error")
			}
		})
		t.Run("case-variant ancestor", func(t *testing.T) {
			ws, err := OpenWorkspaceWithOptions(childMeta, OpenOptions{MetaDir: wsUpper})
			if err == nil {
				_ = ws.Close()
				t.Fatal("case-variant ancestor MetaDir succeeded, want error")
			}
		})
		t.Run("case-variant same dir normalizes", func(t *testing.T) {
			ws, err := OpenWorkspaceWithOptions(wsDir, OpenOptions{MetaDir: wsUpper})
			if err != nil {
				t.Fatalf("case-variant same dir failed: %v", err)
			}
			defer ws.Close()
			if ws.MetaDir() != "" {
				t.Errorf("MetaDir() = %q, want empty for case-variant same dir", ws.MetaDir())
			}
		})
	}
}
