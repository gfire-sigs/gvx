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
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var epoch2020 = time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)

func TestSettingTimesBeforeCreationKeepsTheLinksOfADirectory(t *testing.T) {
	// tar x, cp -a, and rsync -a set the times of a directory after they fill
	// it. APFS lowers the birth time then, and the links key on the directory.
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	if err := ws.Mkdir("d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ws.Symlink("tgt", "d/l"); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "d/f", 0o751)
	if err := ws.chtimes("d", &epoch2020, &epoch2020); err != nil {
		t.Fatal(err)
	}
	if target, err := ws.Readlink("d/l"); err != nil || target != "tgt" {
		t.Fatalf("Readlink(d/l) after chtimes = (%q, %v), want tgt", target, err)
	}
	mustSync(t, ws)
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := plainWS(t, dir, workspaceOptions{})
	if target, err := reopened.Readlink("d/l"); err != nil || target != "tgt" {
		t.Fatalf("Readlink(d/l) after reopen = (%q, %v), want tgt", target, err)
	}
	requireMode(t, reopened, "d", 0o755, 0)
	requireMode(t, reopened, "d/f", 0o751, 0)
}

func TestSettingTimesBeforeCreationThenRenamingAnAncestorKeepsTheFileRecord(t *testing.T) {
	// A package manager extracts to a staging directory, sets the times, and
	// renames the directory.
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	if err := ws.Mkdir("stage", 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "stage/f", 0o755)
	if err := ws.Chown("stage/f", 1234, 5); err != nil {
		t.Fatal(err)
	}
	if err := ws.chtimes("stage/f", &epoch2020, &epoch2020); err != nil {
		t.Fatal(err)
	}
	if err := ws.chtimes("stage", &epoch2020, &epoch2020); err != nil {
		t.Fatal(err)
	}
	if err := ws.Rename("stage", "pkg"); err != nil {
		t.Fatal(err)
	}
	requireMode(t, ws, "pkg/f", 0o755, 1234)
	mustSync(t, ws)
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	requireMode(t, plainWS(t, dir, workspaceOptions{}), "pkg/f", 0o755, 1234)
}

func TestHostLoweredBirthTimeOfADirectoryKeepsItsLinks(t *testing.T) {
	dir := resolvedTempDir(t)
	ws, host := identityWS(t, dir)
	if err := ws.Mkdir("d", 0o750); err != nil {
		t.Fatal(err)
	}
	if err := ws.Symlink("tgt", "d/l"); err != nil {
		t.Fatal(err)
	}
	before, err := ws.host.lstat("d")
	if err != nil {
		t.Fatal(err)
	}
	// A host tool sets an earlier time on the directory: same inode number,
	// earlier birth time.
	host.set(func(info hostInfo) hostInfo {
		if info.fid.ino == before.fid.ino && info.kind == hostKindDir {
			info.fid.btime -= int64(time.Hour)
		}
		return info
	})
	requireMode(t, ws, "d", 0o750, 0)
	if target, err := ws.Readlink("d/l"); err != nil || target != "tgt" {
		t.Fatalf("Readlink(d/l) after the host lowered the birth time = (%q, %v), want tgt", target, err)
	}
}

func TestHostMoveToAnotherDirectoryKeepsTheRecordAtTheNewPath(t *testing.T) {
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	for _, d := range []string{"a", "b"} {
		if err := ws.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWriteFile(t, ws, "a/x", 0o751)
	if err := os.Rename(filepath.Join(dir, "a", "x"), filepath.Join(dir, "b", "x")); err != nil {
		t.Fatal(err)
	}
	requireMode(t, ws, "b/x", 0o751, 0)
}

func TestHostFileAtAnOldNameNeverGainsSetuid(t *testing.T) {
	for name, replace := range map[string]func(t *testing.T, dir string){
		"delete and create": func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "x")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "x"), []byte("new"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"save by rename": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "x.tmp"), []byte("new"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(dir, "x.tmp"), filepath.Join(dir, "x")); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := resolvedTempDir(t)
			ws := plainWS(t, dir, workspaceOptions{})
			mustWriteFile(t, ws, "x", 0o4755)
			if err := ws.Chown("x", 1234, 0); err != nil {
				t.Fatal(err)
			}
			replace(t, dir)
			attr, _, err := ws.Stat("x")
			if err != nil || attr.Mode&0o6000 != 0 {
				t.Fatalf("Stat(x) = (%+v, %v), want no set-user-ID and no set-group-ID bit on a file that a host process wrote", attr, err)
			}
		})
	}
}

func TestSameNameInAnotherDirectoryNeverAdoptsTheRecord(t *testing.T) {
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	for _, d := range []string{"a", "b"} {
		if err := ws.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWriteFile(t, ws, "a/x", 0o751)
	if err := os.Remove(filepath.Join(dir, "a", "x")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b", "x"), []byte("n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if attr, _, err := ws.Stat("b/x"); err != nil || attr.Mode&0o7777 == 0o751 {
		t.Fatalf("Stat(b/x) = (%+v, %v): a file in another directory adopted the record of a/x", attr, err)
	}
}

func TestDirectoryRenameDoesNotBreakAdoptionBelowIt(t *testing.T) {
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	if err := ws.Mkdir("d", 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "d/doc", 0o751)
	if err := ws.Rename("d", "e"); err != nil {
		t.Fatal(err)
	}
	// The editor saves into the renamed directory.
	if err := os.WriteFile(filepath.Join(dir, "e", "doc.tmp"), []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "e", "doc.tmp"), filepath.Join(dir, "e", "doc")); err != nil {
		t.Fatal(err)
	}
	requireMode(t, ws, "e/doc", 0o751, 0)
}

func TestCreateFailsForAnEntryWithoutAnIdentity(t *testing.T) {
	dir := resolvedTempDir(t)
	ws, host := identityWS(t, dir)
	host.set(func(info hostInfo) hostInfo {
		info.fidOK = false
		return info
	})
	if err := ws.WriteFile("f", []byte("x"), 0o644); !errors.Is(err, errMissingIdentity) {
		t.Fatalf("WriteFile on a file system without identities = %v, want errMissingIdentity", err)
	}
	if err := ws.Mkdir("d", 0o755); !errors.Is(err, errMissingIdentity) {
		t.Fatalf("Mkdir on a file system without identities = %v, want errMissingIdentity", err)
	}
	for _, name := range []string{"f", "d"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("host entry %s survived a refused create: %v", name, err)
		}
	}
	if n := ws.meta.size(); n != 0 {
		t.Fatalf("the table holds %d records after refused creates, want 0", n)
	}
}
