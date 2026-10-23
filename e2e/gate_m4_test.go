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

//go:build darwin || windows || linux

package e2e

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/lockdownprobe"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/hostfs"
)

// M4 gate of SPEC section 4: POSIX rename and unlink torture on /workspace,
// the .gvx_meta table, and the host lockdown.

const (
	gitImage  = "alpine/git:latest"
	nodeImage = "node:22-alpine"
)

// wsEntry is the guest-visible state of one workspace path as hostfs reports
// it after the guest stopped.
type wsEntry struct {
	// Kind is "dir", "file", or "symlink".
	Kind string
	// Perm holds the permission bits.
	Perm uint32
	UID  uint32
	GID  uint32
	// Content is the file body or the symlink target.
	Content string
}

func (e wsEntry) String() string {
	return fmt.Sprintf("%s %04o %d:%d %q", e.Kind, e.Perm, e.UID, e.GID, e.Content)
}

func dirEntry(perm uint32) wsEntry { return wsEntry{Kind: "dir", Perm: perm} }

func fileEntry(perm uint32, content string) wsEntry {
	return wsEntry{Kind: "file", Perm: perm, Content: content}
}

func linkEntry(target string) wsEntry {
	return wsEntry{Kind: "symlink", Perm: 0o777, Content: target}
}

// snapshotWorkspace reopens the workspace through hostfs in read-only mode and
// returns every entry. A fresh open reads .gvx_meta from disk, so the result
// shows what a later sandbox would see.
func snapshotWorkspace(t *testing.T, dir string) map[string]wsEntry {
	t.Helper()
	ws, err := hostfs.OpenWorkspace(dir, true)
	if err != nil {
		t.Fatalf("reopen workspace %s: %v", dir, err)
	}
	defer func() {
		if err := ws.Close(); err != nil {
			t.Errorf("close reopened workspace: %v", err)
		}
	}()
	names, err := ws.ListEntries()
	if err != nil {
		t.Fatalf("list reopened workspace: %v", err)
	}
	out := make(map[string]wsEntry, len(names))
	for _, name := range names {
		attr, _, err := ws.Stat(name)
		if err != nil {
			t.Fatalf("stat %s in reopened workspace: %v", name, err)
		}
		e := wsEntry{Perm: attr.Mode & 0o7777, UID: attr.UID, GID: attr.GID}
		switch attr.Mode & linux.S_IFMT {
		case linux.S_IFDIR:
			e.Kind = "dir"
		case linux.S_IFLNK:
			e.Kind = "symlink"
			if e.Content, err = ws.Readlink(name); err != nil {
				t.Fatalf("readlink %s in reopened workspace: %v", name, err)
			}
		case linux.S_IFREG:
			e.Kind = "file"
			data, err := ws.ReadFile(name)
			if err != nil {
				t.Fatalf("read %s in reopened workspace: %v", name, err)
			}
			e.Content = string(data)
		default:
			t.Fatalf("%s has unexpected mode %o", name, attr.Mode)
		}
		out[name] = e
	}
	return out
}

// requireEntries compares the entries below prefix with want. An empty prefix
// compares the whole workspace.
func requireEntries(t *testing.T, got map[string]wsEntry, prefix string, want map[string]wsEntry) {
	t.Helper()
	inScope := func(name string) bool {
		return prefix == "" || name == prefix || strings.HasPrefix(name, prefix+"/")
	}
	var problems []string
	for name, w := range want {
		g, ok := got[name]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("missing %s, want %s", name, w))
		case g != w:
			problems = append(problems, fmt.Sprintf("%s = %s, want %s", name, g, w))
		}
	}
	for name, g := range got {
		if _, ok := want[name]; !ok && inScope(name) {
			problems = append(problems, fmt.Sprintf("unexpected %s = %s", name, g))
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Errorf("workspace entries differ:\n  %s", strings.Join(problems, "\n  "))
	}
}

// metaTable is the on-disk form of .gvx_meta.
type metaTable struct {
	Version int                         `json:"version"`
	Entries map[string]hostfs.POSIXAttr `json:"entries"`
}

// readMetaTable parses the .gvx_meta file of dir. A torn write fails the parse.
func readMetaTable(t *testing.T, dir string) metaTable {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, hostfs.MetaFileName))
	if err != nil {
		t.Fatalf("read %s: %v", hostfs.MetaFileName, err)
	}
	var table metaTable
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatalf("%s is not a complete JSON table (%d bytes): %v", hostfs.MetaFileName, len(raw), err)
	}
	if table.Version != 1 {
		t.Fatalf("%s version = %d, want 1", hostfs.MetaFileName, table.Version)
	}
	return table
}

// requireMetaConsistent compares .gvx_meta with the host tree below prefix
// (the whole workspace for an empty prefix). Every host file and directory has
// a record of the matching type, every record has a host path unless it is a
// virtual symlink, and every record has a recorded parent directory.
func requireMetaConsistent(t *testing.T, dir, prefix string) {
	t.Helper()
	table := readMetaTable(t, dir)
	inScope := func(name string) bool {
		return prefix == "" || name == prefix || strings.HasPrefix(name, prefix+"/")
	}
	var problems []string
	for name, attr := range table.Entries {
		if !inScope(name) {
			continue
		}
		if parent := filepath.ToSlash(filepath.Dir(name)); parent != "." {
			if p, ok := table.Entries[parent]; !ok || p.Mode&linux.S_IFMT != linux.S_IFDIR {
				problems = append(problems, fmt.Sprintf("record %s has no directory record for its parent %s", name, parent))
			}
		}
		info, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(name)))
		switch attr.Mode & linux.S_IFMT {
		case linux.S_IFLNK:
			if attr.Symlink == "" {
				problems = append(problems, fmt.Sprintf("symlink record %s has no target", name))
			}
		case linux.S_IFDIR:
			if err != nil || !info.IsDir() {
				problems = append(problems, fmt.Sprintf("directory record %s has no host directory (%v)", name, err))
			}
		case linux.S_IFREG:
			if err != nil || !info.Mode().IsRegular() {
				problems = append(problems, fmt.Sprintf("file record %s has no host file (%v)", name, err))
			}
		default:
			problems = append(problems, fmt.Sprintf("record %s has unexpected mode %o", name, attr.Mode))
		}
	}
	walkRoot := dir
	if prefix != "" {
		walkRoot = filepath.Join(dir, filepath.FromSlash(prefix))
	}
	err := filepath.WalkDir(walkRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." || strings.HasPrefix(rel, hostfs.MetaFileName) {
			return nil
		}
		if _, ok := table.Entries[rel]; !ok {
			problems = append(problems, fmt.Sprintf("host path %s has no %s record", rel, hostfs.MetaFileName))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", walkRoot, err)
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Errorf("%s is inconsistent with the host tree (%d problems):\n  %s", hostfs.MetaFileName, len(problems), strings.Join(firstN(problems, 20), "\n  "))
	}
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// hostCaseInsensitive reports whether the volume of dir resolves names
// without regard to case, as default APFS and NTFS volumes do.
func hostCaseInsensitive(t *testing.T, dir string) bool {
	t.Helper()
	probe := filepath.Join(dir, "CaseProbe.tmp")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Fatalf("create case probe: %v", err)
	}
	_, err := os.Lstat(filepath.Join(dir, "caseprobe.tmp"))
	if rmErr := os.Remove(probe); rmErr != nil {
		t.Fatalf("remove case probe: %v", rmErr)
	}
	return err == nil
}

// requireGuestMarkers fails the test unless the guest stopped with 0 after it
// printed every marker.
func requireGuestMarkers(t *testing.T, code int, stdout, stderr string, markers ...string) {
	t.Helper()
	if code != 0 {
		t.Fatalf("guest exit code = %d, want 0\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}
	for _, m := range markers {
		if !strings.Contains(stdout, m+"\n") {
			t.Fatalf("guest stdout lacks %q\nstdout=%s\nstderr=%s", m, stdout, stderr)
		}
	}
}

// posixTortureWant lists the workspace that posixTortureScript leaves behind.
func posixTortureWant(caseInsensitive bool) map[string]wsEntry {
	want := map[string]wsEntry{
		"f":              fileEntry(0o644, "new\n"),
		"r":              fileEntry(0o644, "v2\n"),
		"target":         fileEntry(0o644, "gen200\n"),
		"l2":             fileEntry(0o644, "linked\n"),
		"perm":           {Kind: "file", Perm: 0o640, UID: 1234, GID: 5678, Content: "x\n"},
		"d3":             dirEntry(0o755),
		"d3/k":           fileEntry(0o644, "inside\n"),
		"real":           dirEntry(0o755),
		"real/file":      fileEntry(0o644, "via-link\n"),
		"dirlink2":       linkEntry("real"),
		"dangling":       linkEntry("missing"),
		"cs":             dirEntry(0o755),
		"cs/Renamed.txt": fileEntry(0o644, "upper\n"),
		"cs/casey.txt":   fileEntry(0o644, "x\n"),
	}
	if !caseInsensitive {
		want["cs/file.txt"] = fileEntry(0o644, "lower\n")
		want["cs/FILE.TXT"] = fileEntry(0o644, "shout\n")
	}
	return want
}

func tortureScript(caseInsensitive bool) string {
	flag := "0"
	if caseInsensitive {
		flag = "1"
	}
	openDirRename := "1"
	if runtime.GOOS == "windows" {
		// NTFS refuses to rename a directory that has an open descendant.
		openDirRename = "0"
	}
	return "CASE_INSENSITIVE=" + flag + "\nOPEN_DIR_RENAME=" + openDirRename + "\n" + posixTortureScript
}

var posixTortureMarkers = []string{"T1-OK", "T2-OK", "T3-OK", "T4-OK", "T5-OK", "T6-OK", "T7-OK", "T8-OK", "T9-OK", "T10-OK", "ALL-OK"}

func TestE2EGateM4PosixTortureBusybox(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			workspace := t.TempDir()
			caseInsensitive := hostCaseInsensitive(t, workspace)
			code, stdout, stderr := runGuest(t, guestSpec{
				plat:      b.plat,
				image:     busyboxImage,
				argv:      []string{"sh", "-c", tortureScript(caseInsensitive)},
				workspace: workspace,
			})
			requireGuestMarkers(t, code, stdout, stderr, posixTortureMarkers...)

			requireEntries(t, snapshotWorkspace(t, workspace), "", posixTortureWant(caseInsensitive))
			requireMetaConsistent(t, workspace, "")
			// The host holds the exact-case names that the guest chose.
			names := hostDirNames(t, filepath.Join(workspace, "cs"))
			wantNames := []string{"Renamed.txt", "casey.txt"}
			if !caseInsensitive {
				wantNames = []string{"FILE.TXT", "Renamed.txt", "casey.txt", "file.txt"}
			}
			if strings.Join(names, ",") != strings.Join(wantNames, ",") {
				t.Errorf("host listing of cs = %v, want %v", names, wantNames)
			}
			for name, want := range map[string]string{"f": "new\n", "target": "gen200\n", "d3/k": "inside\n"} {
				got, err := os.ReadFile(filepath.Join(workspace, filepath.FromSlash(name)))
				if err != nil || string(got) != want {
					t.Errorf("host file %s = (%q, %v), want %q", name, got, err, want)
				}
			}
		})
	}
}

// hostDirNames returns the sorted entry names of dir as the host stores them.
func hostDirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read host directory %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func TestE2EGateM4GitWorkloads(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			workspace := t.TempDir()
			code, stdout, stderr := runGuest(t, guestSpec{
				plat:      b.plat,
				image:     gitImage,
				argv:      []string{"sh", "-c", gitScript},
				workspace: workspace,
				timeout:   10 * time.Minute,
			})
			requireGuestMarkers(t, code, stdout, stderr, "REBASE-OK", "BULK-OK", "GC-OK", "ALL-OK")

			repo := filepath.Join(workspace, "repo")
			head, err := os.ReadFile(filepath.Join(repo, ".git", "HEAD"))
			if err != nil || string(head) != "ref: refs/heads/feature\n" {
				t.Errorf("host .git/HEAD = (%q, %v), want the feature branch", head, err)
			}
			packs, err := filepath.Glob(filepath.Join(repo, ".git", "objects", "pack", "*.pack"))
			if err != nil || len(packs) == 0 {
				t.Errorf("host pack files = (%v, %v), want at least one after git gc", packs, err)
			}
			requireBulkTree(t, filepath.Join(repo, "tree"), 2100)

			entries := snapshotWorkspace(t, workspace)
			for name, want := range map[string]wsEntry{
				"repo/a.txt":  fileEntry(0o644, "one\n"),
				"repo/b.txt":  fileEntry(0o644, "two\n"),
				"repo/f.txt":  fileEntry(0o644, "feat\nfeat2\n"),
				"repo/run.sh": fileEntry(0o755, "#!/bin/sh\necho hi\n"),
				"repo/link":   linkEntry("a.txt"),
			} {
				if got := entries[name]; got != want {
					t.Errorf("%s = %s, want %s", name, got, want)
				}
			}
			requireMetaConsistent(t, workspace, "")

			// A fresh sandbox on the same workspace sees an intact repository.
			out := mustRunGuest(t, guestSpec{
				plat:      b.plat,
				image:     gitImage,
				workspace: workspace,
				argv: []string{"sh", "-c", `set -eu
cd /workspace/repo
git fsck --full >/dev/null 2>&1
echo "branch=$(git rev-parse --abbrev-ref HEAD)"
echo "commits=$(git rev-list --count HEAD)"
echo "dirty=$(git status --porcelain | wc -l | tr -d ' ')"
echo "files=$(git ls-files | wc -l | tr -d ' ')"`},
			})
			requireContains(t, "reopened repository", out, "branch=feature\n", "commits=5\n", "dirty=0\n", "files=2105\n")
		})
	}
}

// requireBulkTree verifies that dir holds count files f<N>.txt spread over 40
// directories, each with its own number as content.
func requireBulkTree(t *testing.T, dir string, count int) {
	t.Helper()
	seen := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		base := d.Name()
		n, convErr := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(base, "f"), ".txt"))
		if convErr != nil {
			return fmt.Errorf("unexpected file %s", p)
		}
		if wantDir := "d" + strconv.Itoa(n%40); filepath.Base(filepath.Dir(p)) != wantDir {
			return fmt.Errorf("%s is in %s, want %s", base, filepath.Base(filepath.Dir(p)), wantDir)
		}
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			return readErr
		}
		if want := "file " + strconv.Itoa(n) + "\n"; string(data) != want {
			return fmt.Errorf("%s = %q, want %q", p, data, want)
		}
		seen++
		return nil
	})
	if err != nil {
		t.Errorf("verify bulk tree %s: %v", dir, err)
	}
	if seen != count {
		t.Errorf("bulk tree holds %d files, want %d", seen, count)
	}
}

func TestE2EGateM4NodeModulesTorture(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			workspace := t.TempDir()
			code, stdout, stderr := runGuest(t, guestSpec{
				plat:      b.plat,
				image:     nodeImage,
				argv:      []string{"node", "-e", nodeTortureScript},
				workspace: workspace,
			})
			requireGuestMarkers(t, code, stdout, stderr, "tree=ok", "rename-over=ok", "rename-dir=ok", "rm-rf-open=ok", "misc=ok", "ALL-OK")

			entries := snapshotWorkspace(t, workspace)
			want := map[string]wsEntry{
				"app":                dirEntry(0o755),
				"app/.store":         dirEntry(0o755),
				"app/store-copy":     dirEntry(0o755),
				"app/conf.json":      fileEntry(0o644, `{"gen":100}`),
				"app/empty-target":   dirEntry(0o755),
				"app/empty-target/f": fileEntry(0o644, "payload"),
				"app/Readme.md":      fileEntry(0o644, "up"),
			}
			for i := range 5 {
				body := fmt.Sprintf("module.exports = %d;\n", i)
				want[fmt.Sprintf("app/.store/blob%d.js", i)] = fileEntry(0o644, body)
				want[fmt.Sprintf("app/store-copy/blob%d.js", i)] = fileEntry(0o644, body)
			}
			requireEntries(t, entries, "app", want)
			for name := range entries {
				if strings.HasPrefix(name, "app/node_modules") {
					t.Errorf("%s survived rm -rf of node_modules", name)
				}
			}
			requireMetaConsistent(t, workspace, "")

			info, err := os.Stat(filepath.Join(workspace, "app", "Readme.md"))
			wantTime := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
			if err != nil || !info.ModTime().Equal(wantTime) {
				t.Errorf("host mtime of Readme.md = (%v, %v), want %v", info, err, wantTime)
			}
			if got := hostDirNames(t, filepath.Join(workspace, "app")); strings.Join(got, ",") != ".store,Readme.md,conf.json,empty-target,store-copy" {
				t.Errorf("host listing of app = %v", got)
			}
		})
	}
}

// killScript builds durable state, calls sync, and then mutates the top
// level of /workspace until the test kills the process.
const killScript = `set -eu
cd /workspace
mkdir -p base/sub
i=0
while [ $i -lt 40 ]; do
  echo "payload $i" > base/sub/f$i
  i=$((i + 1))
done
ln -s sub/f0 base/link0
ln -s ../base base/sub/up
chmod 0750 base/sub/f1
chown 42:43 base/sub/f2
mv base/sub/f3 base/moved3
rm base/sub/f4
sync
echo PHASE1-SYNCED
n=0
while :; do
  echo "tmp $n" > churn.tmp
  mv -f churn.tmp "churn$((n % 7))"
  ln -sf "churn$((n % 7))" "churnlink$((n % 5))"
  chmod "06$((n % 8))$((n % 8))" "churn$((n % 7))"
  n=$((n + 1))
  echo "iter $n"
done
`

// killPhase1Want lists the durable state that killScript leaves under base.
func killPhase1Want() map[string]wsEntry {
	want := map[string]wsEntry{
		"base":        dirEntry(0o755),
		"base/sub":    dirEntry(0o755),
		"base/moved3": fileEntry(0o644, "payload 3\n"),
		"base/link0":  linkEntry("sub/f0"),
		"base/sub/up": linkEntry("../base"),
	}
	for i := range 40 {
		if i == 3 || i == 4 {
			continue
		}
		e := fileEntry(0o644, fmt.Sprintf("payload %d\n", i))
		switch i {
		case 1:
			e.Perm = 0o750
		case 2:
			e.UID, e.GID = 42, 43
		}
		want[fmt.Sprintf("base/sub/f%d", i)] = e
	}
	return want
}

// TestE2EGateM4MetaSurvivesSigkill kills a child rungv in the middle of a
// metadata-heavy run. The workspace then reopens in a fresh sandbox, and the
// state that the guest synced before the kill is intact.
func TestE2EGateM4MetaSurvivesSigkill(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			rungv := toolPath(t, rungvPkg)
			workspace := t.TempDir()

			// The child runs with the default lockdown.
			cmd := exec.Command(rungv, "run", "-platform="+b.name, "-net=none",
				"-cache-dir="+sharedCacheDir(t), "-workspace="+workspace,
				"-image="+busyboxImage, "--", "sh", "-c", killScript)
			stdout, stderr := newOutputLog(), newOutputLog()
			cmd.Stdout, cmd.Stderr = stdout, stderr
			t.Cleanup(func() {
				if t.Failed() {
					t.Logf("rungv stderr:\n%s", stderr.String())
				}
			})
			if err := cmd.Start(); err != nil {
				t.Fatalf("start rungv: %v", err)
			}
			exited := make(chan struct{})
			var waitErr error
			go func() {
				waitErr = cmd.Wait()
				close(exited)
			}()
			t.Cleanup(func() {
				_ = cmd.Process.Kill()
				<-exited
			})

			stdout.waitFor(t, 0, "PHASE1-SYNCED\n", 4*time.Minute, exited)
			// Phase 2 is under way once the guest reports later iterations.
			stdout.waitFor(t, 0, "iter 30\n", time.Minute, exited)
			if err := cmd.Process.Kill(); err != nil {
				t.Fatalf("SIGKILL rungv: %v", err)
			}
			<-exited
			var exitErr *exec.ExitError
			if !errors.As(waitErr, &exitErr) || exitErr.ExitCode() == 0 {
				t.Fatalf("rungv wait after kill = %v, want a non-zero exit", waitErr)
			}

			// The table on disk is a complete earlier or later version, never
			// a torn one, and the synced state is in it.
			table := readMetaTable(t, workspace)
			for name, w := range killPhase1Want() {
				attr, ok := table.Entries[name]
				if !ok {
					t.Errorf("%s lost from the table after SIGKILL", name)
					continue
				}
				if attr.Mode&0o7777 != w.Perm || attr.UID != w.UID || attr.GID != w.GID {
					t.Errorf("%s record = (%04o, %d:%d), want %s", name, attr.Mode&0o7777, attr.UID, attr.GID, w)
				}
			}
			requireMetaConsistent(t, workspace, "base")
			requireEntries(t, snapshotWorkspace(t, workspace), "base", killPhase1Want())

			// A fresh sandbox reads the same state through the guest VFS.
			out := mustRunGuest(t, guestSpec{
				plat:      b.plat,
				image:     busyboxImage,
				workspace: workspace,
				argv: []string{"sh", "-c", `set -eu
cd /workspace/base
for p in sub/f1 sub/f2 sub/f5 moved3 link0 sub/up; do stat -c '%n %a %u:%g %F' $p; done
echo "f5=$(cat sub/f5)"
echo "moved3=$(cat moved3)"
echo "link0=$(readlink link0) via=$(cat link0)"
echo "up=$(readlink sub/up)"
echo "subcount=$(ls -A sub | wc -l | tr -d ' ')"
echo "base=$(ls -A . | tr '\n' ' ')"
ls /workspace >/dev/null
echo REOPEN-OK`},
			})
			requireContains(t, "fresh sandbox view", out,
				"sub/f1 750 0:0 regular file\n",
				"sub/f2 644 42:43 regular file\n",
				"sub/f5 644 0:0 regular file\n",
				"moved3 644 0:0 regular file\n",
				"link0 777 0:0 symbolic link\n",
				"sub/up 777 0:0 symbolic link\n",
				"f5=payload 5\n", "moved3=payload 3\n",
				"link0=sub/f0 via=payload 0\n",
				"up=../base\n",
				"subcount=39\n",
				"base=link0 moved3 sub \n",
				"REOPEN-OK\n")
		})
	}
}

// TestE2EGateM4TortureUnderDefaultLockdown runs the torture script through
// the CLI with the default lockdown, so the Seatbelt or JobObject profile
// covers every workspace operation of the script.
func TestE2EGateM4TortureUnderDefaultLockdown(t *testing.T) {
	requireRegistry(t)
	rungv := toolPath(t, rungvPkg)
	workspace := t.TempDir()
	caseInsensitive := hostCaseInsensitive(t, workspace)
	stdout, stderr, code := runTool(t, rungv, "run", "-platform="+string(autoPlatform()), "-net=none",
		"-cache-dir="+sharedCacheDir(t), "-workspace="+workspace,
		"-image="+busyboxImage, "--", "sh", "-c", tortureScript(caseInsensitive))
	requireGuestMarkers(t, code, stdout, stderr, posixTortureMarkers...)
	if strings.Contains(stderr, "lockdown disabled") {
		t.Fatalf("the run reports a disabled lockdown without -lockdown=false: %q", stderr)
	}
	requireEntries(t, snapshotWorkspace(t, workspace), "", posixTortureWant(caseInsensitive))
	requireMetaConsistent(t, workspace, "")
}

// TestE2EGateM4LockdownDefaultBlocksSubprocess runs a real image workload
// under the lockdown probe. By default the host process cannot create a
// subprocess, read outside the workspace, or write outside it, and the guest
// still works on /workspace. The opt-out run proves that each escape works
// without the lockdown.
func TestE2EGateM4LockdownDefaultBlocksSubprocess(t *testing.T) {
	probe := toolPath(t, lockdownProbePkg)
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			run := func(extra ...string) (lockdownprobe.Report, string) {
				t.Helper()
				workspace := t.TempDir()
				outside := t.TempDir()
				secret := filepath.Join(outside, "secret.txt")
				if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
					t.Fatalf("write secret: %v", err)
				}
				args := append([]string{
					"-platform=" + b.name, "-image=" + busyboxImage, "-workspace=" + workspace,
					"-cache-dir=" + sharedCacheDir(t), "-outside-file=" + secret, "-outside-dir=" + outside,
				}, extra...)
				args = append(args, "--", "sh", "-c", "echo guest-in-workspace > /workspace/probe.txt && cat /workspace/probe.txt")
				stdout, stderr, code := runTool(t, probe, args...)
				if code != 0 {
					t.Fatalf("lockdownprobe exit code = %d\nstdout=%s\nstderr=%s", code, stdout, stderr)
				}
				var rep lockdownprobe.Report
				if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
					t.Fatalf("decode probe report %q: %v", stdout, err)
				}
				if rep.NewErr != "" {
					t.Fatalf("gvx.New failed in the probe: %s", rep.NewErr)
				}
				if rep.GuestRunErr != "" || rep.GuestExitCode != 0 || rep.GuestStdout != "guest-in-workspace\n" {
					t.Fatalf("guest = (code %d, stdout %q, err %q), want a clean run that echoes its file", rep.GuestExitCode, rep.GuestStdout, rep.GuestRunErr)
				}
				got, err := os.ReadFile(filepath.Join(workspace, "probe.txt"))
				if err != nil || string(got) != "guest-in-workspace\n" {
					t.Fatalf("host probe.txt = (%q, %v), want the guest write", got, err)
				}
				return rep, outside
			}

			// No lockdown flag: the default applies.
			rep, outside := run()
			if !rep.Lockdown.Applied || !rep.LockedAPI {
				t.Errorf("default run: Lockdown.Applied=%v IsLockedDown=%v, want both true", rep.Lockdown.Applied, rep.LockedAPI)
			}
			// The Linux seccomp filter cannot read paths, so a workspace keeps
			// opens relative to a directory descriptor, and the status says so.
			wantUnbound := runtime.GOOS != "linux"
			if !rep.Lockdown.SubprocessBlocked || rep.Lockdown.UnboundFileOpenBlocked != wantUnbound {
				t.Errorf("default run: lockdown status %+v, want a subprocess block and UnboundFileOpenBlocked=%v", rep.Lockdown, wantUnbound)
			}
			if rep.SpawnErr == "" {
				t.Errorf("default run: host subprocess creation succeeded")
			}
			if rep.ReadOutsideErr == "" || rep.WriteOutsideErr == "" {
				t.Errorf("default run: outside read %q and write %q, want two refusals", rep.ReadOutsideErr, rep.WriteOutsideErr)
			}
			if _, err := os.Stat(filepath.Join(outside, "escape.txt")); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("default run: escape.txt exists outside the workspace: %v", err)
			}

			rep, _ = run("-lockdown=false")
			if rep.Lockdown.Applied || rep.LockedAPI || rep.SpawnErr != "" || rep.ReadOutsideErr != "" || rep.WriteOutsideErr != "" {
				t.Errorf("opt-out run: status %+v, locked %v, spawn %q, read %q, write %q, want no lockdown and three working escapes",
					rep.Lockdown, rep.LockedAPI, rep.SpawnErr, rep.ReadOutsideErr, rep.WriteOutsideErr)
			}
		})
	}
}
