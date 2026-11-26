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
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

func openContainedEnv(t *testing.T, dir string, extra ...func(*workspaceOptions)) (*env, func()) {
	t.Helper()
	opts := workspaceOptions{
		coalesce:    defaultCoalesceWindow,
		symlinkMode: SymlinkContained,
		noOrphanGC:  true,
	}
	for _, fn := range extra {
		fn(&opts)
	}
	return openEnvAt(t, dir, opts)
}

func mustReadlink(t *testing.T, e *env, p string) string {
	t.Helper()
	got, err := e.readlink(p)
	if err != nil {
		t.Fatalf("readlink(%q): %v", p, err)
	}
	return got
}

func mustGetXattr(t *testing.T, e *env, p, name string) string {
	t.Helper()
	got, err := e.getXattr(p, name)
	if err != nil {
		t.Fatalf("getXattr(%q, %q): %v", p, name, err)
	}
	return got
}

func TestClassifyContainedTarget(t *testing.T) {
	cases := []struct {
		name         string
		linkRel      string
		target       string
		wantOK       bool
		wantLeading  int
		wantResolved string
	}{
		// Accepted contained relative targets (len(comps) > leadingParents).
		{"root plain sibling", "link", "README", true, 0, "README"},
		{"root dot prefix", "link", "./README", true, 0, "README"},
		{"root subdir target", "link", "sub/dir/file", true, 0, "sub/dir/file"},
		{"root double slash and trailing slash", "link", "sub//dir/", true, 0, "sub/dir"},
		{"npm bin link", "node_modules/.bin/tsc", "../typescript/bin/tsc", true, 1, "node_modules/typescript/bin/tsc"},
		{"pnpm nested peer link", "node_modules/.pnpm/a/node_modules/b", "../../b/node_modules/b", true, 2, "node_modules/.pnpm/b/node_modules/b"},
		{"sibling dir link", "a/link", "../b/file", true, 1, "b/file"},
		{"deep sibling link", "a/b/c/link", "../../../x/y/z/w", true, 3, "x/y/z/w"},

		// Rejected targets: empty, NUL, absolute, Windows separators/colons.
		{"empty target", "link", "", false, 0, ""},
		{"nul byte", "link", "foo\x00bar", false, 0, ""},
		{"absolute path", "link", "/etc/passwd", false, 0, ""},
		{"absolute workspace path", "a/link", "/workspace/README", false, 0, ""},
		{"backslash", "link", `sub\file`, false, 0, ""},
		{"colon drive or ADS", "link", "C:file", false, 0, ""},
		{"colon in filename", "link", "a:b", false, 0, ""},

		// Rejected targets: escaping root, interior "..", root-pointing, depth-reducing.
		{"escape from root", "link", "../outside/file", false, 0, ""},
		{"escape from depth 1", "a/link", "../../outside/a/b", false, 0, ""},
		{"interior dotdot simple", "a/link", "sub/../file", false, 0, ""},
		{"interior dotdot chain amplification", "a/hop", "b/c/d/jump/../../etc/passwd", false, 0, ""},
		{"self dot loop", "a/self", ".", false, 0, ""},
		{"root dot loop", "self", ".", false, 0, ""},
		{"bare parent loop", "a/b/up", "..", false, 0, ""},
		{"bare double parent to root", "a/b/up", "../..", false, 0, ""},
		{"depth-reducing single parent", "a/link", "../README", false, 0, ""},
		{"depth-reducing two parents", "a/b/c/sub", "../../x", false, 0, ""},
		{"depth-reducing equal count", "a/b/link", "../../x/y", false, 0, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := classifyContainedTarget(tc.linkRel, tc.target)
			if ok != tc.wantOK {
				t.Fatalf("classifyContainedTarget(%q, %q) ok = %v, want %v (got=%+v)", tc.linkRel, tc.target, ok, tc.wantOK, got)
			}
			if !ok {
				return
			}
			if got.leadingParents != tc.wantLeading {
				t.Errorf("leadingParents = %d, want %d", got.leadingParents, tc.wantLeading)
			}
			if got.resolved != tc.wantResolved {
				t.Errorf("resolved = %q, want %q", got.resolved, tc.wantResolved)
			}
		})
	}
}

func TestOpenWorkspaceSymlinkModeValidation(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(t.TempDir(), "single.txt")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenWorkspaceWithOptions(dir, OpenOptions{SymlinkMode: "bogus"}); err == nil {
		t.Fatal("OpenWorkspaceWithOptions with invalid SymlinkMode succeeded, want error")
	}
	if _, err := OpenWorkspaceWithOptions(filePath, OpenOptions{SymlinkMode: SymlinkContained}); err == nil {
		t.Fatal("OpenWorkspaceWithOptions on single-file mount with SymlinkContained succeeded, want error")
	}
	ws, err := OpenWorkspaceWithOptions(dir, OpenOptions{})
	if err != nil {
		t.Fatalf("default OpenWorkspaceWithOptions: %v", err)
	}
	if ws.SymlinkMode() != SymlinkVirtual {
		t.Errorf("default SymlinkMode() = %q, want %q", ws.SymlinkMode(), SymlinkVirtual)
	}
	if err := ws.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSymlinkContainedMaterializesAndFallsBack(t *testing.T) {
	dir := t.TempDir()
	e, cleanup := openContainedEnv(t, dir)
	defer cleanup()

	e.writeFile("README", []byte("hello"))
	e.mustMkdir("node_modules")
	e.mustMkdir("node_modules/.bin")
	e.mustMkdir("node_modules/typescript")
	e.mustMkdir("node_modules/typescript/bin")
	e.writeFile("node_modules/typescript/bin/tsc", []byte("#!/bin/sh\n"))

	// Eligible contained targets.
	if err := e.symlink("link", "README"); err != nil {
		t.Fatalf("symlink(link): %v", err)
	}
	if err := e.symlink("node_modules/.bin/tsc", "../typescript/bin/tsc"); err != nil {
		t.Fatalf("symlink(tsc): %v", err)
	}

	// Non-eligible targets that must stay virtual.
	virtualCases := map[string]string{
		"abs":          "/usr/bin/env",
		"escape":       "../../etc/passwd",
		"interior":     "node_modules/../README",
		"meta_leak":    MetaFileName,
		"meta_lock":    MetaLockFileName,
		"internal_tmp": ".gvx_tmp_foo",
		"codec_pref":   "~gvx~abc",
	}
	for name, target := range virtualCases {
		if err := e.symlink(name, target); err != nil {
			t.Fatalf("symlink(%s -> %s): %v", name, target, err)
		}
		if got := mustReadlink(t, e, name); got != target {
			t.Errorf("guest readlink(%s) = %q, want %q", name, got, target)
		}
		if _, err := os.Lstat(e.host(name)); !os.IsNotExist(err) {
			t.Errorf("non-eligible symlink %q materialized on host (lstat err=%v)", name, err)
		}
	}

	// Guest reads both contained links identically on all hosts.
	if got := mustReadlink(t, e, "link"); got != "README" {
		t.Errorf("guest readlink(link) = %q, want README", got)
	}
	if got := string(e.readFile("link")); got != "hello" {
		t.Errorf("readFile(link) = %q, want hello", got)
	}
	if got := mustReadlink(t, e, "node_modules/.bin/tsc"); got != "../typescript/bin/tsc" {
		t.Errorf("guest readlink(tsc) = %q, want ../typescript/bin/tsc", got)
	}

	if runtime.GOOS == "windows" {
		// Windows falls back to virtual for all guest symlinks.
		if _, err := os.Lstat(e.host("link")); !os.IsNotExist(err) {
			t.Errorf("Windows unexpectedly materialized link on host (err=%v)", err)
		}
		return
	}

	// Unix hosts materialize contained links natively.
	for rel, want := range map[string]string{
		"link":                  "README",
		"node_modules/.bin/tsc": "../typescript/bin/tsc",
	} {
		got, err := os.Readlink(e.host(rel))
		if err != nil {
			t.Fatalf("os.Readlink(%s): %v", rel, err)
		}
		if got != want {
			t.Errorf("host Readlink(%s) = %q, want %q", rel, got, want)
		}
	}

	// Verify VirtualSymlinks lists only the virtual fallback entries.
	gotVirt, err := e.ws.VirtualSymlinks()
	if err != nil {
		t.Fatalf("VirtualSymlinks: %v", err)
	}
	if len(gotVirt) != len(virtualCases) {
		t.Fatalf("VirtualSymlinks() len = %d (%+v), want %d", len(gotVirt), gotVirt, len(virtualCases))
	}
	for _, vs := range gotVirt {
		want, ok := virtualCases[vs.Path]
		if !ok || vs.Target != want {
			t.Errorf("unexpected VirtualSymlink %+v", vs)
		}
	}
}

func TestSymlinkContainedExternalMetaDirAllowsLiteralMetaTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-only host symlink materialization test")
	}
	wsDir := t.TempDir()
	metaDir := t.TempDir()
	e, cleanup := openContainedEnv(t, wsDir, func(o *workspaceOptions) {
		o.metaDir = metaDir
	})
	defer cleanup()

	e.writeFile(MetaFileName, []byte("user-file"))
	if err := e.symlink("meta_ref", MetaFileName); err != nil {
		t.Fatalf("symlink to literal .gvx_meta with external MetaDir: %v", err)
	}
	got, err := os.Readlink(e.host("meta_ref"))
	if err != nil {
		t.Fatalf("os.Readlink(meta_ref): %v", err)
	}
	if got != MetaFileName {
		t.Errorf("os.Readlink(meta_ref) = %q, want %q", got, MetaFileName)
	}
}

func TestSymlinkContainedBlocksMultiHopAndDirSubstitution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-only host symlink materialization test")
	}
	dir := t.TempDir()
	e, cleanup := openContainedEnv(t, dir)
	defer cleanup()

	// Setup a/b/c/d/dir.
	e.mkdirChain("a/b/c/d/dir")

	// Dynamic directory-to-symlink substitution test:
	// 1) Create a/hop targeting b/c/d/dir/../../etc/passwd while dir is a real directory.
	if err := e.symlink("a/hop", "b/c/d/dir/../../etc/passwd"); err != nil {
		t.Fatalf("symlink(a/hop): %v", err)
	}
	// Must stay virtual because of interior "..".
	if _, err := os.Lstat(e.host("a/hop")); !os.IsNotExist(err) {
		t.Fatalf("interior dotdot link a/hop materialized on host: %v", err)
	}

	// 2) Replace dir with a climbing symlink ../../..
	if err := e.vfsObj.RmdirAt(e.ctx, e.creds, e.pop("a/b/c/d/dir")); err != nil {
		t.Fatalf("rmdir: %v", err)
	}
	if err := e.symlink("a/b/c/d/dir", "../../.."); err != nil {
		t.Fatalf("symlink(a/b/c/d/dir): %v", err)
	}
	// Bare "../.." must also stay virtual (len(comps) == 0).
	if _, err := os.Lstat(e.host("a/b/c/d/dir")); !os.IsNotExist(err) {
		t.Fatalf("bare parent link materialized on host: %v", err)
	}

	// Pre-existing interior-dotdot host symlink with depth-reducing replacement:
	// Host has a/b/c/existing targeting sub/../../../secret (clean = a/secret).
	e.mustMkdir("a/b/c/sub")
	if err := os.Symlink("sub/../../../secret", e.host("a/b/c/existing")); err != nil {
		t.Fatalf("os.Symlink: %v", err)
	}
	if err := e.vfsObj.RmdirAt(e.ctx, e.creds, e.pop("a/b/c/sub")); err != nil {
		t.Fatalf("rmdir sub: %v", err)
	}
	// Guest attempts depth-reducing symlink a/b/c/sub targeting ../../x (k=2, m=1).
	if err := e.symlink("a/b/c/sub", "../../x"); err != nil {
		t.Fatalf("symlink(a/b/c/sub): %v", err)
	}
	if _, err := os.Lstat(e.host("a/b/c/sub")); !os.IsNotExist(err) {
		t.Fatalf("depth-reducing symlink a/b/c/sub materialized on host: %v", err)
	}
}

func TestSymlinkContainedBlocksPreExistingUnsafeHostSymlinkChains(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-only host symlink materialization test")
	}
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "ext")); err != nil {
		t.Fatalf("os.Symlink(ext): %v", err)
	}
	if err := os.Symlink("ext", filepath.Join(dir, "alias")); err != nil {
		t.Fatalf("os.Symlink(alias): %v", err)
	}

	e, cleanup := openContainedEnv(t, dir)
	defer cleanup()

	// Direct target through hidden escaping host symlink must stay virtual.
	if err := e.symlink("direct", "ext/secret"); err != nil {
		t.Fatalf("symlink(direct): %v", err)
	}
	if _, err := os.Lstat(e.host("direct")); !os.IsNotExist(err) {
		t.Fatalf("symlink chaining through ext materialized on host: %v", err)
	}

	// Two-hop target through alias and ext to outside must also stay virtual.
	if err := e.symlink("chained", "alias/secret"); err != nil {
		t.Fatalf("symlink(chained): %v", err)
	}
	if _, err := os.Lstat(e.host("chained")); !os.IsNotExist(err) {
		t.Fatalf("symlink chaining through alias and ext materialized on host: %v", err)
	}
}

func TestRenameAndExchangeEnforceSymlinkContainment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-only native host symlink test")
	}

	// Test both default SymlinkVirtual (pre-existing host symlinks) and SymlinkContained.
	for _, mode := range []SymlinkMode{SymlinkVirtual, SymlinkContained} {
		t.Run("mode="+string(mode), func(t *testing.T) {
			dir := t.TempDir()
			e, cleanup := openEnvAt(t, dir, workspaceOptions{
				coalesce:    defaultCoalesceWindow,
				symlinkMode: mode,
				noOrphanGC:  true,
			})
			defer cleanup()

			// 1. Single host symlink moved shallower demotes to virtual and never escapes on host.
			e.mkdirChain("a/b")
			e.mustMkdir("pkg")
			e.writeFile("pkg/tool", []byte("ok"))
			if err := os.Symlink("../../pkg/tool", e.host("a/b/link")); err != nil {
				t.Fatalf("seed host symlink: %v", err)
			}
			// Warm VFS dentry cache and verify metadata before rename.
			if got := mustReadlink(t, e, "a/b/link"); got != "../../pkg/tool" {
				t.Fatalf("readlink before rename = %q", got)
			}
			// Also attach ownership and xattr to verify preservation across demotion.
			if err := e.ws.Chown("a/b/link", 1234, 5678); err != nil {
				t.Fatalf("Chown host symlink: %v", err)
			}
			if err := e.setXattr("a/b/link", "trusted.tag", "keepme", 0); err != nil {
				t.Fatalf("setXattr host symlink: %v", err)
			}

			// Move from depth 2 to depth 0 (would escape on host if kept native).
			if err := e.rename("a/b/link", "link"); err != nil {
				t.Fatalf("rename(a/b/link, link): %v", err)
			}
			if _, err := os.Lstat(e.host("link")); !os.IsNotExist(err) {
				t.Fatalf("unsafe moved symlink exists on host: err=%v", err)
			}
			if _, err := os.Lstat(e.host("a/b/link")); !os.IsNotExist(err) {
				t.Fatalf("old host symlink still exists on host: err=%v", err)
			}
			if got := mustReadlink(t, e, "link"); got != "../../pkg/tool" {
				t.Errorf("guest readlink after demotion = %q, want ../../pkg/tool", got)
			}
			st, err := e.lstat("link")
			if err != nil {
				t.Fatalf("lstat demoted link: %v", err)
			}
			if st.UID != 1234 || st.GID != 5678 {
				t.Errorf("demoted link owner = %d:%d, want 1234:5678", st.UID, st.GID)
			}
			if got := mustGetXattr(t, e, "link", "trusted.tag"); got != "keepme" {
				t.Errorf("demoted link xattr = %q, want keepme", got)
			}

			// 2. Directory containing climbing host symlink moved shallower demotes before host rename.
			e.mkdirChain("d1/d2/d3")
			if err := os.Symlink("../../../pkg/tool", e.host("d1/d2/d3/deep")); err != nil {
				t.Fatalf("seed deep host symlink: %v", err)
			}
			if got := mustReadlink(t, e, "d1/d2/d3/deep"); got != "../../../pkg/tool" {
				t.Fatalf("readlink(d1/d2/d3/deep) = %q", got)
			}
			if err := e.rename("d1/d2/d3", "d3"); err != nil {
				t.Fatalf("rename(d1/d2/d3, d3): %v", err)
			}
			if _, err := os.Lstat(e.host("d3/deep")); !os.IsNotExist(err) {
				t.Fatalf("unsafe symlink inside moved dir exists on host: err=%v", err)
			}
			if got := mustReadlink(t, e, "d3/deep"); got != "../../../pkg/tool" {
				t.Errorf("guest readlink(d3/deep) = %q, want ../../../pkg/tool", got)
			}

			// 3. Safe same-depth single-symlink rename stays a native host symlink.
			e.mkdirChain("safe/sub")
			if err := os.Symlink("../pkg/tool", e.host("safe/oklink")); err != nil {
				t.Fatalf("seed safe host symlink: %v", err)
			}
			if err := e.rename("safe/oklink", "safe/oklink2"); err != nil {
				t.Fatalf("rename safe link: %v", err)
			}
			if got, err := os.Readlink(e.host("safe/oklink2")); err != nil || got != "../pkg/tool" {
				t.Errorf("safe renamed host symlink = (%q, %v), want (../pkg/tool, nil)", got, err)
			}

			// 4. Hidden escaping host symlink inside directory blocks ALL directory renames (deeper, shallower, same-parent).
			e.mkdirChain("hid/sub")
			if err := os.Symlink("../../../outside_secret", e.host("hid/sub/esc")); err != nil {
				t.Fatalf("seed hidden escaping symlink: %v", err)
			}
			e.mkdirChain("deep/x/y")
			wantErrno(t, "move hidden-link dir deeper (unhide attempt)", e.rename("hid/sub", "deep/x/y/sub"), linuxerr.EACCES)
			wantErrno(t, "move hidden-link dir shallower", e.rename("hid/sub", "sub_moved"), linuxerr.EACCES)
			wantErrno(t, "move hidden-link dir same-parent", e.rename("hid/sub", "hid/sub2"), linuxerr.EACCES)

			// 5. RENAME_EXCHANGE: single climbing symlink swapped with shallow regular file.
			e.mkdirChain("ex/sub")
			e.writeFile("shallow_file", []byte("data"))
			if err := os.Symlink("../../pkg/tool", e.host("ex/sub/exlink")); err != nil {
				t.Fatalf("seed exlink: %v", err)
			}
			if err := e.renameFlags("ex/sub/exlink", "shallow_file", linux.RENAME_EXCHANGE); err != nil {
				t.Fatalf("RENAME_EXCHANGE(ex/sub/exlink, shallow_file): %v", err)
			}
			if _, err := os.Lstat(e.host("shallow_file")); !os.IsNotExist(err) {
				t.Fatalf("exchanged climbing symlink exists on host at shallow_file: %v", err)
			}
			if got := mustReadlink(t, e, "shallow_file"); got != "../../pkg/tool" {
				t.Errorf("readlink(shallow_file) = %q, want ../../pkg/tool", got)
			}
			if got := string(e.readFile("ex/sub/exlink")); got != "data" {
				t.Errorf("readFile(ex/sub/exlink) = %q, want data", got)
			}

			// 6. RENAME_EXCHANGE: two host symlinks both unsafe at each other's positions (double demotion).
			e.mkdirChain("dbl/a")
			if err := os.Symlink("../../pkg/tool", e.host("dbl/a/l1")); err != nil {
				t.Fatalf("seed l1: %v", err)
			}
			if err := os.Symlink("pkg/../pkg/tool", e.host("l2")); err != nil {
				t.Fatalf("seed l2: %v", err)
			}
			if err := e.renameFlags("dbl/a/l1", "l2", linux.RENAME_EXCHANGE); err != nil {
				t.Fatalf("RENAME_EXCHANGE double demotion: %v", err)
			}
			if _, err := os.Lstat(e.host("l2")); !os.IsNotExist(err) {
				t.Fatalf("double-demoted l2 still on host: %v", err)
			}
			if _, err := os.Lstat(e.host("dbl/a/l1")); !os.IsNotExist(err) {
				t.Fatalf("double-demoted dbl/a/l1 still on host: %v", err)
			}
			if got := mustReadlink(t, e, "l2"); got != "../../pkg/tool" {
				t.Errorf("readlink(l2) = %q, want ../../pkg/tool", got)
			}
			if got := mustReadlink(t, e, "dbl/a/l1"); got != "pkg/../pkg/tool" {
				t.Errorf("readlink(dbl/a/l1) = %q, want pkg/../pkg/tool", got)
			}

			// 7. RENAME_EXCHANGE: directory containing climbing symlink swapped with shallow directory.
			e.mkdirChain("exdir/deep/src")
			e.mustMkdir("exdir_shallow")
			if err := os.Symlink("../../../pkg/tool", e.host("exdir/deep/src/klink")); err != nil {
				t.Fatalf("seed klink: %v", err)
			}
			if err := e.renameFlags("exdir/deep/src", "exdir_shallow", linux.RENAME_EXCHANGE); err != nil {
				t.Fatalf("RENAME_EXCHANGE dirs: %v", err)
			}
			if _, err := os.Lstat(e.host("exdir_shallow/klink")); !os.IsNotExist(err) {
				t.Fatalf("exchanged dir climbing symlink exists on host: %v", err)
			}
			if got := mustReadlink(t, e, "exdir_shallow/klink"); got != "../../../pkg/tool" {
				t.Errorf("readlink(exdir_shallow/klink) = %q, want ../../../pkg/tool", got)
			}

			// 8. RENAME_EXCHANGE: directory containing hidden escaping symlink is rejected.
			e.mustMkdir("swap_target_dir")
			wantErrno(t, "RENAME_EXCHANGE hidden-link dir", e.renameFlags("hid/sub", "swap_target_dir", linux.RENAME_EXCHANGE), linuxerr.EACCES)

			// 9. RENAME_WHITEOUT of climbing host symlink demotes and creates whiteout.
			e.mkdirChain("wo/sub")
			if err := os.Symlink("../../pkg/tool", e.host("wo/sub/wlink")); err != nil {
				t.Fatalf("seed wlink: %v", err)
			}
			if err := e.renameFlags("wo/sub/wlink", "wlink_out", linux.RENAME_WHITEOUT); err != nil {
				t.Fatalf("RENAME_WHITEOUT: %v", err)
			}
			if _, err := os.Lstat(e.host("wlink_out")); !os.IsNotExist(err) {
				t.Fatalf("whiteout-renamed climbing symlink exists on host: %v", err)
			}
			if got := mustReadlink(t, e, "wlink_out"); got != "../../pkg/tool" {
				t.Errorf("readlink(wlink_out) = %q, want ../../pkg/tool", got)
			}
			woStat, err := e.lstat("wo/sub/wlink")
			if err != nil {
				t.Fatalf("lstat whiteout: %v", err)
			}
			if woStat.Mode&linux.S_IFMT != linux.S_IFCHR || woStat.RdevMajor != 0 || woStat.RdevMinor != 0 {
				t.Errorf("whiteout stat = mode %#o rdev %d:%d, want chr 0:0", woStat.Mode, woStat.RdevMajor, woStat.RdevMinor)
			}

			// 10. Single-symlink demotion over a hard-linked destination preserves surviving link metadata.
			e.mkdirChain("hl/sub")
			e.writeFile("hl_a", []byte("shared"))
			if err := e.link("hl_a", "hl_b"); err != nil {
				t.Fatalf("link: %v", err)
			}
			e.chmod("hl_a", 0o751)
			if err := e.ws.Chown("hl_a", 42, 43); err != nil {
				t.Fatalf("chown hl_a: %v", err)
			}
			if err := os.Symlink("../../pkg/tool", e.host("hl/sub/over")); err != nil {
				t.Fatalf("seed over: %v", err)
			}
			if err := e.rename("hl/sub/over", "hl_a"); err != nil {
				t.Fatalf("rename over hard link: %v", err)
			}
			stB, err := e.lstat("hl_b")
			if err != nil {
				t.Fatalf("lstat surviving hard link hl_b: %v", err)
			}
			if stB.Mode&0o777 != 0o751 || stB.UID != 42 || stB.GID != 43 {
				t.Errorf("surviving hard link metadata = mode %#o %d:%d, want 0751 42:43", stB.Mode&0o777, stB.UID, stB.GID)
			}
		})
	}
}

func TestHostSymlinkMetadataPersistenceAndOrphanGC(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-only native host symlink test")
	}
	dir := t.TempDir()
	e, cleanup := openContainedEnv(t, dir)

	e.writeFile("target", []byte("data"))
	// Create symlink as non-root user (1001:2002) via VFS.
	userCreds := auth.NewUserCredentials(1001, 2002, nil, nil, auth.NewRootUserNamespace())
	e.chmod(".", 0o777)
	if err := e.vfsObj.SymlinkAt(e.ctx, userCreds, e.pop("userlink"), "target"); err != nil {
		t.Fatalf("SymlinkAt as non-root: %v", err)
	}
	// Verify materialized on host.
	if got, err := os.Readlink(e.host("userlink")); err != nil || got != "target" {
		t.Fatalf("host Readlink(userlink) = (%q, %v), want (target, nil)", got, err)
	}
	st, err := e.lstat("userlink")
	if err != nil {
		t.Fatalf("lstat(userlink): %v", err)
	}
	if st.UID != 1001 || st.GID != 2002 || st.Mode&0o777 != 0o777 {
		t.Fatalf("lstat(userlink) = mode %#o %d:%d, want 0777 1001:2002", st.Mode&0o777, st.UID, st.GID)
	}

	// lchown with ClearPrivs (which supplies non-nil mode pointer in vfs_stat.go)
	// must update UID/GID while keeping mode 0777 and reading target from host.
	if err := e.vfsObj.SetStatAt(e.ctx, e.creds, e.pop("userlink"), &vfs.SetStatOptions{
		Stat: linux.Statx{
			Mask: linux.STATX_UID | linux.STATX_GID,
			UID:  3003,
			GID:  4004,
		},
		ClearPrivs: true,
	}); err != nil {
		t.Fatalf("SetStatAt lchown: %v", err)
	}
	// Linux forbids user.* xattrs on symlinks; trusted.* requires CAP_SYS_ADMIN.
	wantErrno(t, "user.* xattr on host symlink", e.setXattr("userlink", "user.k", "v1", 0), linuxerr.EPERM)
	if err := e.setXattr("userlink", "trusted.k", "v1", 0); err != nil {
		t.Fatalf("setXattr on host symlink: %v", err)
	}
	if got := mustGetXattr(t, e, "userlink", "trusted.k"); got != "v1" {
		t.Fatalf("getXattr(userlink) = %q, want v1", got)
	}

	// Orphan GC must keep live host-symlink metadata records.
	e.ws.orphanPass()
	if err := e.ws.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	cleanup()

	// Reopen and verify UID/GID/xattr persisted and ReadMeta resolves it.
	recs, err := ReadMeta(filepath.Join(dir, MetaFileName))
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	recAttr, ok := recs["userlink"]
	if !ok || recAttr.UID != 3003 || recAttr.GID != 4004 || recAttr.Symlink != "" || string(recAttr.Xattrs["trusted.k"]) != "v1" {
		t.Fatalf("ReadMeta[userlink] = %+v (ok=%v), want UID=3003 GID=4004 Symlink=\"\" xattr=v1", recAttr, ok)
	}

	e2, cleanup2 := openContainedEnv(t, dir)
	defer cleanup2()
	st2, err := e2.lstat("userlink")
	if err != nil {
		t.Fatalf("lstat after reopen: %v", err)
	}
	if st2.UID != 3003 || st2.GID != 4004 || st2.Mode&0o777 != 0o777 {
		t.Errorf("reopened lstat = mode %#o %d:%d, want 0777 3003:4004", st2.Mode&0o777, st2.UID, st2.GID)
	}
	if got := mustGetXattr(t, e2, "userlink", "trusted.k"); got != "v1" {
		t.Errorf("reopened xattr = %q, want v1", got)
	}
	if got := mustReadlink(t, e2, "userlink"); got != "target" {
		t.Errorf("reopened readlink = %q, want target", got)
	}

	// Delete host symlink externally and confirm orphan GC reaps its record.
	if err := os.Remove(e2.host("userlink")); err != nil {
		t.Fatalf("os.Remove: %v", err)
	}
	e2.ws.orphanPass()
	if err := e2.ws.Sync(); err != nil {
		t.Fatalf("Sync after orphan GC: %v", err)
	}
	recsAfter, err := ReadMeta(filepath.Join(dir, MetaFileName))
	if err != nil {
		t.Fatalf("ReadMeta after orphan GC: %v", err)
	}
	if _, stillPresent := recsAfter["userlink"]; stillPresent {
		t.Errorf("orphan GC failed to reap deleted host symlink record: %+v", recsAfter)
	}
}

func TestVirtualSymlinksQueryAPI(t *testing.T) {
	dir := t.TempDir()

	// Missing .gvx_meta returns empty list without error.
	empty, err := VirtualSymlinksAt(filepath.Join(dir, MetaFileName), dir)
	if err != nil || len(empty) != 0 {
		t.Fatalf("VirtualSymlinksAt(empty) = (%v, %v), want (nil, nil)", empty, err)
	}
	if _, err := VirtualSymlinksAt(filepath.Join(dir, MetaFileName), filepath.Join(dir, "missing")); err == nil {
		t.Fatal("VirtualSymlinksAt(missing workspace) succeeded, want error")
	}

	e, cleanup := openContainedEnv(t, dir)
	e.mustMkdir("sub")
	e.writeFile("sub/f", []byte("x"))
	if err := e.symlink("sub/virt_abs", "/bin/sh"); err != nil {
		t.Fatalf("symlink virt_abs: %v", err)
	}
	if err := e.symlink("sub/contained", "f"); err != nil {
		t.Fatalf("symlink contained: %v", err)
	}
	if err := e.symlink("root_virt", "../../out"); err != nil {
		t.Fatalf("symlink root_virt: %v", err)
	}
	// Rename parent directory and verify VirtualSymlinks reports live post-rename paths.
	if err := e.rename("sub", "renamed_sub"); err != nil {
		t.Fatalf("rename sub: %v", err)
	}
	if err := e.ws.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	want := []VirtualSymlink{
		{Path: "renamed_sub/virt_abs", Target: "/bin/sh"},
		{Path: "root_virt", Target: "../../out"},
	}
	if runtime.GOOS == "windows" {
		want = []VirtualSymlink{
			{Path: "renamed_sub/contained", Target: "f"},
			{Path: "renamed_sub/virt_abs", Target: "/bin/sh"},
			{Path: "root_virt", Target: "../../out"},
		}
	}

	gotLive, err := e.ws.VirtualSymlinks()
	if err != nil {
		t.Fatalf("Workspace.VirtualSymlinks: %v", err)
	}
	if !reflect.DeepEqual(gotLive, want) {
		t.Errorf("Workspace.VirtualSymlinks() = %+v, want %+v", gotLive, want)
	}
	cleanup()

	gotOffline, err := VirtualSymlinksAt(filepath.Join(dir, MetaFileName), dir)
	if err != nil {
		t.Fatalf("VirtualSymlinksAt: %v", err)
	}
	if !reflect.DeepEqual(gotOffline, want) {
		t.Errorf("VirtualSymlinksAt() = %+v, want %+v", gotOffline, want)
	}
}

func TestSymlinkContainedNameCodecAndDarwinMaxLenFallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-only test")
	}

	// Modeled case-insensitive volume: case collision on link name or target falls back to virtual.
	dir := t.TempDir()
	caps := WorkspaceCaps{
		CaseSensitive: false,
		StableIDs:     true,
	}
	opts := volumeOptions(caps, true, false, false)
	opts.symlinkMode = SymlinkContained
	opts.noOrphanGC = true
	e, cleanup := openEnvAt(t, dir, opts)
	defer cleanup()

	e.writeFile("readme.md", []byte("lower"))
	e.writeFile("README.md", []byte("upper"))

	// Target "README.md" is stored under a ~gvx~ escape on the host, so a host
	// symlink would resolve to "readme.md". Fall back to virtual.
	if err := e.symlink("to_upper", "README.md"); err != nil {
		t.Fatalf("symlink to_upper: %v", err)
	}
	if _, err := os.Lstat(e.host("to_upper")); !os.IsNotExist(err) {
		t.Fatalf("case-colliding target symlink materialized on host: %v", err)
	}
	if got := string(e.readFile("to_upper")); got != "upper" {
		t.Errorf("readFile(to_upper) = %q, want upper", got)
	}

	// Link name colliding in case with existing file ("lower" vs "LOWER") must fall back to virtual.
	e.writeFile("lower", []byte("a"))
	if err := e.symlink("LOWER", "readme.md"); err != nil {
		t.Fatalf("symlink LOWER: %v", err)
	}
	if got := mustReadlink(t, e, "LOWER"); got != "readme.md" {
		t.Errorf("readlink(LOWER) = %q, want readme.md", got)
	}
	vlinks, err := e.ws.VirtualSymlinks()
	if err != nil {
		t.Fatalf("VirtualSymlinks: %v", err)
	}
	foundLower := false
	for _, vl := range vlinks {
		if vl.Path == "LOWER" {
			foundLower = true
		}
	}
	if !foundLower {
		t.Errorf("case-colliding link LOWER not found in VirtualSymlinks: %+v", vlinks)
	}

	// Long target (> 1023 bytes) succeeds on macOS by falling back to virtual.
	longTarget := strings.Repeat("a/", 600) + "leaf"
	if err := e.symlink("longlink", longTarget); err != nil {
		t.Fatalf("symlink(longlink): %v", err)
	}
	if got := mustReadlink(t, e, "longlink"); got != longTarget {
		t.Errorf("readlink(longlink) len = %d, want %d", len(got), len(longTarget))
	}
	if runtime.GOOS == "darwin" {
		if _, err := os.Lstat(e.host("longlink")); !os.IsNotExist(err) {
			t.Errorf("darwin >1023-byte target materialized on host: %v", err)
		}
	}
}

func assertAllHostSymlinksContained(t *testing.T, rootDir string) {
	t.Helper()
	if err := filepath.WalkDir(rootDir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.Type()&fs.ModeSymlink == 0 {
			return nil
		}
		rel, err := filepath.Rel(rootDir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		target, err := os.Readlink(p)
		if err != nil {
			return err
		}
		if _, ok := classifyContainedTarget(rel, target); !ok {
			t.Errorf("unsafe host symlink on disk: %q -> %q", rel, target)
		}
		return nil
	}); err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
}

func TestSymlinkContainedMultiSandboxConcurrentRenameRace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-only multi-sandbox symlinkat race test")
	}
	dir := t.TempDir()
	wsA, err := OpenWorkspaceWithOptions(dir, OpenOptions{SymlinkMode: SymlinkContained})
	if err != nil {
		t.Fatalf("open wsA: %v", err)
	}
	defer wsA.Close()
	wsB, err := OpenWorkspaceWithOptions(dir, OpenOptions{SymlinkMode: SymlinkContained})
	if err != nil {
		t.Fatalf("open wsB: %v", err)
	}
	defer wsB.Close()

	if err := wsA.MkdirAll("a/b/c", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := wsA.MkdirAll("pkg/bin", 0o755); err != nil {
		t.Fatalf("MkdirAll pkg/bin: %v", err)
	}
	if err := wsA.WriteFile("pkg/bin/tool", []byte("ok"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Warm wsA's dirPin for a/b/c so stale-pin revalidation is exercised directly.
	if _, _, err := wsA.Stat("a/b/c"); err != nil {
		t.Fatalf("warm Stat(a/b/c): %v", err)
	}

	const iters = 40
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range iters {
			name := "a/b/c/l" + string(rune('a'+i%26))
			_ = wsA.Symlink("../../../pkg/bin/tool/x", name)
			_ = wsA.Unlink(name)
		}
	}()
	go func() {
		defer wg.Done()
		for range iters {
			_ = wsB.Rename("a/b/c", "c")
			_ = wsB.Rename("c", "a/b/c")
		}
	}()
	wg.Wait()

	assertAllHostSymlinksContained(t, dir)
}

func TestSymlinkContainedMultiSandboxTypeSwapAndRetargetRace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-only multi-sandbox race test")
	}
	dir := t.TempDir()
	wsA, err := OpenWorkspaceWithOptions(dir, OpenOptions{SymlinkMode: SymlinkContained})
	if err != nil {
		t.Fatalf("open wsA: %v", err)
	}
	defer wsA.Close()
	wsB, err := OpenWorkspaceWithOptions(dir, OpenOptions{SymlinkMode: SymlinkContained})
	if err != nil {
		t.Fatalf("open wsB: %v", err)
	}
	defer wsB.Close()

	if err := wsA.MkdirAll("a/b", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := wsA.MkdirAll("pkg/bin", 0o755); err != nil {
		t.Fatalf("MkdirAll pkg/bin: %v", err)
	}
	if err := wsA.WriteFile("pkg/bin/tool", []byte("ok"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := wsA.WriteFile("a/b/sibling", []byte("sib"), 0o644); err != nil {
		t.Fatalf("WriteFile sibling: %v", err)
	}
	if err := wsA.WriteFile("shallow_swap", []byte("sw"), 0o644); err != nil {
		t.Fatalf("WriteFile shallow_swap: %v", err)
	}

	const iters = 50
	var wg sync.WaitGroup
	wg.Add(4)
	// Race 1: wsA renames a/b/f to root while wsB swaps a/b/f between regular file and climbing symlink.
	go func() {
		defer wg.Done()
		for range iters {
			_ = wsA.Rename("a/b/f", "f_moved")
			_ = wsA.Unlink("f_moved")
		}
	}()
	// Race 2: wsA exchanges a/b/l with shallow_swap while wsB retargets a/b/l.
	go func() {
		defer wg.Done()
		for range iters {
			_, _ = wsA.exchange("a/b/l", "shallow_swap")
		}
	}()
	// Race 3: wsA hard-links a/b/f to root while wsB swaps a/b/f between regular file and climbing symlink.
	go func() {
		defer wg.Done()
		for range iters {
			_ = wsA.link("a/b/f", "f_linked")
			_ = wsA.Unlink("f_linked")
		}
	}()
	go func() {
		defer wg.Done()
		for i := range iters {
			_ = wsB.Unlink("a/b/f")
			if i%2 == 0 {
				_ = wsB.WriteFile("a/b/f", []byte("reg"), 0o644)
			} else {
				_ = wsB.Symlink("../../pkg/bin/tool", "a/b/f")
			}
			_ = wsB.Unlink("a/b/l")
			if i%2 == 0 {
				_ = wsB.Symlink("sibling", "a/b/l")
			} else {
				_ = wsB.Symlink("../../pkg/bin/tool", "a/b/l")
			}
		}
	}()
	wg.Wait()

	assertAllHostSymlinksContained(t, dir)
}

func TestRenameAndExchangeRemapOverridesAndHiddenShadowedLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-only native host symlink test")
	}
	dir := t.TempDir()
	e, cleanup := openContainedEnv(t, dir)
	defer cleanup()

	// 1. Override remapping across directory rename catches symlink cycles formed
	// only at the destination directory path (dirA renamed to dirB).
	e.mkdirChain("dirA/x")
	if err := e.symlink("dirA/x/a", "../../dirB/x/b"); err != nil {
		t.Fatalf("symlink dirA/x/a: %v", err)
	}
	if err := e.symlink("dirA/x/b", "../../dirB/x/a"); err != nil {
		t.Fatalf("symlink dirA/x/b: %v", err)
	}
	if err := e.rename("dirA", "dirB"); err != nil {
		t.Fatalf("rename(dirA, dirB): %v", err)
	}
	if _, err := os.Lstat(e.host("dirB/x/a")); !os.IsNotExist(err) {
		t.Errorf("post-rename cycle link dirB/x/a stayed on host: %v", err)
	}
	if _, err := os.Lstat(e.host("dirB/x/b")); !os.IsNotExist(err) {
		t.Errorf("post-rename cycle link dirB/x/b stayed on host: %v", err)
	}
	if got := mustReadlink(t, e, "dirB/x/a"); got != "../../dirB/x/b" {
		t.Errorf("readlink(dirB/x/a) = %q, want ../../dirB/x/b", got)
	}

	// 2. Hidden-name host symlink inside a directory blocks rename with EACCES.
	e.mustMkdir("hid_name")
	if err := os.Symlink("../../outside_secret", e.host("hid_name/~gvx~secret")); err != nil {
		t.Fatalf("seed hidden-name symlink: %v", err)
	}
	wantErrno(t, "rename dir with hidden-name unsafe symlink", e.rename("hid_name", "hid_name2"), linuxerr.EACCES)

	// 3. Hidden-name subdirectory holding an escaping host symlink blocks rename with EACCES.
	e.mustMkdir("hid_subdir")
	if err := os.Mkdir(e.host("hid_subdir/.gvx_tmp_dir"), 0o755); err != nil {
		t.Fatalf("mkdir hidden subdir: %v", err)
	}
	if err := os.Symlink("../../../outside_secret", e.host("hid_subdir/.gvx_tmp_dir/esc")); err != nil {
		t.Fatalf("seed symlink in hidden subdir: %v", err)
	}
	wantErrno(t, "rename dir with hidden subdir escaping symlink", e.rename("hid_subdir", "hid_subdir2"), linuxerr.EACCES)

	// 4. Host symlink shadowed by a virtual symlink blocks shallower directory rename with EACCES.
	e.mkdirChain("shd/deep")
	e.mustMkdir("pkg")
	e.writeFile("pkg/tool", []byte("ok"))
	if err := e.symlink("shd/deep/shadowed", "/guest/virtual/target"); err != nil {
		t.Fatalf("create virtual symlink: %v", err)
	}
	if err := os.Symlink("../../pkg/tool", e.host("shd/deep/shadowed")); err != nil {
		t.Fatalf("seed shadowed host symlink: %v", err)
	}
	wantErrno(t, "rename dir with shadowed unsafe host symlink", e.rename("shd/deep", "shd_shallow"), linuxerr.EACCES)
}

func TestSymlinkRenameAndExchangeDemotionKeepOPathFDAndMetadata(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-only native host symlink test")
	}
	dir := t.TempDir()
	e, cleanup := openContainedEnv(t, dir)
	defer cleanup()

	e.mkdirChain("deep/sub")
	e.mustMkdir("pkg")
	e.writeFile("pkg/bin", []byte("x"))
	if err := e.symlink("deep/sub/l", "../../pkg/bin/item"); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// Open O_PATH|O_NOFOLLOW FD on the native host symlink before demoting rename.
	fd, err := e.open("deep/sub/l", linux.O_PATH|linux.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatalf("open O_PATH: %v", err)
	}
	defer fd.DecRef(e.ctx)

	// Rename to root demotes the host symlink to virtual in place.
	if err := e.rename("deep/sub/l", "l"); err != nil {
		t.Fatalf("rename: %v", err)
	}

	// Open O_PATH FD must remain live and usable.
	st, err := fd.Stat(e.ctx, vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil {
		t.Fatalf("O_PATH fd.Stat after demotion: %v", err)
	}
	if st.Mode&linux.S_IFMT != linux.S_IFLNK {
		t.Errorf("O_PATH fd.Stat mode = %#o, want S_IFLNK", st.Mode)
	}
	if err := e.setXattr("l", "trusted.after", "yes", 0); err != nil {
		t.Fatalf("setXattr after demotion: %v", err)
	}
	if got := mustGetXattr(t, e, "l", "trusted.after"); got != "yes" {
		t.Errorf("getXattr after demotion = %q, want yes", got)
	}
	if got := mustReadlink(t, e, "l"); got != "../../pkg/bin/item" {
		t.Errorf("readlink after demotion = %q, want ../../pkg/bin/item", got)
	}

	// Verify top-level RENAME_EXCHANGE demotion refreshes live metadata key and preserves O_PATH FD.
	if err := e.symlink("deep/sub/exl", "../../pkg/bin/item"); err != nil {
		t.Fatalf("symlink exl: %v", err)
	}
	if err := e.ws.Chown("deep/sub/exl", 777, 888); err != nil {
		t.Fatalf("Chown exl: %v", err)
	}
	if err := e.setXattr("deep/sub/exl", "trusted.ex", "keep", 0); err != nil {
		t.Fatalf("setXattr exl: %v", err)
	}
	e.writeFile("root_target", []byte("swapme"))
	exFD, err := e.open("deep/sub/exl", linux.O_PATH|linux.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatalf("open O_PATH exl: %v", err)
	}
	defer exFD.DecRef(e.ctx)

	if err := e.renameFlags("deep/sub/exl", "root_target", linux.RENAME_EXCHANGE); err != nil {
		t.Fatalf("RENAME_EXCHANGE exl: %v", err)
	}
	if _, err := os.Lstat(e.host("root_target")); !os.IsNotExist(err) {
		t.Fatalf("exchanged climbing symlink still exists on host: %v", err)
	}
	exSt, err := exFD.Stat(e.ctx, vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil {
		t.Fatalf("O_PATH exFD.Stat after exchange demotion: %v", err)
	}
	if exSt.Mode&linux.S_IFMT != linux.S_IFLNK || exSt.UID != 777 || exSt.GID != 888 {
		t.Errorf("O_PATH exFD.Stat = mode %#o %d:%d, want S_IFLNK 777:888", exSt.Mode, exSt.UID, exSt.GID)
	}
	if got := mustGetXattr(t, e, "root_target", "trusted.ex"); got != "keep" {
		t.Errorf("getXattr(root_target, trusted.ex) = %q, want keep", got)
	}
	if err := e.setXattr("root_target", "trusted.after_ex", "ok", 0); err != nil {
		t.Fatalf("setXattr(root_target, trusted.after_ex): %v", err)
	}
	if got := mustGetXattr(t, e, "root_target", "trusted.after_ex"); got != "ok" {
		t.Errorf("getXattr(root_target, trusted.after_ex) = %q, want ok", got)
	}

	// Verify closed workspace fails closed under withMetaExclusiveLocked.
	if err := e.ws.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := e.ws.Symlink("pkg/bin", "after_close"); !errors.Is(err, os.ErrClosed) {
		t.Errorf("Symlink after Close = %v, want os.ErrClosed", err)
	}
}
