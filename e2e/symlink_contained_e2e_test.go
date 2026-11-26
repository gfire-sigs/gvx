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
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/hostfs"
)

func buildE2EGuestSymlinkProbeELF(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable for compiling guest symlink probe")
	}
	srcDir := t.TempDir()
	src := `package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func must(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
		os.Exit(1)
	}
}

func main() {
	root := "/work"
	must(os.WriteFile(filepath.Join(root, "README"), []byte("hello\n"), 0o644), "write README")
	for _, dir := range []string{"node_modules/.bin", "node_modules/pkg/bin", "deep/sub"} {
		must(os.MkdirAll(filepath.Join(root, dir), 0o755), "mkdir "+dir)
	}
	must(os.WriteFile(filepath.Join(root, "node_modules/pkg/bin/cli"), []byte("tool\n"), 0o755), "write cli")
	must(os.Symlink("README", filepath.Join(root, "link")), "symlink link")
	must(os.Symlink("../pkg/bin/cli", filepath.Join(root, "node_modules/.bin/cli")), "symlink cli")
	must(os.Symlink("/etc/passwd", filepath.Join(root, "abs_link")), "symlink abs_link")
	must(os.Symlink("../../node_modules/pkg/bin/cli", filepath.Join(root, "deep/sub/move_me")), "symlink move_me")
	must(os.Rename(filepath.Join(root, "deep/sub/move_me"), filepath.Join(root, "demoted_link")), "rename move_me")

	linkData, err := os.ReadFile(filepath.Join(root, "link"))
	must(err, "read link")
	cliData, err := os.ReadFile(filepath.Join(root, "node_modules/.bin/cli"))
	must(err, "read cli")
	absTarget, err := os.Readlink(filepath.Join(root, "abs_link"))
	must(err, "readlink abs_link")
	demotedTarget, err := os.Readlink(filepath.Join(root, "demoted_link"))
	must(err, "readlink demoted_link")

	fmt.Printf("read_link=%s\n", strings.TrimSpace(string(linkData)))
	fmt.Printf("read_cli=%s\n", strings.TrimSpace(string(cliData)))
	fmt.Printf("readlink_abs=%s\n", absTarget)
	fmt.Printf("readlink_demoted=%s\n", demotedTarget)
}
`
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module e2esymprobe\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	outPath := filepath.Join(srcDir, "symprobe")
	cmd := exec.Command("go", "build", "-ldflags=-linkmode=internal", "-o", outPath, ".")
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build guest symlink probe: %v\n%s", err, out)
	}
	return outPath
}

// TestE2EHostfsSymlinkContained verifies opt-in SymlinkContained end-to-end
// offline inside a real guest kernel: contained relative symlinks materialize
// on Unix hosts, non-contained targets stay virtual, and depth-reducing renames
// demote climbing links before touching the host directory.
func TestE2EHostfsSymlinkContained(t *testing.T) {
	probeBin := buildE2EGuestSymlinkProbeELF(t)

	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			workDir := t.TempDir()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			var stdout, stderr bytes.Buffer
			sb, err := gvx.New(ctx, gvx.Config{
				Platform:    b.plat,
				NetworkMode: gvx.NetModeNone,
				OCICacheDir: t.TempDir(),
				BinaryPath:  probeBin,
				Argv:        []string{"/bin/symprobe"},
				Mounts: []gvx.Mount{{
					Kind:        gvx.MountBind,
					HostPath:    workDir,
					GuestPath:   "/work",
					SymlinkMode: gvx.SymlinkContained,
				}},
				Stdout:              &stdout,
				Stderr:              &stderr,
				DisableHostLockdown: true,
			})
			skipWhenFixedAddressRefused(t, "New(symprobe)", err)
			defer func() {
				if cerr := sb.Close(); cerr != nil {
					t.Errorf("Close: %v", cerr)
				}
			}()
			code, err := sb.Run(ctx)
			skipWhenFixedAddressRefused(t, "Run(symprobe)", err)
			if code != 0 {
				t.Fatalf("symprobe exited %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
			}

			requireContains(t, "guest symlink output", stdout.String(),
				"read_link=hello\n",
				"read_cli=tool\n",
				"readlink_abs=/etc/passwd\n",
				"readlink_demoted=../../node_modules/pkg/bin/cli\n",
			)

			if runtime.GOOS != "windows" {
				for rel, want := range map[string]string{
					"link":                  "README",
					"node_modules/.bin/cli": "../pkg/bin/cli",
				} {
					got, err := os.Readlink(filepath.Join(workDir, filepath.FromSlash(rel)))
					if err != nil || got != want {
						t.Errorf("host Readlink(%s) = (%q, %v), want (%q, nil)", rel, got, err, want)
					}
				}
			}
			for _, rel := range []string{"abs_link", "demoted_link"} {
				if _, err := os.Lstat(filepath.Join(workDir, rel)); !os.IsNotExist(err) {
					t.Errorf("virtual symlink %q materialized on host (lstat err=%v)", rel, err)
				}
			}

			vlinks, err := hostfs.VirtualSymlinksAt(filepath.Join(workDir, hostfs.MetaFileName), workDir)
			if err != nil {
				t.Fatalf("VirtualSymlinksAt: %v", err)
			}
			wantVirt := map[string]string{
				"abs_link":     "/etc/passwd",
				"demoted_link": "../../node_modules/pkg/bin/cli",
			}
			if runtime.GOOS == "windows" {
				wantVirt["link"] = "README"
				wantVirt["node_modules/.bin/cli"] = "../pkg/bin/cli"
			}
			if len(vlinks) != len(wantVirt) {
				t.Fatalf("VirtualSymlinksAt = %+v, want %v", vlinks, wantVirt)
			}
			for _, vl := range vlinks {
				if wantVirt[vl.Path] != vl.Target {
					t.Errorf("VirtualSymlinksAt entry %+v mismatch", vl)
				}
			}
		})
	}
}
