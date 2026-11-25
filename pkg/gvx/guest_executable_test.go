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

package gvx

import (
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/ktime"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// TestResolveGuestExecutableUsesWorkingDirectory proves that a relative
// executable path resolves against the working directory, as execve(2) does.
// Images such as qdrant/qdrant set WORKDIR /qdrant and run ./entrypoint.sh.
func TestResolveGuestExecutableUsesWorkingDirectory(t *testing.T) {
	mf := newTestMemoryFile(t, "guest-executable-test")
	clock := &ktime.SyntheticClock{}
	clock.Store(ktime.FromNanoseconds(1_700_000_000_000_000_000))
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	sctx := newTestSentryContext(t, mf, clock, creds)
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(sctx); err != nil {
		t.Fatalf("vfs.Init: %v", err)
	}
	defer vfsObj.Release(sctx)
	if err := registerKernelVFS(vfsObj, nil); err != nil {
		t.Fatalf("registerKernelVFS: %v", err)
	}
	mntns, err := vfsObj.NewMountNamespace(sctx, creds, "", "tmpfs", &vfs.MountOptions{}, nil)
	if err != nil {
		t.Fatalf("NewMountNamespace: %v", err)
	}
	defer mntns.DecRef(sctx)
	sctx = vfs.WithMountNamespace(sctx, mntns)
	root := mntns.Root(sctx)
	defer root.DecRef(sctx)

	for _, file := range []string{
		"/qdrant/entrypoint.sh",
		"/opt/app/bin/tool",
		"/opt/releases/v2/app/start.sh",
		"/opt/releases/v2/shared/run.sh",
		"/usr/bin/sh",
	} {
		if err := vfsEnsureEmptyFile(sctx, vfsObj, creds, root, file, 0o755); err != nil {
			t.Fatalf("create %s: %v", file, err)
		}
	}
	for _, link := range []struct {
		path   string
		target string
	}{
		{path: "/app", target: "/opt/releases/v2/app"},
		{path: "/qdrant/run-link", target: "/opt/releases/v2/shared/run.sh"},
		{path: "/qdrant/broken-link", target: "/no/such/file"},
	} {
		pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(link.path)}
		if err := vfsObj.SymlinkAt(sctx, creds, &pop, link.target); err != nil {
			t.Fatalf("symlink %s -> %s: %v", link.path, link.target, err)
		}
	}

	tests := []struct {
		name    string
		cmd     string
		workDir string
		path    string
		want    string
	}{
		{name: "dot slash below workdir", cmd: "./entrypoint.sh", workDir: "/qdrant", want: "/qdrant/entrypoint.sh"},
		{name: "relative subdirectory", cmd: "bin/tool", workDir: "/opt/app", want: "/opt/app/bin/tool"},
		{name: "parent directory", cmd: "../qdrant/entrypoint.sh", workDir: "/opt", want: "/qdrant/entrypoint.sh"},
		{name: "absolute path ignores workdir", cmd: "/usr/bin/sh", workDir: "/qdrant", want: "/usr/bin/sh"},
		{name: "empty workdir is the root", cmd: "./usr/bin/sh", workDir: "", want: "/usr/bin/sh"},
		{name: "bare name searches PATH", cmd: "sh", workDir: "/qdrant", path: "/usr/bin", want: "/usr/bin/sh"},
		{name: "relative PATH entry", cmd: "tool", workDir: "/opt/app", path: "bin", want: "/opt/app/bin/tool"},
		{name: "empty PATH entry is the workdir", cmd: "entrypoint.sh", workDir: "/qdrant", path: "/usr/bin:", want: "/qdrant/entrypoint.sh"},
		{name: "symlinked workdir traverses real parent", cmd: "../shared/run.sh", workDir: "/app", want: "/opt/releases/v2/shared/run.sh"},
		{name: "symlinked workdir with relative parent PATH", cmd: "run.sh", workDir: "/app", path: "../shared", want: "/opt/releases/v2/shared/run.sh"},
		{name: "absolute path traverses symlink before parent", cmd: "/app/../shared/run.sh", workDir: "/", want: "/app/../shared/run.sh"},
		{name: "relative symlink preserves link path", cmd: "./run-link", workDir: "/qdrant", want: "/qdrant/run-link"},
		{name: "dot slash outside workdir", cmd: "./entrypoint.sh", workDir: "/"},
		{name: "bare name does not search workdir", cmd: "entrypoint.sh", workDir: "/qdrant", path: "/usr/bin"},
		{name: "trailing slash on relative regular file", cmd: "./entrypoint.sh/", workDir: "/qdrant"},
		{name: "trailing slash on absolute regular file", cmd: "/usr/bin/sh/", workDir: "/"},
		{name: "missing intermediate before parent", cmd: "./missing/../entrypoint.sh", workDir: "/qdrant"},
		{name: "missing workdir rejects parent escape", cmd: "../usr/bin/sh", workDir: "/no-such-dir"},
		{name: "non-directory workdir rejects relative lookup", cmd: "./sh", workDir: "/usr/bin/sh"},
		{name: "non-directory workdir rejects dot in empty PATH", cmd: ".", workDir: "/usr/bin/sh", path: ":"},
		{name: "directory is not executable", cmd: "./bin", workDir: "/opt/app"},
		{name: "broken symlink is not executable", cmd: "./broken-link", workDir: "/qdrant"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var envv []string
			if tc.path != "" {
				envv = []string{"PATH=" + tc.path}
			}
			got, err := resolveGuestExecutable(sctx, vfsObj, creds, root, tc.cmd, tc.workDir, envv)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("resolveGuestExecutable(%q, %q) = %q, want an error", tc.cmd, tc.workDir, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("resolveGuestExecutable(%q, %q) = %q, %v; want %q", tc.cmd, tc.workDir, got, err, tc.want)
			}
		})
	}
}
