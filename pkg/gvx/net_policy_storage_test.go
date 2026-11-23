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
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestProtectedStorageOpensDisjointWorkspaceAndBundle(t *testing.T) {
	if runtime.GOOS == "android" {
		t.Skip("Android does not permit openat2 for live hostfs mounts")
	}
	base := t.TempDir()
	workspace := filepath.Join(base, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(base, "control.token")
	if err := os.WriteFile(tokenPath, []byte("control fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := os.Open(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = token.Close() })
	sb := &Sandbox{cfg: Config{
		WorkspacePath: workspace,
		CheckpointDir: filepath.Join(base, "checkpoint", "bundle"),
		NetPolicy: &NetPolicyOptions{ControlPaths: []string{tokenPath}, ControlFiles: []*os.File{token},
			Policy: NetPolicyConfig{RulesV4: policyAllowAll, RulesV6: policyAllowAll}},
	}}
	t.Cleanup(func() {
		if err := sb.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := sb.initNetPolicy(nil); err != nil {
		t.Fatal(err)
	}
	if err := sb.openMounts(); err != nil {
		t.Fatal(err)
	}
	if err := sb.workspace.WriteFile("work.txt", []byte("workspace fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb.ckptFiles, err = sb.openCheckpointOutput()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sb.ckptFiles.manifest.WriteString("bundle fixture"); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		filepath.Join(workspace, "work.txt"):                            "workspace fixture",
		filepath.Join(sb.cfg.CheckpointDir, checkpointManifestFileName): "bundle fixture",
		tokenPath: "control fixture",
	} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Errorf("read %q = %q, %v; want %q", path, got, err, want)
		}
	}
}

func TestProtectedStorageRejectsWorkspaceInsideBundle(t *testing.T) {
	base := t.TempDir()
	workspace := filepath.Join(base, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	sb := &Sandbox{cfg: Config{
		WorkspacePath: workspace,
		CheckpointDir: base,
		NetPolicy:     &NetPolicyOptions{Policy: NetPolicyConfig{RulesV4: policyAllowAll, RulesV6: policyAllowAll}},
	}}
	t.Cleanup(func() { _ = sb.Close() })
	if err := sb.initNetPolicy(nil); err != nil {
		t.Fatal(err)
	}
	if err := sb.openMounts(); !errors.Is(err, ErrInvalidConfig) || NetPolicyErrorCode(err) != "invalid_policy" {
		t.Fatalf("open workspace inside private bundle: %v; want invalid_policy", err)
	}
	if entries, err := os.ReadDir(workspace); err != nil || len(entries) != 0 {
		t.Fatalf("rejected workspace contains %v, %v; want no entries", entries, err)
	}
}

func TestProtectedStorageRejectsMismatchedControlFile(t *testing.T) {
	base := t.TempDir()
	named := filepath.Join(base, "approved.token")
	opened := filepath.Join(base, "other.token")
	for _, name := range []string{named, opened} {
		if err := os.WriteFile(name, []byte("control fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(opened)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sb := &Sandbox{cfg: Config{NetPolicy: &NetPolicyOptions{
		ControlPaths: []string{named}, ControlFiles: []*os.File{f},
		Policy: NetPolicyConfig{RulesV4: policyAllowAll, RulesV6: policyAllowAll},
	}}}
	t.Cleanup(func() { _ = sb.Close() })
	if err := sb.initNetPolicy(nil); !errors.Is(err, ErrInvalidConfig) || NetPolicyErrorCode(err) != "invalid_policy" {
		t.Fatalf("initialize with a different control descriptor: %v; want invalid_policy", err)
	}
}
