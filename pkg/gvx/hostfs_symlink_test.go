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
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/fsimpl/hostfs"
)

const (
	symlinkLockdownChildEnv = "GVX_TEST_SYMLINK_LOCKDOWN_CHILD"
	symlinkLockdownWSEnv    = "GVX_TEST_SYMLINK_LOCKDOWN_WS"
)

func TestMountSymlinkModeConfigValidation(t *testing.T) {
	t.Setenv(VolumeDirEnv, t.TempDir())
	wsDir := t.TempDir()
	filePath := filepath.Join(t.TempDir(), "single.txt")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	invalidConfigs := []struct {
		name string
		cfg  Config
	}{
		{
			name: "WorkspaceSymlinkMode without WorkspacePath",
			cfg:  Config{WorkspaceSymlinkMode: SymlinkContained},
		},
		{
			name: "invalid WorkspaceSymlinkMode",
			cfg:  Config{WorkspacePath: wsDir, WorkspaceSymlinkMode: "invalid"},
		},
		{
			name: "invalid Mount.SymlinkMode",
			cfg:  Config{Mounts: []Mount{{Kind: MountBind, HostPath: wsDir, GuestPath: "/w", SymlinkMode: "invalid"}}},
		},
		{
			name: "SymlinkMode on tmpfs",
			cfg:  Config{Mounts: []Mount{{Kind: MountTmpfs, GuestPath: "/t", SymlinkMode: SymlinkContained}}},
		},
		{
			name: "SymlinkMode on overlay",
			cfg:  Config{Mounts: []Mount{{Kind: MountOverlay, VolumeName: "base", GuestPath: "/ov", SymlinkMode: SymlinkContained}}},
		},
		{
			name: "SymlinkMode on explicit ext4lite volume",
			cfg:  Config{Mounts: []Mount{{Kind: MountVolume, VolumeName: "vol", Driver: DriverExt4lite, GuestPath: "/v", SymlinkMode: SymlinkContained}}},
		},
		{
			name: "SymlinkMode on default ext4lite volume",
			cfg:  Config{Mounts: []Mount{{Kind: MountVolume, VolumeName: "vol", GuestPath: "/v", SymlinkMode: SymlinkContained}}},
		},
		{
			name: "SymlinkMode on ephemeral volume",
			cfg:  Config{Mounts: []Mount{{Kind: MountVolume, Ephemeral: true, GuestPath: "/v", SymlinkMode: SymlinkContained}}},
		},
		{
			name: "SymlinkMode on image path volume",
			cfg:  Config{Mounts: []Mount{{Kind: MountVolume, ImagePath: filepath.Join(t.TempDir(), "v.ext4"), GuestPath: "/v", SymlinkMode: SymlinkContained}}},
		},
		{
			name: "SymlinkMode on single-file bind mount",
			cfg:  Config{Mounts: []Mount{{Kind: MountBind, HostPath: filePath, GuestPath: "/f", SymlinkMode: SymlinkContained}}},
		},
	}

	for _, tc := range invalidConfigs {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			err := cfg.normalize()
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("normalize() = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestOpenMountsSymlinkModeConflictValidation(t *testing.T) {
	wsDir := t.TempDir()

	cfg := Config{Mounts: []Mount{
		{Kind: MountBind, HostPath: wsDir, GuestPath: "/a", SymlinkMode: SymlinkContained},
		{Kind: MountBind, HostPath: wsDir, GuestPath: "/b", SymlinkMode: SymlinkVirtual},
	}}
	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	sb := &Sandbox{cfg: cfg}
	t.Cleanup(func() { _ = sb.closeMounts() })
	if err := sb.openMounts(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("openMounts(conflicting SymlinkMode) = %v, want ErrInvalidConfig", err)
	}

	// Matching SymlinkMode across RO and RW mounts of one host directory succeeds.
	cfgOK := Config{Mounts: []Mount{
		{Kind: MountBind, HostPath: wsDir, GuestPath: "/ro", ReadOnly: true, SymlinkMode: SymlinkContained},
		{Kind: MountBind, HostPath: wsDir, GuestPath: "/rw", ReadOnly: false, SymlinkMode: SymlinkContained},
	}}
	if err := cfgOK.normalize(); err != nil {
		t.Fatalf("normalize(matching): %v", err)
	}
	sbOK := &Sandbox{cfg: cfgOK}
	t.Cleanup(func() { _ = sbOK.closeMounts() })
	if err := sbOK.openMounts(); err != nil {
		t.Fatalf("openMounts(matching): %v", err)
	}
	for _, ws := range sbOK.workspaces {
		if ws.SymlinkMode() != hostfs.SymlinkContained {
			t.Errorf("workspace SymlinkMode() = %q, want %q", ws.SymlinkMode(), hostfs.SymlinkContained)
		}
	}
}

func TestParseMountSymlinksOption(t *testing.T) {
	wsDir := t.TempDir()
	m, err := ParseMount("type=bind,src=" + wsDir + ",dst=/work,symlinks=contained")
	if err != nil {
		t.Fatalf("ParseMount(bind contained): %v", err)
	}
	if m.SymlinkMode != SymlinkContained {
		t.Errorf("SymlinkMode = %q, want %q", m.SymlinkMode, SymlinkContained)
	}

	mVol, err := ParseMount("type=volume,src=myvol,dst=/vol,driver=hostfs,symlinks=virtual")
	if err != nil {
		t.Fatalf("ParseMount(hostfs volume virtual): %v", err)
	}
	if mVol.SymlinkMode != SymlinkVirtual {
		t.Errorf("SymlinkMode = %q, want %q", mVol.SymlinkMode, SymlinkVirtual)
	}

	badSpecs := []string{
		"type=bind,src=" + wsDir + ",dst=/work,symlinks=",
		"type=bind,src=" + wsDir + ",dst=/work,symlinks",
		"type=bind,src=" + wsDir + ",dst=/work,symlinks=bogus",
		"type=bind,src=" + wsDir + ",dst=/work,symlinks=contained,symlinks=virtual",
		"type=tmpfs,dst=/tmp,symlinks=contained",
		"type=overlay,src=base,dst=/ov,symlinks=contained",
		"type=volume,src=v,dst=/v,driver=ext4lite,symlinks=contained",
		"type=volume,ephemeral,dst=/v,symlinks=contained",
		"type=volume,src=/tmp/v.ext4,dst=/v,symlinks=contained",
	}
	for _, spec := range badSpecs {
		if _, err := ParseMount(spec); err == nil {
			t.Errorf("ParseMount(%q) succeeded, want error", spec)
		}
	}
}

func TestSymlinkContainedWorksUnderHostLockdown(t *testing.T) {
	if os.Getenv(symlinkLockdownChildEnv) == "1" {
		wsDir := os.Getenv(symlinkLockdownWSEnv)
		cfg := Config{
			NetworkMode:          NetModeNone,
			WorkspacePath:        wsDir,
			WorkspaceSymlinkMode: SymlinkContained,
		}
		if err := cfg.normalize(); err != nil {
			t.Fatalf("normalize: %v", err)
		}
		sb := &Sandbox{cfg: cfg}
		if err := sb.openMounts(); err != nil {
			t.Fatalf("openMounts: %v", err)
		}
		defer func() {
			if err := sb.closeMounts(); err != nil {
				t.Fatalf("closeMounts: %v", err)
			}
		}()

		st, err := applyHostfsTestLockdownOpts(sb.lockdownOptions())
		if err != nil {
			t.Fatalf("applyHostfsTestLockdownOpts: %v", err)
		}
		installHostLockdownBridges()
		if !st.Applied || !st.SubprocessBlocked {
			t.Fatalf("lockdown status = %+v, want Applied && SubprocessBlocked", st)
		}
		if runtime.GOOS != "android" && !st.UnboundFileOpenBlocked {
			t.Fatalf("lockdown status = %+v, want UnboundFileOpenBlocked", st)
		}

		if err := sb.workspace.WriteFile("README", []byte("hi"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := sb.workspace.MkdirAll("sub/bin", 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := sb.workspace.Symlink("README", "link"); err != nil {
			t.Fatalf("Symlink(link) under lockdown: %v", err)
		}
		if err := sb.workspace.Symlink("../../sub/bin/tool", "sub/bin/nested"); err != nil {
			t.Fatalf("Symlink(nested) under lockdown: %v", err)
		}
		if err := sb.workspace.Symlink("/etc/passwd", "abs"); err != nil {
			t.Fatalf("Symlink(abs) under lockdown: %v", err)
		}
		if err := sb.workspace.Rename("sub/bin/nested", "demoted"); err != nil {
			t.Fatalf("Rename(demoted) under lockdown: %v", err)
		}
		if err := sb.workspace.Sync(); err != nil {
			t.Fatalf("Sync under lockdown: %v", err)
		}
		return
	}

	wsDir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.v", "-test.run=^TestSymlinkContainedWorksUnderHostLockdown$")
	cmd.Env = append(os.Environ(),
		symlinkLockdownChildEnv+"=1",
		symlinkLockdownWSEnv+"="+wsDir,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("locked child failed: %v\n%s", err, out)
	}

	if runtime.GOOS != "windows" {
		got, err := os.Readlink(filepath.Join(wsDir, "link"))
		if err != nil || got != "README" {
			t.Fatalf("host Readlink(link) = (%q, %v), want (README, nil)", got, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(wsDir, "abs")); !os.IsNotExist(err) {
		t.Errorf("absolute symlink abs materialized on host: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(wsDir, "demoted")); !os.IsNotExist(err) {
		t.Errorf("demoted symlink exists on host: %v", err)
	}
	vlinks, err := hostfs.VirtualSymlinksAt(filepath.Join(wsDir, hostfs.MetaFileName), wsDir)
	if err != nil {
		t.Fatalf("VirtualSymlinksAt: %v", err)
	}
	wantPaths := map[string]string{"abs": "/etc/passwd", "demoted": "../../sub/bin/tool"}
	if runtime.GOOS == "windows" {
		wantPaths["link"] = "README"
	}
	if len(vlinks) != len(wantPaths) {
		t.Fatalf("VirtualSymlinksAt = %+v, want %v", vlinks, wantPaths)
	}
	for _, vl := range vlinks {
		if wantPaths[vl.Path] != vl.Target {
			t.Errorf("VirtualSymlinksAt entry %+v mismatch", vl)
		}
	}
}
