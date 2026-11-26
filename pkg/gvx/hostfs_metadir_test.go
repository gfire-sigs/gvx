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
	"sync"
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/fsimpl/hostfs"
)

const (
	metaDirLockdownChildEnv = "GVX_TEST_METADIR_LOCKDOWN_CHILD"
	metaDirLockdownWSEnv    = "GVX_TEST_METADIR_LOCKDOWN_WS"
	metaDirLockdownMetaEnv  = "GVX_TEST_METADIR_LOCKDOWN_META"
)

func isCaseInsensitiveVolume(t *testing.T, dir string) bool {
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

func TestMountMetaDirConfigValidation(t *testing.T) {
	t.Setenv(VolumeDirEnv, t.TempDir())
	wsDir := t.TempDir()
	metaDir := t.TempDir()
	filePath := filepath.Join(t.TempDir(), "single.txt")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fsRoot := string(filepath.Separator)
	if runtime.GOOS == "windows" {
		fsRoot = filepath.VolumeName(wsDir) + `\`
	}

	cases := []struct {
		name string
		cfg  Config
	}{
		{
			name: "WorkspaceMetaDir without WorkspacePath",
			cfg:  Config{WorkspaceMetaDir: metaDir},
		},
		{
			name: "WorkspaceMetaDir missing",
			cfg:  Config{WorkspacePath: wsDir, WorkspaceMetaDir: filepath.Join(t.TempDir(), "nope")},
		},
		{
			name: "WorkspaceMetaDir is a file",
			cfg:  Config{WorkspacePath: wsDir, WorkspaceMetaDir: filePath},
		},
		{
			name: "WorkspaceMetaDir is filesystem root",
			cfg:  Config{WorkspacePath: wsDir, WorkspaceMetaDir: fsRoot},
		},
		{
			name: "MetaDir on tmpfs",
			cfg:  Config{Mounts: []Mount{{Kind: MountTmpfs, GuestPath: "/t", MetaDir: metaDir}}},
		},
		{
			name: "MetaDir on overlay",
			cfg:  Config{Mounts: []Mount{{Kind: MountOverlay, VolumeName: "base", GuestPath: "/ov", MetaDir: metaDir}}},
		},
		{
			name: "MetaDir on explicit ext4lite volume",
			cfg:  Config{Mounts: []Mount{{Kind: MountVolume, VolumeName: "vol", Driver: DriverExt4lite, GuestPath: "/v", MetaDir: metaDir}}},
		},
		{
			name: "MetaDir on default ext4lite volume",
			cfg:  Config{Mounts: []Mount{{Kind: MountVolume, VolumeName: "vol", GuestPath: "/v", MetaDir: metaDir}}},
		},
		{
			name: "MetaDir on ephemeral volume",
			cfg:  Config{Mounts: []Mount{{Kind: MountVolume, Ephemeral: true, GuestPath: "/v", MetaDir: metaDir}}},
		},
		{
			name: "MetaDir on image path volume",
			cfg:  Config{Mounts: []Mount{{Kind: MountVolume, ImagePath: filepath.Join(t.TempDir(), "v.ext4"), GuestPath: "/v", MetaDir: metaDir}}},
		},
		{
			name: "MetaDir on single-file bind mount",
			cfg:  Config{Mounts: []Mount{{Kind: MountBind, HostPath: filePath, GuestPath: "/f", MetaDir: metaDir}}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			err := cfg.normalize()
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("normalize() = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestOpenMountsMetaDirOverlapAndConflictValidation(t *testing.T) {
	parent := t.TempDir()
	wsA := filepath.Join(parent, "wsA")
	wsB := filepath.Join(parent, "wsB")
	metaA := filepath.Join(parent, "metaA")
	metaAChild := filepath.Join(metaA, "nested")
	metaB := filepath.Join(parent, "metaB")
	wsAChild := filepath.Join(wsA, "submeta")
	for _, d := range []string{wsA, wsB, metaA, metaAChild, metaB, wsAChild} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name string
		cfg  Config
	}{
		{
			name: "MetaDir inside workspace",
			cfg:  Config{WorkspacePath: wsA, WorkspaceMetaDir: wsAChild},
		},
		{
			name: "MetaDir ancestor of workspace",
			cfg:  Config{WorkspacePath: wsA, WorkspaceMetaDir: parent},
		},
		{
			name: "same host dir with conflicting MetaDir",
			cfg: Config{Mounts: []Mount{
				{Kind: MountBind, HostPath: wsA, GuestPath: "/a1", MetaDir: metaA},
				{Kind: MountBind, HostPath: wsA, GuestPath: "/a2", MetaDir: metaB},
			}},
		},
		{
			name: "same host dir with external vs default MetaDir",
			cfg: Config{Mounts: []Mount{
				{Kind: MountBind, HostPath: wsA, GuestPath: "/a1", MetaDir: metaA},
				{Kind: MountBind, HostPath: wsA, GuestPath: "/a2"},
			}},
		},
		{
			name: "two distinct host dirs sharing one MetaDir",
			cfg: Config{Mounts: []Mount{
				{Kind: MountBind, HostPath: wsA, GuestPath: "/a", MetaDir: metaA},
				{Kind: MountBind, HostPath: wsB, GuestPath: "/b", MetaDir: metaA},
			}},
		},
		{
			name: "external MetaDir equals another mount host dir",
			cfg: Config{Mounts: []Mount{
				{Kind: MountBind, HostPath: wsA, GuestPath: "/a", MetaDir: wsB},
				{Kind: MountBind, HostPath: wsB, GuestPath: "/b", MetaDir: metaB},
			}},
		},
		{
			name: "external MetaDir inside another mount host dir",
			cfg: Config{Mounts: []Mount{
				{Kind: MountBind, HostPath: wsA, GuestPath: "/a", MetaDir: metaA},
				{Kind: MountBind, HostPath: wsB, GuestPath: "/b", MetaDir: wsAChild},
			}},
		},
		{
			name: "nested external MetaDirs",
			cfg: Config{Mounts: []Mount{
				{Kind: MountBind, HostPath: wsA, GuestPath: "/a", MetaDir: metaA},
				{Kind: MountBind, HostPath: wsB, GuestPath: "/b", MetaDir: metaAChild},
			}},
		},
	}

	if isCaseInsensitiveVolume(t, parent) {
		cases = append(cases,
			struct {
				name string
				cfg  Config
			}{
				name: "case-variant MetaDir inside workspace",
				cfg:  Config{WorkspacePath: wsA, WorkspaceMetaDir: filepath.Join(parent, "WSA", "submeta")},
			},
			struct {
				name string
				cfg  Config
			}{
				name: "case-variant MetaDir ancestor of workspace",
				cfg:  Config{WorkspacePath: wsAChild, WorkspaceMetaDir: filepath.Join(parent, "WSA")},
			},
			struct {
				name string
				cfg  Config
			}{
				name: "case-variant distinct host dirs sharing one MetaDir",
				cfg: Config{Mounts: []Mount{
					{Kind: MountBind, HostPath: wsA, GuestPath: "/a", MetaDir: metaA},
					{Kind: MountBind, HostPath: wsB, GuestPath: "/b", MetaDir: filepath.Join(parent, "METAA")},
				}},
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			if err := cfg.normalize(); err != nil {
				if errors.Is(err, ErrInvalidConfig) {
					return
				}
				t.Fatalf("unexpected normalize error: %v", err)
			}
			sb := &Sandbox{cfg: cfg}
			t.Cleanup(func() { _ = sb.closeMounts() })
			err := sb.openMounts()
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("openMounts() = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestOpenMountsMetaDirRejectsOverlapBeforeCreatingHostDir(t *testing.T) {
	parent := t.TempDir()
	missingChild := filepath.Join(parent, "should-not-be-created")
	cfg := Config{Mounts: []Mount{{
		Kind:                    MountBind,
		HostPath:                missingChild,
		GuestPath:               "/child",
		MetaDir:                 parent,
		CreateHostPathIfMissing: true,
	}}}
	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	sb := &Sandbox{cfg: cfg}
	t.Cleanup(func() { _ = sb.closeMounts() })
	err := sb.openMounts()
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("openMounts() = %v, want ErrInvalidConfig", err)
	}
	if _, statErr := os.Stat(missingChild); !os.IsNotExist(statErr) {
		t.Errorf("invalid MetaDir overlap created %q on disk (stat err=%v)", missingChild, statErr)
	}
}

func TestOpenServeMountsRejectsOverlapWithExternalMetaDir(t *testing.T) {
	wsDir := t.TempDir()
	metaDir := t.TempDir()
	metaSub := filepath.Join(metaDir, "sub")
	if err := os.MkdirAll(metaSub, 0o755); err != nil {
		t.Fatal(err)
	}

	for name, servePath := range map[string]string{
		"equal to MetaDir": metaDir,
		"inside MetaDir":   metaSub,
		"ancestor of Meta": filepath.Dir(metaDir),
	} {
		t.Run(name, func(t *testing.T) {
			cfg := Config{
				WorkspacePath:    wsDir,
				WorkspaceMetaDir: metaDir,
				ServeMounts:      []ServeMount{{GuestPath: "/rpc", HostPath: servePath}},
			}
			sb := &Sandbox{cfg: cfg}
			t.Cleanup(func() {
				sb.closeServeMounts()
				_ = sb.closeMounts()
			})
			if err := sb.openMountsForRestore(); err != nil {
				t.Fatalf("openMountsForRestore: %v", err)
			}
			err := sb.openServeMountsForRestore()
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("openServeMountsForRestore(%q) = %v, want ErrInvalidConfig", servePath, err)
			}
		})
	}
}

func TestOpenMountsMetaDirSameHostROAndRWDeduplicatesHostMounts(t *testing.T) {
	parent := t.TempDir()
	wsDir := filepath.Join(parent, "ws")
	metaDir := filepath.Join(parent, "meta")
	for _, d := range []string{wsDir, metaDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	metaRW := metaDir
	if isCaseInsensitiveVolume(t, parent) {
		metaRW = filepath.Join(parent, "META")
	}

	cfg := Config{Mounts: []Mount{
		{Kind: MountBind, HostPath: wsDir, GuestPath: "/ro", ReadOnly: true, MetaDir: metaDir},
		{Kind: MountBind, HostPath: wsDir, GuestPath: "/rw", ReadOnly: false, MetaDir: metaRW},
	}}
	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	sb := &Sandbox{cfg: cfg}
	t.Cleanup(func() {
		if err := sb.closeMounts(); err != nil {
			t.Errorf("closeMounts: %v", err)
		}
	})
	if err := sb.openMounts(); err != nil {
		t.Fatalf("openMounts: %v", err)
	}

	metaHits := 0
	var metaRO bool
	for _, hm := range sb.hostMounts() {
		if sameHostPath(hm.Path, metaDir) {
			metaHits++
			metaRO = hm.ReadOnly
		}
	}
	if metaHits != 1 {
		t.Fatalf("hostMounts() contains MetaDir %d times, want 1", metaHits)
	}
	if metaRO {
		t.Errorf("deduplicated MetaDir ReadOnly = true, want false (RW wins over RO)")
	}
}

func TestOpenMountsHostfsVolumeSupportsMetaDir(t *testing.T) {
	t.Setenv(VolumeDirEnv, t.TempDir())
	metaDir := t.TempDir()
	cfg := Config{Mounts: []Mount{
		{Kind: MountVolume, VolumeName: "work", Driver: DriverHostfs, GuestPath: "/work", MetaDir: metaDir},
	}}
	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	sb := &Sandbox{cfg: cfg}
	t.Cleanup(func() {
		if err := sb.closeMounts(); err != nil {
			t.Errorf("closeMounts: %v", err)
		}
	})
	if err := sb.openMounts(); err != nil {
		t.Fatalf("openMounts: %v", err)
	}
	if len(sb.workspaces) != 1 || sb.workspaces[0].MetaDir() == "" {
		t.Fatalf("workspaces = %v, want 1 workspace with external MetaDir", sb.workspaces)
	}
}

func TestExternalMetaDirTwoConcurrentSandboxesInProcess(t *testing.T) {
	wsA, metaA := t.TempDir(), t.TempDir()
	wsB, metaB := t.TempDir(), t.TempDir()

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	runOne := func(wsDir, metaDir, fileName string) {
		defer wg.Done()
		cfg := Config{WorkspacePath: wsDir, WorkspaceMetaDir: metaDir}
		if err := cfg.normalize(); err != nil {
			errs <- err
			return
		}
		sb := &Sandbox{cfg: cfg}
		if err := sb.openMounts(); err != nil {
			errs <- err
			return
		}
		defer func() {
			if cerr := sb.closeMounts(); cerr != nil {
				errs <- cerr
			}
		}()
		f, err := sb.workspace.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			errs <- err
			return
		}
		if _, err := f.Write([]byte("ok")); err != nil {
			_ = f.Close()
			errs <- err
			return
		}
		if err := f.Close(); err != nil {
			errs <- err
			return
		}
		if err := sb.workspace.Chmod(fileName, 0o751); err != nil {
			errs <- err
			return
		}
		if err := sb.workspace.Sync(); err != nil {
			errs <- err
			return
		}
	}

	wg.Add(2)
	go runOne(wsA, metaA, "a.bin")
	go runOne(wsB, metaB, "b.bin")
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent sandbox error: %v", err)
	}

	for _, pair := range [][3]string{{wsA, metaA, "a.bin"}, {wsB, metaB, "b.bin"}} {
		wsDir, metaDir, fileName := pair[0], pair[1], pair[2]
		if _, err := os.Stat(filepath.Join(wsDir, hostfs.MetaFileName)); !os.IsNotExist(err) {
			t.Errorf("%s leaked %s into workspace", wsDir, hostfs.MetaFileName)
		}
		recs, err := hostfs.ReadMetaAt(filepath.Join(metaDir, hostfs.MetaFileName), wsDir)
		if err != nil {
			t.Fatalf("ReadMetaAt(%s): %v", metaDir, err)
		}
		if attr, ok := recs[fileName]; !ok || attr.Mode&0o777 != 0o751 {
			t.Errorf("ReadMetaAt[%s] = %+v (ok=%v), want mode 0751", fileName, attr, ok)
		}
	}
}

func TestExternalMetaDirWorksUnderHostLockdown(t *testing.T) {
	if os.Getenv(metaDirLockdownChildEnv) == "1" {
		wsDir := os.Getenv(metaDirLockdownWSEnv)
		metaDir := os.Getenv(metaDirLockdownMetaEnv)

		cfg := Config{
			NetworkMode:      NetModeNone,
			WorkspacePath:    wsDir,
			WorkspaceMetaDir: metaDir,
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

		f, err := sb.workspace.OpenFile("tool.sh", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatalf("OpenFile under lockdown: %v", err)
		}
		if _, err := f.Write([]byte("#!/bin/sh\n")); err != nil {
			_ = f.Close()
			t.Fatalf("Write under lockdown: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("Close under lockdown: %v", err)
		}
		if err := sb.workspace.Chmod("tool.sh", 0o755); err != nil {
			t.Fatalf("Chmod under lockdown: %v", err)
		}
		if err := sb.workspace.Symlink("tool.sh", "tool-link"); err != nil {
			t.Fatalf("Symlink under lockdown: %v", err)
		}
		if err := sb.workspace.Sync(); err != nil {
			t.Fatalf("Sync under lockdown: %v", err)
		}
		return
	}

	wsDir := t.TempDir()
	metaDir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.v", "-test.run=^TestExternalMetaDirWorksUnderHostLockdown$")
	cmd.Env = append(os.Environ(),
		metaDirLockdownChildEnv+"=1",
		metaDirLockdownWSEnv+"="+wsDir,
		metaDirLockdownMetaEnv+"="+metaDir,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("locked child failed: %v\n%s", err, out)
	}

	// Verify workspace has zero metadata files and MetaDir holds persisted records.
	if _, err := os.Stat(filepath.Join(wsDir, hostfs.MetaFileName)); !os.IsNotExist(err) {
		t.Errorf("workspace unexpectedly contains %s", hostfs.MetaFileName)
	}
	if _, err := os.Stat(filepath.Join(wsDir, hostfs.MetaLockFileName)); !os.IsNotExist(err) {
		t.Errorf("workspace unexpectedly contains %s", hostfs.MetaLockFileName)
	}
	recs, err := hostfs.ReadMetaAt(filepath.Join(metaDir, hostfs.MetaFileName), wsDir)
	if err != nil {
		t.Fatalf("ReadMetaAt: %v", err)
	}
	if attr, ok := recs["tool.sh"]; !ok || attr.Mode&0o777 != 0o755 {
		t.Errorf("ReadMetaAt[tool.sh] = %+v (ok=%v), want mode 0755", attr, ok)
	}
	if attr, ok := recs["tool-link"]; !ok || attr.Symlink != "tool.sh" {
		t.Errorf("ReadMetaAt[tool-link] = %+v (ok=%v), want symlink target %q", attr, ok, "tool.sh")
	}
}
