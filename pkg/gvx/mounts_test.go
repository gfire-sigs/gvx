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
	"slices"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/oci"
)

func TestParseVolume(t *testing.T) {
	for _, tc := range []struct {
		spec string
		want Mount
	}{
		{"data:/data", Mount{Kind: MountVolume, VolumeName: "data", GuestPath: "/data"}},
		{"data:/data:rw", Mount{Kind: MountVolume, VolumeName: "data", GuestPath: "/data"}},
		{"my-vol_1.2:/d:ro", Mount{Kind: MountVolume, VolumeName: "my-vol_1.2", GuestPath: "/d", ReadOnly: true}},
		{"/host/dir:/data", Mount{Kind: MountBind, HostPath: "/host/dir", GuestPath: "/data", CreateHostPathIfMissing: true}},
		{"/host/dir:/data:ro", Mount{Kind: MountBind, HostPath: "/host/dir", GuestPath: "/data", ReadOnly: true, CreateHostPathIfMissing: true}},
		{"./relative:/data", Mount{Kind: MountBind, HostPath: "./relative", GuestPath: "/data", CreateHostPathIfMissing: true}},
		{"sub/dir:/data", Mount{Kind: MountBind, HostPath: "sub/dir", GuestPath: "/data", CreateHostPathIfMissing: true}},
		{`C:\data:/data:ro`, Mount{Kind: MountBind, HostPath: `C:\data`, GuestPath: "/data", ReadOnly: true, CreateHostPathIfMissing: true}},
		{`C:\data:/data`, Mount{Kind: MountBind, HostPath: `C:\data`, GuestPath: "/data", CreateHostPathIfMissing: true}},
		{`d:\My Files\x:/x:rw`, Mount{Kind: MountBind, HostPath: `d:\My Files\x`, GuestPath: "/x", CreateHostPathIfMissing: true}},
		{"C:/data:/data", Mount{Kind: MountBind, HostPath: "C:/data", GuestPath: "/data", CreateHostPathIfMissing: true}},
		{"C:/data:/data:ro", Mount{Kind: MountBind, HostPath: "C:/data", GuestPath: "/data", ReadOnly: true, CreateHostPathIfMissing: true}},
		{"/host/file.txt:/data/file.txt", Mount{Kind: MountBind, HostPath: "/host/file.txt", GuestPath: "/data/file.txt", CreateHostPathIfMissing: true}},
		{"/host/file.txt:/data/file.txt:ro", Mount{Kind: MountBind, HostPath: "/host/file.txt", GuestPath: "/data/file.txt", ReadOnly: true, CreateHostPathIfMissing: true}},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			got, err := ParseVolume(tc.spec)
			if err != nil {
				t.Fatalf("ParseVolume(%q) failed: %v", tc.spec, err)
			}
			if got != tc.want {
				t.Fatalf("ParseVolume(%q) = %+v, want %+v", tc.spec, got, tc.want)
			}
		})
	}

	for _, spec := range []string{
		"", "data", "data:", ":/data", "/host:", "data:data", "data:/a:zz", "data:/a:ro:extra", "data:/a:ro,z",
		"bad name:/a", "-bad:/a", ".:/a", "..:/a", `C:\data`, `C:\data:data`, `C:\data:/a:zz`,
	} {
		if m, err := ParseVolume(spec); err == nil {
			t.Errorf("ParseVolume(%q) = %+v, want an error", spec, m)
		}
	}
}

func TestParseMount(t *testing.T) {
	for _, tc := range []struct {
		spec string
		want Mount
	}{
		{"type=bind,src=/h,dst=/g", Mount{Kind: MountBind, HostPath: "/h", GuestPath: "/g"}},
		{"type=bind,source=/h,target=/g,readonly", Mount{Kind: MountBind, HostPath: "/h", GuestPath: "/g", ReadOnly: true}},
		{"type=bind,source=/h,destination=/g,ro=true", Mount{Kind: MountBind, HostPath: "/h", GuestPath: "/g", ReadOnly: true}},
		{"type=bind,source=/h,destination=/g,readonly=false", Mount{Kind: MountBind, HostPath: "/h", GuestPath: "/g"}},
		{`type=bind,src=C:\data,dst=/g,ro`, Mount{Kind: MountBind, HostPath: `C:\data`, GuestPath: "/g", ReadOnly: true}},
		{`type=bind,"src=/h,x",dst=/g`, Mount{Kind: MountBind, HostPath: "/h,x", GuestPath: "/g"}},
		{"type=bind,src=/h/file.txt,dst=/g/file.txt", Mount{Kind: MountBind, HostPath: "/h/file.txt", GuestPath: "/g/file.txt"}},
		{"type=bind,src=/h/file.txt,dst=/g/file.txt,ro", Mount{Kind: MountBind, HostPath: "/h/file.txt", GuestPath: "/g/file.txt", ReadOnly: true}},
		{"type=volume,src=data,dst=/v", Mount{Kind: MountVolume, VolumeName: "data", GuestPath: "/v"}},
		{"src=data,dst=/v,ro", Mount{Kind: MountVolume, VolumeName: "data", GuestPath: "/v", ReadOnly: true}},
		{"type=tmpfs,dst=/t", Mount{Kind: MountTmpfs, GuestPath: "/t"}},
		{"type=tmpfs,target=/t,tmpfs-size=64m", Mount{Kind: MountTmpfs, GuestPath: "/t", TmpfsSizeBytes: 64 << 20}},
		{"type=tmpfs,target=/t,tmpfs-size=4096", Mount{Kind: MountTmpfs, GuestPath: "/t", TmpfsSizeBytes: 4096}},
		{"TYPE=Tmpfs,Target=/t,RO", Mount{Kind: MountTmpfs, GuestPath: "/t", ReadOnly: true}},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			got, err := ParseMount(tc.spec)
			if err != nil {
				t.Fatalf("ParseMount(%q) failed: %v", tc.spec, err)
			}
			if got != tc.want {
				t.Fatalf("ParseMount(%q) = %+v, want %+v", tc.spec, got, tc.want)
			}
		})
	}

	for _, spec := range []string{
		"", "type=bind", "type=bind,dst=/g", "type=bind,src=/h", "type=nfs,src=x,dst=/g", "type=tmpfs,src=/x,dst=/t",
		"type=bind,src=/h,dst=/g,tmpfs-size=1m", "type=volume,src=v,dst=/g,tmpfs-size=1m", "type=bind,src=/h,dst=/g,bogus=1",
		"type=volume,src=bad name,dst=/g", "type=volume,dst=/g", "type=tmpfs,dst=/t,tmpfs-size=0", "type=tmpfs,dst=/t,tmpfs-size=big",
		"type=bind,src=/h,dst=/g,readonly=maybe", `type=bind,src="/h,dst=/g`,
	} {
		if m, err := ParseMount(spec); err == nil {
			t.Errorf("ParseMount(%q) = %+v, want an error", spec, m)
		}
	}
}

func TestParseTmpfs(t *testing.T) {
	for _, tc := range []struct {
		spec string
		want Mount
	}{
		{"/t", Mount{Kind: MountTmpfs, GuestPath: "/t"}},
		{"/t:size=64m", Mount{Kind: MountTmpfs, GuestPath: "/t", TmpfsSizeBytes: 64 << 20}},
		{"/t:size=64M", Mount{Kind: MountTmpfs, GuestPath: "/t", TmpfsSizeBytes: 64 << 20}},
		{"/t:size=1g,ro", Mount{Kind: MountTmpfs, GuestPath: "/t", TmpfsSizeBytes: 1 << 30, ReadOnly: true}},
		{"/t:size=512k", Mount{Kind: MountTmpfs, GuestPath: "/t", TmpfsSizeBytes: 512 << 10}},
		{"/t:size=100b", Mount{Kind: MountTmpfs, GuestPath: "/t", TmpfsSizeBytes: 100}},
		{"/t:size=100", Mount{Kind: MountTmpfs, GuestPath: "/t", TmpfsSizeBytes: 100}},
		{"/t:ro,rw", Mount{Kind: MountTmpfs, GuestPath: "/t"}},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			got, err := ParseTmpfs(tc.spec)
			if err != nil {
				t.Fatalf("ParseTmpfs(%q) failed: %v", tc.spec, err)
			}
			if got != tc.want {
				t.Fatalf("ParseTmpfs(%q) = %+v, want %+v", tc.spec, got, tc.want)
			}
		})
	}

	for _, spec := range []string{
		"", ":size=1m", "/t:size=", "/t:size=0", "/t:size=-1m", "/t:size=12x", "/t:size=m", "/t:noexec", "/t:size",
		"/t:size=9999999999999g", "/t:", "/t:size=1m,,ro",
	} {
		if m, err := ParseTmpfs(spec); err == nil {
			t.Errorf("ParseTmpfs(%q) = %+v, want an error", spec, m)
		}
	}
}

func TestConfigNormalizeRejectsInvalidMounts(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	tmpfs := func(guest string) Mount { return Mount{Kind: MountTmpfs, GuestPath: guest} }

	for _, tc := range []struct {
		name    string
		cfg     Config
		wantMsg string
	}{
		{"relative guest path", Config{Mounts: []Mount{tmpfs("data")}}, "absolute"},
		{"guest path with trailing slash", Config{Mounts: []Mount{tmpfs("/data/")}}, "clean"},
		{"guest path with empty element", Config{Mounts: []Mount{tmpfs("/a//b")}}, "clean"},
		{"guest path with dot-dot", Config{Mounts: []Mount{tmpfs("/a/../b")}}, "clean"},
		{"guest root", Config{Mounts: []Mount{tmpfs("/")}}, "/"},
		{"proc", Config{Mounts: []Mount{tmpfs("/proc")}}, "/proc"},
		{"below proc", Config{Mounts: []Mount{tmpfs("/proc/self")}}, "/proc"},
		{"sys", Config{Mounts: []Mount{tmpfs("/sys")}}, "/sys"},
		{"below sys", Config{Mounts: []Mount{tmpfs("/sys/fs")}}, "/sys"},
		{"dev", Config{Mounts: []Mount{tmpfs("/dev")}}, "/dev"},
		{"below dev", Config{Mounts: []Mount{tmpfs("/dev/null")}}, "/dev"},
		{"dev shm itself", Config{Mounts: []Mount{tmpfs("/dev/shm")}}, "/dev"},
		{"duplicate guest path", Config{Mounts: []Mount{tmpfs("/a"), {Kind: MountVolume, VolumeName: "v", GuestPath: "/a"}}}, "/a"},
		{"mount at workspace with WorkspacePath", Config{WorkspacePath: dir, Mounts: []Mount{tmpfs("/workspace")}}, "WorkspacePath"},
		{"missing bind source", Config{Mounts: []Mount{{Kind: MountBind, HostPath: missing, GuestPath: "/a"}}}, "does not exist"},
		{"bind without source", Config{Mounts: []Mount{{Kind: MountBind, GuestPath: "/a"}}}, "HostPath"},
		{"bind with volume name", Config{Mounts: []Mount{{Kind: MountBind, HostPath: dir, VolumeName: "v", GuestPath: "/a"}}}, "VolumeName"},
		{"bind with size", Config{Mounts: []Mount{{Kind: MountBind, HostPath: dir, GuestPath: "/a", TmpfsSizeBytes: 1}}}, "TmpfsSizeBytes"},
		{"volume with bad name", Config{Mounts: []Mount{{Kind: MountVolume, VolumeName: "../x", GuestPath: "/a"}}}, "volume name"},
		{"volume with empty name", Config{Mounts: []Mount{{Kind: MountVolume, GuestPath: "/a"}}}, "volume name"},
		{"volume with host path", Config{Mounts: []Mount{{Kind: MountVolume, VolumeName: "v", HostPath: dir, GuestPath: "/a"}}}, "HostPath"},
		{"volume with create flag", Config{Mounts: []Mount{{Kind: MountVolume, VolumeName: "v", GuestPath: "/a", CreateHostPathIfMissing: true}}}, "CreateHostPathIfMissing"},
		{"tmpfs with host path", Config{Mounts: []Mount{{Kind: MountTmpfs, HostPath: dir, GuestPath: "/a"}}}, "HostPath"},
		{"tmpfs with negative size", Config{Mounts: []Mount{{Kind: MountTmpfs, GuestPath: "/a", TmpfsSizeBytes: -1}}}, "TmpfsSizeBytes"},
		{"unknown kind", Config{Mounts: []Mount{{Kind: "nfs", GuestPath: "/a"}}}, "kind"},
		{"empty kind", Config{Mounts: []Mount{{GuestPath: "/a"}}}, "kind"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.normalize()
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("normalize() error = %v, want ErrInvalidConfig", err)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("normalize() error = %q, want it to mention %q", err, tc.wantMsg)
			}
		})
	}
}

func TestConfigNormalizeRejectsBindSourceOfOtherFileType(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows host has no device file at a fixed path")
	}
	cfg := Config{Mounts: []Mount{{Kind: MountBind, HostPath: os.DevNull, GuestPath: "/null"}}}
	err := cfg.normalize()
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "neither a directory nor a regular file") {
		t.Fatalf("normalize() error = %v, want ErrInvalidConfig that names the file type", err)
	}
	cfg.Mounts[0].CreateHostPathIfMissing = true
	if err := cfg.normalize(); err == nil {
		t.Fatal("normalize() accepted a device file with CreateHostPathIfMissing")
	}
}

func TestConfigNormalizeAcceptsMounts(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	file := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Mounts: []Mount{
		{Kind: MountBind, HostPath: dir, GuestPath: "/workspace"},
		{Kind: MountBind, HostPath: missing, GuestPath: "/created", CreateHostPathIfMissing: true},
		{Kind: MountBind, HostPath: dir, GuestPath: "/again", ReadOnly: true},
		{Kind: MountBind, HostPath: file, GuestPath: "/data/file.txt"},
		{Kind: MountBind, HostPath: file, GuestPath: "/file-ro.txt", ReadOnly: true},
		{Kind: MountBind, HostPath: file, GuestPath: "/file-create.txt", CreateHostPathIfMissing: true},
		{Kind: MountVolume, VolumeName: "Data-1.x_y", GuestPath: "/vol"},
		{Kind: MountTmpfs, GuestPath: "/dev/shm/inner", TmpfsSizeBytes: 4096},
		{Kind: MountTmpfs, GuestPath: "/a/b/c"},
	}}
	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize() failed: %v", err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("normalize() created the bind source: stat error = %v", err)
	}
	withWorkspace := Config{WorkspacePath: dir, Mounts: []Mount{{Kind: MountTmpfs, GuestPath: "/scratch"}}}
	if err := withWorkspace.normalize(); err != nil {
		t.Fatalf("normalize() with WorkspacePath and another mount failed: %v", err)
	}
}

func TestSortMountsByDepthKeepsOrderWithinOneDepth(t *testing.T) {
	var mounts []sandboxMount
	for _, p := range []string{"/a/b/c", "/z", "/a/b", "/m", "/a"} {
		mounts = append(mounts, sandboxMount{Mount: Mount{GuestPath: p}})
	}
	sortMountsByDepth(mounts)
	var got []string
	for _, m := range mounts {
		got = append(got, m.GuestPath)
	}
	if want := []string{"/z", "/m", "/a", "/a/b", "/a/b/c"}; !slices.Equal(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestOpenMountsPreparesHostDirectoriesAndWorkspaces(t *testing.T) {
	root := t.TempDir()
	workspaceDir := filepath.Join(root, "ws")
	roDir := filepath.Join(root, "ro")
	created := filepath.Join(root, "made", "deep")
	for _, d := range []string{workspaceDir, roDir} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := Config{
		OCICacheDir:   filepath.Join(root, "cache"),
		WorkspacePath: workspaceDir,
		Mounts: []Mount{
			{Kind: MountTmpfs, GuestPath: "/a/b/scratch"},
			{Kind: MountBind, HostPath: roDir, GuestPath: "/mnt/ro", ReadOnly: true},
			{Kind: MountBind, HostPath: created, GuestPath: "/mnt/made", CreateHostPathIfMissing: true},
			{Kind: MountVolume, VolumeName: "data", GuestPath: "/vol"},
		},
	}
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	sb := &Sandbox{cfg: cfg}
	t.Cleanup(func() {
		if err := sb.closeMounts(); err != nil {
			t.Errorf("closeMounts() failed: %v", err)
		}
	})
	if err := sb.openMounts(); err != nil {
		t.Fatalf("openMounts() failed: %v", err)
	}

	if sb.Workspace() == nil || sb.Workspace().HostPath() != workspaceDir {
		t.Fatalf("Workspace() = %v, want the workspace of %s", sb.Workspace(), workspaceDir)
	}
	var guestOrder []string
	for _, m := range sb.mounts {
		guestOrder = append(guestOrder, m.GuestPath)
	}
	if want := []string{"/workspace", "/vol", "/mnt/ro", "/mnt/made", "/a/b/scratch"}; !slices.Equal(guestOrder, want) {
		t.Fatalf("mount order = %v, want %v", guestOrder, want)
	}
	volumeRoot := filepath.Join(root, "cache", "volumes")
	wantHost := []hostlockdown.HostMount{
		{Path: workspaceDir}, {Path: roDir, ReadOnly: true}, {Path: created},
	}
	if got := sb.hostMounts(); !slices.Equal(got, wantHost) {
		t.Fatalf("hostMounts() = %+v, want %+v (an ext4lite volume needs no host path)", got, wantHost)
	}
	if !sb.usesHostDirs() {
		t.Error("usesHostDirs() = false with bind mounts")
	}
	if info, err := os.Stat(created); err != nil || !info.IsDir() {
		t.Fatalf("bind source %s was not created: %v", created, err)
	}
	info, err := os.Stat(volumeRoot)
	if err != nil || !info.IsDir() {
		t.Fatalf("volume directory %s was not created: %v", volumeRoot, err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Errorf("volume directory mode = %v, want 0700", info.Mode().Perm())
	}
	if info, err := os.Stat(filepath.Join(volumeRoot, "data.ext4")); err != nil || info.Size() == 0 {
		t.Errorf("volume image = %v, %v; want a non-empty file", info, err)
	}
	if len(sb.workspaces) != 3 || len(sb.volumes) != 1 {
		t.Errorf("open workspaces = %d and volumes = %d, want 3 and 1", len(sb.workspaces), len(sb.volumes))
	}
}

func TestOpenMountsBindsOneFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(file, []byte("host data"), 0o600); err != nil {
		t.Fatal(err)
	}
	realFile, err := filepath.EvalSymlinks(file)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Mounts: []Mount{
		{Kind: MountBind, HostPath: file, GuestPath: "/data.txt"},
		{Kind: MountBind, HostPath: filepath.Join(dir, ".", "data.txt"), GuestPath: "/again.txt"},
		{Kind: MountBind, HostPath: file, GuestPath: "/ro.txt", ReadOnly: true, CreateHostPathIfMissing: true},
		{Kind: MountBind, HostPath: dir, GuestPath: "/dir"},
	}}
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	sb := &Sandbox{cfg: cfg}
	t.Cleanup(func() {
		if err := sb.closeMounts(); err != nil {
			t.Errorf("closeMounts() failed: %v", err)
		}
	})
	if err := sb.openMounts(); err != nil {
		t.Fatalf("openMounts() failed: %v", err)
	}
	// A file mount and a mount of its parent are different workspaces. Two
	// mounts of one file with the same access share one workspace.
	if len(sb.workspaces) != 3 {
		t.Fatalf("open workspaces = %d, want 3 (shared writable file, read-only file, directory)", len(sb.workspaces))
	}
	byGuest := make(map[string]sandboxMount)
	for _, m := range sb.mounts {
		byGuest[m.GuestPath] = m
	}
	if byGuest["/data.txt"].workspace != byGuest["/again.txt"].workspace {
		t.Error("two writable mounts of one file use two workspaces, want one")
	}
	if byGuest["/data.txt"].workspace == byGuest["/ro.txt"].workspace {
		t.Error("a read-only and a writable mount of one file share a workspace")
	}
	if byGuest["/data.txt"].workspace == byGuest["/dir"].workspace {
		t.Error("a file mount and a mount of its parent directory share a workspace")
	}
	for _, guest := range []string{"/data.txt", "/again.txt", "/ro.txt"} {
		m := byGuest[guest]
		if !m.hostFile || m.hostPath != realFile || !m.workspace.SingleFile() {
			t.Errorf("mount %s: hostFile = %v, hostPath = %q, SingleFile = %v; want a file mount of %q", guest, m.hostFile, m.hostPath, m.workspace.SingleFile(), realFile)
		}
	}
	if m := byGuest["/dir"]; m.hostFile || m.workspace.SingleFile() {
		t.Errorf("directory mount: hostFile = %v, SingleFile = %v; want false", m.hostFile, m.workspace.SingleFile())
	}
	if got, err := os.ReadFile(file); err != nil || string(got) != "host data" {
		t.Errorf("host file = %q, %v; want it unchanged", got, err)
	}

	var files, dirs int
	for _, hm := range sb.hostMounts() {
		switch {
		case hm.File && hm.Path == realFile:
			files++
		case !hm.File && hm.Path == dir:
			dirs++
		default:
			t.Errorf("unexpected hostMounts() entry %+v", hm)
		}
	}
	if files != 3 || dirs != 1 {
		t.Errorf("hostMounts() has %d file entries and %d directory entries, want 3 and 1", files, dirs)
	}
	if !sb.usesHostDirs() {
		t.Error("usesHostDirs() = false with a file mount")
	}
}

func TestOpenMountsCreatesDirectoryOnlyAndKeepsExistingFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(file, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	created := filepath.Join(dir, "made")
	sb := &Sandbox{cfg: Config{Mounts: []Mount{
		{Kind: MountBind, HostPath: file, GuestPath: "/data.txt", CreateHostPathIfMissing: true},
		{Kind: MountBind, HostPath: created, GuestPath: "/made", CreateHostPathIfMissing: true},
	}}}
	t.Cleanup(func() {
		if err := sb.closeMounts(); err != nil {
			t.Errorf("closeMounts() failed: %v", err)
		}
	})
	if err := sb.openMounts(); err != nil {
		t.Fatalf("openMounts() failed: %v", err)
	}
	if info, err := os.Stat(file); err != nil || !info.Mode().IsRegular() {
		t.Errorf("host file after openMounts() = %v, %v; want a regular file", info, err)
	}
	if info, err := os.Stat(created); err != nil || !info.IsDir() {
		t.Errorf("created bind source = %v, %v; want a directory", info, err)
	}
}

func TestOpenMountsRejectsFileAsWorkspacePath(t *testing.T) {
	file := filepath.Join(t.TempDir(), "data.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sb := &Sandbox{cfg: Config{WorkspacePath: file}}
	err := sb.openMounts()
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "WorkspacePath") {
		t.Fatalf("openMounts() error = %v, want ErrInvalidConfig that names WorkspacePath", err)
	}
	if err := sb.closeMounts(); err != nil {
		t.Fatalf("closeMounts() after a failed openMounts() = %v, want success", err)
	}
}

func TestOpenMountsVolumeDriverSelection(t *testing.T) {
	cache := t.TempDir()
	volumes := filepath.Join(cache, "volumes")
	if err := os.MkdirAll(filepath.Join(volumes, "legacy"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(volumes, "legacy", "keep.txt"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{OCICacheDir: cache, Mounts: []Mount{
		{Kind: MountVolume, VolumeName: "legacy", GuestPath: "/legacy"},
		{Kind: MountVolume, VolumeName: "fresh", GuestPath: "/fresh"},
		{Kind: MountVolume, VolumeName: "forced", GuestPath: "/forced", Driver: DriverHostfs},
	}}
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	sb := &Sandbox{cfg: cfg}
	t.Cleanup(func() {
		if err := sb.closeMounts(); err != nil {
			t.Errorf("closeMounts() failed: %v", err)
		}
	})
	if err := sb.openMounts(); err != nil {
		t.Fatalf("openMounts() failed: %v", err)
	}
	got := map[string]MountDriver{}
	for _, m := range sb.mounts {
		got[m.VolumeName] = m.Driver
	}
	want := map[string]MountDriver{"legacy": DriverHostfs, "fresh": DriverExt4lite, "forced": DriverHostfs}
	for name, driver := range want {
		if got[name] != driver {
			t.Errorf("volume %s uses %q, want %q", name, got[name], driver)
		}
	}
	if _, err := os.Stat(filepath.Join(volumes, "legacy.ext4")); err == nil {
		t.Error("a legacy volume directory got an image file beside it")
	}
	if _, err := os.Stat(filepath.Join(volumes, "fresh.ext4")); err != nil {
		t.Errorf("the new volume has no image: %v", err)
	}
}

func TestOpenMountsRejectsBusyAndDuplicateVolumes(t *testing.T) {
	cache := t.TempDir()
	open := func(mounts ...Mount) (*Sandbox, error) {
		cfg := Config{OCICacheDir: cache, Mounts: mounts}
		if err := cfg.normalize(); err != nil {
			t.Fatal(err)
		}
		sb := &Sandbox{cfg: cfg}
		return sb, sb.openMounts()
	}
	first, err := open(Mount{Kind: MountVolume, VolumeName: "shared", GuestPath: "/a"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := open(Mount{Kind: MountVolume, VolumeName: "shared", GuestPath: "/a"})
	if err == nil || !strings.Contains(err.Error(), "in use") {
		t.Errorf("a second sandbox on the same volume = %v, want an in-use error", err)
	}
	if cerr := second.closeMounts(); cerr != nil {
		t.Errorf("closeMounts() after a failed openMounts() = %v", cerr)
	}
	if err := first.closeMounts(); err != nil {
		t.Fatal(err)
	}
	again, err := open(Mount{Kind: MountVolume, VolumeName: "shared", GuestPath: "/a"})
	if err != nil {
		t.Fatalf("reopen of a closed volume: %v", err)
	}
	if err := again.closeMounts(); err != nil {
		t.Fatal(err)
	}
	dup, err := open(
		Mount{Kind: MountVolume, VolumeName: "twice", GuestPath: "/a"},
		Mount{Kind: MountVolume, VolumeName: "twice", GuestPath: "/b"},
	)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("one volume mounted twice = %v, want ErrInvalidConfig", err)
	}
	if err := dup.closeMounts(); err != nil {
		t.Fatal(err)
	}
	_, err = open(Mount{Kind: MountVolume, VolumeName: "missing", GuestPath: "/a", ReadOnly: true})
	if err == nil {
		t.Error("a read-only mount of a missing volume succeeded")
	}
}

func TestOpenMountsSharesOneWorkspacePerDirectoryAndAccess(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Mounts: []Mount{
		{Kind: MountBind, HostPath: dir, GuestPath: "/one"},
		{Kind: MountBind, HostPath: dir, GuestPath: "/two"},
		{Kind: MountBind, HostPath: dir, GuestPath: "/three", ReadOnly: true},
		{Kind: MountBind, HostPath: filepath.Join(dir, "."), GuestPath: "/four"},
	}}
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	sb := &Sandbox{cfg: cfg}
	t.Cleanup(func() {
		if err := sb.closeMounts(); err != nil {
			t.Errorf("closeMounts() failed: %v", err)
		}
	})
	if err := sb.openMounts(); err != nil {
		t.Fatalf("openMounts() failed: %v", err)
	}
	if len(sb.workspaces) != 2 {
		t.Fatalf("open workspaces = %d, want 2 (one writable, one read-only)", len(sb.workspaces))
	}
	if sb.Workspace() != nil {
		t.Errorf("Workspace() is set without a mount at /workspace")
	}
	if got := len(sb.hostMounts()); got != 4 {
		t.Errorf("hostMounts() has %d entries, want one for each mount", got)
	}
}

func TestOpenMountsFailsForMissingBindSourceAndReleasesHandles(t *testing.T) {
	dir := t.TempDir()
	sb := &Sandbox{cfg: Config{WorkspacePath: dir, Mounts: []Mount{{Kind: MountBind, HostPath: filepath.Join(dir, "gone"), GuestPath: "/gone"}}}}
	if err := sb.openMounts(); err == nil {
		t.Fatal("openMounts() succeeded for a missing bind source")
	}
	if err := sb.closeMounts(); err != nil {
		t.Fatalf("closeMounts() after a failed openMounts() = %v, want success", err)
	}
	if sb.Workspace() != nil || len(sb.workspaces) != 0 {
		t.Fatalf("closeMounts() left %d workspaces and Workspace() = %v", len(sb.workspaces), sb.Workspace())
	}
}

func TestVolumeRootLiesBelowTheCacheDirectoryOverride(t *testing.T) {
	override := t.TempDir()
	got, err := Config{OCICacheDir: override}.volumeRoot()
	if err != nil || got != filepath.Join(override, "volumes") {
		t.Fatalf("volumeRoot() with OCICacheDir = (%q, %v), want %q", got, err, filepath.Join(override, "volumes"))
	}

	layers, layersErr := oci.DefaultCacheDir()
	got, err = Config{}.volumeRoot()
	if layersErr != nil {
		if err == nil {
			t.Fatalf("volumeRoot() succeeded although DefaultCacheDir failed: %v", layersErr)
		}
		return
	}
	if want := filepath.Join(filepath.Dir(layers), "volumes"); err != nil || got != want {
		t.Fatalf("volumeRoot() = (%q, %v), want %q next to the layer cache", got, err, want)
	}
}

func TestConfigHasHostDirsIgnoresTmpfs(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want bool
	}{
		{"no mounts", Config{}, false},
		{"tmpfs only", Config{Mounts: []Mount{{Kind: MountTmpfs, GuestPath: "/t"}}}, false},
		{"workspace", Config{WorkspacePath: "/w"}, true},
		{"bind", Config{Mounts: []Mount{{Kind: MountBind, HostPath: "/h", GuestPath: "/b"}}}, true},
		{"bind of a file path", Config{Mounts: []Mount{{Kind: MountBind, HostPath: "/h/file.txt", GuestPath: "/f.txt"}}}, true},
		{"volume", Config{Mounts: []Mount{{Kind: MountVolume, VolumeName: "v", GuestPath: "/v"}}}, false},
		{"volume with the ext4lite driver", Config{Mounts: []Mount{{Kind: MountVolume, VolumeName: "v", GuestPath: "/v", Driver: DriverExt4lite}}}, false},
		{"volume with the hostfs driver", Config{Mounts: []Mount{{Kind: MountVolume, VolumeName: "v", GuestPath: "/v", Driver: DriverHostfs}}}, true},
	} {
		if got := tc.cfg.hasHostDirs(); got != tc.want {
			t.Errorf("%s: hasHostDirs() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestTmpfsMountDataCarriesSizeAndMode(t *testing.T) {
	if got, want := tmpfsMountData(0), "mode=1777"; got != want {
		t.Errorf("tmpfsMountData(0) = %q, want %q", got, want)
	}
	if got, want := tmpfsMountData(1<<20), "size=1048576,mode=1777"; got != want {
		t.Errorf("tmpfsMountData(1 MiB) = %q, want %q", got, want)
	}
}

func TestParseMountDriver(t *testing.T) {
	for _, tc := range []struct {
		spec string
		want MountDriver
	}{
		{"type=volume,src=data,dst=/v", ""},
		{"src=data,dst=/v,driver=hostfs", DriverHostfs},
		{"src=data,dst=/v,driver=ext4lite", DriverExt4lite},
		{"src=data,dst=/v,driver=EXT4LITE", DriverExt4lite},
	} {
		m, err := ParseMount(tc.spec)
		if err != nil || m.Driver != tc.want || m.Kind != MountVolume {
			t.Errorf("ParseMount(%q) = %+v, %v; want a volume with driver %q", tc.spec, m, err, tc.want)
		}
	}
	for _, spec := range []string{
		"src=data,dst=/v,driver=zfs",
		"type=bind,src=/h,dst=/b,driver=hostfs",
		"type=tmpfs,dst=/t,driver=ext4lite",
	} {
		if m, err := ParseMount(spec); err == nil {
			t.Errorf("ParseMount(%q) = %+v, want an error", spec, m)
		}
	}
}
