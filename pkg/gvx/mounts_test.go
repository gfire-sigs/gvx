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

package gvx_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/oci"
)

func TestParseVolume(t *testing.T) {
	for _, tc := range []struct {
		spec string
		want gvx.Mount
	}{
		{"data:/data", gvx.Mount{Kind: gvx.MountVolume, VolumeName: "data", GuestPath: "/data"}},
		{"data:/data:rw", gvx.Mount{Kind: gvx.MountVolume, VolumeName: "data", GuestPath: "/data"}},
		{"my-vol_1.2:/d:ro", gvx.Mount{Kind: gvx.MountVolume, VolumeName: "my-vol_1.2", GuestPath: "/d", ReadOnly: true}},
		{"/host/dir:/data", gvx.Mount{Kind: gvx.MountBind, HostPath: "/host/dir", GuestPath: "/data", CreateHostPathIfMissing: true}},
		{"/host/dir:/data:ro", gvx.Mount{Kind: gvx.MountBind, HostPath: "/host/dir", GuestPath: "/data", ReadOnly: true, CreateHostPathIfMissing: true}},
		{"./relative:/data", gvx.Mount{Kind: gvx.MountBind, HostPath: "./relative", GuestPath: "/data", CreateHostPathIfMissing: true}},
		{"sub/dir:/data", gvx.Mount{Kind: gvx.MountBind, HostPath: "sub/dir", GuestPath: "/data", CreateHostPathIfMissing: true}},
		{`C:\data:/data:ro`, gvx.Mount{Kind: gvx.MountBind, HostPath: `C:\data`, GuestPath: "/data", ReadOnly: true, CreateHostPathIfMissing: true}},
		{`C:\data:/data`, gvx.Mount{Kind: gvx.MountBind, HostPath: `C:\data`, GuestPath: "/data", CreateHostPathIfMissing: true}},
		{`d:\My Files\x:/x:rw`, gvx.Mount{Kind: gvx.MountBind, HostPath: `d:\My Files\x`, GuestPath: "/x", CreateHostPathIfMissing: true}},
		{"C:/data:/data", gvx.Mount{Kind: gvx.MountBind, HostPath: "C:/data", GuestPath: "/data", CreateHostPathIfMissing: true}},
		{"C:/data:/data:ro", gvx.Mount{Kind: gvx.MountBind, HostPath: "C:/data", GuestPath: "/data", ReadOnly: true, CreateHostPathIfMissing: true}},
		{"/host/file.txt:/data/file.txt", gvx.Mount{Kind: gvx.MountBind, HostPath: "/host/file.txt", GuestPath: "/data/file.txt", CreateHostPathIfMissing: true}},
		{"/host/file.txt:/data/file.txt:ro", gvx.Mount{Kind: gvx.MountBind, HostPath: "/host/file.txt", GuestPath: "/data/file.txt", ReadOnly: true, CreateHostPathIfMissing: true}},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			got, err := gvx.ParseVolume(tc.spec)
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
		if m, err := gvx.ParseVolume(spec); err == nil {
			t.Errorf("ParseVolume(%q) = %+v, want an error", spec, m)
		}
	}
}

func TestParseMount(t *testing.T) {
	for _, tc := range []struct {
		spec string
		want gvx.Mount
	}{
		{"type=bind,src=/h,dst=/g", gvx.Mount{Kind: gvx.MountBind, HostPath: "/h", GuestPath: "/g"}},
		{"type=bind,source=/h,target=/g,readonly", gvx.Mount{Kind: gvx.MountBind, HostPath: "/h", GuestPath: "/g", ReadOnly: true}},
		{"type=bind,source=/h,destination=/g,ro=true", gvx.Mount{Kind: gvx.MountBind, HostPath: "/h", GuestPath: "/g", ReadOnly: true}},
		{"type=bind,source=/h,destination=/g,readonly=false", gvx.Mount{Kind: gvx.MountBind, HostPath: "/h", GuestPath: "/g"}},
		{`type=bind,src=C:\data,dst=/g,ro`, gvx.Mount{Kind: gvx.MountBind, HostPath: `C:\data`, GuestPath: "/g", ReadOnly: true}},
		{`type=bind,"src=/h,x",dst=/g`, gvx.Mount{Kind: gvx.MountBind, HostPath: "/h,x", GuestPath: "/g"}},
		{"type=bind,src=/h/file.txt,dst=/g/file.txt", gvx.Mount{Kind: gvx.MountBind, HostPath: "/h/file.txt", GuestPath: "/g/file.txt"}},
		{"type=bind,src=/h/file.txt,dst=/g/file.txt,ro", gvx.Mount{Kind: gvx.MountBind, HostPath: "/h/file.txt", GuestPath: "/g/file.txt", ReadOnly: true}},
		{"type=volume,src=data,dst=/v", gvx.Mount{Kind: gvx.MountVolume, VolumeName: "data", GuestPath: "/v"}},
		{"src=data,dst=/v,ro", gvx.Mount{Kind: gvx.MountVolume, VolumeName: "data", GuestPath: "/v", ReadOnly: true}},
		{"type=volume,src=/disk/data.ext4,dst=/v", gvx.Mount{Kind: gvx.MountVolume, ImagePath: "/disk/data.ext4", GuestPath: "/v"}},
		{"src=./data.ext4,dst=/v,driver=ext4lite", gvx.Mount{Kind: gvx.MountVolume, ImagePath: "./data.ext4", GuestPath: "/v", Driver: gvx.DriverExt4lite}},
		{`src=D:\vols\data.ext4,dst=/v,ro`, gvx.Mount{Kind: gvx.MountVolume, ImagePath: `D:\vols\data.ext4`, GuestPath: "/v", ReadOnly: true}},
		{"type=tmpfs,dst=/t", gvx.Mount{Kind: gvx.MountTmpfs, GuestPath: "/t"}},
		{"type=tmpfs,target=/t,tmpfs-size=64m", gvx.Mount{Kind: gvx.MountTmpfs, GuestPath: "/t", TmpfsSizeBytes: 64 << 20}},
		{"type=tmpfs,target=/t,tmpfs-size=4096", gvx.Mount{Kind: gvx.MountTmpfs, GuestPath: "/t", TmpfsSizeBytes: 4096}},
		{"TYPE=Tmpfs,Target=/t,RO", gvx.Mount{Kind: gvx.MountTmpfs, GuestPath: "/t", ReadOnly: true}},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			got, err := gvx.ParseMount(tc.spec)
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
		"type=volume,src=/disk/data.ext4,dst=/v,driver=hostfs",
	} {
		if m, err := gvx.ParseMount(spec); err == nil {
			t.Errorf("ParseMount(%q) = %+v, want an error", spec, m)
		}
	}
}

func TestParseTmpfs(t *testing.T) {
	for _, tc := range []struct {
		spec string
		want gvx.Mount
	}{
		{"/t", gvx.Mount{Kind: gvx.MountTmpfs, GuestPath: "/t"}},
		{"/t:size=64m", gvx.Mount{Kind: gvx.MountTmpfs, GuestPath: "/t", TmpfsSizeBytes: 64 << 20}},
		{"/t:size=64M", gvx.Mount{Kind: gvx.MountTmpfs, GuestPath: "/t", TmpfsSizeBytes: 64 << 20}},
		{"/t:size=1g,ro", gvx.Mount{Kind: gvx.MountTmpfs, GuestPath: "/t", TmpfsSizeBytes: 1 << 30, ReadOnly: true}},
		{"/t:size=512k", gvx.Mount{Kind: gvx.MountTmpfs, GuestPath: "/t", TmpfsSizeBytes: 512 << 10}},
		{"/t:size=100b", gvx.Mount{Kind: gvx.MountTmpfs, GuestPath: "/t", TmpfsSizeBytes: 100}},
		{"/t:size=100", gvx.Mount{Kind: gvx.MountTmpfs, GuestPath: "/t", TmpfsSizeBytes: 100}},
		{"/t:ro,rw", gvx.Mount{Kind: gvx.MountTmpfs, GuestPath: "/t"}},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			got, err := gvx.ParseTmpfs(tc.spec)
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
		if m, err := gvx.ParseTmpfs(spec); err == nil {
			t.Errorf("ParseTmpfs(%q) = %+v, want an error", spec, m)
		}
	}
}

func TestConfigNormalizeRejectsInvalidMounts(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	tmpfs := func(guest string) gvx.Mount { return gvx.Mount{Kind: gvx.MountTmpfs, GuestPath: guest} }

	for _, tc := range []struct {
		name    string
		cfg     gvx.Config
		wantMsg string
	}{
		{"relative guest path", gvx.Config{Mounts: []gvx.Mount{tmpfs("data")}}, "absolute"},
		{"guest path with trailing slash", gvx.Config{Mounts: []gvx.Mount{tmpfs("/data/")}}, "clean"},
		{"guest path with empty element", gvx.Config{Mounts: []gvx.Mount{tmpfs("/a//b")}}, "clean"},
		{"guest path with dot-dot", gvx.Config{Mounts: []gvx.Mount{tmpfs("/a/../b")}}, "clean"},
		{"guest root", gvx.Config{Mounts: []gvx.Mount{tmpfs("/")}}, "/"},
		{"proc", gvx.Config{Mounts: []gvx.Mount{tmpfs("/proc")}}, "/proc"},
		{"below proc", gvx.Config{Mounts: []gvx.Mount{tmpfs("/proc/self")}}, "/proc"},
		{"sys", gvx.Config{Mounts: []gvx.Mount{tmpfs("/sys")}}, "/sys"},
		{"below sys", gvx.Config{Mounts: []gvx.Mount{tmpfs("/sys/fs")}}, "/sys"},
		{"dev", gvx.Config{Mounts: []gvx.Mount{tmpfs("/dev")}}, "/dev"},
		{"below dev", gvx.Config{Mounts: []gvx.Mount{tmpfs("/dev/null")}}, "/dev"},
		{"dev shm itself", gvx.Config{Mounts: []gvx.Mount{tmpfs("/dev/shm")}}, "/dev"},
		{"duplicate guest path", gvx.Config{Mounts: []gvx.Mount{tmpfs("/a"), {Kind: gvx.MountVolume, VolumeName: "v", GuestPath: "/a"}}}, "/a"},
		{"mount at workspace with WorkspacePath", gvx.Config{WorkspacePath: dir, Mounts: []gvx.Mount{tmpfs("/workspace")}}, "WorkspacePath"},
		{"missing bind source", gvx.Config{Mounts: []gvx.Mount{{Kind: gvx.MountBind, HostPath: missing, GuestPath: "/a"}}}, "does not exist"},
		{"bind without source", gvx.Config{Mounts: []gvx.Mount{{Kind: gvx.MountBind, GuestPath: "/a"}}}, "HostPath"},
		{"bind with volume name", gvx.Config{Mounts: []gvx.Mount{{Kind: gvx.MountBind, HostPath: dir, VolumeName: "v", GuestPath: "/a"}}}, "VolumeName"},
		{"bind with size", gvx.Config{Mounts: []gvx.Mount{{Kind: gvx.MountBind, HostPath: dir, GuestPath: "/a", TmpfsSizeBytes: 1}}}, "TmpfsSizeBytes"},
		{"volume with bad name", gvx.Config{Mounts: []gvx.Mount{{Kind: gvx.MountVolume, VolumeName: "../x", GuestPath: "/a"}}}, "volume name"},
		{"volume with empty name", gvx.Config{Mounts: []gvx.Mount{{Kind: gvx.MountVolume, GuestPath: "/a"}}}, "volume name"},
		{"volume with host path", gvx.Config{Mounts: []gvx.Mount{{Kind: gvx.MountVolume, VolumeName: "v", HostPath: dir, GuestPath: "/a"}}}, "HostPath"},
		{"volume with create flag", gvx.Config{Mounts: []gvx.Mount{{Kind: gvx.MountVolume, VolumeName: "v", GuestPath: "/a", CreateHostPathIfMissing: true}}}, "CreateHostPathIfMissing"},
		{"tmpfs with host path", gvx.Config{Mounts: []gvx.Mount{{Kind: gvx.MountTmpfs, HostPath: dir, GuestPath: "/a"}}}, "HostPath"},
		{"tmpfs with negative size", gvx.Config{Mounts: []gvx.Mount{{Kind: gvx.MountTmpfs, GuestPath: "/a", TmpfsSizeBytes: -1}}}, "TmpfsSizeBytes"},
		{"unknown kind", gvx.Config{Mounts: []gvx.Mount{{Kind: "nfs", GuestPath: "/a"}}}, "kind"},
		{"empty kind", gvx.Config{Mounts: []gvx.Mount{{GuestPath: "/a"}}}, "kind"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := gvx.NormalizeConfigForTest(&tc.cfg)
			if !errors.Is(err, gvx.ErrInvalidConfig) {
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
	cfg := gvx.Config{Mounts: []gvx.Mount{{Kind: gvx.MountBind, HostPath: os.DevNull, GuestPath: "/null"}}}
	err := gvx.NormalizeConfigForTest(&cfg)
	if !errors.Is(err, gvx.ErrInvalidConfig) || !strings.Contains(err.Error(), "neither a directory nor a regular file") {
		t.Fatalf("normalize() error = %v, want ErrInvalidConfig that names the file type", err)
	}
	cfg.Mounts[0].CreateHostPathIfMissing = true
	if err := gvx.NormalizeConfigForTest(&cfg); err == nil {
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
	cfg := gvx.Config{Mounts: []gvx.Mount{
		{Kind: gvx.MountBind, HostPath: dir, GuestPath: "/workspace"},
		{Kind: gvx.MountBind, HostPath: missing, GuestPath: "/created", CreateHostPathIfMissing: true},
		{Kind: gvx.MountBind, HostPath: dir, GuestPath: "/again", ReadOnly: true},
		{Kind: gvx.MountBind, HostPath: file, GuestPath: "/data/file.txt"},
		{Kind: gvx.MountBind, HostPath: file, GuestPath: "/file-ro.txt", ReadOnly: true},
		{Kind: gvx.MountBind, HostPath: file, GuestPath: "/file-create.txt", CreateHostPathIfMissing: true},
		{Kind: gvx.MountVolume, VolumeName: "Data-1.x_y", GuestPath: "/vol"},
		{Kind: gvx.MountTmpfs, GuestPath: "/dev/shm/inner", TmpfsSizeBytes: 4096},
		{Kind: gvx.MountTmpfs, GuestPath: "/a/b/c"},
	}}
	if err := gvx.NormalizeConfigForTest(&cfg); err != nil {
		t.Fatalf("normalize() failed: %v", err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("normalize() created the bind source: stat error = %v", err)
	}
	withWorkspace := gvx.Config{WorkspacePath: dir, Mounts: []gvx.Mount{{Kind: gvx.MountTmpfs, GuestPath: "/scratch"}}}
	if err := gvx.NormalizeConfigForTest(&withWorkspace); err != nil {
		t.Fatalf("normalize() with WorkspacePath and another mount failed: %v", err)
	}
}

func TestSortMountsByDepthKeepsOrderWithinOneDepth(t *testing.T) {
	got := gvx.SortMountPathsByDepthForTest([]string{"/a/b/c", "/z", "/a/b", "/m", "/a"})
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
	cfg := gvx.Config{
		OCICacheDir:   filepath.Join(root, "cache"),
		WorkspacePath: workspaceDir,
		Mounts: []gvx.Mount{
			{Kind: gvx.MountTmpfs, GuestPath: "/a/b/scratch"},
			{Kind: gvx.MountBind, HostPath: roDir, GuestPath: "/mnt/ro", ReadOnly: true},
			{Kind: gvx.MountBind, HostPath: created, GuestPath: "/mnt/made", CreateHostPathIfMissing: true},
			{Kind: gvx.MountVolume, VolumeName: "data", GuestPath: "/vol"},
		},
	}
	if err := gvx.NormalizeConfigForTest(&cfg); err != nil {
		t.Fatal(err)
	}
	sb := gvx.NewSandboxForMountTest(cfg)
	t.Cleanup(func() {
		if err := gvx.CloseMountsForTest(sb); err != nil {
			t.Errorf("closeMounts() failed: %v", err)
		}
	})
	if err := gvx.OpenMountsForTest(sb); err != nil {
		t.Fatalf("openMounts() failed: %v", err)
	}

	if sb.Workspace() == nil || sb.Workspace().HostPath() != workspaceDir {
		t.Fatalf("Workspace() = %v, want the workspace of %s", sb.Workspace(), workspaceDir)
	}
	var guestOrder []string
	for _, m := range gvx.PreparedMountsForTest(sb) {
		guestOrder = append(guestOrder, m.GuestPath)
	}
	if want := []string{"/workspace", "/vol", "/mnt/ro", "/mnt/made", "/a/b/scratch"}; !slices.Equal(guestOrder, want) {
		t.Fatalf("mount order = %v, want %v", guestOrder, want)
	}
	volumeRoot := filepath.Join(root, "cache", "volumes")
	wantHost := []hostlockdown.HostMount{
		{Path: workspaceDir}, {Path: roDir, ReadOnly: true}, {Path: created},
	}
	if got := gvx.HostMountsForTest(sb); !slices.Equal(got, wantHost) {
		t.Fatalf("hostMounts() = %+v, want %+v (an ext4lite volume needs no host path)", got, wantHost)
	}
	if !gvx.UsesHostDirsForTest(sb) {
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
	if gotWS, gotVol := gvx.OpenWorkspaceCountForTest(sb), gvx.OpenVolumeCountForTest(sb); gotWS != 3 || gotVol != 1 {
		t.Errorf("open workspaces = %d and volumes = %d, want 3 and 1", gotWS, gotVol)
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
	cfg := gvx.Config{Mounts: []gvx.Mount{
		{Kind: gvx.MountBind, HostPath: file, GuestPath: "/data.txt"},
		{Kind: gvx.MountBind, HostPath: filepath.Join(dir, ".", "data.txt"), GuestPath: "/again.txt"},
		{Kind: gvx.MountBind, HostPath: file, GuestPath: "/ro.txt", ReadOnly: true, CreateHostPathIfMissing: true},
		{Kind: gvx.MountBind, HostPath: dir, GuestPath: "/dir"},
	}}
	if err := gvx.NormalizeConfigForTest(&cfg); err != nil {
		t.Fatal(err)
	}
	sb := gvx.NewSandboxForMountTest(cfg)
	t.Cleanup(func() {
		if err := gvx.CloseMountsForTest(sb); err != nil {
			t.Errorf("closeMounts() failed: %v", err)
		}
	})
	if err := gvx.OpenMountsForTest(sb); err != nil {
		t.Fatalf("openMounts() failed: %v", err)
	}
	// A file mount and a mount of its parent are different workspaces. Two
	// mounts of one file with the same access share one workspace.
	if got := gvx.OpenWorkspaceCountForTest(sb); got != 3 {
		t.Fatalf("open workspaces = %d, want 3 (shared writable file, read-only file, directory)", got)
	}
	byGuest := make(map[string]gvx.PreparedMountForTest)
	for _, m := range gvx.PreparedMountsForTest(sb) {
		byGuest[m.GuestPath] = m
	}
	if byGuest["/data.txt"].Workspace != byGuest["/again.txt"].Workspace {
		t.Error("two writable mounts of one file use two workspaces, want one")
	}
	if byGuest["/data.txt"].Workspace == byGuest["/ro.txt"].Workspace {
		t.Error("a read-only and a writable mount of one file share a workspace")
	}
	if byGuest["/data.txt"].Workspace == byGuest["/dir"].Workspace {
		t.Error("a file mount and a mount of its parent directory share a workspace")
	}
	for _, guest := range []string{"/data.txt", "/again.txt", "/ro.txt"} {
		m := byGuest[guest]
		if !m.HostFile || m.HostPath != realFile || !m.Workspace.SingleFile() {
			t.Errorf("mount %s: HostFile = %v, HostPath = %q, SingleFile = %v; want a file mount of %q", guest, m.HostFile, m.HostPath, m.Workspace.SingleFile(), realFile)
		}
	}
	if m := byGuest["/dir"]; m.HostFile || m.Workspace.SingleFile() {
		t.Errorf("directory mount: HostFile = %v, SingleFile = %v; want false", m.HostFile, m.Workspace.SingleFile())
	}
	if got, err := os.ReadFile(file); err != nil || string(got) != "host data" {
		t.Errorf("host file = %q, %v; want it unchanged", got, err)
	}

	var files, dirs int
	for _, hm := range gvx.HostMountsForTest(sb) {
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
	if !gvx.UsesHostDirsForTest(sb) {
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
	sb := gvx.NewSandboxForMountTest(gvx.Config{Mounts: []gvx.Mount{
		{Kind: gvx.MountBind, HostPath: file, GuestPath: "/data.txt", CreateHostPathIfMissing: true},
		{Kind: gvx.MountBind, HostPath: created, GuestPath: "/made", CreateHostPathIfMissing: true},
	}})
	t.Cleanup(func() {
		if err := gvx.CloseMountsForTest(sb); err != nil {
			t.Errorf("closeMounts() failed: %v", err)
		}
	})
	if err := gvx.OpenMountsForTest(sb); err != nil {
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
	sb := gvx.NewSandboxForMountTest(gvx.Config{WorkspacePath: file})
	err := gvx.OpenMountsForTest(sb)
	if !errors.Is(err, gvx.ErrInvalidConfig) || !strings.Contains(err.Error(), "WorkspacePath") {
		t.Fatalf("openMounts() error = %v, want ErrInvalidConfig that names WorkspacePath", err)
	}
	if err := gvx.CloseMountsForTest(sb); err != nil {
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
	cfg := gvx.Config{OCICacheDir: cache, Mounts: []gvx.Mount{
		{Kind: gvx.MountVolume, VolumeName: "legacy", GuestPath: "/legacy"},
		{Kind: gvx.MountVolume, VolumeName: "fresh", GuestPath: "/fresh"},
		{Kind: gvx.MountVolume, VolumeName: "forced", GuestPath: "/forced", Driver: gvx.DriverHostfs},
	}}
	if err := gvx.NormalizeConfigForTest(&cfg); err != nil {
		t.Fatal(err)
	}
	sb := gvx.NewSandboxForMountTest(cfg)
	t.Cleanup(func() {
		if err := gvx.CloseMountsForTest(sb); err != nil {
			t.Errorf("closeMounts() failed: %v", err)
		}
	})
	if err := gvx.OpenMountsForTest(sb); err != nil {
		t.Fatalf("openMounts() failed: %v", err)
	}
	got := map[string]gvx.MountDriver{}
	for _, m := range gvx.PreparedMountsForTest(sb) {
		got[m.VolumeName] = m.Driver
	}
	want := map[string]gvx.MountDriver{"legacy": gvx.DriverHostfs, "fresh": gvx.DriverExt4lite, "forced": gvx.DriverHostfs}
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
	open := func(mounts ...gvx.Mount) (*gvx.Sandbox, error) {
		cfg := gvx.Config{OCICacheDir: cache, Mounts: mounts}
		if err := gvx.NormalizeConfigForTest(&cfg); err != nil {
			t.Fatal(err)
		}
		sb := gvx.NewSandboxForMountTest(cfg)
		return sb, gvx.OpenMountsForTest(sb)
	}
	first, err := open(gvx.Mount{Kind: gvx.MountVolume, VolumeName: "shared", GuestPath: "/a"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := open(gvx.Mount{Kind: gvx.MountVolume, VolumeName: "shared", GuestPath: "/a"})
	if err == nil || !strings.Contains(err.Error(), "in use") {
		t.Errorf("a second sandbox on the same volume = %v, want an in-use error", err)
	}
	if cerr := gvx.CloseMountsForTest(second); cerr != nil {
		t.Errorf("closeMounts() after a failed openMounts() = %v", cerr)
	}
	if err := gvx.CloseMountsForTest(first); err != nil {
		t.Fatal(err)
	}
	again, err := open(gvx.Mount{Kind: gvx.MountVolume, VolumeName: "shared", GuestPath: "/a"})
	if err != nil {
		t.Fatalf("reopen of a closed volume: %v", err)
	}
	if err := gvx.CloseMountsForTest(again); err != nil {
		t.Fatal(err)
	}
	dup, err := open(
		gvx.Mount{Kind: gvx.MountVolume, VolumeName: "twice", GuestPath: "/a"},
		gvx.Mount{Kind: gvx.MountVolume, VolumeName: "twice", GuestPath: "/b"},
	)
	if !errors.Is(err, gvx.ErrInvalidConfig) {
		t.Errorf("one volume mounted twice = %v, want ErrInvalidConfig", err)
	}
	if err := gvx.CloseMountsForTest(dup); err != nil {
		t.Fatal(err)
	}
	_, err = open(gvx.Mount{Kind: gvx.MountVolume, VolumeName: "missing", GuestPath: "/a", ReadOnly: true})
	if err == nil {
		t.Error("a read-only mount of a missing volume succeeded")
	}
}

// A volume at an ImagePath keeps its files across sandboxes, is refused when
// it is busy or mounted twice, and needs its directory to exist.
func TestOpenMountsVolumeAtImagePath(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join(dir, "data.ext4")
	open := func(mounts ...gvx.Mount) (*gvx.Sandbox, error) {
		cfg := gvx.Config{OCICacheDir: t.TempDir(), Mounts: mounts}
		if err := gvx.NormalizeConfigForTest(&cfg); err != nil {
			t.Fatal(err)
		}
		sb := gvx.NewSandboxForMountTest(cfg)
		return sb, gvx.OpenMountsForTest(sb)
	}

	first, err := open(gvx.Mount{Kind: gvx.MountVolume, ImagePath: image, GuestPath: "/a"})
	if err != nil {
		t.Fatalf("open a new image: %v", err)
	}
	if info, err := os.Stat(image); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("image file after open = %v, %v; want a regular file", info, err)
	}
	busy, err := open(gvx.Mount{Kind: gvx.MountVolume, ImagePath: image, GuestPath: "/a"})
	if err == nil || !strings.Contains(err.Error(), "in use") {
		t.Errorf("a second sandbox on the same image = %v, want an in-use error", err)
	}
	if err := gvx.CloseMountsForTest(busy); err != nil {
		t.Fatal(err)
	}
	if err := gvx.CloseMountsForTest(first); err != nil {
		t.Fatal(err)
	}

	// A relative path and an absolute path to one image are the same volume.
	t.Chdir(dir)
	dup, err := open(
		gvx.Mount{Kind: gvx.MountVolume, ImagePath: "data.ext4", GuestPath: "/a"},
		gvx.Mount{Kind: gvx.MountVolume, ImagePath: image, GuestPath: "/b"},
	)
	if !errors.Is(err, gvx.ErrInvalidConfig) {
		t.Errorf("one image mounted twice = %v, want ErrInvalidConfig", err)
	}
	if err := gvx.CloseMountsForTest(dup); err != nil {
		t.Fatal(err)
	}

	for _, m := range []gvx.Mount{
		{Kind: gvx.MountVolume, ImagePath: filepath.Join(dir, "no-such-dir", "x.ext4"), GuestPath: "/a"},
		{Kind: gvx.MountVolume, ImagePath: filepath.Join(dir, "missing.ext4"), GuestPath: "/a", ReadOnly: true},
		{Kind: gvx.MountVolume, ImagePath: dir, GuestPath: "/a"},
	} {
		sb, err := open(m)
		if err == nil {
			t.Errorf("openMounts(%+v) succeeded, want an error", m)
		}
		if err := gvx.CloseMountsForTest(sb); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "missing.ext4")); !os.IsNotExist(err) {
		t.Errorf("a read-only mount created the image: %v", err)
	}
}

func TestOpenMountsSharesOneWorkspacePerDirectoryAndAccess(t *testing.T) {
	dir := t.TempDir()
	cfg := gvx.Config{Mounts: []gvx.Mount{
		{Kind: gvx.MountBind, HostPath: dir, GuestPath: "/one"},
		{Kind: gvx.MountBind, HostPath: dir, GuestPath: "/two"},
		{Kind: gvx.MountBind, HostPath: dir, GuestPath: "/three", ReadOnly: true},
		{Kind: gvx.MountBind, HostPath: filepath.Join(dir, "."), GuestPath: "/four"},
	}}
	if err := gvx.NormalizeConfigForTest(&cfg); err != nil {
		t.Fatal(err)
	}
	sb := gvx.NewSandboxForMountTest(cfg)
	t.Cleanup(func() {
		if err := gvx.CloseMountsForTest(sb); err != nil {
			t.Errorf("closeMounts() failed: %v", err)
		}
	})
	if err := gvx.OpenMountsForTest(sb); err != nil {
		t.Fatalf("openMounts() failed: %v", err)
	}
	if got := gvx.OpenWorkspaceCountForTest(sb); got != 2 {
		t.Fatalf("open workspaces = %d, want 2 (one writable, one read-only)", got)
	}
	if sb.Workspace() != nil {
		t.Errorf("Workspace() is set without a mount at /workspace")
	}
	if got := len(gvx.HostMountsForTest(sb)); got != 4 {
		t.Errorf("hostMounts() has %d entries, want one for each mount", got)
	}
}

// Each directory mount keeps its own table, so no layout is refused. A layout
// that does not line up in the guest works as it did before the tables.
func TestOpenMountsAllowsNestedDirectories(t *testing.T) {
	root := t.TempDir()
	inner := filepath.Join(root, "node_modules")
	if err := os.Mkdir(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		cfg  gvx.Config
	}{
		{
			name: "compose layout through the workspace",
			cfg:  gvx.Config{WorkspacePath: root, Mounts: []gvx.Mount{{Kind: gvx.MountBind, HostPath: inner, GuestPath: "/workspace/node_modules"}}},
		},
		{
			name: "compose layout through two bind mounts",
			cfg: gvx.Config{Mounts: []gvx.Mount{
				{Kind: gvx.MountBind, HostPath: root, GuestPath: "/app"},
				{Kind: gvx.MountBind, HostPath: inner, GuestPath: "/app/node_modules"},
			}},
		},
		{
			name: "layout that does not line up in the guest",
			cfg: gvx.Config{Mounts: []gvx.Mount{
				{Kind: gvx.MountBind, HostPath: root, GuestPath: "/app"},
				{Kind: gvx.MountBind, HostPath: inner, GuestPath: "/var/log/app"},
			}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := gvx.NormalizeConfigForTest(&tc.cfg); err != nil {
				t.Fatal(err)
			}
			sb := gvx.NewSandboxForMountTest(tc.cfg)
			t.Cleanup(func() {
				if err := gvx.CloseMountsForTest(sb); err != nil {
					t.Errorf("closeMounts() failed: %v", err)
				}
			})
			if err := gvx.OpenMountsForTest(sb); err != nil {
				t.Fatalf("openMounts() = %v, want success", err)
			}
			if got := gvx.OpenWorkspaceCountForTest(sb); got != 2 {
				t.Fatalf("openMounts() opened %d workspaces, want 2: the inner directory keeps its own table", got)
			}
		})
	}
}

func TestOpenMountsFailsForMissingBindSourceAndReleasesHandles(t *testing.T) {
	dir := t.TempDir()
	sb := gvx.NewSandboxForMountTest(gvx.Config{WorkspacePath: dir, Mounts: []gvx.Mount{{Kind: gvx.MountBind, HostPath: filepath.Join(dir, "gone"), GuestPath: "/gone"}}})
	if err := gvx.OpenMountsForTest(sb); err == nil {
		t.Fatal("openMounts() succeeded for a missing bind source")
	}
	if err := gvx.CloseMountsForTest(sb); err != nil {
		t.Fatalf("closeMounts() after a failed openMounts() = %v, want success", err)
	}
	if sb.Workspace() != nil || gvx.OpenWorkspaceCountForTest(sb) != 0 {
		t.Fatalf("closeMounts() left %d workspaces and Workspace() = %v", gvx.OpenWorkspaceCountForTest(sb), sb.Workspace())
	}
}

func TestVolumeRootLiesBelowTheCacheDirectoryOverride(t *testing.T) {
	override := t.TempDir()
	got, err := gvx.VolumeRootForTest(gvx.Config{OCICacheDir: override})
	if err != nil || got != filepath.Join(override, "volumes") {
		t.Fatalf("volumeRoot() with OCICacheDir = (%q, %v), want %q", got, err, filepath.Join(override, "volumes"))
	}

	layers, layersErr := oci.DefaultCacheDir()
	got, err = gvx.VolumeRootForTest(gvx.Config{})
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
		cfg  gvx.Config
		want bool
	}{
		{"no mounts", gvx.Config{}, false},
		{"tmpfs only", gvx.Config{Mounts: []gvx.Mount{{Kind: gvx.MountTmpfs, GuestPath: "/t"}}}, false},
		{"workspace", gvx.Config{WorkspacePath: "/w"}, true},
		{"bind", gvx.Config{Mounts: []gvx.Mount{{Kind: gvx.MountBind, HostPath: "/h", GuestPath: "/b"}}}, true},
		{"bind of a file path", gvx.Config{Mounts: []gvx.Mount{{Kind: gvx.MountBind, HostPath: "/h/file.txt", GuestPath: "/f.txt"}}}, true},
		{"volume", gvx.Config{Mounts: []gvx.Mount{{Kind: gvx.MountVolume, VolumeName: "v", GuestPath: "/v"}}}, false},
		{"volume with the ext4lite driver", gvx.Config{Mounts: []gvx.Mount{{Kind: gvx.MountVolume, VolumeName: "v", GuestPath: "/v", Driver: gvx.DriverExt4lite}}}, false},
		{"volume with the hostfs driver", gvx.Config{Mounts: []gvx.Mount{{Kind: gvx.MountVolume, VolumeName: "v", GuestPath: "/v", Driver: gvx.DriverHostfs}}}, true},
	} {
		if got := gvx.HasHostDirsForTest(tc.cfg); got != tc.want {
			t.Errorf("%s: hasHostDirs() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestTmpfsMountDataCarriesSizeAndMode(t *testing.T) {
	if got, want := gvx.TmpfsMountDataForTest(0), "mode=1777"; got != want {
		t.Errorf("tmpfsMountData(0) = %q, want %q", got, want)
	}
	if got, want := gvx.TmpfsMountDataForTest(1<<20), "size=1048576,mode=1777"; got != want {
		t.Errorf("tmpfsMountData(1 MiB) = %q, want %q", got, want)
	}
}

func TestParseMountDriver(t *testing.T) {
	for _, tc := range []struct {
		spec string
		want gvx.MountDriver
	}{
		{"type=volume,src=data,dst=/v", ""},
		{"src=data,dst=/v,driver=hostfs", gvx.DriverHostfs},
		{"src=data,dst=/v,driver=ext4lite", gvx.DriverExt4lite},
		{"src=data,dst=/v,driver=EXT4LITE", gvx.DriverExt4lite},
	} {
		m, err := gvx.ParseMount(tc.spec)
		if err != nil || m.Driver != tc.want || m.Kind != gvx.MountVolume {
			t.Errorf("ParseMount(%q) = %+v, %v; want a volume with driver %q", tc.spec, m, err, tc.want)
		}
	}
	for _, spec := range []string{
		"src=data,dst=/v,driver=zfs",
		"type=bind,src=/h,dst=/b,driver=hostfs",
		"type=tmpfs,dst=/t,driver=ext4lite",
	} {
		if m, err := gvx.ParseMount(spec); err == nil {
			t.Errorf("ParseMount(%q) = %+v, want an error", spec, m)
		}
	}
}
