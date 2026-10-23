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
	file := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
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
		{"bind source is a file", Config{Mounts: []Mount{{Kind: MountBind, HostPath: file, GuestPath: "/a"}}}, "files are not supported"},
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

func TestConfigNormalizeAcceptsMounts(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	cfg := Config{Mounts: []Mount{
		{Kind: MountBind, HostPath: dir, GuestPath: "/workspace"},
		{Kind: MountBind, HostPath: missing, GuestPath: "/created", CreateHostPathIfMissing: true},
		{Kind: MountBind, HostPath: dir, GuestPath: "/again", ReadOnly: true},
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
	volumeDir := filepath.Join(root, "cache", "volumes", "data")
	wantHost := []hostlockdown.HostMount{
		{Path: workspaceDir}, {Path: volumeDir}, {Path: roDir, ReadOnly: true}, {Path: created},
	}
	if got := sb.hostMounts(); !slices.Equal(got, wantHost) {
		t.Fatalf("hostMounts() = %+v, want %+v", got, wantHost)
	}
	if info, err := os.Stat(created); err != nil || !info.IsDir() {
		t.Fatalf("bind source %s was not created: %v", created, err)
	}
	info, err := os.Stat(volumeDir)
	if err != nil || !info.IsDir() {
		t.Fatalf("volume directory %s was not created: %v", volumeDir, err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Errorf("volume directory mode = %v, want 0700", info.Mode().Perm())
	}
	if len(sb.workspaces) != 4 {
		t.Errorf("open workspaces = %d, want one for each bind and volume mount", len(sb.workspaces))
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
		{"volume", Config{Mounts: []Mount{{Kind: MountVolume, VolumeName: "v", GuestPath: "/v"}}}, true},
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
