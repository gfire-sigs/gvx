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

//go:build darwin || windows

package gvx

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"z.gfire.dev/gvx/internal/hvtest"
	"z.gfire.dev/gvx/internal/systraptest"
	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
)

// guestMountTable is one parsed line of /proc/mounts.
type guestMountTable struct {
	order    []string
	fsType   map[string]string
	options  map[string]string
	readOnly map[string]bool
}

func parseProcMounts(t *testing.T, text string) guestMountTable {
	t.Helper()
	table := guestMountTable{fsType: map[string]string{}, options: map[string]string{}, readOnly: map[string]bool{}}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		target := fields[1]
		table.order = append(table.order, target)
		table.fsType[target] = fields[2]
		table.options[target] = fields[3]
		table.readOnly[target] = strings.Split(fields[3], ",")[0] == "ro"
	}
	return table
}

// TestSandboxMountsInGuest runs a guest that prints /proc/mounts and one file
// from each bind and volume mount. The run needs the hardware backend or the
// systrap engine of the host.
func TestSandboxMountsInGuest(t *testing.T) {
	if !hvtest.Available() {
		systraptest.Require(t)
	}
	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	layer, err := testimage.Tar(testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755})
	if err != nil {
		t.Fatal(err)
	}

	for _, readOnlyRoot := range []bool{false, true} {
		name := "writable root"
		if readOnlyRoot {
			name = "read-only root"
		}
		t.Run(name, func(t *testing.T) {
			writable, readOnly := t.TempDir(), t.TempDir()
			for dir, text := range map[string]string{writable: "from-writable\n", readOnly: "from-read-only\n"} {
				if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte(text), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfg := hostTestConfig(t)
			cfg.OCILayerTars = [][]byte{layer}
			volumeDir := filepath.Join(cfg.OCICacheDir, "volumes", "data")
			if err := os.MkdirAll(volumeDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(volumeDir, "hello.txt"), []byte("from-volume\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			// The nested tmpfs comes first, so the test also proves that
			// the guest mounts by increasing depth.
			cfg.Mounts = []Mount{
				{Kind: MountTmpfs, GuestPath: "/mnt/a/inner", TmpfsSizeBytes: 1 << 20},
				{Kind: MountBind, HostPath: writable, GuestPath: "/mnt/a"},
				{Kind: MountBind, HostPath: readOnly, GuestPath: "/mnt/b", ReadOnly: true},
				{Kind: MountVolume, VolumeName: "data", GuestPath: "/vol"},
				{Kind: MountTmpfs, GuestPath: "/scratch", TmpfsSizeBytes: 1 << 20, ReadOnly: true},
			}
			cfg.ReadOnlyRoot = readOnlyRoot
			cfg.Argv = []string{"/bin/cat", "/proc/mounts", "/mnt/a/hello.txt", "/mnt/b/hello.txt", "/vol/hello.txt"}
			code, stdout, stderr := runConfig(t, cfg)
			if code != 0 {
				t.Fatalf("guest exit code = %d, want 0 (stdout=%q stderr=%q)", code, stdout, stderr)
			}
			if want := "from-writable\nfrom-read-only\nfrom-volume\n"; !strings.HasSuffix(stdout, want) {
				t.Errorf("guest output does not end with the mount files %q:\n%s", want, stdout)
			}

			table := parseProcMounts(t, stdout)
			for target, want := range map[string]struct {
				fsType   string
				readOnly bool
			}{
				"/":            {"overlay", readOnlyRoot},
				"/proc":        {"proc", false},
				"/sys":         {"sysfs", false},
				"/dev":         {"dev", false},
				"/dev/pts":     {"devpts", false},
				"/dev/shm":     {"tmpfs", false},
				"/mnt/a":       {"hostfs", false},
				"/mnt/b":       {"hostfs", true},
				"/vol":         {"hostfs", false},
				"/scratch":     {"tmpfs", true},
				"/mnt/a/inner": {"tmpfs", false},
			} {
				if got := table.fsType[target]; got != want.fsType {
					t.Errorf("mount %s type = %q, want %q", target, got, want.fsType)
				}
				if got := table.readOnly[target]; got != want.readOnly {
					t.Errorf("mount %s read-only = %v, want %v (options %q)", target, got, want.readOnly, table.options[target])
				}
			}
			if got := table.options["/scratch"]; !strings.Contains(got, "size=1024k") {
				t.Errorf("tmpfs /scratch options = %q, want the 1 MiB size limit", got)
			}
			if outer, inner := slices.Index(table.order, "/mnt/a"), slices.Index(table.order, "/mnt/a/inner"); outer < 0 || inner < outer {
				t.Errorf("mount order = %v, want /mnt/a before /mnt/a/inner", table.order)
			}
		})
	}
}

// TestSandboxProcMountInfoWithHostMount runs a guest that reads
// /proc/self/mountinfo while a host directory is mounted. Package managers
// and container tools read this file, and a failure there ends the sandbox.
func TestSandboxProcMountInfoWithHostMount(t *testing.T) {
	if !hvtest.Available() {
		systraptest.Require(t)
	}
	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	layer, err := testimage.Tar(testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755})
	if err != nil {
		t.Fatal(err)
	}
	cfg := hostTestConfig(t)
	cfg.OCILayerTars = [][]byte{layer}
	cfg.Mounts = []Mount{{Kind: MountBind, HostPath: t.TempDir(), GuestPath: "/mnt/a"}}
	cfg.Argv = []string{"/bin/cat", "/proc/self/mountinfo"}
	code, stdout, stderr := runConfig(t, cfg)
	if code != 0 {
		t.Fatalf("guest exit code = %d, want 0 (stdout=%q stderr=%q)", code, stdout, stderr)
	}
	var found bool
	for _, line := range strings.Split(stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 4 && fields[4] == "/mnt/a" {
			found = true
			if fields[3] != "/" || !slices.Contains(fields, "hostfs") {
				t.Errorf("mountinfo line for /mnt/a = %q, want the root \"/\" of a hostfs mount", line)
			}
		}
	}
	if !found {
		t.Errorf("mountinfo has no line for /mnt/a:\n%s", stdout)
	}
}

// TestSandboxGuestWritesFollowMountAccess runs a guest that creates one file.
// The exit code and the host directories show which mounts accept writes.
func TestSandboxGuestWritesFollowMountAccess(t *testing.T) {
	if !hvtest.Available() {
		systraptest.Require(t)
	}
	for _, tc := range []struct {
		name         string
		guestPath    string
		readOnlyRoot bool
		wantCode     int
		hostDir      string // "writable", "read-only", "volume", or "" for no host file
	}{
		{"writable bind", "/mnt/a/out.txt", false, 0, "writable"},
		{"read-only bind", "/mnt/b/out.txt", false, 1, "read-only"},
		{"volume", "/vol/out.txt", false, 0, "volume"},
		{"tmpfs", "/scratch/out.txt", false, 0, ""},
		{"tmpfs under a read-only root", "/scratch/out.txt", true, 0, ""},
		{"bind under a read-only root", "/mnt/a/out.txt", true, 0, "writable"},
		{"root file", "/etc/out.txt", false, 0, ""},
		{"root file under a read-only root", "/etc/out.txt", true, 1, ""},
		{"tmp under a read-only root", "/tmp/out.txt", true, 1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, tc.guestPath, "guest-ran\n")
			if err != nil {
				t.Fatal(err)
			}
			hostDirs := map[string]string{"writable": t.TempDir(), "read-only": t.TempDir()}
			cfg := hostTestConfig(t)
			hostDirs["volume"] = filepath.Join(cfg.OCICacheDir, "volumes", "data")
			cfg.ELFBytes = writeELF
			cfg.Argv = []string{"/bin/app"}
			cfg.ReadOnlyRoot = tc.readOnlyRoot
			cfg.Mounts = []Mount{
				{Kind: MountBind, HostPath: hostDirs["writable"], GuestPath: "/mnt/a"},
				{Kind: MountBind, HostPath: hostDirs["read-only"], GuestPath: "/mnt/b", ReadOnly: true},
				{Kind: MountVolume, VolumeName: "data", GuestPath: "/vol"},
				{Kind: MountTmpfs, GuestPath: "/scratch"},
			}
			code, stdout, stderr := runConfig(t, cfg)
			if code != tc.wantCode {
				t.Fatalf("guest write to %s exited with %d, want %d (stdout=%q stderr=%q)", tc.guestPath, code, tc.wantCode, stdout, stderr)
			}
			for name, dir := range hostDirs {
				_, err := os.Stat(filepath.Join(dir, "out.txt"))
				if want := name == tc.hostDir && tc.wantCode == 0; (err == nil) != want {
					t.Errorf("host file in the %s directory exists = %v, want %v (stat error %v)", name, err == nil, want, err)
				}
			}
		})
	}
}
