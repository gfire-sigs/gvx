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
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/internal/lockdownprobe"
)

// TestE2EFileSystemFeatures runs the guest program fsfeatures on an ext4lite
// volume and on a hostfs workspace. The program calls open with O_TMPFILE,
// linkat, fallocate, preadv2, and pwritev2, so each call travels from the guest
// through the system call layer to the driver. The ext4lite image must pass
// e2fsck afterwards, when the tool exists.
func TestE2EFileSystemFeatures(t *testing.T) {
	probe := toolPath(t, lockdownProbePkg)
	layouts := []struct {
		name string
		// mount returns the flags that mount the file system, the directory of
		// the mount in the guest, and the image to check, or "".
		mount func(cacheDir string) (flags []string, guestDir, image string)
	}{
		{"ext4lite", func(cacheDir string) ([]string, string, string) {
			return []string{"-volume=featvol:/data"}, "/data", filepath.Join(cacheDir, "volumes", "featvol.ext4")
		}},
		{"hostfs", func(string) ([]string, string, string) {
			return []string{"-workspace=" + t.TempDir()}, "/workspace", ""
		}},
	}
	for _, b := range fixedAddressBackends() {
		for _, layout := range layouts {
			t.Run(b.name+"/"+layout.name, func(t *testing.T) {
				requireFixedAddressBackend(t, b)
				guest := acceptprog.BuildFSFeatures(t, hostArch())
				cacheDir := t.TempDir()
				flags, guestDir, image := layout.mount(cacheDir)
				args := append([]string{"-bin=" + guest, "-cache-dir=" + cacheDir, "-platform=" + string(b.plat)}, flags...)
				stdout, stderr, code := runTool(t, probe, append(args, layout.name, guestDir)...)
				if code != 0 {
					t.Fatalf("lockdownprobe: exit code %d\nstdout=%s\nstderr=%s", code, stdout, stderr)
				}
				var rep lockdownprobe.Report
				if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
					t.Fatalf("decode the probe report %q: %v", stdout, err)
				}
				if msg := rep.NewErr; msg != "" {
					if strings.Contains(msg, "not position-independent") {
						t.Skipf("this engine cannot hold an executable that links at a fixed address: %s", msg)
					}
					t.Fatalf("New failed: %s", msg)
				}
				if msg := rep.GuestRunErr; strings.Contains(msg, "not position-independent") {
					t.Skipf("this engine cannot hold an executable that links at a fixed address: %s", msg)
				}
				if rep.GuestRunErr != "" || rep.GuestExitCode != 0 || rep.GuestStdout != layout.name+" ok\n" {
					t.Fatalf("guest = (code %d, stdout %q, err %q), want a clean run\nstderr of the probe: %s", rep.GuestExitCode, rep.GuestStdout, rep.GuestRunErr, stderr)
				}
				if image == "" {
					return
				}
				requireCleanImage(t, image, "feature")
				if bin, err := exec.LookPath("e2fsck"); err == nil {
					if out, err := exec.Command(bin, "-fn", image).CombinedOutput(); err != nil {
						t.Errorf("e2fsck -fn on the volume image: %v\n%s", err, out)
					}
				} else if os.Getenv("EXT4LITE_REQUIRE_E2FSCK") != "" {
					t.Error("e2fsck is not installed, and EXT4LITE_REQUIRE_E2FSCK is set")
				}
			})
		}
	}
}
