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
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/internal/lockdownprobe"
)

// TestE2EVolumePersistsAcrossSandboxes starts two sandboxes in a row on the
// volume testvol. The first guest writes a tree and syncs every object. The
// second guest checks the content, the permissions, the links, and the
// attributes. Both sandboxes run with the default host lockdown, so every
// host handle of the volume exists before the lockdown. The probe also tries
// to open host files after the lockdown, and every attempt must fail.
func TestE2EVolumePersistsAcrossSandboxes(t *testing.T) {
	probe := toolPath(t, lockdownProbePkg)
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			guest := acceptprog.BuildVolumeTree(t, hostArch())
			cacheDir := t.TempDir()
			outside := t.TempDir()
			secret := filepath.Join(outside, "secret.txt")
			if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
				t.Fatal(err)
			}
			run := func(mode string) lockdownprobe.Report {
				t.Helper()
				stdout, stderr, code := runTool(t, probe,
					"-bin="+guest, "-cache-dir="+cacheDir, "-platform="+string(b.plat),
					"-volume=testvol:/data",
					"-outside-file="+secret, "-outside-dir="+outside,
					mode, "/data")
				if code != 0 {
					t.Fatalf("lockdownprobe %s: exit code %d\nstdout=%s\nstderr=%s", mode, code, stdout, stderr)
				}
				var rep lockdownprobe.Report
				if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
					t.Fatalf("decode the probe report %q: %v", stdout, err)
				}
				if msg := rep.NewErr; msg != "" {
					if strings.Contains(msg, "not position-independent") {
						t.Skipf("this engine cannot hold an executable that links at a fixed address: %s", msg)
					}
					t.Fatalf("%s: New failed: %s", mode, msg)
				}
				if !rep.Lockdown.Applied || !rep.LockedAPI {
					t.Errorf("%s: Lockdown.Applied=%v IsLockedDown=%v, want both true", mode, rep.Lockdown.Applied, rep.LockedAPI)
				}
				if !rep.Lockdown.UnboundFileOpenBlocked {
					t.Errorf("%s: UnboundFileOpenBlocked = false, want true for a sandbox with only an ext4lite volume", mode)
				}
				if rep.WriteOutsideErr == "" || rep.ReadOutsideErr == "" {
					t.Errorf("%s: host access outside the volume = (read err %q, write err %q), want both denied", mode, rep.ReadOutsideErr, rep.WriteOutsideErr)
				}
				if msg := rep.GuestRunErr; strings.Contains(msg, "not position-independent") {
					t.Skipf("this engine cannot hold an executable that links at a fixed address: %s", msg)
				}
				if rep.GuestRunErr != "" || rep.GuestExitCode != 0 || rep.GuestStdout != mode+" ok\n" {
					t.Fatalf("%s: guest = (code %d, stdout %q, err %q), want a clean run", mode, rep.GuestExitCode, rep.GuestStdout, rep.GuestRunErr)
				}
				return rep
			}
			run("write")
			image := filepath.Join(cacheDir, "volumes", "testvol.ext4")
			info, err := os.Stat(image)
			if err != nil {
				t.Fatalf("the volume image is missing after the first sandbox: %v", err)
			}
			if info.Size() == 0 || info.Size()%(16<<20) != 0 {
				t.Errorf("the image has %d bytes after a clean close, want a multiple of 16 MiB", info.Size())
			}
			if _, err := os.Stat(filepath.Join(cacheDir, "volumes", "testvol")); err == nil {
				t.Error("the volume created a hostfs directory beside the image")
			}
			requireCleanImage(t, image, "write")
			run("verify")
			requireCleanImage(t, image, "verify")
			keepImage(t, image)
			if bin, err := exec.LookPath("e2fsck"); err == nil {
				if out, err := exec.Command(bin, "-fn", image).CombinedOutput(); err != nil {
					t.Errorf("e2fsck -fn on the volume image: %v\n%s", err, out)
				}
			}
		})
	}
}

// keepImage copies the volume image to the directory that the variable
// EXT4LITE_KEEP_IMAGES names. A developer without e2fsck runs it elsewhere.
func keepImage(t *testing.T, image string) {
	dir := os.Getenv("EXT4LITE_KEEP_IMAGES")
	if dir == "" {
		return
	}
	data, err := os.ReadFile(image)
	if err != nil {
		t.Fatal(err)
	}
	name := strings.ReplaceAll(t.Name(), "/", "_") + ".img"
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// requireCleanImage fails the test unless the superblock of the image has the
// valid bit. The close of a sandbox sets the bit, so the next mount runs no
// repair. The superblock starts at byte 1024 and s_state is at offset 0x3A.
func requireCleanImage(t *testing.T, image, after string) {
	t.Helper()
	f, err := os.Open(image)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var state [2]byte
	if _, err := f.ReadAt(state[:], 1024+0x3A); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint16(state[:])&1 == 0 {
		t.Errorf("after the %s sandbox the image is not marked clean (s_state %#x)", after, state)
	}
}
