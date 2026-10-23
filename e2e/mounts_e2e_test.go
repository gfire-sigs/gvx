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
	"path/filepath"
	"runtime"
	"testing"

	"z.gfire.dev/gvx/internal/lockdownprobe"
	"z.gfire.dev/gvx/internal/testelf"
)

// TestE2EHostLockdownKeepsEveryMountReachable starts the sandbox with several
// mounts under the default host lockdown. The guest writes through each mount
// kind. The host must keep every mount reachable and every other path closed.
func TestE2EHostLockdownKeepsEveryMountReachable(t *testing.T) {
	probe := toolPath(t, lockdownProbePkg)
	for _, tc := range []struct {
		name      string
		guestPath string
		wantCode  int
		hostDir   string // "writable", "read-only", or "volume"; "" when the write must not reach the host
	}{
		{"writable bind", "/mnt/a/guest.txt", 0, "writable"},
		{"read-only bind", "/mnt/b/guest.txt", 1, "read-only"},
		{"volume", "/vol/guest.txt", 0, "volume"},
		{"tmpfs", "/scratch/guest.txt", 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			guestELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, tc.guestPath, "guest-ran\n")
			if err != nil {
				t.Fatalf("BuildGuestWriteFileELF64 failed: %v", err)
			}
			elfPath := filepath.Join(t.TempDir(), "guest.elf")
			if err := os.WriteFile(elfPath, guestELF, 0o755); err != nil {
				t.Fatalf("write guest ELF: %v", err)
			}
			cacheDir := t.TempDir()
			hostDirs := map[string]string{
				"writable":  t.TempDir(),
				"read-only": t.TempDir(),
				"volume":    filepath.Join(cacheDir, "volumes", "data"),
			}
			outside := t.TempDir()
			secret := filepath.Join(outside, "secret.txt")
			if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
				t.Fatalf("write secret: %v", err)
			}

			stdout, stderr, code := runTool(t, probe,
				"-bin="+elfPath, "-cache-dir="+cacheDir,
				"-volume="+hostDirs["writable"]+":/mnt/a",
				"-volume="+hostDirs["read-only"]+":/mnt/b:ro",
				"-volume=data:/vol",
				"-tmpfs=/scratch:size=1m",
				"-outside-file="+secret, "-outside-dir="+outside)
			if code != 0 {
				t.Fatalf("lockdownprobe exit code = %d\nstdout=%s\nstderr=%s", code, stdout, stderr)
			}
			var rep lockdownprobe.Report
			if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
				t.Fatalf("decode probe report %q: %v", stdout, err)
			}
			if rep.NewErr != "" {
				t.Fatalf("New failed with several mounts: %s", rep.NewErr)
			}
			if !rep.Lockdown.Applied || !rep.LockedAPI {
				t.Errorf("Lockdown.Applied=%v IsLockedDown=%v, want both true", rep.Lockdown.Applied, rep.LockedAPI)
			}
			if rep.ReadOutsideErr == "" || rep.WriteOutsideErr == "" {
				t.Errorf("host access outside the mounts = (read err %q, write err %q), want both denied", rep.ReadOutsideErr, rep.WriteOutsideErr)
			}
			if rep.GuestRunErr != "" || rep.GuestExitCode != tc.wantCode {
				t.Errorf("guest write to %s = (code %d, err %q), want code %d", tc.guestPath, rep.GuestExitCode, rep.GuestRunErr, tc.wantCode)
			}
			for name, dir := range hostDirs {
				data, err := os.ReadFile(filepath.Join(dir, "guest.txt"))
				if want := name == tc.hostDir && tc.wantCode == 0; (err == nil) != want {
					t.Errorf("guest.txt in the %s directory: read error %v, want present = %v", name, err, want)
				} else if err == nil && string(data) != "guest-ran\n" {
					t.Errorf("guest.txt in the %s directory = %q", name, data)
				}
			}
		})
	}
}
