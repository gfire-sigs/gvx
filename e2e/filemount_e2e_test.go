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
	"slices"
	"testing"

	"z.gfire.dev/gvx/internal/lockdownprobe"
	"z.gfire.dev/gvx/internal/testelf"
)

// TestE2EFileBindMountExposesOnlyTheFile binds one host file under the default
// host lockdown. The host directory also holds a sibling file with a secret.
// The guest must reach only the bound file. The host process must lose access
// to the sibling after the lockdown. No metadata file may appear in the host
// directory.
func TestE2EFileBindMountExposesOnlyTheFile(t *testing.T) {
	probe := toolPath(t, lockdownProbePkg)
	const (
		initialData = "initial\n"
		guestData   = "guest-ran\n"
		secret      = "secret"
	)
	for _, tc := range []struct {
		name      string
		guestPath string
		readOnly  bool
		wantCode  int
		wantData  string // content of the bound host file after the run
	}{
		{"write through the file mount", "/data.txt", false, 0, guestData},
		{"read-only file mount", "/data.txt", true, 1, initialData},
		{"dot-dot out of the file", "/data.txt/../sibling.txt", false, 1, initialData},
		{"sibling name in the guest root", "/sibling.txt", false, 0, initialData},
	} {
		t.Run(tc.name, func(t *testing.T) {
			guestELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, tc.guestPath, guestData)
			if err != nil {
				t.Fatalf("BuildGuestWriteFileELF64 failed: %v", err)
			}
			elfPath := filepath.Join(t.TempDir(), "guest.elf")
			if err := os.WriteFile(elfPath, guestELF, 0o755); err != nil {
				t.Fatalf("write guest ELF: %v", err)
			}

			hostDir := t.TempDir()
			dataFile := filepath.Join(hostDir, "data.txt")
			siblingFile := filepath.Join(hostDir, "sibling.txt")
			for path, content := range map[string]string{dataFile: initialData, siblingFile: secret} {
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatalf("write %s: %v", path, err)
				}
			}
			outside := t.TempDir()

			spec := dataFile + ":/data.txt"
			if tc.readOnly {
				spec += ":ro"
			}
			stdout, stderr, code := runTool(t, probe,
				"-bin="+elfPath, "-cache-dir="+t.TempDir(),
				"-volume="+spec,
				"-outside-file="+siblingFile, "-outside-dir="+outside)
			if code != 0 {
				t.Fatalf("lockdownprobe exit code = %d\nstdout=%s\nstderr=%s", code, stdout, stderr)
			}
			var rep lockdownprobe.Report
			if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
				t.Fatalf("decode probe report %q: %v", stdout, err)
			}
			if rep.NewErr != "" {
				t.Fatalf("New failed with a file mount: %s", rep.NewErr)
			}
			if !rep.Lockdown.Applied || !rep.LockedAPI {
				t.Errorf("Lockdown.Applied=%v IsLockedDown=%v, want both true", rep.Lockdown.Applied, rep.LockedAPI)
			}
			if rep.ReadOutsideErr == "" {
				t.Errorf("host read of the sibling file succeeded after the lockdown: %q", rep.OutsideReadBytes)
			}
			if rep.WriteOutsideErr == "" {
				t.Errorf("host write outside the mounts succeeded after the lockdown")
			}
			if rep.GuestRunErr != "" || rep.GuestExitCode != tc.wantCode {
				t.Errorf("guest write to %s = (code %d, err %q), want code %d", tc.guestPath, rep.GuestExitCode, rep.GuestRunErr, tc.wantCode)
			}

			if got, err := os.ReadFile(dataFile); err != nil || string(got) != tc.wantData {
				t.Errorf("bound host file = %q, %v; want %q", got, err, tc.wantData)
			}
			if got, err := os.ReadFile(siblingFile); err != nil || string(got) != secret {
				t.Errorf("sibling host file = %q, %v; want %q", got, err, secret)
			}
			entries, err := os.ReadDir(hostDir)
			if err != nil {
				t.Fatalf("read the host directory: %v", err)
			}
			var names []string
			for _, entry := range entries {
				names = append(names, entry.Name())
			}
			if want := []string{"data.txt", "sibling.txt"}; !slices.Equal(names, want) {
				t.Errorf("host directory entries = %v, want %v (no metadata file, no new file)", names, want)
			}
		})
	}
}
