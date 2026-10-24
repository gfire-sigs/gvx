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

//go:build darwin

package hostfs

import (
	"os"
	"testing"
)

func TestDarwinProbeReadsTheVolume(t *testing.T) {
	dir := resolvedTempDir(t)
	ws, err := OpenWorkspace(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.Close() }()
	caps := ws.Caps()
	if want := !ws.host.caseInsensitive(); caps.CaseSensitive != want {
		t.Fatalf("CaseSensitive = %v, want %v from the backend", caps.CaseSensitive, want)
	}
	// The temporary directory lives on APFS, which treats NFC and NFD alike.
	if !caps.UnicodeNormalized {
		t.Errorf("UnicodeNormalized = false on the volume of %s, want true for APFS", dir)
	}
	if caps.RestrictsWinNames || caps.LocksOpenDirMove || caps.NativeXattr {
		t.Errorf("caps = %+v: a macOS volume has no Windows rules and keeps xattrs in .gvx_meta", caps)
	}
	if !caps.NativeFallocate {
		t.Errorf("NativeFallocate = false, want true")
	}
	if left := hostNames(t, dir); len(left) != 0 {
		t.Fatalf("the probe left files behind: %q", left)
	}
}

func TestDarwinProbeOfAReadOnlyWorkspaceCreatesNothing(t *testing.T) {
	dir := resolvedTempDir(t)
	if err := os.WriteFile(dir+"/Existing.txt", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ws, err := OpenWorkspace(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.Close() }()
	if !ws.Caps().UnicodeNormalized {
		t.Errorf("a read-only probe must assume the APFS answer: %+v", ws.Caps())
	}
	if left := hostNames(t, dir); len(left) != 1 {
		t.Fatalf("host names = %q, want the one existing file", left)
	}
}

func TestDarwinFoldProbeSeesTheCaseOfTheVolume(t *testing.T) {
	dir := resolvedTempDir(t)
	ws, err := OpenWorkspace(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.Close() }()
	folds, ok := probeFoldsCase(ws.host, false)
	if !ok {
		t.Fatal("the fold probe could not decide on a writable temporary directory")
	}
	if folds != ws.host.caseInsensitive() {
		t.Fatalf("fold probe = %v, but the backend reports caseInsensitive = %v", folds, ws.host.caseInsensitive())
	}
	if left := hostNames(t, dir); len(left) != 0 {
		t.Fatalf("the probe left files behind: %q", left)
	}
}
