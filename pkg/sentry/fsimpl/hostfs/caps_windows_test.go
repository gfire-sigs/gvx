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

//go:build windows

package hostfs

import "testing"

func TestWindowsProbeRecordsTheNameRules(t *testing.T) {
	dir := resolvedTempDir(t)
	ws, err := OpenWorkspace(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.Close() }()
	caps := ws.Caps()
	if !caps.RestrictsWinNames || !caps.LocksOpenDirMove {
		t.Fatalf("caps = %+v, want the Windows name rules and the open-directory lock", caps)
	}
	if caps.UnicodeNormalized || caps.NativeXattr || caps.NativeRenameSwap {
		t.Fatalf("caps = %+v: NTFS keeps names as written and stores xattrs in .gvx_meta", caps)
	}
	if left := hostNames(t, dir); len(left) != 0 {
		t.Fatalf("the probe left files behind: %q", left)
	}
}

func TestWindowsFoldProbeMatchesTheVolume(t *testing.T) {
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
	if ws.Caps().CaseSensitive == folds {
		t.Fatalf("CaseSensitive = %v but the probe found folds = %v", ws.Caps().CaseSensitive, folds)
	}
}

func TestWindowsReadOnlyProbeFollowsAnExistingName(t *testing.T) {
	dir := resolvedTempDir(t)
	rw, err := OpenWorkspace(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = rw.createFile("Existing.txt", 0o644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := rw.Caps().CaseSensitive
	if err := rw.Close(); err != nil {
		t.Fatal(err)
	}
	ro, err := OpenWorkspace(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	if got := ro.Caps().CaseSensitive; got != want {
		t.Fatalf("read-only CaseSensitive = %v, writable probe found %v", got, want)
	}
}
