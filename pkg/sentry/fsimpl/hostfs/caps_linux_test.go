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

//go:build linux

package hostfs

import "testing"

func TestLinuxProbeAssumesAnIdentityVolume(t *testing.T) {
	dir := resolvedTempDir(t)
	ws, err := OpenWorkspace(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.Close() }()
	caps := ws.Caps()
	if !caps.CaseSensitive || caps.UnicodeNormalized || caps.RestrictsWinNames || caps.LocksOpenDirMove {
		t.Fatalf("caps = %+v, want a case-sensitive volume without Windows rules", caps)
	}
	if ws.codec.active || ws.stateful {
		t.Fatal("a Linux volume must use the identity codec")
	}
	if left := hostNames(t, dir); len(left) != 0 {
		t.Fatalf("the probe left files behind: %q", left)
	}
}

func TestLinuxProbeOfAReadOnlyWorkspaceCreatesNothing(t *testing.T) {
	dir := resolvedTempDir(t)
	ws, err := OpenWorkspace(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.Close() }()
	if caps := ws.Caps(); !caps.CaseSensitive || !caps.NativeRenameSwap {
		t.Fatalf("caps = %+v, want the Linux defaults", caps)
	}
	if left := hostNames(t, dir); len(left) != 0 {
		t.Fatalf("host names = %q, want none", left)
	}
}
