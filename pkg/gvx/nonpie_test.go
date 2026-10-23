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
	"strings"
	"testing"

	"z.gfire.dev/gvx/internal/testelf"
)

func TestNonPIEHintNamesTheLinkAddressAndTheHardwareEngine(t *testing.T) {
	const guestMin = 0x1000_0000_0000
	for _, arch := range []string{"amd64", "arm64"} {
		elf, err := testelf.BuildGuestELF64At(arch, 0x400000, 0, "x")
		if err != nil {
			t.Fatalf("BuildGuestELF64At(%s): %v", arch, err)
		}
		for goos, engine := range map[string]string{"windows": "whpx", "darwin": "hvf"} {
			hint := nonPIEHint(elf, guestMin, goos)
			for _, want := range []string{"0x400000", "-platform=" + engine} {
				if !strings.Contains(hint, want) {
					t.Errorf("%s on %s: hint %q does not contain %q", arch, goos, hint, want)
				}
			}
		}
		if hint := nonPIEHint(elf, guestMin, "linux"); hint == "" || strings.Contains(hint, "-platform=") {
			t.Errorf("%s on linux: hint %q, want an explanation without an engine to switch to", arch, hint)
		}
	}
}

func TestNonPIEHintIsEmptyWhenTheExecutableFits(t *testing.T) {
	low, err := testelf.BuildGuestELF64At("arm64", 0x400000, 0, "x")
	if err != nil {
		t.Fatal(err)
	}
	high, err := testelf.BuildGuestELF64At("arm64", 0x1000_0000_0000, 0, "x")
	if err != nil {
		t.Fatal(err)
	}
	dynamic, err := testelf.BuildDynamicGuestELF64("arm64", 0, "x")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		file     []byte
		guestMin uint64
	}{
		{"the platform has a low window", low, 0x10000},
		{"the executable links above the range", high, 0x1000_0000_0000},
		{"a position-independent executable", dynamic, 0x1000_0000_0000},
		{"a prefix that cuts off the program headers", low[:40], 0x1000_0000_0000},
		{"a file that is not ELF", []byte("#!/bin/sh\necho hi\n"), 0x1000_0000_0000},
	} {
		if hint := nonPIEHint(tc.file, tc.guestMin, "windows"); hint != "" {
			t.Errorf("%s: hint %q, want none", tc.name, hint)
		}
	}
}
