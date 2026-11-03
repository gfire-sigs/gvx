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
	"strings"
	"testing"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/internal/hvtest"
	"z.gfire.dev/gvx/pkg/gvx"
)

// codeWriteChecks lists the checks of the guest codewrite.
var codeWriteChecks = []string{
	"self-patch",
	"data-in-code-page",
	"alias-store-into-executing-frame",
	"alias-rewrite-between-runs",
	"read-into-code",
	"write-to-executed-file",
	"process-vm-writev",
}

// TestE2ESystrapCodeWrites runs a guest that changes the code that it runs,
// through every write path of a program and of the kernel. Linux gives each
// write the same meaning, so every backend must pass every check.
func TestE2ESystrapCodeWrites(t *testing.T) {
	bin := acceptprog.BuildCodeWrite(t, hostArch())
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			if (b.plat == gvx.PlatformHVF || b.plat == gvx.PlatformWHPX) && !hvtest.Available() {
				t.Skip("no hardware hypervisor on this host")
			}
			requireFixedAddressBackend(t, b)
			code, stdout, stderr, err := runHostProgram(t, b.plat, bin, []string{"/bin/codewrite"}, nil)
			skipWhenFixedAddressRefused(t, "Run(codewrite)", err)
			if err != nil {
				t.Fatalf("Run(codewrite) on %s: %v\nstdout:\n%s\nstderr:\n%s", b.name, err, stdout, stderr)
			}
			t.Logf("guest output on %s:\n%s", b.name, stdout)
			for _, name := range codeWriteChecks {
				if !strings.Contains(stdout, "PASS "+name+"\n") {
					t.Errorf("check %s did not pass on %s", name, b.name)
				}
			}
			if code != 0 || !strings.Contains(stdout, "CODEWRITE-OK") {
				t.Fatalf("codewrite on %s exited with %d\nstdout:\n%s\nstderr:\n%s", b.name, code, stdout, stderr)
			}
		})
	}
}
