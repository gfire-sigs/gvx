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
	"runtime"
	"strings"
	"testing"

	"z.gfire.dev/gvx/internal/acceptprog"
)

// TestE2EMembarrierCommands checks that membarrier(2) reports and runs the
// global and the private expedited commands on every backend, with the
// registration rules of the Linux system call.
func TestE2EMembarrierCommands(t *testing.T) {
	bin := acceptprog.BuildMembarrierProbe(t, runtime.GOARCH)
	want := []string{
		"query-reports-expedited-commands", "unknown-arguments-fail",
		"private-expedited-needs-registration", "register-private-expedited",
		"register-global-expedited", "commands-from-several-threads",
	}
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			code, out := runParityProbe(t, b, bin, false, "checks")
			if code != 0 || !strings.Contains(out, "DONE") {
				t.Fatalf("membarrierprobe checks exited with %d\n%s", code, out)
			}
			for _, name := range want {
				if !strings.Contains(out, "PASS "+name+"\n") {
					t.Errorf("check %s did not pass\n%s", name, out)
				}
			}
			if strings.Contains(out, "FAIL ") {
				t.Errorf("failed checks:\n%s", out)
			}
		})
	}
}

// TestE2EMembarrierStressCompletes checks that membarrier(2) calls from three
// threads finish while other guest threads make system calls or run without
// any.
func TestE2EMembarrierStressCompletes(t *testing.T) {
	bin := acceptprog.BuildMembarrierProbe(t, runtime.GOARCH)
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			code, out := runParityProbe(t, b, bin, false, "stress")
			if code != 0 || !strings.Contains(out, "PASS stress\n") || !strings.Contains(out, "DONE") {
				t.Fatalf("membarrierprobe stress exited with %d\n%s", code, out)
			}
		})
	}
}
