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

// regProbeChecks lists the checks of the guest regprobe.
var regProbeChecks = []string{
	"syscall",
	"page-fault",
	"page-fault-handler",
	"signal-in-user-code",
	"signal-in-blocking-syscall",
	"signal-in-restarted-syscall",
	"signal-in-unrestarted-syscall",
}

// TestE2ESystrapRegisterState runs a guest that fills the general purpose, vector,
// and FP control registers with distinct values and lets a system call, a page
// fault, and a signal happen. A signal handler overwrites all of them, so a
// backend that saves or restores part of the state fails a check. Linux
// preserves the state in every case, so every backend must pass every check.
func TestE2ESystrapRegisterState(t *testing.T) {
	bin := acceptprog.BuildRegProbe(t, hostArch())
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			if (b.plat == gvx.PlatformHVF || b.plat == gvx.PlatformWHPX) && !hvtest.Available() {
				t.Skip("no hardware hypervisor on this host")
			}
			requireFixedAddressBackend(t, b)
			code, stdout, stderr, err := runHostProgram(t, b.plat, bin, []string{"/bin/regprobe"}, nil)
			skipWhenFixedAddressRefused(t, "Run(regprobe)", err)
			if err != nil {
				t.Fatalf("Run(regprobe) on %s: %v\nstdout:\n%s\nstderr:\n%s", b.name, err, stdout, stderr)
			}
			t.Logf("guest output on %s:\n%s", b.name, stdout)
			for _, name := range regProbeChecks {
				if !strings.Contains(stdout, "PASS "+name+"\n") {
					t.Errorf("check %s did not pass on %s", name, b.name)
				}
			}
			if code != 0 || !strings.Contains(stdout, "REGPROBE-OK") {
				t.Fatalf("regprobe on %s exited with %d\nstdout:\n%s\nstderr:\n%s", b.name, code, stdout, stderr)
			}
		})
	}
}
