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
	"testing"

	"z.gfire.dev/gvx/internal/acceptprog"
)

// forkProbeChecks lists the checks of the guest forkprobe.
var forkProbeChecks = []string{
	"fork-state",
	"clone-thread-state",
	"exec-resets-control-state",
}

// TestE2ESystrapForkState runs a guest that calls clone with every register
// loaded. The child, a forked process or a thread of the guest, must start with
// those registers, including the vector registers and the FP control state.
// After a fork and an execve, the new program must start with the Linux
// defaults of the FP control state. Linux does this on every architecture, so
// every backend must pass every check.
func TestE2ESystrapForkState(t *testing.T) {
	runCPUProbe(t, acceptprog.BuildForkProbe(t, hostArch()), "forkprobe", "FORKPROBE-OK", forkProbeChecks)
}
