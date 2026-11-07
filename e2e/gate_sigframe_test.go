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

// sigFrameChecks lists the checks of the guest sigframeprobe.
var sigFrameChecks = []string{
	"frame-signal-in-user-code",
	"frame-fault-read-only",
	"frame-fault-unmapped",
	"frame-restarted-syscall",
	"frame-interrupted-syscall",
	"frame-edit-registers",
	"frame-edit-pc",
}

// TestE2ESystrapSignalFrame runs a guest whose signal handler copies the frame
// that the kernel built. The frame must hold the registers, the program
// counter, the vector and FP record, and the fault fields of the interrupted
// thread, as Linux builds them. A handler that edits the frame must change the
// registers after the sigreturn. Linux does this on every architecture, so
// every backend must pass every check.
func TestE2ESystrapSignalFrame(t *testing.T) {
	runCPUProbe(t, acceptprog.BuildSigFrameProbe(t, hostArch()), "sigframeprobe", "SIGFRAMEPROBE-OK", sigFrameChecks)
}
