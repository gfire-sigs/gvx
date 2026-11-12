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

//go:build darwin && arm64

package hvf

import (
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// TestStubExitOfWaitInstructionResumesBehindIt feeds the stub exit of a trapped
// WFI or WFE to the worker. The worker must skip the instruction and resume the
// guest. A report of a system call would run a call with the stale number and
// return to the same instruction.
func TestStubExitOfWaitInstructionResumesBehindIt(t *testing.T) {
	const pc = 0x400100
	w := &vcpuWorker{comm: &kernelComm{view: &CommPage{}}}
	comm := w.comm.view
	comm.Vector = vecLowerELSync
	comm.ESR = esr(hvcommon.ECWFx, 0)
	comm.PC = pc

	done, info, at, err := w.onStubExit(arch.New(arch.Host))
	if done || info != nil || err != nil || at != hostarch.NoAccess {
		t.Fatalf("onStubExit = (done=%v, info=%v, at=%v, err=%v), want a resume", done, info, at, err)
	}
	if comm.PC != pc+4 {
		t.Errorf("PC = %#x, want %#x: the guest must resume behind the wait instruction", comm.PC, pc+4)
	}
}
