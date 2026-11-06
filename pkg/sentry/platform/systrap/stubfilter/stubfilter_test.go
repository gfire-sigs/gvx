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

package stubfilter

import (
	"runtime"
	"testing"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/bpf"
)

// auditArch returns the AUDIT_ARCH value of the test binary.
func auditArch(t *testing.T) uint32 {
	t.Helper()
	switch runtime.GOARCH {
	case "amd64":
		return linux.AUDIT_ARCH_X86_64
	case "arm64":
		return linux.AUDIT_ARCH_AARCH64
	}
	t.Skipf("no audit architecture for %s", runtime.GOARCH)
	return 0
}

// sysmsgFilterVerdict runs the sysmsg thread filter on one futex call and
// returns the action.
func sysmsgFilterVerdict(t *testing.T, start uint64, ip uint64, op uint64, args [6]uint64) linux.BPFAction {
	t.Helper()
	program := SysmsgThread(SysmsgThreadVars(start-0x1000, start))
	instructions, _, err := program.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	compiled, err := bpf.Compile(instructions, true)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	args[1] = op
	data := linux.SeccompData{
		Nr:                 unix.SYS_FUTEX,
		Arch:               auditArch(t),
		InstructionPointer: ip,
		Args:               args,
	}
	buf := make([]byte, data.SizeBytes())
	data.MarshalUnsafe(buf)
	ret, err := bpf.Exec[bpf.NativeEndian](compiled, buf)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	return linux.BPFAction(ret)
}

// The sysmsg code of arm64 passes a value in the sixth argument of the futex
// call that wakes the Sentry, and the call ignores it. The filter must allow
// the call, because a nested Sentry runs on a kernel that evaluates the filter
// with the exact arguments.
func TestSysmsgThreadMayWakeTheSentryWithAnyValue(t *testing.T) {
	const start = 0xff00_0000_1000
	for _, val3 := range []uint64{0, 1, 0x29a, 1 << 40} {
		got := sysmsgFilterVerdict(t, start, start+0x40, linux.FUTEX_WAKE, [6]uint64{start + 0x8000, 0, 1, 0, 0, val3})
		if got != linux.SECCOMP_RET_ALLOW {
			t.Errorf("FUTEX_WAKE with val3 %#x: action %#x, want allow %#x", val3, uint32(got), uint32(linux.SECCOMP_RET_ALLOW))
		}
	}
}

// The filter still refuses a wake that does not match the one of the sysmsg
// code.
func TestSysmsgThreadRefusesOtherFutexCalls(t *testing.T) {
	const start = 0xff00_0000_1000
	for _, tc := range []struct {
		name string
		ip   uint64
		op   uint64
		args [6]uint64
	}{
		{"wake from outside the sysmsg code", start - 0x10, linux.FUTEX_WAKE, [6]uint64{start + 0x8000, 0, 1, 0, 0, 0}},
		{"wake of more than one waiter", start + 0x40, linux.FUTEX_WAKE, [6]uint64{start + 0x8000, 0, 2, 0, 0, 0}},
		{"wake with a timeout argument", start + 0x40, linux.FUTEX_WAKE, [6]uint64{start + 0x8000, 0, 1, 7, 0, 0}},
		{"wake of an address below the sysmsg code", start + 0x40, linux.FUTEX_WAKE, [6]uint64{start - 0x10, 0, 1, 0, 0, 0}},
		{"requeue", start + 0x40, linux.FUTEX_REQUEUE, [6]uint64{start + 0x8000, 0, 1, 0, 0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := sysmsgFilterVerdict(t, start, tc.ip, tc.op, tc.args)
			if got == linux.SECCOMP_RET_ALLOW {
				t.Errorf("the filter allows %s", tc.name)
			}
		})
	}
}
