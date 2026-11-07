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

//go:build linux && amd64

package main

import (
	"fmt"

	"z.gfire.dev/gvx/internal/acceptprog/guestcpu"
)

// syscallInsnLen is the length of the instruction SYSCALL (0f 05).
const syscallInsnLen = 2

func isSyscallInsn(b []byte) bool { return len(b) == 2 && b[0] == 0x0f && b[1] == 0x05 }

// checkFaultFrame verifies the fault fields of the sigcontext: trap number 14
// (page fault), the error code (bit 0 protection violation, bit 1 write, bit 2
// user mode), and CR2.
func checkFaultFrame(f *guestcpu.Frame, addr uint64, permission bool) error {
	wantErr := uint64(0x6)
	if permission {
		wantErr = 0x7
	}
	a := f.Arch
	if a.Trapno != 14 || a.Err != wantErr || a.CR2 != addr {
		return fmt.Errorf("sigcontext = {trapno %d, err %#x, cr2 %#x}, want {trapno 14, err %#x, cr2 %#x}",
			a.Trapno, a.Err, a.CR2, wantErr, addr)
	}
	return nil
}
