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

//go:build linux && arm64

package main

import (
	"encoding/binary"
	"fmt"

	"z.gfire.dev/gvx/internal/acceptprog/guestcpu"
)

// syscallInsnLen is the length of the instruction SVC.
const syscallInsnLen = 4

func isSyscallInsn(b []byte) bool {
	return len(b) == 4 && binary.LittleEndian.Uint32(b) == 0xd4000001 // SVC #0
}

// ESR_EL1 fields.
const (
	esrECShift = 26
	esrECDABT  = 0x24 // data abort from a lower exception level
	esrWnR     = 1 << 6
	esrDFSCMsk = 0x3c // the fault type without the level
	esrDFSCTr  = 0x04 // translation fault
	esrDFSCPrm = 0x0c // permission fault
)

// checkFaultFrame verifies fault_address and the esr_context of a store fault.
func checkFaultFrame(f *guestcpu.Frame, addr uint64, permission bool) error {
	a := f.Arch
	if a.FaultAddr != addr {
		return fmt.Errorf("fault_address = %#x, want %#x", a.FaultAddr, addr)
	}
	if !a.HasESR {
		return fmt.Errorf("the frame of a fault has no esr_context: records %+v", a.Records)
	}
	wantDFSC := uint64(esrDFSCTr)
	if permission {
		wantDFSC = esrDFSCPrm
	}
	if a.ESR>>esrECShift != esrECDABT || a.ESR&esrWnR == 0 || a.ESR&esrDFSCMsk != wantDFSC {
		return fmt.Errorf("esr = %#x, want a write data abort (EC %#x, WnR) with fault type %#x", a.ESR, esrECDABT, wantDFSC)
	}
	return nil
}
