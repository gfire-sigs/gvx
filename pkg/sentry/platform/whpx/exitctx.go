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

package whpx

import (
	"encoding/binary"
	"fmt"
)

// Sizes of WHV_RUN_VP_EXIT_CONTEXT in winhvplatformdefs.h.
const (
	exitCtxSizeX64 = 224
	exitCtxSizeA64 = 272

	// exitCtxBufSize holds either layout.
	exitCtxBufSize = 288
)

// Offsets inside WHV_RUN_VP_EXIT_CONTEXT on x64. VpContext starts at byte 8
// and the exit-specific union starts at byte 48.
const (
	x64ExitOffReason    = 0
	x64ExitOffExecState = 8
	x64ExitOffRip       = 32
	x64ExitOffRflags    = 40
	x64ExitOffMemInfo   = 68
	x64ExitOffMemGpa    = 72
	x64ExitOffMemGva    = 80
)

// Offsets inside WHV_RUN_VP_EXIT_CONTEXT on arm64. Eight reserved bytes
// precede the union, which starts at byte 16 with an intercept header.
const (
	a64ExitOffReason     = 0
	a64ExitOffHdrInsnLen = 20
	a64ExitOffHdrAccess  = 21
	a64ExitOffHdrState   = 22
	a64ExitOffHdrPc      = 24
	a64ExitOffHdrCpsr    = 32
	a64ExitOffMemInfo    = 45
	a64ExitOffMemGva     = 56
	a64ExitOffMemGpa     = 64
	a64ExitOffMemSyndrom = 72
	a64ExitOffHvcImm     = 40
)

// exitKind classifies a WHV_RUN_VP_EXIT_CONTEXT for the run loop.
type exitKind uint8

const (
	// exitStub means the in-partition stub stopped the processor with HLT on
	// amd64 or HVC on arm64.
	exitStub exitKind = iota

	// exitCanceled means WHvCancelRunVirtualProcessor ended the run.
	exitCanceled

	// exitMemory means the guest touched a guest physical address that the
	// partition does not map or does not allow.
	exitMemory

	// exitFatal means an exit that no correct guest can produce.
	exitFatal
)

// exitInfo is the decoded part of an exit context that the run loop uses.
type exitInfo struct {
	kind   exitKind
	reason uint32

	// pc is the instruction pointer that the exit reports: VpContext.Rip on
	// amd64 and the intercept header Pc on arm64.
	pc uint64

	// cpl is the privilege level of the guest at the exit on amd64.
	cpl uint8

	// Memory access facts.
	gpa         uint64
	gva         uint64
	gvaValid    bool
	gpaUnmapped bool
	write       bool
	execute     bool

	// hvcImmediate is the HVC immediate on arm64.
	hvcImmediate uint16

	// cpsr is the PSTATE of the guest at the exit on arm64.
	cpsr uint64
}

// String names the exit for error messages.
func (e exitInfo) String() string {
	return fmt.Sprintf("exit reason %#x at pc %#x", e.reason, e.pc)
}

// inKernel reports whether the guest was in kernel mode at the exit.
func (e exitInfo) inKernel(arm64 bool) bool {
	if arm64 {
		return e.cpsr&a64PstateModeMask != 0
	}
	return e.cpl != 3
}

// decodeExitX64 decodes an x64 exit context.
func decodeExitX64(buf []byte) (exitInfo, error) {
	if len(buf) < exitCtxSizeX64 {
		return exitInfo{}, fmt.Errorf("whpx: x64 exit context is %d bytes, want %d", len(buf), exitCtxSizeX64)
	}
	e := exitInfo{
		reason: binary.LittleEndian.Uint32(buf[x64ExitOffReason:]),
		pc:     binary.LittleEndian.Uint64(buf[x64ExitOffRip:]),
		cpl:    uint8(binary.LittleEndian.Uint16(buf[x64ExitOffExecState:]) & 3),
	}
	switch e.reason {
	case x64ExitHalt:
		e.kind = exitStub
	case x64ExitCanceled:
		e.kind = exitCanceled
	case x64ExitMemoryAccess:
		e.kind = exitMemory
		info := binary.LittleEndian.Uint32(buf[x64ExitOffMemInfo:])
		e.gpa = binary.LittleEndian.Uint64(buf[x64ExitOffMemGpa:])
		e.gva = binary.LittleEndian.Uint64(buf[x64ExitOffMemGva:])
		e.write = info&3 == 1
		e.execute = info&3 == 2
		e.gpaUnmapped = info&(1<<2) != 0
		e.gvaValid = info&(1<<3) != 0
	default:
		e.kind = exitFatal
	}
	return e, nil
}

// decodeExitA64 decodes an arm64 exit context.
func decodeExitA64(buf []byte) (exitInfo, error) {
	if len(buf) < exitCtxSizeA64 {
		return exitInfo{}, fmt.Errorf("whpx: arm64 exit context is %d bytes, want %d", len(buf), exitCtxSizeA64)
	}
	e := exitInfo{
		reason: binary.LittleEndian.Uint32(buf[a64ExitOffReason:]),
	}
	switch e.reason {
	case a64ExitHypercall:
		e.kind = exitStub
		e.pc = binary.LittleEndian.Uint64(buf[a64ExitOffHdrPc:])
		e.cpsr = binary.LittleEndian.Uint64(buf[a64ExitOffHdrCpsr:])
		e.hvcImmediate = binary.LittleEndian.Uint16(buf[a64ExitOffHvcImm:])
	case a64ExitCanceled:
		e.kind = exitCanceled
	case a64ExitUnmappedGpa, a64ExitGpaIntercept:
		e.kind = exitMemory
		e.pc = binary.LittleEndian.Uint64(buf[a64ExitOffHdrPc:])
		e.cpsr = binary.LittleEndian.Uint64(buf[a64ExitOffHdrCpsr:])
		e.gva = binary.LittleEndian.Uint64(buf[a64ExitOffMemGva:])
		e.gpa = binary.LittleEndian.Uint64(buf[a64ExitOffMemGpa:])
		e.gvaValid = buf[a64ExitOffMemInfo]&1 != 0
		e.gpaUnmapped = e.reason == a64ExitUnmappedGpa
		switch buf[a64ExitOffHdrAccess] {
		case 1:
			e.write = true
		case 2:
			e.execute = true
		}
	default:
		e.kind = exitFatal
		e.pc = binary.LittleEndian.Uint64(buf[a64ExitOffHdrPc:])
	}
	return e, nil
}
