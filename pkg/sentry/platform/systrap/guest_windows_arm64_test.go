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

//go:build windows && arm64

package systrap

import (
	"encoding/binary"

	"z.gfire.dev/gvx/pkg/sentry/arch"
)

// The arm64 half of the hand-assembled guests of the engine tests. Each helper
// returns position-independent code, so a test joins them with append.

const (
	syscallWidth = 4
	// guestHasFSBase is true for guests that keep a thread pointer in a segment base.
	guestHasFSBase = false
)

func wordBytes(ws ...uint32) []byte {
	b := make([]byte, 0, 4*len(ws))
	for _, w := range ws {
		b = binary.LittleEndian.AppendUint32(b, w)
	}
	return b
}

func movz(rd, imm uint32) uint32        { return 0xd2800000 | imm<<5 | rd }
func movk(rd, imm, shift uint32) uint32 { return 0xf2800000 | shift/16<<21 | imm<<5 | rd }

// movConst returns the instructions that put v in register rd.
func movConst(rd uint32, v uint64) []uint32 {
	ws := []uint32{movz(rd, uint32(v&0xffff))}
	for shift := uint32(16); shift < 64; shift += 16 {
		if part := uint32(v >> shift & 0xffff); part != 0 {
			ws = append(ws, movk(rd, part, shift))
		}
	}
	return ws
}

func gConst(rd uint32, v uint64) []byte { return wordBytes(movConst(rd, v)...) }

// gSyscall loads the system call number and the arguments, then traps.
func gSyscall(nr uint64, args ...uint64) []byte {
	var c []byte
	for i, a := range args {
		c = append(c, gConst(uint32(i), a)...)
	}
	c = append(c, gConst(8, nr)...)
	return append(c, wordBytes(0xd4000001)...) // svc #0
}

// gLoop adds 3 to the return register n times and leaves the sum there.
func gLoop(n uint64) []byte {
	c := gConst(2, n)
	c = append(c, wordBytes(
		movz(0, 0),
		0x91000c00, // loop: add x0, x0, #3
		0xf1000442, // subs x2, x2, #1
		0x54ffffc1, // b.ne loop
	)...)
	return c
}

// gLoadFrom loads eight bytes from addr into the return register.
func gLoadFrom(addr uint64) []byte {
	c := gConst(1, addr)
	return append(c, wordBytes(0xf9400020)...) // ldr x0, [x1]
}

// gStoreTo stores v at addr.
func gStoreTo(addr, v uint64) []byte {
	c := gConst(1, addr)
	c = append(c, gConst(0, v)...)
	return append(c, wordBytes(0xf9000020)...) // str x0, [x1]
}

// gJump jumps to addr.
func gJump(addr uint64) []byte {
	c := gConst(16, addr)
	return append(c, wordBytes(0xd61f0200)...) // br x16
}

// gSpin loops forever.
func gSpin() []byte { return wordBytes(0x14000000) } // b .

// gCountSpin increments the return register forever.
func gCountSpin() []byte { return wordBytes(0x91000400, 0x17ffffff) } // add x0, x0, #1; b -4

// gTraceBreak executes a BRK that the patcher never planted.
func gTraceBreak() []byte { return wordBytes(0xd4200000 | 0x7b<<5) } // brk #0x7b

// gIllegal executes an instruction that does not exist.
func gIllegal() []byte { return wordBytes(0x00000000) } // udf #0

// gDivZero divides by zero. ARM64 integer division by zero returns zero and
// raises no exception, so the guest uses a floating-point trap instead. The
// helper returns nil, and the test skips.
func gDivZero() []byte { return nil }

// gReadThreadPointer reads TPIDR_EL0 into the return register.
func gReadThreadPointer() []byte { return wordBytes(0xd53bd040) } // mrs x0, tpidr_el0

// gWriteThreadPointer writes v to TPIDR_EL0.
func gWriteThreadPointer(v uint64) []byte {
	c := gConst(0, v)
	return append(c, wordBytes(0xd51bd040)...) // msr tpidr_el0, x0
}

// gReadCacheType reads CTR_EL0 into the return register.
func gReadCacheType() []byte { return wordBytes(0xd53b0020) } // mrs x0, ctr_el0

// gInvalidateICache runs IC IVAU on the address in x1.
func gInvalidateICache() []byte { return wordBytes(0xd50b7521) } // ic ivau, x1

// gSetVector loads v into the low quadword of the first vector register.
func gSetVector(v uint64) []byte {
	c := gConst(0, v)
	return append(c, wordBytes(0x9e670000)...) // fmov d0, x0
}

// gVectorToReg moves the low quadword of v0 into the return register.
func gVectorToReg() []byte { return wordBytes(0x9e660000) } // fmov x0, d0

// Accessors of the registers that the guests use.

func regNr(ac *arch.Context64) uint64         { return ac.StateData().Regs.Regs[8] }
func regArg(ac *arch.Context64, i int) uint64 { return ac.StateData().Regs.Regs[i] }
func regRet(ac *arch.Context64) uint64        { return ac.StateData().Regs.Regs[0] }
func regAcc(ac *arch.Context64) uint64        { return ac.StateData().Regs.Regs[0] }
func setRet(ac *arch.Context64, v uint64)     { ac.StateData().Regs.Regs[0] = v }
func regPC(ac *arch.Context64) uint64         { return ac.StateData().Regs.Pc }
func setTLSBase(ac *arch.Context64, v uint64) { ac.StateData().Regs.TPIDR_EL0 = v }

// vectorLow reads the low quadword of V0 from the floating-point state of ac.
// The state is a Linux fpsimd_context: a 16-byte header, then the vectors.
func vectorLow(ac *arch.Context64) uint64 {
	return binary.LittleEndian.Uint64((*ac.FloatingPointData())[16:])
}

// setVectorLow writes the low quadword of V0.
func setVectorLow(ac *arch.Context64, v uint64) {
	binary.LittleEndian.PutUint64((*ac.FloatingPointData())[16:], v)
}
