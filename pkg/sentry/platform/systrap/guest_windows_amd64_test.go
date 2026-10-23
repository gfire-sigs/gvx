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

//go:build windows && amd64

package systrap

import (
	"encoding/binary"

	"z.gfire.dev/gvx/pkg/sentry/arch"
)

// The amd64 half of the hand-assembled guests of the engine tests. Each helper
// returns position-independent code, so a test joins them with append.

const (
	syscallWidth = 2
	// guestHasFSBase is true for guests that keep a thread pointer in a segment base.
	guestHasFSBase = true
)

func imm64(prefix []byte, v uint64) []byte {
	b := append([]byte(nil), prefix...)
	return binary.LittleEndian.AppendUint64(b, v)
}

// argRegs holds the movabs prefixes of RDI, RSI, RDX, R10, R8, R9.
var argRegs = [][]byte{{0x48, 0xBF}, {0x48, 0xBE}, {0x48, 0xBA}, {0x49, 0xBA}, {0x49, 0xB8}, {0x49, 0xB9}}

// gSyscall loads the system call number and the arguments, then traps.
func gSyscall(nr uint64, args ...uint64) []byte {
	var c []byte
	for i, a := range args {
		c = append(c, imm64(argRegs[i], a)...)
	}
	c = append(c, imm64([]byte{0x48, 0xB8}, nr)...)
	return append(c, 0x0F, 0x05)
}

// gLoop adds 3 to the accumulator n times and leaves the sum there.
func gLoop(n uint64) []byte {
	c := imm64([]byte{0x48, 0xB9}, n)  // mov rcx, n
	c = append(c, 0x31, 0xDB)          // xor ebx, ebx
	c = append(c, 0x48, 0x83, 0xC3, 3) // loop: add rbx, 3
	c = append(c, 0x48, 0xFF, 0xC9)    // dec rcx
	return append(c, 0x75, 0xF7)       // jnz loop
}

// gLoadFrom loads eight bytes from addr into the accumulator.
func gLoadFrom(addr uint64) []byte {
	c := imm64([]byte{0x48, 0xBA}, addr) // mov rdx, addr
	return append(c, 0x48, 0x8B, 0x1A)   // mov rbx, [rdx]
}

// gStoreTo stores v at addr.
func gStoreTo(addr, v uint64) []byte {
	c := imm64([]byte{0x48, 0xBB}, addr) // mov rbx, addr
	c = append(c, imm64([]byte{0x48, 0xB8}, v)...)
	return append(c, 0x48, 0x89, 0x03) // mov [rbx], rax
}

// gJump jumps to addr.
func gJump(addr uint64) []byte {
	c := imm64([]byte{0x48, 0xB8}, addr)
	return append(c, 0xFF, 0xE0) // jmp rax
}

// gSpin loops forever.
func gSpin() []byte { return []byte{0xEB, 0xFE} }

// gCountSpin increments the accumulator forever.
func gCountSpin() []byte { return []byte{0x48, 0xFF, 0xC3, 0xEB, 0xFB} } // inc rbx; jmp -5

// gTraceBreak executes an INT3 that the patcher never planted.
func gTraceBreak() []byte { return []byte{0xCC} }

// gIllegal executes an instruction that does not exist.
func gIllegal() []byte { return []byte{0x0F, 0x0B} } // ud2

// gDivZero divides by zero.
func gDivZero() []byte {
	return []byte{0x31, 0xC9, 0x48, 0x31, 0xD2, 0xB8, 1, 0, 0, 0, 0x48, 0xF7, 0xF1} // xor ecx,ecx; xor rdx,rdx; mov eax,1; div rcx
}

// gReadThreadPointer loads the word at offset 0 of the thread pointer into the
// accumulator.
func gReadThreadPointer() []byte { return []byte{0x64, 0x48, 0x8B, 0x1C, 0x25, 0, 0, 0, 0} } // mov rbx, fs:[0]

// gSetVector loads v into the low quadword of the first vector register.
func gSetVector(v uint64) []byte {
	c := imm64([]byte{0x48, 0xB8}, v)              // mov rax, v
	return append(c, 0x66, 0x48, 0x0F, 0x6E, 0xC0) // movq xmm0, rax
}

// gVectorToReg moves the low quadword of xmm0 into the accumulator.
func gVectorToReg() []byte { return []byte{0x66, 0x48, 0x0F, 0x7E, 0xC3} } // movq rbx, xmm0

// Accessors of the registers that the guests use.

func regNr(ac *arch.Context64) uint64 { return ac.StateData().Regs.Orig_rax }
func regArg(ac *arch.Context64, i int) uint64 {
	r := &ac.StateData().Regs
	return [...]uint64{r.Rdi, r.Rsi, r.Rdx, r.R10, r.R8, r.R9}[i]
}
func regRet(ac *arch.Context64) uint64        { return ac.StateData().Regs.Rax }
func regAcc(ac *arch.Context64) uint64        { return ac.StateData().Regs.Rbx }
func setRet(ac *arch.Context64, v uint64)     { ac.StateData().Regs.Rax = v }
func regPC(ac *arch.Context64) uint64         { return ac.StateData().Regs.Rip }
func setTLSBase(ac *arch.Context64, v uint64) { ac.StateData().Regs.Fs_base = v }

// vectorLow reads the low quadword of the first vector register from the
// floating-point state of ac. The first 512 bytes of the Linux xsave image are
// an FXSAVE image, which keeps XMM0 at offset 160.
func vectorLow(ac *arch.Context64) uint64 {
	return binary.LittleEndian.Uint64((*ac.FloatingPointData())[160:])
}

// setVectorLow writes the low quadword of the first vector register.
func setVectorLow(ac *arch.Context64, v uint64) {
	binary.LittleEndian.PutUint64((*ac.FloatingPointData())[160:], v)
}
