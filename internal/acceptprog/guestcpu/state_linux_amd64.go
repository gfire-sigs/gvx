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

package guestcpu

import "fmt"

// Index of each general purpose register in State.GPR. RSP is not here: Run
// keeps its own stack pointer.
const (
	RAX = iota
	RBX
	RCX
	RDX
	RSI
	RDI
	RBP
	R8
	R9
	R10
	R11
	R12
	R13
	R14
	R15
	numGPR
)

var gprNames = [numGPR]string{"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP",
	"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}

// Test values of the FP control state. Both differ from the Linux defaults
// (MXCSR 0x1f80 and x87 control word 0x37f) in the rounding mode, the
// precision control, the flush-to-zero bits, and the exception flags.
const (
	testMXCSR = 0xbfe1
	testFCW   = 0x0e7f
	// restorerFlag is SA_RESTORER. The kernel of amd64 returns from a handler
	// to the address that sigaction names.
	restorerFlag = 0x04000000
)

// State is the register state that Run loads and stores.
type State struct {
	GPR [numGPR]uint64
	// RSP is the stack pointer of the thread while it runs the event. Run
	// stores it in the input State and in the output State.
	RSP uint64
	// Vec holds YMM0 to YMM15. The upper half of each is valid only when the
	// CPU and the guest kernel support AVX (VectorBytes is 32).
	Vec   [16][4]uint64
	MXCSR uint32
	FCW   uint16
	_     [2]byte
}

// frame slots of the stack of Run, shared with the assembly through go_asm.h.
const (
	// slotCtl holds the MXCSR (4 bytes) and the x87 control word (2 bytes)
	// that Run restores.
	slotCtl = 0
	// slotOut holds the address of the output State until the state is stored.
	slotOut = 8
	// frameSize is the size of the stack frame of Run.
	frameSize = 16
)

// hasAVX reports whether the CPU and the guest kernel support the YMM
// registers. The guest kernel enables AVX in XCR0 when the CPU has it.
var hasAVX = detectAVX()

func detectAVX() bool {
	maxLeaf, _, _, _ := cpuid(0, 0)
	if maxLeaf < 1 {
		return false
	}
	_, _, ecx, _ := cpuid(1, 0)
	const osxsave, avx = 1 << 27, 1 << 28
	return ecx&osxsave != 0 && ecx&avx != 0 && xgetbv()&6 == 6
}

func cpuid(leaf, sub uint32) (eax, ebx, ecx, edx uint32)
func xgetbv() uint32
func restorerPC() uintptr
func sigreturn()

// VectorBytes returns the number of bytes of each vector register that Run
// loads and stores: 32 (YMM) when the CPU and the guest kernel support AVX, and
// 16 (XMM) otherwise.
func VectorBytes() int {
	if hasAVX {
		return 32
	}
	return 16
}

// NewState returns a State with a distinct test value in every register and a
// non-default FP control state. The seed selects the values.
func NewState(seed uint64) State {
	var s State
	x := seed
	for i := range s.GPR {
		s.GPR[i] = splitmix(&x)
	}
	for i := range s.Vec {
		for j := 0; j < VectorBytes()/8; j++ {
			s.Vec[i][j] = splitmix(&x)
		}
	}
	s.MXCSR = testMXCSR
	s.FCW = testFCW
	return s
}

func trashPattern() State {
	var s State
	for i := range s.GPR {
		s.GPR[i] = 0xbad0bad0bad0bad0 + uint64(i)
	}
	for i := range s.Vec {
		for j := range s.Vec[i] {
			s.Vec[i][j] = 0xfeedfacefeedface ^ uint64(i*4+j)
		}
	}
	// The Linux defaults differ from the test values.
	s.MXCSR = 0x1f80
	s.FCW = 0x37f
	return s
}

// SetSyscall makes the State run system call nr with args. The registers that
// do not hold the number or an argument keep their test values.
func (s *State) SetSyscall(nr uintptr, args ...uintptr) {
	argRegs := [...]int{RDI, RSI, RDX, R10, R8, R9}
	s.GPR[RAX] = uint64(nr)
	for i, a := range args {
		s.GPR[argRegs[i]] = uint64(a)
	}
}

// SetFaultAddr makes EventFault store to addr.
func (s *State) SetFaultAddr(addr uintptr) { s.GPR[RSI] = uint64(addr) }

// SetResult sets the register that holds the result of a system call.
func (s *State) SetResult(v uint64) { s.GPR[RAX] = v }

// Result returns the register that holds the result of a system call.
func (s *State) Result() uint64 { return s.GPR[RAX] }

// ExpectSpinExit sets the registers that EventSpin changes to the value that
// they hold when the loop ends.
func (s *State) ExpectSpinExit() {}

// clobberedBySyscall lists the registers that the instruction SYSCALL changes
// besides the result.
var clobberedBySyscall = []int{RCX, R11}

// diffs returns one line for each register of got that differs from want.
// It ignores the registers in skip. It compares RSP when want has one.
func diffs(want, got *State, skip ...int) []string {
	var out []string
	skipped := make(map[int]bool, len(skip))
	for _, r := range skip {
		skipped[r] = true
	}
	for i := range want.GPR {
		if !skipped[i] && want.GPR[i] != got.GPR[i] {
			out = append(out, fmt.Sprintf("%s = %#x, want %#x", gprNames[i], got.GPR[i], want.GPR[i]))
		}
	}
	if want.RSP != 0 && want.RSP != got.RSP {
		out = append(out, fmt.Sprintf("RSP = %#x, want %#x", got.RSP, want.RSP))
	}
	for i := range want.Vec {
		for j := 0; j < VectorBytes()/8; j++ {
			if want.Vec[i][j] != got.Vec[i][j] {
				out = append(out, fmt.Sprintf("YMM%d[%d] = %#x, want %#x", i, j, got.Vec[i][j], want.Vec[i][j]))
			}
		}
	}
	if want.MXCSR != got.MXCSR {
		out = append(out, fmt.Sprintf("MXCSR = %#x, want %#x", got.MXCSR, want.MXCSR))
	}
	if want.FCW != got.FCW {
		out = append(out, fmt.Sprintf("x87 control word = %#x, want %#x", got.FCW, want.FCW))
	}
	return out
}

// SyscallClobbers returns the registers that a system call changes besides the
// result register.
func SyscallClobbers() []int { return clobberedBySyscall }
