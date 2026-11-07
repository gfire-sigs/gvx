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

package guestcpu

import "fmt"

// Index of each general purpose register in State.X. X30 is the link register.
const numGPR = 31

// Control values that NewEditState uses: round towards minus infinity, default
// NaN mode, and the flags DZC and OFC.
const (
	editFPCR = 0x02800000
	editFPSR = 0x08000006
)

// Test values of the FP control state. FPCR selects round towards plus
// infinity and flush-to-zero. FPSR holds the cumulative flags IOC, IXC, and QC.
const (
	testFPCR = 0x01400000
	testFPSR = 0x08000011
	// restorerFlag is zero: the kernel of arm64 returns from a handler through
	// a trampoline in the vDSO and ignores the field restorer.
	restorerFlag = 0
)

// State is the register state that Run loads and stores.
type State struct {
	X [numGPR]uint64
	// SP is the stack pointer of the thread while it runs the event. Run
	// stores it in the input State and in the output State.
	SP   uint64
	FPSR uint64
	FPCR uint64
	// V holds V0 to V31 as two 64-bit halves each.
	V [32][2]uint64
}

// frame slots of the stack of Run, shared with the assembly through go_asm.h.
const (
	// slotFP and slotLR hold X29 and X30 of the caller.
	slotFP = 0
	slotLR = 8
	// slotOut holds the address of the output State until the state is stored.
	slotOut = 16
	// slotStash holds the value of the register that points to the State.
	slotStash = 24
	// slotFPCR and slotFPSR hold the FP control state that Run restores.
	slotFPCR = 32
	slotFPSR = 40
	// slotG and slotPlatform hold X28, the g register of the Go runtime, and
	// X18, the platform register.
	slotG        = 48
	slotPlatform = 56
	// frameSize is the size of the stack frame of Run. The stack pointer of
	// arm64 stays 16-byte aligned.
	frameSize = 64
)

func restorerPC() uintptr { return 0 }

// VectorBytes returns the number of bytes of each vector register that Run
// loads and stores.
func VectorBytes() int { return 16 }

// NewState returns a State with a distinct test value in every register and a
// non-default FP control state. The seed selects the values.
func NewState(seed uint64) State {
	var s State
	x := seed
	for i := range s.X {
		s.X[i] = splitmix(&x)
	}
	for i := range s.V {
		for j := range s.V[i] {
			s.V[i][j] = splitmix(&x)
		}
	}
	s.FPCR = testFPCR
	s.FPSR = testFPSR
	return s
}

// NewEditState returns a State like NewState with FP control values that differ
// from those of NewState. A frame edit with it shows that the kernel takes the
// control registers from the frame.
func NewEditState(seed uint64) State {
	s := NewState(seed)
	s.FPCR = editFPCR
	s.FPSR = editFPSR
	return s
}

func trashPattern() State {
	var s State
	for i := range s.X {
		s.X[i] = 0xbad0bad0bad0bad0 + uint64(i)
	}
	for i := range s.V {
		for j := range s.V[i] {
			s.V[i][j] = 0xfeedfacefeedface ^ uint64(i*2+j)
		}
	}
	// The default FPCR and FPSR differ from the test values.
	return s
}

// SetSyscall makes the State run system call nr with args. The registers that
// do not hold the number or an argument keep their test values.
func (s *State) SetSyscall(nr uintptr, args ...uintptr) {
	s.X[8] = uint64(nr)
	for i, a := range args {
		s.X[i] = uint64(a)
	}
}

// SetFaultAddr makes EventFault store to addr.
func (s *State) SetFaultAddr(addr uintptr) { s.X[1] = uint64(addr) }

// SetResult sets the register that holds the result of a system call.
func (s *State) SetResult(v uint64) { s.X[0] = v }

// Result returns the register that holds the result of a system call.
func (s *State) Result() uint64 { return s.X[0] }

// ExpectSpinExit sets the registers that EventSpin changes to the value that
// they hold when the loop ends: X0 holds the spin flag.
func (s *State) ExpectSpinExit() { s.X[0] = 1 }

// SyscallClobbers returns the registers that a system call changes besides the
// result register. The instruction SVC changes none.
func SyscallClobbers() []int { return nil }

// diffs returns one line for each register of got that differs from want.
// It ignores the registers in skip. It compares SP when want has one.
func diffs(want, got *State, skip ...int) []string {
	var out []string
	skipped := make(map[int]bool, len(skip))
	for _, r := range skip {
		skipped[r] = true
	}
	for i := range want.X {
		if !skipped[i] && want.X[i] != got.X[i] {
			out = append(out, fmt.Sprintf("X%d = %#x, want %#x", i, got.X[i], want.X[i]))
		}
	}
	if want.SP != 0 && want.SP != got.SP {
		out = append(out, fmt.Sprintf("SP = %#x, want %#x", got.SP, want.SP))
	}
	for i := range want.V {
		if want.V[i] != got.V[i] {
			out = append(out, fmt.Sprintf("V%d = %#x, want %#x", i, got.V[i], want.V[i]))
		}
	}
	if want.FPCR != got.FPCR {
		out = append(out, fmt.Sprintf("FPCR = %#x, want %#x", got.FPCR, want.FPCR))
	}
	if want.FPSR != got.FPSR {
		out = append(out, fmt.Sprintf("FPSR = %#x, want %#x", got.FPSR, want.FPSR))
	}
	return out
}
