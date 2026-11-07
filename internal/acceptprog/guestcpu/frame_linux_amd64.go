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

import (
	"errors"
	"fmt"
)

// Layout of the frame of amd64 (struct ucontext, struct sigcontext, and the
// xsave area). The assembly and the decoder use these constants.
const (
	// ucBytes is the number of bytes of the ucontext that ModeCapture copies:
	// the whole struct ucontext including uc_sigmask.
	ucBytes = 304
	// fpMax is the size of the buffer that holds the xsave area and magic2.
	fpMax = 16384

	ucStackSP   = 16
	ucStackSize = 32
	ucR8        = 40
	ucR9        = 48
	ucR10       = 56
	ucR11       = 64
	ucR12       = 72
	ucR13       = 80
	ucR14       = 88
	ucR15       = 96
	ucRDI       = 104
	ucRSI       = 112
	ucRBP       = 120
	ucRBX       = 128
	ucRDX       = 136
	ucRAX       = 144
	ucRCX       = 152
	ucRSP       = 160
	ucRIP       = 168
	ucErr       = 192
	ucTrapno    = 200
	ucCR2       = 216
	ucFpstate   = 224
	ucSigmask   = 296

	// Offsets in the xsave area that fpstate points to.
	fpFCW     = 0
	fpMXCSR   = 24
	fpXMM     = 160
	fpSWBytes = 464
	fpXHeader = 512
	fpYMMHi   = 576

	// faultInsnLen is the length of the instruction of runFault that faults.
	faultInsnLen = 7

	// FPXStateMagic1 and FPXStateMagic2 delimit the xsave area in a frame.
	FPXStateMagic1 = 0x46505853
	FPXStateMagic2 = 0x46505845
)

// ucGPR maps an index of State.GPR to the offset of the register in the
// ucontext.
var ucGPR = [numGPR]int{
	RAX: ucRAX, RBX: ucRBX, RCX: ucRCX, RDX: ucRDX, RSI: ucRSI, RDI: ucRDI,
	RBP: ucRBP, R8: ucR8, R9: ucR9, R10: ucR10, R11: ucR11, R12: ucR12,
	R13: ucR13, R14: ucR14, R15: ucR15,
}

var spinScratch []int

// ArchFrame holds the fields of the frame that exist on amd64.
type ArchFrame struct {
	Err, Trapno, CR2 uint64
	// FpstateAddr is the address of the xsave area.
	FpstateAddr uint64
	// SWMagic1, SWExtendedSize, SWXFeatures, and SWXStateSize are the software
	// bytes of the xsave area (struct _fpx_sw_bytes).
	SWMagic1, SWExtendedSize, SWXStateSize uint32
	SWXFeatures                            uint64
	// XStateBV is the XSTATE_BV field of the xsave header. A set bit marks a
	// component that is not in its initial state.
	XStateBV uint64
	// Magic2 is the word behind the xsave area, or zero when it is out of range.
	Magic2 uint32
}

func parseFrame(c *capture, f *Frame) error {
	uc := c.UC[:]
	for i := range f.Regs.GPR {
		f.Regs.GPR[i] = le64(uc, ucGPR[i])
	}
	f.SP = le64(uc, ucRSP)
	f.Regs.RSP = f.SP
	f.PC = le64(uc, ucRIP)
	a := &f.Arch
	a.Err = le64(uc, ucErr)
	a.Trapno = le64(uc, ucTrapno)
	a.CR2 = le64(uc, ucCR2)
	a.FpstateAddr = le64(uc, ucFpstate)
	if c.FPAddr == 0 {
		return errors.New("the frame has no FP state (fpstate is nil)")
	}
	fp := c.FP[:]
	if sz := int(le32(fp, fpSWBytes+16)); sz < fpXHeader+64 || sz+4 > fpMax {
		return fmt.Errorf("the xsave area has the size %d", sz)
	}
	f.Regs.FCW = le16(fp, fpFCW)
	f.Regs.MXCSR = le32(fp, fpMXCSR)
	a.SWMagic1 = le32(fp, fpSWBytes)
	a.SWExtendedSize = le32(fp, fpSWBytes+4)
	a.SWXFeatures = le64(fp, fpSWBytes+8)
	a.SWXStateSize = le32(fp, fpSWBytes+16)
	a.XStateBV = le64(fp, fpXHeader)
	for i := range f.Regs.Vec {
		f.Regs.Vec[i][0] = le64(fp, fpXMM+16*i)
		f.Regs.Vec[i][1] = le64(fp, fpXMM+16*i+8)
		if hasAVX && a.XStateBV&4 != 0 {
			f.Regs.Vec[i][2] = le64(fp, fpYMMHi+16*i)
			f.Regs.Vec[i][3] = le64(fp, fpYMMHi+16*i+8)
		}
	}
	a.Magic2 = le32(fp, int(a.SWXStateSize))
	return a.validateXSave()
}

// validateXSave verifies the software bytes, the magic words, and the header of
// the xsave area.
func (a *ArchFrame) validateXSave() error {
	if a.FpstateAddr%64 != 0 {
		return fmt.Errorf("fpstate %#x is not 64-byte aligned", a.FpstateAddr)
	}
	if a.SWMagic1 != FPXStateMagic1 {
		return fmt.Errorf("the xsave area has magic1 %#x, want %#x", a.SWMagic1, FPXStateMagic1)
	}
	if a.SWExtendedSize != a.SWXStateSize+4 {
		return fmt.Errorf("extended_size = %d, want xstate_size %d + 4", a.SWExtendedSize, a.SWXStateSize)
	}
	if a.Magic2 != FPXStateMagic2 {
		return fmt.Errorf("the word behind the xsave area is %#x, want %#x", a.Magic2, FPXStateMagic2)
	}
	// A clear XSTATE_BV bit of x87 or SSE means the initial state, and the
	// area still holds the register values, so the probe does not require
	// those bits. It requires the AVX bit, because the decoder reads the upper
	// halves of the YMM registers only when it is set.
	want := uint64(0)
	if hasAVX {
		want = 4
	}
	if a.XStateBV&want != want {
		return fmt.Errorf("XSTATE_BV = %#x, want bits %#x set", a.XStateBV, want)
	}
	if a.SWXFeatures&want != want {
		return fmt.Errorf("the xfeatures of the software bytes = %#x, want bits %#x set", a.SWXFeatures, want)
	}
	return nil
}
