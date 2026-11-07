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

import (
	"errors"
	"fmt"
)

// Layout of the frame of arm64 (struct ucontext, struct sigcontext, and the
// records of the reserved area). The assembly and the decoder use these
// constants.
const (
	// ucBytes is the number of bytes of the ucontext that ModeCapture copies:
	// the registers, the fpsimd_context, a few records of 16 bytes (esr_context
	// and others), and the end marker. The frame of the Sentry holds 1152 bytes
	// from the ucontext (992 for the ucontext, 32 for the records behind it, and
	// 128 for the siginfo), so the copy must stay below that.
	ucBytes = 1136
	// fpMax is zero: the FP record is part of the ucontext on arm64.
	fpMax = 0

	ucStackSP    = 16
	ucStackFlags = 24
	ucStackSize  = 32
	ucSigmask    = 40
	ucFaultAddr  = 176
	ucRegs       = 184
	ucSP         = 432
	ucPC         = 440
	// ucReserved is the start of the records. The first record is the
	// fpsimd_context.
	ucReserved = 464
	// ucFpsimd is the offset of the fpsimd_context in the ucontext.
	ucFpsimd = ucReserved

	// faultInsnLen is the length of the instruction of runFault that faults.
	faultInsnLen = 4

	// Offsets in the fpsimd_context.
	fpsimdFPSR  = 8
	fpsimdFPCR  = 12
	fpsimdVregs = 16
	// FpsimdMagic and FpsimdSize identify the fpsimd_context.
	FpsimdMagic = 0x46508001
	FpsimdSize  = 0x210
	// ESRMagic and ESRSize identify the esr_context.
	ESRMagic = 0x45535201
	ESRSize  = 16
)

var spinScratch = []int{0}

// Record is one record of the reserved area of the frame.
type Record struct {
	Magic, Size uint32
	Offset      int
}

// ArchFrame holds the fields of the frame that exist on arm64.
type ArchFrame struct {
	// FaultAddr is fault_address of the sigcontext.
	FaultAddr uint64
	// Records lists the records in the reserved area up to the end marker.
	Records []Record
	// ESR is the value of the esr_context, and HasESR tells that the frame has
	// that record.
	ESR    uint64
	HasESR bool
}

func parseFrame(c *capture, f *Frame) error {
	uc := c.UC[:]
	for i := range f.Regs.X {
		f.Regs.X[i] = le64(uc, ucRegs+8*i)
	}
	f.SP = le64(uc, ucSP)
	f.Regs.SP = f.SP
	f.PC = le64(uc, ucPC)
	a := &f.Arch
	a.FaultAddr = le64(uc, ucFaultAddr)
	haveFpsimd, haveEnd := false, false
	for off := ucReserved; off+8 <= ucBytes; {
		magic, size := le32(uc, off), le32(uc, off+4)
		if magic == 0 {
			if size != 0 {
				return fmt.Errorf("the end marker at %d has size %d, want 0", off, size)
			}
			haveEnd = true
			break
		}
		if size < 8 || size%16 != 0 || off+int(size) > ucBytes {
			return fmt.Errorf("record %#x at offset %d has size %d", magic, off, size)
		}
		a.Records = append(a.Records, Record{Magic: magic, Size: size, Offset: off})
		switch magic {
		case FpsimdMagic:
			if size != FpsimdSize {
				return fmt.Errorf("the fpsimd_context has size %#x, want %#x", size, FpsimdSize)
			}
			f.Regs.FPSR = uint64(le32(uc, off+fpsimdFPSR))
			f.Regs.FPCR = uint64(le32(uc, off+fpsimdFPCR))
			for i := range f.Regs.V {
				f.Regs.V[i][0] = le64(uc, off+fpsimdVregs+16*i)
				f.Regs.V[i][1] = le64(uc, off+fpsimdVregs+16*i+8)
			}
			haveFpsimd = true
		case ESRMagic:
			if size != ESRSize {
				return fmt.Errorf("the esr_context has size %d, want %d", size, ESRSize)
			}
			a.ESR = le64(uc, off+8)
			a.HasESR = true
		}
		off += int(size)
	}
	if !haveEnd {
		return fmt.Errorf("the records of the frame have no end marker within %d bytes: %+v", ucBytes, a.Records)
	}
	if !haveFpsimd {
		return errors.New("the frame has no fpsimd_context")
	}
	if len(a.Records) == 0 || a.Records[0].Offset != ucFpsimd || a.Records[0].Magic != FpsimdMagic {
		return fmt.Errorf("the first record of the frame is %+v, want the fpsimd_context at %d", a.Records[0], ucFpsimd)
	}
	return nil
}
