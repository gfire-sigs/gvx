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

//go:build arm64

package arch

import (
	"encoding/binary"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch/fpu"
)

const (
	// fpsimdMagic is the magic number of the first record in the reserved
	// area of a signal frame (FPSIMD_MAGIC in arch/arm64/include/uapi/asm/sigcontext.h).
	fpsimdMagic = 0x46508001

	// fpsimdContextSize is the size of struct fpsimd_context.
	fpsimdContextSize = 0x210

	// esrMagic is the magic number of struct esr_context.
	esrMagic = 0x45535201

	// esrContextSize is the size of struct esr_context.
	esrContextSize = 16

	// sigFrameTrailerSize is the size of the records after the fpsimd record: a
	// slot for an esr_context, or the end marker with padding in its place.
	sigFrameTrailerSize = esrContextSize + 16

	// segvAccerr is the si_code of a fault on a mapped page with the wrong permission.
	segvAccerr = 2

	// Fields of the ESR_EL1 value that Linux reports to a handler.
	esrECShift   = 26
	esrECIABTLow = 0x20 // Instruction abort from a lower exception level.
	esrECDABTLow = 0x24 // Data abort from a lower exception level.
	esrIL        = 1 << 25
	esrWnR       = 1 << 6
	esrDFSCTrans = 0x07 // Translation fault, level 3.
	esrDFSCPerm  = 0x0f // Permission fault, level 3.
)

// SetFaultAccess records the access of a user fault that the Sentry could not
// resolve and turns into a signal. The next signal frame of SIGSEGV or SIGBUS
// reports it in the ESR record, as Linux does. A nested Sentry reads the
// record to learn if the fault is a read, a write, or an instruction fetch.
func (c *Context64) SetFaultAccess(at hostarch.AccessType) {
	c.faultAccess = at
}

// faultESR returns the ESR_EL1 value for the recorded fault, or false when no
// fault is recorded. The recorded access is cleared.
func (c *Context64) faultESR(info *linux.SignalInfo) (uint64, bool) {
	at := c.faultAccess
	c.faultAccess = hostarch.AccessType{}
	if !at.Any() || (info.Signo != int32(linux.SIGSEGV) && info.Signo != int32(linux.SIGBUS)) {
		return 0, false
	}
	esr := uint64(esrIL)
	switch {
	case at.Execute:
		esr |= esrECIABTLow << esrECShift
	case at.Write:
		esr |= esrECDABTLow<<esrECShift | esrWnR
	default:
		esr |= esrECDABTLow << esrECShift
	}
	if info.Code == segvAccerr {
		esr |= esrDFSCPerm
	} else {
		esr |= esrDFSCTrans
	}
	return esr, true
}

// signalFrameTrailer returns the records that follow the fpsimd record: the
// esr_context when esr is valid, and the end marker. Linux writes the end
// marker at the end of the reserved area, and a handler walks the records
// until it finds it.
func signalFrameTrailer(esr uint64, haveESR bool) [sigFrameTrailerSize]byte {
	var trailer [sigFrameTrailerSize]byte
	if haveESR {
		binary.LittleEndian.PutUint32(trailer[0:], esrMagic)
		binary.LittleEndian.PutUint32(trailer[4:], esrContextSize)
		binary.LittleEndian.PutUint64(trailer[8:], esr)
	}
	// The end marker is eight zero bytes, which the array already holds.
	return trailer
}

// fpStateToSignalFrame writes the floating point registers of c, and the
// record header that Linux writes, into the reserved area of a signal frame.
// The memory layout of fpu.State is the layout of struct fpsimd_context, so the
// copy is one marshal call.
func (c *Context64) fpStateToSignalFrame(frame *FpsimdContext) {
	frame.UnmarshalBytes(c.fpState)
	frame.Head = aarch64Ctx{Magic: fpsimdMagic, Size: fpsimdContextSize}
}

// fpStateFromSignalFrame reads the floating point registers from the reserved
// area of a signal frame into state. It keeps state unchanged when the frame
// has no valid fpsimd record, as Linux ignores a frame without one.
func fpStateFromSignalFrame(state fpu.State, frame *FpsimdContext) {
	if frame.Head.Magic != fpsimdMagic || frame.Head.Size != fpsimdContextSize {
		return
	}
	frame.MarshalBytes(state)
}

// layoutTaskSize returns the largest address space size with an address layout
// that does not exceed taskSize. A nested Sentry sees a task size below the
// hardware size, because its host Sentry keeps the top of the address space for
// its stub processes.
func layoutTaskSize(taskSize uintptr) uintptr {
	for _, size := range []uintptr{1 << 52, 1 << 48, 1 << 39} {
		if taskSize >= size {
			return size
		}
	}
	return taskSize
}
