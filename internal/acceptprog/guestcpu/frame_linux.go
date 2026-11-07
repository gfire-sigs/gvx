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

//go:build linux && (amd64 || arm64)

package guestcpu

import (
	"encoding/binary"
	"errors"
	"syscall"
)

// Offsets in the siginfo that the kernel passes to a handler.
const (
	siSigno = 0
	siCode  = 8
	// siAddr is the offset of si_addr of a fault and of si_pid of a signal that
	// kill or tgkill sends.
	siAddr  = 16
	siBytes = 128
)

// capture is the memory that evilHandler fills in ModeCapture. The assembly
// takes the offset of each field from go_asm.h.
type capture struct {
	Info   [siBytes]byte
	Sig    uint64
	UCAddr uint64
	// FPAddr is the address of the xsave area on amd64.
	FPAddr uint64
	UC     [ucBytes]byte
	FP     [fpMax]byte
}

// SigInfo is the part of the siginfo that the probes read.
type SigInfo struct {
	Signo, Code int32
	// Pid is si_pid of a signal that kill or tgkill sends.
	Pid uint32
	// Addr is si_addr of a fault.
	Addr uint64
}

// Frame is the decoded signal frame that the kernel built for evilHandler.
type Frame struct {
	Info SigInfo
	// Regs holds the general purpose registers, the vector registers, and the
	// FP control state of the interrupted thread as the frame records them.
	// The stack pointer of Regs is SP.
	Regs State
	// PC and SP are the program counter and the stack pointer in the frame.
	PC, SP uint64
	// StackSP and StackSize are the base and the size in uc_stack, the signal
	// stack of the interrupted thread.
	StackSP, StackSize uint64
	// Sigmask is uc_sigmask, the signal mask of the interrupted thread.
	Sigmask uint64
	// Arch holds the fields that exist on one architecture only.
	Arch ArchFrame
}

// Signal returns the signal number that the handler received.
func (f *Frame) Signal() syscall.Signal { return syscall.Signal(f.Info.Signo) }

// CapturedFrame decodes the frame that evilHandler copied at its last call in
// ModeCapture.
func CapturedFrame() (*Frame, error) {
	c := &captured
	if c.Sig == 0 {
		return nil, errors.New("the handler captured no frame")
	}
	f := &Frame{
		Info: SigInfo{
			Signo: int32(binary.LittleEndian.Uint32(c.Info[siSigno:])),
			Code:  int32(binary.LittleEndian.Uint32(c.Info[siCode:])),
			Pid:   binary.LittleEndian.Uint32(c.Info[siAddr:]),
			Addr:  binary.LittleEndian.Uint64(c.Info[siAddr:]),
		},
		StackSP:   binary.LittleEndian.Uint64(c.UC[ucStackSP:]),
		StackSize: binary.LittleEndian.Uint64(c.UC[ucStackSize:]),
		Sigmask:   binary.LittleEndian.Uint64(c.UC[ucSigmask:]),
	}
	if int32(c.Sig) != f.Info.Signo {
		return nil, errors.New("the signal number of the handler differs from si_signo")
	}
	if err := parseFrame(c, f); err != nil {
		return nil, err
	}
	return f, nil
}

func le64(b []byte, off int) uint64 { return binary.LittleEndian.Uint64(b[off:]) }
func le32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }
func le16(b []byte, off int) uint16 { return binary.LittleEndian.Uint16(b[off:]) }

// SpinScratch returns the registers that the loop of EventSpin uses as
// scratch. Their value in a frame of EventSpin is not a test value.
func SpinScratch() []int { return spinScratch }
