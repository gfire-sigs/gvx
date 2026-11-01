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
	"testing"
	"unsafe"
)

// The structs below restate WHV_RUN_VP_EXIT_CONTEXT from winhvplatformdefs.h
// with Go field types of the same size and alignment. unsafe.Offsetof then
// gives the offsets that the C compiler produces, independent of the
// constants in exitctx.go.

type whvSegmentRegister struct {
	Base       uint64
	Limit      uint32
	Selector   uint16
	Attributes uint16
}

type whvX64VpExitContext struct {
	ExecutionState uint16
	LengthAndCr8   uint8
	Reserved       uint8
	Reserved2      uint32
	Cs             whvSegmentRegister
	Rip            uint64
	Rflags         uint64
}

type whvX64MemoryAccessContext struct {
	InstructionByteCount uint8
	Reserved             [3]uint8
	InstructionBytes     [16]uint8
	AccessInfo           uint32
	Gpa                  uint64
	Gva                  uint64
}

type whvX64RunVpExitContext struct {
	ExitReason   uint32
	Reserved     uint32
	VpContext    whvX64VpExitContext
	MemoryAccess whvX64MemoryAccessContext
	_            [224 - 8 - 40 - 40]byte
}

type whvInterceptMessageHeader struct {
	VpIndex             uint32
	InstructionLength   uint8
	InterceptAccessType uint8
	ExecutionState      uint16
	Pc                  uint64
	Cpsr                uint64
}

type whvA64MemoryAccessContext struct {
	Header               whvInterceptMessageHeader
	Reserved0            uint32
	InstructionByteCount uint8
	AccessInfo           uint8
	Reserved1            uint16
	InstructionBytes     [4]uint8
	Reserved2            uint32
	Gva                  uint64
	Gpa                  uint64
	Syndrome             uint64
}

type whvA64RunVpExitContext struct {
	ExitReason uint32
	Reserved   uint32
	Reserved1  uint64
	Union      [32]uint64
}

func TestExitContextLayoutMatchesTheHeader(t *testing.T) {
	var x whvX64RunVpExitContext
	for _, c := range []struct {
		name      string
		got, want uintptr
	}{
		{"sizeof x64 exit context", unsafe.Sizeof(x), exitCtxSizeX64},
		{"sizeof WHV_X64_VP_EXIT_CONTEXT", unsafe.Sizeof(x.VpContext), 40},
		{"sizeof WHV_MEMORY_ACCESS_CONTEXT (x64)", unsafe.Sizeof(x.MemoryAccess), 40},
		{"x64 ExecutionState", unsafe.Offsetof(x.VpContext) + unsafe.Offsetof(x.VpContext.ExecutionState), x64ExitOffExecState},
		{"x64 Rip", unsafe.Offsetof(x.VpContext) + unsafe.Offsetof(x.VpContext.Rip), x64ExitOffRip},
		{"x64 Rflags", unsafe.Offsetof(x.VpContext) + unsafe.Offsetof(x.VpContext.Rflags), x64ExitOffRflags},
		{"x64 AccessInfo", unsafe.Offsetof(x.MemoryAccess) + unsafe.Offsetof(x.MemoryAccess.AccessInfo), x64ExitOffMemInfo},
		{"x64 Gpa", unsafe.Offsetof(x.MemoryAccess) + unsafe.Offsetof(x.MemoryAccess.Gpa), x64ExitOffMemGpa},
		{"x64 Gva", unsafe.Offsetof(x.MemoryAccess) + unsafe.Offsetof(x.MemoryAccess.Gva), x64ExitOffMemGva},
	} {
		if c.got != c.want {
			t.Errorf("%s is %d, constant says %d", c.name, c.got, c.want)
		}
	}
	var a whvA64RunVpExitContext
	var m whvA64MemoryAccessContext
	const unionOff = 16
	if unsafe.Offsetof(a.Union) != unionOff {
		t.Fatalf("arm64 union starts at %d, want %d", unsafe.Offsetof(a.Union), unionOff)
	}
	for _, c := range []struct {
		name      string
		got, want uintptr
	}{
		{"sizeof arm64 exit context", unsafe.Sizeof(a), exitCtxSizeA64},
		{"sizeof WHV_MEMORY_ACCESS_CONTEXT (arm64)", unsafe.Sizeof(m), 64},
		{"arm64 header InstructionLength", unionOff + unsafe.Offsetof(m.Header.InstructionLength), a64ExitOffHdrInsnLen},
		{"arm64 header InterceptAccessType", unionOff + unsafe.Offsetof(m.Header.InterceptAccessType), a64ExitOffHdrAccess},
		{"arm64 header ExecutionState", unionOff + unsafe.Offsetof(m.Header.ExecutionState), a64ExitOffHdrState},
		{"arm64 header Pc", unionOff + unsafe.Offsetof(m.Header.Pc), a64ExitOffHdrPc},
		{"arm64 header Cpsr", unionOff + unsafe.Offsetof(m.Header.Cpsr), a64ExitOffHdrCpsr},
		{"arm64 AccessInfo", unionOff + unsafe.Offsetof(m.AccessInfo), a64ExitOffMemInfo},
		{"arm64 Gva", unionOff + unsafe.Offsetof(m.Gva), a64ExitOffMemGva},
		{"arm64 Gpa", unionOff + unsafe.Offsetof(m.Gpa), a64ExitOffMemGpa},
		{"arm64 Syndrome", unionOff + unsafe.Offsetof(m.Syndrome), a64ExitOffMemSyndrom},
	} {
		if c.got != c.want {
			t.Errorf("%s is %d, constant says %d", c.name, c.got, c.want)
		}
	}
	if exitCtxBufSize < exitCtxSizeA64 || exitCtxBufSize < exitCtxSizeX64 {
		t.Errorf("exit buffer of %d bytes is smaller than a context", exitCtxBufSize)
	}
}

func asBytes[T any](v *T) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(v)), unsafe.Sizeof(*v))
}

func TestDecodeExitX64(t *testing.T) {
	var halt whvX64RunVpExitContext
	halt.ExitReason = x64ExitHalt
	halt.VpContext.ExecutionState = 0
	halt.VpContext.Rip = 0xFFFFFF8000001234
	e, err := decodeExitX64(asBytes(&halt))
	if err != nil {
		t.Fatal(err)
	}
	if e.kind != exitStub || e.pc != 0xFFFFFF8000001234 || e.cpl != 0 {
		t.Errorf("halt decodes to %+v", e)
	}

	var cancel whvX64RunVpExitContext
	cancel.ExitReason = x64ExitCanceled
	cancel.VpContext.ExecutionState = 3 // CPL 3 in bits 0 and 1.
	cancel.VpContext.Rip = 0x401000
	if e, _ = decodeExitX64(asBytes(&cancel)); e.kind != exitCanceled || e.cpl != 3 || e.pc != 0x401000 {
		t.Errorf("cancel decodes to %+v", e)
	}
	// Bits above the CPL must not leak into it.
	cancel.VpContext.ExecutionState = 0x4 | 0x10 | 0x1
	if e, _ = decodeExitX64(asBytes(&cancel)); e.cpl != 1 {
		t.Errorf("CPL is %d for ExecutionState %#x, want 1", e.cpl, cancel.VpContext.ExecutionState)
	}

	for _, c := range []struct {
		info        uint32
		write, exec bool
		unmapped    bool
		gvaValid    bool
	}{
		{info: 0},
		{info: 1, write: true},
		{info: 2 | 1<<2 | 1<<3, exec: true, unmapped: true, gvaValid: true},
	} {
		var mem whvX64RunVpExitContext
		mem.ExitReason = x64ExitMemoryAccess
		mem.MemoryAccess.AccessInfo = c.info
		mem.MemoryAccess.Gpa = 0x1_2345_6000
		mem.MemoryAccess.Gva = 0x7FFF_0000_1000
		e, _ := decodeExitX64(asBytes(&mem))
		if e.kind != exitMemory || e.gpa != 0x1_2345_6000 || e.gva != 0x7FFF_0000_1000 ||
			e.write != c.write || e.execute != c.exec || e.gpaUnmapped != c.unmapped || e.gvaValid != c.gvaValid {
			t.Errorf("memory exit with AccessInfo %#x decodes to %+v", c.info, e)
		}
	}

	for _, reason := range []uint32{x64ExitIoPortAccess, x64ExitUnrecoverable, x64ExitInvalidVpRegister, x64ExitUnsupportedFeature,
		x64ExitInterruptWindow, x64ExitMsrAccess, x64ExitCpuid, x64ExitException, x64ExitRdtsc, x64ExitHypercall, x64ExitNone} {
		var other whvX64RunVpExitContext
		other.ExitReason = reason
		if e, _ := decodeExitX64(asBytes(&other)); e.kind != exitFatal {
			t.Errorf("exit reason %#x decodes to kind %d, want fatal", reason, e.kind)
		}
	}
	if _, err := decodeExitX64(make([]byte, exitCtxSizeX64-1)); err == nil {
		t.Error("decoder accepted a short x64 buffer")
	}
}

func TestDecodeExitA64(t *testing.T) {
	// The arm64 exit context is a byte buffer whose union members share
	// storage, so the test builds each case in a raw buffer.
	buf := func() []byte { return make([]byte, exitCtxSizeA64) }
	put := func(b []byte, off uintptr, v any) {
		switch x := v.(type) {
		case uint32:
			*(*uint32)(unsafe.Pointer(&b[off])) = x
		case uint64:
			*(*uint64)(unsafe.Pointer(&b[off])) = x
		case uint16:
			*(*uint16)(unsafe.Pointer(&b[off])) = x
		case uint8:
			b[off] = x
		}
	}
	const unionOff = 16
	var m whvA64MemoryAccessContext

	// Cancelled runs carry only the cancel reason, so no field may be read.
	cancel := buf()
	put(cancel, 0, uint32(a64ExitCanceled))
	if e, _ := decodeExitA64(cancel); e.kind != exitCanceled {
		t.Errorf("cancel decodes to %+v", e)
	}

	for _, c := range []struct {
		reason   uint32
		access   uint8
		info     uint8
		write    bool
		exec     bool
		unmapped bool
		gvaValid bool
	}{
		{reason: a64ExitUnmappedGpa, access: 0, info: 1, unmapped: true, gvaValid: true},
		{reason: a64ExitGpaIntercept, access: 1, info: 0, write: true},
		{reason: a64ExitUnmappedGpa, access: 2, info: 3, exec: true, unmapped: true, gvaValid: true},
	} {
		mem := buf()
		put(mem, 0, c.reason)
		put(mem, unionOff+unsafe.Offsetof(m.Header.InterceptAccessType), c.access)
		put(mem, unionOff+unsafe.Offsetof(m.Header.Pc), uint64(0x400000))
		put(mem, unionOff+unsafe.Offsetof(m.Header.Cpsr), uint64(0))
		put(mem, unionOff+unsafe.Offsetof(m.AccessInfo), c.info)
		put(mem, unionOff+unsafe.Offsetof(m.Gva), uint64(0x7000_0000))
		put(mem, unionOff+unsafe.Offsetof(m.Gpa), uint64(0x9000_1000))
		e, _ := decodeExitA64(mem)
		if e.kind != exitMemory || e.gva != 0x7000_0000 || e.gpa != 0x9000_1000 || e.pc != 0x400000 ||
			e.write != c.write || e.execute != c.exec || e.gpaUnmapped != c.unmapped || e.gvaValid != c.gvaValid {
			t.Errorf("memory exit %+v decodes to %+v", c, e)
		}
	}

	for _, reason := range []uint32{a64ExitNone, a64ExitInvalidVpRegister, a64ExitUnrecoverable, a64ExitUnsupportedFeature, a64ExitSynicSint, a64ExitReset, 0x1234} {
		other := buf()
		put(other, 0, reason)
		if e, _ := decodeExitA64(other); e.kind != exitFatal {
			t.Errorf("exit reason %#x decodes to kind %d, want fatal", reason, e.kind)
		}
	}
	if _, err := decodeExitA64(make([]byte, exitCtxSizeA64-1)); err == nil {
		t.Error("decoder accepted a short arm64 buffer")
	}
}
