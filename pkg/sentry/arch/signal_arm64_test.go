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

package arch

import (
	"encoding/binary"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/cpuid"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/usermem"
)

// signalFrameFixture holds the context and the signal frame of one delivery.
type signalFrameFixture struct {
	ctx    *Context64
	st     *Stack
	buf    []byte
	ucAddr hostarch.Addr
}

func deliverSignalWithFPRegs(t *testing.T) *signalFrameFixture {
	t.Helper()
	return deliverFaultWithFPRegs(t, linux.SIGSEGV, hostarch.AccessType{})
}

// deliverFaultWithFPRegs delivers sig after a user fault with the access at.
func deliverFaultWithFPRegs(t *testing.T, sig linux.Signal, at hostarch.AccessType) *signalFrameFixture {
	t.Helper()
	ctx := New(ARM64)
	ctx.SetFaultAccess(at)
	var fp FpsimdContext
	fp.Fpsr = 0x11
	fp.Fpcr = 0x22
	for i := range fp.Vregs {
		fp.Vregs[i] = 0x0101010101010101 * uint64(i+1)
	}
	fp.MarshalBytes(ctx.fpState)

	buf := make([]byte, 1<<14)
	st := &Stack{Arch: ctx, IO: &usermem.BytesIO{Bytes: buf}, Bottom: hostarch.Addr(len(buf))}
	act := &linux.SigAction{Handler: 0x1000}
	info := &linux.SignalInfo{Signo: int32(sig), Code: 1}
	if err := ctx.SignalSetup(st, act, info, &linux.SignalStack{}, 0, cpuid.FeatureSet{}); err != nil {
		t.Fatalf("SignalSetup: %v", err)
	}
	return &signalFrameFixture{ctx: ctx, st: st, buf: buf, ucAddr: st.Bottom}
}

func (f *signalFrameFixture) frame() UContext64 {
	var uc UContext64
	uc.UnmarshalBytes(f.buf[f.ucAddr:])
	return uc
}

// Linux puts the floating point registers of the interrupted thread in the
// signal frame, under a header with the magic FPSIMD_MAGIC. A sysmsg stub of
// a nested Sentry reads the header and the registers to find its context.
func TestSignalFrameHasTheFloatingPointRecord(t *testing.T) {
	f := deliverSignalWithFPRegs(t)
	rec := f.frame().MContext.Fpsimd64
	if rec.Head.Magic != fpsimdMagic || rec.Head.Size != fpsimdContextSize {
		t.Errorf("record head = {%#x, %#x}, want {%#x, %#x}", rec.Head.Magic, rec.Head.Size, fpsimdMagic, fpsimdContextSize)
	}
	if rec.Fpsr != 0x11 || rec.Fpcr != 0x22 {
		t.Errorf("fpsr, fpcr = %#x, %#x, want 0x11, 0x22", rec.Fpsr, rec.Fpcr)
	}
	for i, v := range rec.Vregs {
		if want := 0x0101010101010101 * uint64(i+1); v != want {
			t.Fatalf("vregs[%d] = %#x, want %#x", i, v, want)
		}
	}
}

// A handler that edits the registers in the frame changes the registers after
// sigreturn. A nested Sentry switches the application context this way.
func TestSigreturnLoadsTheFloatingPointRecordOfTheFrame(t *testing.T) {
	f := deliverSignalWithFPRegs(t)
	uc := f.frame()
	uc.MContext.Fpsimd64.Vregs[3] = 0xdeadbeef
	uc.MContext.Fpsimd64.Fpcr = 0x33
	uc.MarshalBytes(f.buf[f.ucAddr:])

	f.st.Bottom = f.ucAddr
	if _, _, err := f.ctx.SignalRestore(f.st, true, cpuid.FeatureSet{}); err != nil {
		t.Fatalf("SignalRestore: %v", err)
	}
	var got FpsimdContext
	got.UnmarshalBytes(f.ctx.fpState)
	if got.Vregs[3] != 0xdeadbeef || got.Fpcr != 0x33 {
		t.Errorf("vregs[3], fpcr = %#x, %#x, want 0xdeadbeef, 0x33", got.Vregs[3], got.Fpcr)
	}
	if got.Vregs[4] != 0x0101010101010101*5 || got.Fpsr != 0x11 {
		t.Errorf("registers that the frame did not change differ: vregs[4], fpsr = %#x, %#x", got.Vregs[4], got.Fpsr)
	}
}

// A frame without the record leaves the saved registers in place.
func TestSigreturnKeepsTheFloatingPointStateWithoutARecord(t *testing.T) {
	f := deliverSignalWithFPRegs(t)
	uc := f.frame()
	uc.MContext.Fpsimd64 = FpsimdContext{}
	uc.MarshalBytes(f.buf[f.ucAddr:])

	f.st.Bottom = f.ucAddr
	if _, _, err := f.ctx.SignalRestore(f.st, true, cpuid.FeatureSet{}); err != nil {
		t.Fatalf("SignalRestore: %v", err)
	}
	var got FpsimdContext
	got.UnmarshalBytes(f.ctx.fpState)
	if got.Vregs[3] != 0x0101010101010101*4 || got.Fpsr != 0x11 || got.Fpcr != 0x22 {
		t.Errorf("the saved registers changed: vregs[3], fpsr, fpcr = %#x, %#x, %#x", got.Vregs[3], got.Fpsr, got.Fpcr)
	}
}

// trailer returns the bytes that follow the floating point record.
func (f *signalFrameFixture) trailer() []byte {
	start := f.ucAddr + hostarch.Addr((*UContext64)(nil).SizeBytes())
	return f.buf[start : start+sigFrameTrailerSize]
}

// A handler walks the records of the reserved area until it finds the end
// marker, so a signal frame has to end the records. A frame without the marker
// makes a nested Sentry stub loop forever.
func TestSignalFrameEndsTheRecordsWithoutAFault(t *testing.T) {
	f := deliverSignalWithFPRegs(t)
	if got := binary.LittleEndian.Uint32(f.trailer()); got != 0 {
		t.Errorf("magic after the floating point record = %#x, want 0, the end marker", got)
	}
}

// Linux puts the ESR of a fault in the record after the floating point
// record. A nested Sentry stub reads it to tell a read from a write and from an
// instruction fetch.
func TestSignalFrameReportsTheFaultAccess(t *testing.T) {
	for _, tc := range []struct {
		name string
		sig  linux.Signal
		at   hostarch.AccessType
	}{
		{"read", linux.SIGSEGV, hostarch.Read},
		{"write", linux.SIGSEGV, hostarch.Write},
		{"execute", linux.SIGSEGV, hostarch.Execute},
		{"read through SIGBUS", linux.SIGBUS, hostarch.Read},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := deliverFaultWithFPRegs(t, tc.sig, tc.at)
			trailer := f.trailer()
			if magic, size := binary.LittleEndian.Uint32(trailer), binary.LittleEndian.Uint32(trailer[4:]); magic != esrMagic || size != esrContextSize {
				t.Fatalf("record head = {%#x, %d}, want {%#x, %d}", magic, size, esrMagic, esrContextSize)
			}
			esr := binary.LittleEndian.Uint64(trailer[8:])
			if got := hostarch.ESRAccessType(esr); got != tc.at {
				t.Errorf("ESR %#x reports the access %v, want %v", esr, got, tc.at)
			}
			if end := binary.LittleEndian.Uint32(trailer[esrContextSize:]); end != 0 {
				t.Errorf("magic after the ESR record = %#x, want 0, the end marker", end)
			}
		})
	}
}

// The ESR of one fault does not leak into the frame of a later signal.
func TestSignalFrameForgetsTheFaultAccess(t *testing.T) {
	f := deliverFaultWithFPRegs(t, linux.SIGSEGV, hostarch.Write)
	st := &Stack{Arch: f.ctx, IO: &usermem.BytesIO{Bytes: f.buf}, Bottom: hostarch.Addr(len(f.buf))}
	info := &linux.SignalInfo{Signo: int32(linux.SIGSEGV)}
	if err := f.ctx.SignalSetup(st, &linux.SigAction{Handler: 0x1000}, info, &linux.SignalStack{}, 0, cpuid.FeatureSet{}); err != nil {
		t.Fatalf("SignalSetup: %v", err)
	}
	f.ucAddr = st.Bottom
	if got := binary.LittleEndian.Uint32(f.trailer()); got != 0 {
		t.Errorf("magic after the floating point record = %#x, want 0: the frame has a stale ESR", got)
	}
}

// A nested Sentry sees a task size below the hardware size. The layout is the
// one of the largest size that fits.
func TestLayoutTaskSize(t *testing.T) {
	for _, tc := range []struct{ in, want uintptr }{
		{1 << 52, 1 << 52},
		{1 << 48, 1 << 48},
		{1<<48 - 1<<41, 1 << 39},
		{1<<52 - 1<<45, 1 << 48},
		{1 << 39, 1 << 39},
		{1<<39 - 1<<32, 1<<39 - 1<<32},
	} {
		if got := layoutTaskSize(tc.in); got != tc.want {
			t.Errorf("layoutTaskSize(%#x) = %#x, want %#x", tc.in, got, tc.want)
		}
	}
}
