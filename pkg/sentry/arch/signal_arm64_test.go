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
	"unsafe"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/cpuid"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch/fpu"
	"z.gfire.dev/gvx/pkg/usermem"
)

// signalFrameFixture holds the context and the signal frame of one delivery.
type signalFrameFixture struct {
	ctx      *Context64
	st       *Stack
	buf      []byte
	ucAddr   hostarch.Addr
	infoAddr hostarch.Addr
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
	fp.Head = aarch64Ctx{Magic: fpsimdMagic, Size: fpsimdContextSize}
	fp.Fpsr = 0x11
	fp.Fpcr = 0x22
	for i := range fp.Vregs {
		fp.Vregs[i] = 0x0101010101010101 * uint64(i+1)
	}
	putFPState(ctx.fpState, fp)

	buf := make([]byte, 1<<14)
	st := &Stack{Arch: ctx, IO: &usermem.BytesIO{Bytes: buf}, Bottom: hostarch.Addr(len(buf))}
	act := &linux.SigAction{Handler: 0x1000, Restorer: 0x2000}
	info := &linux.SignalInfo{Signo: int32(sig), Code: 1}
	info.SetAddr(0x7fff00001234)
	if err := ctx.SignalSetup(st, act, info, &linux.SignalStack{}, 0, cpuid.FeatureSet{}); err != nil {
		t.Fatalf("SignalSetup: %v", err)
	}
	return &signalFrameFixture{
		ctx:      ctx,
		st:       st,
		buf:      buf,
		ucAddr:   st.Bottom,
		infoAddr: hostarch.Addr(ctx.Regs.Regs[1]),
	}
}

// putFPState serializes fp with the generated go_marshal encoder and copies
// the body after the 8-byte aarch64_ctx header into state. Using MarshalBytes
// instead of the FPSIMDOff constants detects any offset mismatch between the
// ABI definition of FpsimdContext and fpStateToSignalFrame.
func putFPState(state fpu.State, fp FpsimdContext) {
	raw := make([]byte, fp.SizeBytes())
	fp.MarshalBytes(raw)
	hdrSize := (*aarch64Ctx)(nil).SizeBytes()
	copy(state, raw[hdrSize:])
}

// getFPState decodes state through the generated go_marshal decoder for
// FpsimdContext. See putFPState.
func getFPState(state fpu.State) FpsimdContext {
	var fp FpsimdContext
	hdrSize := (*aarch64Ctx)(nil).SizeBytes()
	raw := make([]byte, fp.SizeBytes())
	copy(raw[hdrSize:], state[:fp.SizeBytes()-hdrSize])
	fp.UnmarshalBytes(raw)
	return fp
}

// TestFPSIMDLayoutMatchesABI verifies that the shared fpu.State offset
// constants match the generated ABI layout of FpsimdContext.
func TestFPSIMDLayoutMatchesABI(t *testing.T) {
	var fp FpsimdContext
	hdrSize := unsafe.Sizeof(fp.Head)
	if got, want := uintptr(FPSIMDOffFPSR), unsafe.Offsetof(fp.Fpsr)-hdrSize; got != want {
		t.Fatalf("FPSIMDOffFPSR = %d, want %d", got, want)
	}
	if got, want := uintptr(FPSIMDOffFPCR), unsafe.Offsetof(fp.Fpcr)-hdrSize; got != want {
		t.Fatalf("FPSIMDOffFPCR = %d, want %d", got, want)
	}
	if got, want := uintptr(FPSIMDOffV), unsafe.Offsetof(fp.Vregs)-hdrSize; got != want {
		t.Fatalf("FPSIMDOffV = %d, want %d", got, want)
	}
	if got, want := FPSIMDBodySize, fp.SizeBytes()-(*aarch64Ctx)(nil).SizeBytes(); got != want {
		t.Fatalf("FPSIMDBodySize = %d, want %d", got, want)
	}
	if got := len(fpu.NewState()); got < FPSIMDBodySize {
		t.Fatalf("len(fpu.NewState()) = %d, want >= %d", got, FPSIMDBodySize)
	}
}

// TestSignalSetupBuildsLinuxABIFrameAndRegisters verifies that SignalSetup
// populates the handler registers, siginfo, and ucontext on the user stack and
// that SignalRestore recovers the interrupted context.
func TestSignalSetupBuildsLinuxABIFrameAndRegisters(t *testing.T) {
	ctx := New(ARM64)
	for i := range ctx.Regs.Regs {
		ctx.Regs.Regs[i] = 0x1000_0000_0000_0000 | uint64(i+1)
	}
	ctx.Regs.Sp = 0x4000
	ctx.Regs.Pc = 0x800400
	ctx.Regs.Pstate = linux.PSR_MODE_EL0t | linux.PSR_N_BIT | linux.PSR_C_BIT
	wantRegs := ctx.Regs

	var fp FpsimdContext
	fp.Head = aarch64Ctx{Magic: fpsimdMagic, Size: fpsimdContextSize}
	fp.Fpsr = 0x15
	fp.Fpcr = 0x01000000
	for i := range fp.Vregs {
		fp.Vregs[i] = 0xfeedface00000000 | uint64(i)
	}
	putFPState(ctx.fpState, fp)
	ctx.SetFaultAccess(hostarch.Write)

	buf := make([]byte, 1<<14)
	st := &Stack{Arch: ctx, IO: &usermem.BytesIO{Bytes: buf}, Bottom: hostarch.Addr(len(buf))}
	act := &linux.SigAction{Handler: 0x550000, Restorer: 0x660000}
	info := &linux.SignalInfo{Signo: int32(linux.SIGSEGV), Code: segvAccerr}
	const faultAddr = 0x7fff12345678
	info.SetAddr(faultAddr)
	alt := &linux.SignalStack{Addr: 0x1000, Size: 0x3000, Flags: linux.SS_ONSTACK}
	const wantSigset = linux.SignalSet(0x1234)

	if err := ctx.SignalSetup(st, act, info, alt, wantSigset, cpuid.FeatureSet{}); err != nil {
		t.Fatalf("SignalSetup: %v", err)
	}
	if ctx.Regs.Sp != uint64(st.Bottom) || ctx.Regs.Sp%16 != 0 {
		t.Fatalf("handler Sp = %#x (st.Bottom %#x), want 16-byte aligned frame bottom", ctx.Regs.Sp, st.Bottom)
	}
	if ctx.Regs.Pc != act.Handler {
		t.Errorf("handler Pc = %#x, want %#x", ctx.Regs.Pc, act.Handler)
	}
	if ctx.Regs.Regs[0] != uint64(linux.SIGSEGV) {
		t.Errorf("handler X0 (signo) = %d, want %d", ctx.Regs.Regs[0], linux.SIGSEGV)
	}
	if ctx.Regs.Regs[2] != uint64(st.Bottom) {
		t.Errorf("handler X2 (ucontext) = %#x, want %#x", ctx.Regs.Regs[2], st.Bottom)
	}
	if ctx.Regs.Regs[30] != act.Restorer {
		t.Errorf("handler X30 (restorer) = %#x, want %#x", ctx.Regs.Regs[30], act.Restorer)
	}
	for i, b := range ctx.fpState[:FPSIMDBodySize] {
		if b != 0 {
			t.Fatalf("handler fpState[%d] = %#x, want 0", i, b)
		}
	}

	var gotInfo linux.SignalInfo
	gotInfo.UnmarshalBytes(buf[ctx.Regs.Regs[1]:])
	if gotInfo.Signo != int32(linux.SIGSEGV) || gotInfo.Code != segvAccerr || gotInfo.Addr() != faultAddr {
		t.Errorf("siginfo = {signo:%d code:%d addr:%#x}, want {signo:%d code:%d addr:%#x}",
			gotInfo.Signo, gotInfo.Code, gotInfo.Addr(), linux.SIGSEGV, segvAccerr, uint64(faultAddr))
	}

	gotSet, gotStack, err := ctx.SignalRestore(st, true, cpuid.FeatureSet{})
	if err != nil {
		t.Fatalf("SignalRestore: %v", err)
	}
	if gotSet != wantSigset {
		t.Errorf("restored sigset = %#x, want %#x", gotSet, wantSigset)
	}
	if gotStack != *alt {
		t.Errorf("restored stack = %+v, want %+v", gotStack, *alt)
	}
	if ctx.Regs != wantRegs {
		t.Errorf("restored Regs = %+v, want %+v", ctx.Regs, wantRegs)
	}
}

// A signal and its sigreturn leave every floating point register as it was.
// A record header written over the state once set FPCR to 0x210, which enables
// the divide-by-zero trap, and FPSR to the magic number.
func TestSignalRoundTripKeepsTheFloatingPointState(t *testing.T) {
	f := deliverSignalWithFPRegs(t)
	f.st.Bottom = f.ucAddr
	if _, _, err := f.ctx.SignalRestore(f.st, true, cpuid.FeatureSet{}); err != nil {
		t.Fatalf("SignalRestore: %v", err)
	}
	got := getFPState(f.ctx.fpState)
	if got.Fpsr != 0x11 || got.Fpcr != 0x22 {
		t.Errorf("fpsr, fpcr after sigreturn = %#x, %#x, want 0x11, 0x22", got.Fpsr, got.Fpcr)
	}
	for i, v := range got.Vregs {
		if want := 0x0101010101010101 * uint64(i+1); v != want {
			t.Fatalf("vregs[%d] after sigreturn = %#x, want %#x", i, v, want)
		}
	}
}

func (f *signalFrameFixture) frame() UContext64 {
	var uc UContext64
	uc.UnmarshalBytes(f.buf[f.ucAddr:])
	return uc
}

// walkReservedRecords walks the Linux arm64 __reserved context records in the
// raw stack frame starting at the fpsimd_context offset inside ucontext up to
// the siginfo boundary.
func (f *signalFrameFixture) walkReservedRecords(t *testing.T) []aarch64Ctx {
	t.Helper()
	var uc UContext64
	reservedOff := int(unsafe.Offsetof(uc.MContext) + unsafe.Offsetof(uc.MContext.Fpsimd64))
	raw := f.buf[int(f.ucAddr)+reservedOff : f.infoAddr]
	var records []aarch64Ctx
	for off := 0; off+8 <= len(raw); {
		var hdr aarch64Ctx
		hdr.UnmarshalBytes(raw[off:])
		if hdr.Magic == 0 {
			if hdr.Size != 0 {
				t.Fatalf("terminator record at offset %d has size %d, want 0", off, hdr.Size)
			}
			return records
		}
		if hdr.Size < 8 || hdr.Size%16 != 0 || off+int(hdr.Size) > len(raw) {
			t.Fatalf("invalid record header {%#x, %d} at offset %d (len %d)", hdr.Magic, hdr.Size, off, len(raw))
		}
		records = append(records, hdr)
		off += int(hdr.Size)
	}
	t.Fatalf("reserved area [%#x, %#x) lacks a zero terminator record", int(f.ucAddr)+reservedOff, f.infoAddr)
	return nil
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
	got := getFPState(f.ctx.fpState)
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
	got := getFPState(f.ctx.fpState)
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
	records := f.walkReservedRecords(t)
	if len(records) != 1 || records[0] != (aarch64Ctx{Magic: fpsimdMagic, Size: fpsimdContextSize}) {
		t.Fatalf("reserved records = %+v, want only fpsimd_context", records)
	}
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
			records := f.walkReservedRecords(t)
			wantRecords := []aarch64Ctx{
				{Magic: fpsimdMagic, Size: fpsimdContextSize},
				{Magic: esrMagic, Size: esrContextSize},
			}
			if len(records) != len(wantRecords) || records[0] != wantRecords[0] || records[1] != wantRecords[1] {
				t.Fatalf("reserved records = %+v, want %+v", records, wantRecords)
			}
			trailer := f.trailer()
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
	f.infoAddr = hostarch.Addr(f.ctx.Regs.Regs[1])
	if records := f.walkReservedRecords(t); len(records) != 1 {
		t.Fatalf("reserved records on second signal = %+v, want only fpsimd_context", records)
	}
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
