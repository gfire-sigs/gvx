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

//go:build windows

package systrap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/sys/windows"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/cpuid"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/pkg/usermem"
)

// The engine runs guest machine code on the real CPU of the host, so these
// tests need no hypervisor. Each test builds a guest from the helpers in
// guest_windows_*_test.go, maps it, and runs it through Context.Switch.

const (
	codeVA  = 0x5555_0000_0000
	dataVA  = 0x5555_1000_0000
	stackVA = 0x7000_0000_0000
)

// testMM is the MemoryManager of the engine tests.
type testMM struct {
	usermem.IO
	as platform.AddressSpace
}

func (*testMM) MMap(context.Context, memmap.MMapOpts) (hostarch.Addr, error) {
	return 0, unix.ENOSYS
}

func (m *testMM) AddressSpace() platform.AddressSpace { return m.as }

func (*testMM) FindVMAByName(hostarch.AddrRange, string) (hostarch.Addr, uint64, error) {
	return 0, 0, unix.ENOENT
}

type rig struct {
	t    testing.TB
	p    *Platform
	mf   *pgalloc.MemoryFile
	as   *addressSpace
	mm   *testMM
	ctx  *Context
	ac   *arch.Context64
	rctx context.Context
}

func newPlatform(t testing.TB) *Platform {
	t.Helper()
	p, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return p
}

func newRig(t testing.TB, p *Platform) *rig {
	t.Helper()
	mf, err := pgalloc.NewDefaultMemoryFile(pgalloc.MemoryFileOpts{})
	if err != nil {
		t.Fatalf("NewDefaultMemoryFile: %v", err)
	}
	t.Cleanup(mf.Destroy)
	return newRigOn(t, p, mf)
}

// newRigOn returns a rig with a new address space and context that use the
// memory file mf. The caller destroys mf.
func newRigOn(t testing.TB, p *Platform, mf *pgalloc.MemoryFile) *rig {
	t.Helper()
	asI, err := p.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		t.Fatalf("NewAddressSpace: %v", err)
	}
	as := asI.(*addressSpace)
	r := &rig{t: t, p: p, mf: mf, as: as, mm: &testMM{as: as}, rctx: context.Background()}
	r.ctx = p.NewContext(r.rctx).(*Context)
	r.ac = arch.New(arch.Host)
	t.Cleanup(func() {
		r.ctx.Release()
		as.Release()
	})
	return r
}

// newRigIn returns a rig that shares the memory file and the address space of
// r but has its own context and register state.
func (r *rig) newThread() *rig {
	t := &rig{t: r.t, p: r.p, mf: r.mf, as: r.as, mm: r.mm, rctx: r.rctx}
	t.ctx = r.p.NewContext(r.rctx).(*Context)
	t.ac = arch.New(arch.Host)
	r.t.Cleanup(t.ctx.Release)
	return t
}

// mapPage allocates one frame, fills it with code or data and maps it at va.
// It returns the Sentry view of the frame.
func (r *rig) mapPage(va uint64, at hostarch.AccessType, content ...[]byte) []byte {
	r.t.Helper()
	fr, err := r.mf.Allocate(blockSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		r.t.Fatalf("Allocate: %v", err)
	}
	bs, err := r.mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		r.t.Fatalf("MapInternal: %v", err)
	}
	mem := bs.Head().ToSlice()
	off := 0
	for _, c := range content {
		off += copy(mem[off:], c)
	}
	if err := r.as.MapFile(hostarch.Addr(va), r.mf, fr, at, false); err != nil {
		r.t.Fatalf("MapFile %#x: %v", va, err)
	}
	return mem
}

func load64(b []byte) uint64     { return binary.LittleEndian.Uint64(b) }
func store64(b []byte, v uint64) { binary.LittleEndian.PutUint64(b, v) }

var execAccess = hostarch.AccessType{Read: true, Execute: true}

// program maps the code and a stack, and points ac at the code.
func (r *rig) program(content ...[]byte) []byte {
	r.t.Helper()
	mem := r.mapPage(codeVA, execAccess, content...)
	r.mapPage(stackVA, hostarch.ReadWrite)
	r.ac.SetIP(codeVA)
	r.ac.SetStack(stackVA + blockSize - 0x100)
	return mem
}

func (r *rig) run() (*linux.SignalInfo, hostarch.AccessType, error) {
	return r.ctx.Switch(r.rctx, r.mm, r.ac, -1)
}

func describe(si *linux.SignalInfo) string {
	if si == nil {
		return "nil"
	}
	return fmt.Sprintf("signal %d code %d addr %#x", si.Signo, si.Code, si.Addr())
}

func mustSyscall(t testing.TB, si *linux.SignalInfo, err error, wantNo uint64, ac *arch.Context64) {
	t.Helper()
	if si != nil || err != nil {
		t.Fatalf("Switch = (%s, %v), want a system call", describe(si), err)
	}
	if got := regNr(ac); got != wantNo {
		t.Fatalf("system call number = %d, want %d", got, wantNo)
	}
}

func wantSignal(t testing.TB, si *linux.SignalInfo, err error, sig linux.Signal) {
	t.Helper()
	if !errors.Is(err, platform.ErrContextSignal) || si == nil || si.Signo != int32(sig) {
		t.Fatalf("Switch = (%s, %v), want signal %d", describe(si), err, sig)
	}
}

func TestSyscallRoundTrip(t *testing.T) {
	r := newRig(t, newPlatform(t))
	r.program(gSyscall(93, 42, 7), gSyscall(94, 1, 2, 3, 4, 5, 6))
	si, _, err := r.run()
	mustSyscall(t, si, err, 93, r.ac)
	if regArg(r.ac, 0) != 42 || regArg(r.ac, 1) != 7 {
		t.Errorf("arguments = %d, %d, want 42, 7", regArg(r.ac, 0), regArg(r.ac, 1))
	}
	if got, want := regPC(r.ac), uint64(codeVA+len(gSyscall(93, 42, 7))); got != want {
		t.Errorf("pc after the first system call = %#x, want %#x", got, want)
	}
	setRet(r.ac, 1000)
	si, _, err = r.run()
	mustSyscall(t, si, err, 94, r.ac)
	for i := 0; i < 6; i++ {
		if got := regArg(r.ac, i); got != uint64(i+1) {
			t.Errorf("argument %d = %d, want %d", i, got, i+1)
		}
	}
	if got := r.as.PatchedBlocks(); got != 1 {
		t.Errorf("patched blocks = %d, want 1", got)
	}
}

func TestNativeArithmetic(t *testing.T) {
	r := newRig(t, newPlatform(t))
	// The guest runs 300000 add instructions on the host CPU before it reports
	// the sum.
	r.program(gLoop(100000), gSyscall(93))
	si, _, err := r.run()
	mustSyscall(t, si, err, 93, r.ac)
	if got := regAcc(r.ac); got != 300000 {
		t.Errorf("sum = %d, want 300000", got)
	}
}

func TestSentryChangesAreVisible(t *testing.T) {
	r := newRig(t, newPlatform(t))
	r.program(gSyscall(1), gStoreTo(dataVA, 0x1122334455667788), gSyscall(2))
	data := r.mapPage(dataVA, hostarch.ReadWrite)
	si, _, err := r.run()
	mustSyscall(t, si, err, 1, r.ac)
	si, _, err = r.run()
	mustSyscall(t, si, err, 2, r.ac)
	if got := load64(data); got != 0x1122334455667788 {
		t.Errorf("the guest wrote %#x, want 0x1122334455667788", got)
	}
}

func TestFaultsBecomeSegv(t *testing.T) {
	cases := []struct {
		name string
		prog [][]byte
		at   hostarch.AccessType
		addr uint64
		code int32
	}{
		{"read of an unmapped address", [][]byte{gLoadFrom(0x7000_0123_0000)}, hostarch.Read, 0x7000_0123_0000, segvMapErr},
		{"write to a read-only page", [][]byte{gStoreTo(dataVA, 1)}, hostarch.Write, dataVA, segvAccErr},
		{"jump to a data page", [][]byte{gJump(dataVA)}, hostarch.Execute, dataVA, segvAccErr},
		{"jump to an unmapped address", [][]byte{gJump(0x7000_0456_0000)}, hostarch.Execute, 0x7000_0456_0000, segvMapErr},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, newPlatform(t))
			r.program(c.prog...)
			r.mapPage(dataVA, hostarch.Read)
			si, at, err := r.run()
			wantSignal(t, si, err, linux.SIGSEGV)
			if si.Code != c.code || si.Addr() != c.addr || at != c.at {
				t.Errorf("fault = code %d addr %#x access %v, want code %d addr %#x access %v", si.Code, si.Addr(), at, c.code, c.addr, c.at)
			}
		})
	}
}

func TestFaultThenMapRetries(t *testing.T) {
	r := newRig(t, newPlatform(t))
	r.program(gLoadFrom(dataVA), gSyscall(93))
	si, at, err := r.run()
	wantSignal(t, si, err, linux.SIGSEGV)
	if at != hostarch.Read || si.Addr() != dataVA {
		t.Fatalf("fault = access %v addr %#x, want a read at %#x", at, si.Addr(), uint64(dataVA))
	}
	data := r.mapPage(dataVA, hostarch.Read)
	store64(data, 0xfeedface)
	si, _, err = r.run()
	mustSyscall(t, si, err, 93, r.ac)
	if got := regAcc(r.ac); got != 0xfeedface {
		t.Errorf("the retried load returned %#x, want 0xfeedface", got)
	}
}

func TestExecuteAfterWrite(t *testing.T) {
	// A writable and executable page: the guest writes a system call into it and
	// jumps there. The engine must patch the new code before it runs.
	r := newRig(t, newPlatform(t))
	target := uint64(dataVA)
	code := gSyscall(77)
	var prog []byte
	for i := 0; i < len(code); i += 8 {
		var chunk [8]byte
		copy(chunk[:], code[i:])
		prog = append(prog, gStoreTo(target+uint64(i), load64(chunk[:]))...)
	}
	prog = append(prog, gJump(target)...)
	r.program(prog)
	r.mapPage(dataVA, hostarch.AccessType{Read: true, Write: true, Execute: true})
	si, _, err := r.run()
	mustSyscall(t, si, err, 77, r.ac)
}

func TestWritableExecutableBlockRepatches(t *testing.T) {
	// The page at dataVA allows write and execute. The guest runs a system call
	// there. A routine in the code page then overwrites that system call and
	// jumps back. The write must succeed and the new code must run patched.
	r := newRig(t, newPlatform(t))
	newCode := gSyscall(12)
	var rewrite []byte
	for i := 0; i < len(newCode); i += 8 {
		var chunk [8]byte
		copy(chunk[:], newCode[i:])
		rewrite = append(rewrite, gStoreTo(dataVA+uint64(i), load64(chunk[:]))...)
	}
	rewrite = append(rewrite, gJump(dataVA)...)
	page := r.program(gJump(dataVA))
	copy(page[0x800:], rewrite)
	r.mapPage(dataVA, hostarch.AccessType{Read: true, Write: true, Execute: true}, gSyscall(11))
	si, _, err := r.run()
	mustSyscall(t, si, err, 11, r.ac)
	r.ac.SetIP(codeVA + 0x800)
	si, _, err = r.run()
	mustSyscall(t, si, err, 12, r.ac)
	if got := r.as.PatchedBlocks(); got < 3 {
		t.Errorf("patched blocks = %d, want at least 3 (code page, data page, data page after the write)", got)
	}
}

func TestSelfWritingPageFaults(t *testing.T) {
	// A guest that writes to the page it executes would make the engine swap
	// the write permission and the execute permission forever. The engine
	// reports SIGSEGV instead.
	r := newRig(t, newPlatform(t))
	r.mapPage(codeVA, hostarch.AccessType{Read: true, Write: true, Execute: true}, gStoreTo(codeVA+0x400, 1))
	r.mapPage(stackVA, hostarch.ReadWrite)
	r.ac.SetIP(codeVA)
	r.ac.SetStack(stackVA + blockSize - 0x100)
	si, at, err := r.run()
	wantSignal(t, si, err, linux.SIGSEGV)
	if at != hostarch.Write {
		t.Errorf("access = %v, want a write", at)
	}
}

func TestRegisterPreservation(t *testing.T) {
	// The vector registers live in the thread, and the Sentry reads and writes
	// them through the CONTEXT record at every stop.
	r := newRig(t, newPlatform(t))
	r.program(gSyscall(1), gSetVector(0xabcdef0123456789), gSyscall(2), gVectorToReg(), gSyscall(3))
	si, _, err := r.run()
	mustSyscall(t, si, err, 1, r.ac)
	si, _, err = r.run()
	mustSyscall(t, si, err, 2, r.ac)
	si, _, err = r.run()
	mustSyscall(t, si, err, 3, r.ac)
	if got := regAcc(r.ac); got != 0xabcdef0123456789 {
		t.Errorf("the vector register held %#x across the system call, want 0xabcdef0123456789", got)
	}
}

func TestVectorStateReachesTheSentryAndBack(t *testing.T) {
	// The Sentry copies the vector registers only when it asks for them. A
	// change that the Sentry makes must reach the guest at the next start.
	r := newRig(t, newPlatform(t))
	r.program(gSetVector(0x1111), gSyscall(1), gVectorToReg(), gSyscall(2))
	si, _, err := r.run()
	mustSyscall(t, si, err, 1, r.ac)
	if err := r.ctx.PullFullState(r.as, r.ac); err != nil {
		t.Fatalf("PullFullState: %v", err)
	}
	if got := vectorLow(r.ac); got != 0x1111 {
		t.Errorf("the Sentry read vector low %#x, want 0x1111", got)
	}
	setVectorLow(r.ac, 0x2222)
	r.ctx.FullStateChanged()
	si, _, err = r.run()
	mustSyscall(t, si, err, 2, r.ac)
	if got := regAcc(r.ac); got != 0x2222 {
		t.Errorf("the guest read vector low %#x, want 0x2222 from the Sentry", got)
	}
}

func TestThreadsShareAddressSpace(t *testing.T) {
	r := newRig(t, newPlatform(t))
	r.program(gSyscall(5))
	t2 := r.newThread()
	t2.ac.SetIP(codeVA)
	t2.ac.SetStack(stackVA + blockSize/2)
	si, _, err := r.run()
	mustSyscall(t, si, err, 5, r.ac)
	si, _, err = t2.run()
	mustSyscall(t, si, err, 5, t2.ac)
	if r.as.PatchedBlocks() != 1 {
		t.Errorf("patched blocks = %d, want 1", r.as.PatchedBlocks())
	}
}

func TestInterruptStopsRunningGuest(t *testing.T) {
	r := newRig(t, newPlatform(t))
	r.program(gCountSpin())
	type result struct {
		si  *linux.SignalInfo
		err error
	}
	done := make(chan result, 1)
	go func() {
		si, _, err := r.run()
		done <- result{si, err}
	}()
	time.Sleep(200 * time.Millisecond)
	r.ctx.Interrupt()
	select {
	case res := <-done:
		if !errors.Is(res.err, platform.ErrContextInterrupt) || res.si != nil {
			t.Fatalf("Switch = (%s, %v), want an interrupt", describe(res.si), res.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("an interrupt did not stop a spinning guest")
	}
	first := regAcc(r.ac)
	if first == 0 {
		t.Errorf("the guest counted nothing before the interrupt")
	}
	// The thread resumes from the captured state.
	go func() {
		si, _, err := r.run()
		done <- result{si, err}
	}()
	time.Sleep(100 * time.Millisecond)
	r.ctx.Interrupt()
	res := <-done
	if !errors.Is(res.err, platform.ErrContextInterrupt) {
		t.Fatalf("second Switch = (%s, %v), want an interrupt", describe(res.si), res.err)
	}
	if got := regAcc(r.ac); got <= first {
		t.Errorf("the counter did not advance after the resume: %d then %d", first, got)
	}
}

func TestInterruptBeforeSwitch(t *testing.T) {
	r := newRig(t, newPlatform(t))
	r.program(gSyscall(3))
	r.ctx.Interrupt()
	si, _, err := r.run()
	if si != nil || !errors.Is(err, platform.ErrContextInterrupt) {
		t.Fatalf("Switch = (%s, %v), want ErrContextInterrupt", describe(si), err)
	}
	si, _, err = r.run()
	mustSyscall(t, si, err, 3, r.ac)
}

func TestTraceBreakIsSigtrap(t *testing.T) {
	r := newRig(t, newPlatform(t))
	r.program(gTraceBreak())
	si, _, err := r.run()
	wantSignal(t, si, err, linux.SIGTRAP)
}

func TestIllegalInstructionIsSigill(t *testing.T) {
	r := newRig(t, newPlatform(t))
	r.program(gIllegal())
	si, _, err := r.run()
	wantSignal(t, si, err, linux.SIGILL)
}

func TestDivideByZeroIsSigfpe(t *testing.T) {
	code := gDivZero()
	if code == nil {
		t.Skip("integer division by zero raises no exception on this architecture")
	}
	r := newRig(t, newPlatform(t))
	r.program(code)
	si, _, err := r.run()
	wantSignal(t, si, err, linux.SIGFPE)
	if si.Code != fpeIntDiv {
		t.Errorf("code = %d, want FPE_INTDIV", si.Code)
	}
}

func TestThreadPointerSurvivesSystemCalls(t *testing.T) {
	r := newRig(t, newPlatform(t))
	if guestHasFSBase {
		// The thread pointer word lives at fs:[0], so the guest reads it through
		// the segment base. Windows resets the base when it switches the thread
		// out, and the engine loads it again at every start.
		r.program(gSyscall(1), gReadThreadPointer(), gSyscall(2), gReadThreadPointer(), gSyscall(3))
		page := r.mapPage(dataVA, hostarch.ReadWrite)
		store64(page, 0x1111)
		setTLSBase(r.ac, dataVA)
		si, _, err := r.run()
		mustSyscall(t, si, err, 1, r.ac)
		si, _, err = r.run()
		mustSyscall(t, si, err, 2, r.ac)
		if got := regAcc(r.ac); got != 0x1111 {
			t.Errorf("fs:[0] = %#x, want 0x1111", got)
		}
		store64(page, 0x2222)
		si, _, err = r.run()
		mustSyscall(t, si, err, 3, r.ac)
		if got := regAcc(r.ac); got != 0x2222 {
			t.Errorf("fs:[0] after a second stop = %#x, want 0x2222", got)
		}
		return
	}
	const tls = 0x5555_2000_0000
	r.program(gSyscall(1), gReadThreadPointer(), gSyscall(2))
	setTLSBase(r.ac, tls)
	si, _, err := r.run()
	mustSyscall(t, si, err, 1, r.ac)
	si, _, err = r.run()
	mustSyscall(t, si, err, 2, r.ac)
	if got := regAcc(r.ac); got != tls {
		t.Errorf("the guest read thread pointer %#x, want %#x", got, uint64(tls))
	}
}

func TestManySystemCalls(t *testing.T) {
	r := newRig(t, newPlatform(t))
	var prog []byte
	const n = 150
	for i := 0; i < n; i++ {
		prog = append(prog, gSyscall(uint64(100+i%50), uint64(i))...)
	}
	// 150 system calls of up to 32 bytes each fit one page.
	if len(prog) > blockSize {
		t.Fatalf("program of %d bytes does not fit one page", len(prog))
	}
	r.program(prog)
	start := time.Now()
	for i := 0; i < n; i++ {
		si, _, err := r.run()
		mustSyscall(t, si, err, uint64(100+i%50), r.ac)
		if got := regArg(r.ac, 0); got != uint64(i) {
			t.Fatalf("call %d: argument = %d", i, got)
		}
	}
	t.Logf("%d system calls took %v (%v each)", n, time.Since(start), time.Since(start)/n)
}

func TestAddressSpacesAreIndependent(t *testing.T) {
	p := newPlatform(t)
	mf, err := pgalloc.NewDefaultMemoryFile(pgalloc.MemoryFileOpts{})
	if err != nil {
		t.Fatalf("NewDefaultMemoryFile: %v", err)
	}
	t.Cleanup(mf.Destroy)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := newRigOn(t, p, mf)
			r.program(gSyscall(uint64(200+i), uint64(i)))
			si, _, err := r.run()
			if si != nil || err != nil || regNr(r.ac) != uint64(200+i) {
				t.Errorf("address space %d: Switch = (%s, %v), number %d", i, describe(si), err, regNr(r.ac))
			}
		}(i)
	}
	wg.Wait()
}

func TestUnmapRemovesAccess(t *testing.T) {
	r := newRig(t, newPlatform(t))
	r.program(gLoadFrom(dataVA), gSyscall(1), gLoadFrom(dataVA), gSyscall(2))
	data := r.mapPage(dataVA, hostarch.Read)
	store64(data, 5)
	si, _, err := r.run()
	mustSyscall(t, si, err, 1, r.ac)
	r.as.Unmap(dataVA, blockSize)
	si, _, err = r.run()
	wantSignal(t, si, err, linux.SIGSEGV)
}

func TestParkedThreadDoesNotFreezeTheProcess(t *testing.T) {
	// Thread A stops at a system call and waits in the Sentry. Thread B of the
	// same stub process must keep running meanwhile.
	r := newRig(t, newPlatform(t))
	r.program(gSyscall(1))
	b := r.newThread()
	b.ac.SetStack(stackVA + blockSize/2)
	r.mapPage(dataVA, execAccess, gLoop(2_000_000), gSyscall(9))
	b.ac.SetIP(dataVA)
	si, _, err := r.run()
	mustSyscall(t, si, err, 1, r.ac)
	done := make(chan struct{})
	go func() {
		defer close(done)
		si, _, err := b.run()
		if si != nil || err != nil || regNr(b.ac) != 9 {
			t.Errorf("thread B: Switch = (%s, %v), number %d", describe(si), err, regNr(b.ac))
			return
		}
		if got := regAcc(b.ac); got != 6_000_000 {
			t.Errorf("sum = %d, want 6000000", got)
		}
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("thread B did not finish while thread A waited in the Sentry")
	}
}

func TestConcurrentThreads(t *testing.T) {
	r := newRig(t, newPlatform(t))
	var prog []byte
	const calls = 60
	for i := 0; i < calls; i++ {
		prog = append(prog, gSyscall(uint64(300+i))...)
	}
	r.program(prog)
	var wg sync.WaitGroup
	for k := 0; k < 4; k++ {
		th := r
		if k > 0 {
			th = r.newThread()
			th.ac.SetIP(codeVA)
			th.ac.SetStack(uintptr(stackVA + blockSize/2 + k*0x100))
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < calls; i++ {
				si, _, err := th.run()
				if si != nil || err != nil || regNr(th.ac) != uint64(300+i) {
					t.Errorf("call %d: Switch = (%s, %v), number %d", i, describe(si), err, regNr(th.ac))
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestForkStorm(t *testing.T) {
	// Many processes start and exit at once. Some tasks release the address
	// space first and the context second, the way the Sentry does when a
	// process exits while a thread still holds its context.
	p := newPlatform(t)
	// One memory file serves every task. A memory file takes a gigabyte of
	// address space and disk space, and the hosted runners have little disk.
	mf, err := pgalloc.NewDefaultMemoryFile(pgalloc.MemoryFileOpts{})
	if err != nil {
		t.Fatalf("NewDefaultMemoryFile: %v", err)
	}
	t.Cleanup(mf.Destroy)
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for round := 0; round < 4; round++ {
				r := newRigOn(t, p, mf)
				r.program(gSyscall(uint64(400 + i)))
				si, _, err := r.run()
				if si != nil || err != nil || regNr(r.ac) != uint64(400+i) {
					t.Errorf("task %d round %d: Switch = (%s, %v), number %d", i, round, describe(si), err, regNr(r.ac))
					return
				}
				if i%2 == 0 {
					r.as.Release()
					r.ctx.Release()
				} else {
					r.ctx.Release()
					r.as.Release()
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestAddressSpaceChurn(t *testing.T) {
	p := newPlatform(t)
	for i := 0; i < 25; i++ {
		asI, err := p.NewAddressSpace(platform.AddressSpaceOptions{})
		if err != nil {
			t.Fatalf("NewAddressSpace %d: %v", i, err)
		}
		pid := asI.(*addressSpace).sp.pid
		asI.Release()
		if alive(pid) {
			t.Fatalf("stub %d (pid %d) is still alive after Release", i, pid)
		}
	}
}

func TestCloseTerminatesStubs(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatal(err)
	}
	asI, err := p.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pid := asI.(*addressSpace).sp.pid
	if !alive(pid) {
		t.Fatalf("stub %d is not alive before Close", pid)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for alive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("stub %d is still alive after Close", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitPool waits until the pool of p holds poolDepth stubs and returns their
// process IDs.
func waitPool(t *testing.T, p *Platform) []uint32 {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for len(p.pool.ready) < poolDepth {
		if time.Now().After(deadline) {
			t.Fatalf("the pool holds %d stubs after 30 s, want %d", len(p.pool.ready), poolDepth)
		}
		time.Sleep(20 * time.Millisecond)
	}
	p.dbg.mu.Lock()
	defer p.dbg.mu.Unlock()
	var pids []uint32
	for pid := range p.dbg.procs {
		pids = append(pids, pid)
	}
	return pids
}

func TestPooledStubServesNewAddressSpace(t *testing.T) {
	p := newPlatform(t)
	pooled := waitPool(t, p)
	asI, err := p.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	as := asI.(*addressSpace)
	t.Cleanup(as.Release)
	for _, pid := range pooled {
		if pid == as.sp.pid {
			return
		}
	}
	t.Errorf("the address space runs in stub %d, which is not one of the pooled stubs %v", as.sp.pid, pooled)
}

func TestCloseTerminatesPooledStubs(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatal(err)
	}
	pooled := waitPool(t, p)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for _, pid := range pooled {
		for alive(pid) {
			if time.Now().After(deadline) {
				t.Fatalf("pooled stub %d is still alive after Close", pid)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

// alive reports whether the process exists and has not exited.
func alive(pid uint32) bool {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	ev, _ := windows.WaitForSingleObject(h, 0)
	return ev == uint32(windows.WAIT_TIMEOUT)
}

func TestProbe(t *testing.T) {
	info, err := Probe()
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	t.Logf("probe: arch %s, round trip %v, guest range [%#x, %#x)", info.Arch, info.RoundTrip, info.UserMin, info.UserMax)
	if info.RoundTrip <= 0 {
		t.Errorf("round trip = %v", info.RoundTrip)
	}
}

func TestStubsAreConfined(t *testing.T) {
	p := newPlatform(t)
	asI, err := p.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer asI.Release()
	if c := p.Confinement(); c == "none" {
		t.Errorf("the host applied no confinement")
	} else {
		t.Logf("confinement: %s", c)
	}
}

func TestMain(m *testing.M) {
	// The stub host is a copy of this test binary. Its init function runs the
	// host loop before TestMain, so a plain run reaches this point.
	cpuid.Initialize()
	os.Exit(m.Run())
}
