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

//go:build darwin && arm64

package hvf

import (
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/usermem"
)

// Guest instruction encodings used by the tests.
const (
	insnSVC0     uint32 = 0xd4000001
	insnBRK0     uint32 = 0xd4200000
	insnUDF0     uint32 = 0x00000000
	insnBSelf    uint32 = 0x14000000 // B . (branch to itself).
	insnAddX2    uint32 = 0x8b010022 // ADD X2, X1, X1.
	insnOrrV1V0  uint32 = 0x4ea01c01 // MOV V1.16B, V0.16B.
	insnStrX1X2  uint32 = 0xf9000041 // STR X1, [X2].
	insnLdrX1X0  uint32 = 0xf9400001 // LDR X1, [X0].
	insnLdrX0SP  uint32 = 0xf94003e0 // LDR X0, [SP].
	insnMrsMIDR  uint32 = 0xd5380000 // MRS X0, MIDR_EL1.
	insnMrsPFR0  uint32 = 0xd5380400 // MRS X0, ID_AA64PFR0_EL1.
	insnMrsCTR   uint32 = 0xd53b0020 // MRS X0, CTR_EL0.
	insnMrsDCZID uint32 = 0xd53b00e0 // MRS X0, DCZID_EL0.
	insnMrsCNTVC uint32 = 0xd53be040 // MRS X0, CNTVCT_EL0.
	insnMrsCNTPC uint32 = 0xd53be020 // MRS X0, CNTPCT_EL0.
	insnMrsTPRO  uint32 = 0xd53bd060 // MRS X0, TPIDRRO_EL0.
	insnMrsPMCR  uint32 = 0xd53b9c00 // MRS X0, PMCR_EL0.
	insnMsrMIDR  uint32 = 0xd5180000 // MSR MIDR_EL1, X0 (a write).
	insnAddX1One uint32 = 0x91000421 // ADD X1, X1, #1.
)

func movz(rd, imm uint32) uint32 { return 0xd2800000 | imm<<5 | rd }

type stubMemoryManager struct {
	usermem.IO
	as platform.AddressSpace
}

func (s *stubMemoryManager) MMap(context.Context, memmap.MMapOpts) (hostarch.Addr, error) {
	return 0, nil
}

func (s *stubMemoryManager) AddressSpace() platform.AddressSpace { return s.as }

func (s *stubMemoryManager) FindVMAByName(hostarch.AddrRange, string) (hostarch.Addr, uint64, error) {
	return 0, 0, nil
}

func newTestPlatform(t testing.TB) *Platform {
	t.Helper()
	p, err := New()
	if err != nil {
		if os.Getenv(allowNoHypervisorEnv) == "1" {
			t.Skipf("no hypervisor on this host (%s=1): %v", allowNoHypervisorEnv, err)
		}
		t.Fatalf("New failed: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	})
	return p
}

// limitWorkers lowers the vCPU limit of a Platform that has not started a worker.
func limitWorkers(t testing.TB, p *Platform, n int) {
	t.Helper()
	pool := &p.vm.pool
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.started != 0 || n > len(pool.freeSlots) {
		t.Fatalf("limitWorkers(%d): started=%d free=%d", n, pool.started, len(pool.freeSlots))
	}
	pool.freeSlots = pool.freeSlots[len(pool.freeSlots)-n:]
	pool.limit = n
}

// mapHostBytes maps host memory at addr through MapFile. Each call uses a new
// memmap.File, so the registry treats the memory as a new owner.
func mapHostBytes(t testing.TB, as *AddressSpace, addr hostarch.Addr, mem []byte, at hostarch.AccessType) {
	t.Helper()
	if err := as.MapFile(addr, &testFile{mem: mem}, memmap.FileRange{Start: 0, End: uint64(len(mem))}, at, false); err != nil {
		t.Fatalf("MapFile at %#x: %v", uint64(addr), err)
	}
}

// guest is one address space with a code page and a data page.
type guest struct {
	t     testing.TB
	plat  *Platform
	as    *AddressSpace
	mm    *stubMemoryManager
	arena []byte
	file  *testFile // Backs arena. The code page and the data page share its region.
	code  []byte
	data  []byte
	ctx   *Context
	ac    *arch.Context64
}

const (
	guestCodeAddr = hostarch.Addr(0x400000)
	guestDataAddr = hostarch.Addr(0x401000)
)

func newGuest(t testing.TB, plat *Platform, program ...uint32) *guest {
	t.Helper()
	asIface, err := plat.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		t.Fatalf("NewAddressSpace failed: %v", err)
	}
	as := asIface.(*AddressSpace)
	arena, err := memutil.AllocateAnonymousArena(hostPageSize)
	if err != nil {
		t.Fatalf("AllocateAnonymousArena failed: %v", err)
	}
	g := &guest{
		t: t, plat: plat, as: as, mm: &stubMemoryManager{as: as}, arena: arena, file: &testFile{mem: arena},
		code: arena[:pageSize4K], data: arena[pageSize4K : 2*pageSize4K],
	}
	t.Cleanup(func() {
		as.Release()
		if err := memutil.UnmapView(arena); err != nil {
			t.Errorf("UnmapView failed: %v", err)
		}
	})
	for _, m := range []struct {
		va hostarch.Addr
		fr memmap.FileRange
		at hostarch.AccessType
	}{
		{guestCodeAddr, memmap.FileRange{Start: 0, End: pageSize4K}, hostarch.AccessType{Read: true, Execute: true}},
		{guestDataAddr, memmap.FileRange{Start: pageSize4K, End: 2 * pageSize4K}, hostarch.ReadWrite},
	} {
		if err := as.MapFile(m.va, g.file, m.fr, m.at, false); err != nil {
			t.Fatalf("MapFile at %#x: %v", uint64(m.va), err)
		}
	}
	g.setProgram(program...)
	g.ctx = plat.NewContext(context.Background()).(*Context)
	g.ac = arch.New(arch.Host)
	g.ac.SetIP(uintptr(guestCodeAddr))
	g.ac.SetStack(uintptr(guestDataAddr) + 0x800)
	return g
}

func (g *guest) setProgram(program ...uint32) {
	clear(g.code)
	for i, insn := range program {
		binary.LittleEndian.PutUint32(g.code[i*4:], insn)
	}
}

func (g *guest) switchOnce() (*linux.SignalInfo, hostarch.AccessType, error) {
	return g.ctx.Switch(context.Background(), g.mm, g.ac, 0)
}

func (g *guest) regs() *arch.Registers { return &g.ac.StateData().Regs }

// read64 runs LDR X1,[X0] then SVC #0 at the code page and returns the value
// that the guest loaded from va. The guest program must start with those two
// instructions. The call returns the signal that a failed load raises.
func (g *guest) read64(va hostarch.Addr) (uint64, *linux.SignalInfo, error) {
	g.ac.SetIP(uintptr(guestCodeAddr))
	g.regs().Regs[0] = uint64(va)
	g.regs().Regs[1] = 0
	sig, _, err := g.switchOnce()
	return g.regs().Regs[1], sig, err
}

func TestSyscallRoundTripPreservesRegisters(t *testing.T) {
	plat := newTestPlatform(t)
	// X2 = X1 + X1, then a syscall with number 93 and first argument 42.
	g := newGuest(t, plat, insnAddX2, movz(0, 42), movz(8, 93), insnSVC0)
	r := g.regs()
	for i := range r.Regs {
		r.Regs[i] = 0x1000 + uint64(i)*0x11
	}
	want := r.Regs
	r.Pstate = 0xa0000000 // N and C set.
	r.TPIDR_EL0 = 0xfeedface0000
	tlsWant := r.TPIDR_EL0

	sig, _, err := g.switchOnce()
	if sig != nil || err != nil {
		t.Fatalf("Switch = (%v, %v), want a plain syscall return", sig, err)
	}
	if got := g.ac.SyscallNo(); got != 93 {
		t.Errorf("SyscallNo() = %d, want 93", got)
	}
	if got := g.ac.SyscallArgs()[0].Value; got != 42 {
		t.Errorf("syscall argument 0 = %d, want 42", got)
	}
	if got, want := g.ac.IP(), uintptr(guestCodeAddr)+16; got != want {
		t.Errorf("IP() = %#x, want %#x", got, want)
	}
	if got := r.Regs[2]; got != 2*want[1] {
		t.Errorf("X2 = %#x, want X1+X1 = %#x (the guest computed it)", got, 2*want[1])
	}
	for i := 3; i < 31; i++ {
		if i == 8 {
			continue
		}
		if r.Regs[i] != want[i] {
			t.Errorf("X%d = %#x, want %#x", i, r.Regs[i], want[i])
		}
	}
	if r.TPIDR_EL0 != tlsWant {
		t.Errorf("TPIDR_EL0 = %#x, want %#x", r.TPIDR_EL0, tlsWant)
	}
	if r.Pstate&0xf0000000 != 0xa0000000 {
		t.Errorf("PSTATE flags = %#x, want 0xa0000000", r.Pstate&0xf0000000)
	}
	if got := r.Sp; got != uint64(guestDataAddr)+0x800 {
		t.Errorf("SP = %#x, want %#x", got, uint64(guestDataAddr)+0x800)
	}
	if got := g.ac.StateData().OrigR0; got != 42 {
		t.Errorf("OrigR0 = %d, want 42", got)
	}
}

func TestGuestMemoryWriteIsVisibleToHost(t *testing.T) {
	plat := newTestPlatform(t)
	// STR X1,[X2] writes through the data page, then a syscall returns.
	g := newGuest(t, plat, insnStrX1X2, insnSVC0)
	r := g.regs()
	r.Regs[1] = 0x1122334455667788
	r.Regs[2] = uint64(guestDataAddr) + 0x10
	if sig, _, err := g.switchOnce(); sig != nil || err != nil {
		t.Fatalf("Switch = (%v, %v)", sig, err)
	}
	if got := binary.LittleEndian.Uint64(g.data[0x10:]); got != 0x1122334455667788 {
		t.Fatalf("data page = %#x, want the value the guest stored", got)
	}
}

// The Sentry reads and writes guest memory through the host mapping of the
// memory, not through the address space. The guest must see each host write.
func TestHostWriteIsVisibleToGuest(t *testing.T) {
	plat := newTestPlatform(t)
	if plat.SupportsAddressSpaceIO() {
		t.Fatal("SupportsAddressSpaceIO() = true, want false: the Sentry uses the memory file mappings")
	}
	g := newGuest(t, plat, insnLdrX1X0, insnSVC0)
	for i, want := range []uint64{0x1111, 0x2222_3333, 0x4444_5555_6666} {
		binary.LittleEndian.PutUint64(g.data[0x20:], want)
		g.ac.SetIP(uintptr(guestCodeAddr))
		g.regs().Regs[0] = uint64(guestDataAddr) + 0x20
		g.regs().Regs[1] = 0
		if sig, _, err := g.switchOnce(); sig != nil || err != nil {
			t.Fatalf("round %d: Switch = (%v, %v)", i, sig, err)
		}
		if got := g.regs().Regs[1]; got != want {
			t.Fatalf("round %d: the guest read %#x, want the host write %#x", i, got, want)
		}
	}
}

func TestVectorRegistersSurviveSyscallsAndOtherContexts(t *testing.T) {
	plat := newTestPlatform(t)
	// Only one vCPU exists, so both Contexts run on the same hardware state.
	limitWorkers(t, plat, 1)
	a := newGuest(t, plat, insnOrrV1V0, insnSVC0, insnSVC0)
	b := newGuest(t, plat, insnOrrV1V0, insnSVC0)

	fill := func(ac *arch.Context64, seed byte) {
		fp := *ac.FloatingPointData()
		for i := range 32 * 16 {
			fp[i] = seed + byte(i)
		}
		binary.LittleEndian.PutUint32(fp[512:], 0x00000011) // FPSR.
		binary.LittleEndian.PutUint32(fp[516:], 0x03000000) // FPCR: FZ and DN.
	}
	fill(a.ac, 0x10)
	fill(b.ac, 0xa0)
	aWant := append([]byte(nil), *a.ac.FloatingPointData()...)

	if sig, _, err := a.switchOnce(); sig != nil || err != nil {
		t.Fatalf("a.Switch = (%v, %v)", sig, err)
	}
	if sig, _, err := b.switchOnce(); sig != nil || err != nil {
		t.Fatalf("b.Switch = (%v, %v)", sig, err)
	}
	if sig, _, err := a.switchOnce(); sig != nil || err != nil {
		t.Fatalf("a.Switch (second) = (%v, %v)", sig, err)
	}
	got := *a.ac.FloatingPointData()
	// The guest copied V0 into V1: bytes 16..31 now equal bytes 0..15.
	copy(aWant[16:32], aWant[0:16])
	for i := range aWant {
		if got[i] != aWant[i] {
			t.Fatalf("Context a FP state differs at byte %d: got %#x want %#x", i, got[i], aWant[i])
		}
	}
	bGot := *b.ac.FloatingPointData()
	for i := range 16 {
		if bGot[16+i] != bGot[i] {
			t.Fatalf("Context b V1 byte %d = %#x, want V0 byte %#x", i, bGot[16+i], bGot[i])
		}
	}
	if bGot[0] != 0xa0 {
		t.Fatalf("Context b V0 = %#x, want 0xa0: a's registers leaked in", bGot[0])
	}
}

func TestInterruptBeforeSwitchIsNotLost(t *testing.T) {
	plat := newTestPlatform(t)
	g := newGuest(t, plat, insnSVC0)
	g.ctx.Interrupt()
	if _, _, err := g.switchOnce(); !errors.Is(err, platform.ErrContextInterrupt) {
		t.Fatalf("Switch after Interrupt = %v, want ErrContextInterrupt", err)
	}
	// The flag is consumed once: the next Switch runs the guest.
	if sig, _, err := g.switchOnce(); sig != nil || err != nil {
		t.Fatalf("Switch after the interrupt was consumed = (%v, %v), want a syscall", sig, err)
	}
}

func TestStaleCancellationDoesNotInterruptALaterContext(t *testing.T) {
	plat := newTestPlatform(t)
	limitWorkers(t, plat, 1)
	a := newGuest(t, plat, insnSVC0)
	if sig, _, err := a.switchOnce(); sig != nil || err != nil {
		t.Fatalf("warm-up Switch = (%v, %v)", sig, err)
	}
	// Cancel the idle vCPU: hv_vcpu_run returns at once on the next entry.
	plat.vm.pool.slots[0].Load().cancel()
	b := newGuest(t, plat, insnSVC0)
	sig, _, err := b.switchOnce()
	if sig != nil || err != nil {
		t.Fatalf("Switch of another Context = (%v, %v), want a syscall: a stale cancellation leaked", sig, err)
	}
}

// waitInGuest returns when the vCPU that runs c has entered the guest.
func waitInGuest(t testing.TB, c *Context) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		c.hw.mu.Lock()
		w := c.hw.worker
		c.hw.mu.Unlock()
		if w != nil && w.inGuest.Load() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the vCPU never entered the guest")
		}
		runtime.Gosched()
	}
}

type switchResult struct {
	sig *linux.SignalInfo
	at  hostarch.AccessType
	err error
}

func (g *guest) switchAsync() <-chan switchResult {
	ch := make(chan switchResult, 1)
	go func() {
		sig, at, err := g.switchOnce()
		ch <- switchResult{sig, at, err}
	}()
	return ch
}

func receive(t testing.TB, ch <-chan switchResult) switchResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(30 * time.Second):
		t.Fatal("Switch did not return")
		return switchResult{}
	}
}

func TestInterruptInGuestCapturesFullState(t *testing.T) {
	plat := newTestPlatform(t)
	g := newGuest(t, plat, insnBSelf)
	r := g.regs()
	for i := range r.Regs {
		r.Regs[i] = 0xabc000 + uint64(i)*0x101
	}
	wantRegs := r.Regs
	r.Pstate = 0x60000000
	r.TPIDR_EL0 = 0x1234500
	fp := *g.ac.FloatingPointData()
	for i := range 512 {
		fp[i] = byte(i*7 + 3)
	}
	binary.LittleEndian.PutUint32(fp[512:], 0x1f) // FPSR cumulative flags.
	binary.LittleEndian.PutUint32(fp[516:], 0x00400000)
	wantFP := append([]byte(nil), fp...)

	for i := range 50 {
		res := g.switchAsync()
		waitInGuest(t, g.ctx)
		g.ctx.Interrupt()
		got := receive(t, res)
		if !errors.Is(got.err, platform.ErrContextInterrupt) {
			t.Fatalf("iteration %d: Switch = (%v, %v), want ErrContextInterrupt", i, got.sig, got.err)
		}
		if r.Regs != wantRegs {
			t.Fatalf("iteration %d: general registers changed: got %x want %x", i, r.Regs, wantRegs)
		}
		if g.ac.IP() != uintptr(guestCodeAddr) {
			t.Fatalf("iteration %d: IP = %#x, want the loop at %#x", i, g.ac.IP(), guestCodeAddr)
		}
		if r.Sp != uint64(guestDataAddr)+0x800 || r.TPIDR_EL0 != 0x1234500 || r.Pstate&0xf0000000 != 0x60000000 {
			t.Fatalf("iteration %d: SP=%#x TLS=%#x PSTATE=%#x changed", i, r.Sp, r.TPIDR_EL0, r.Pstate)
		}
		gotFP := *g.ac.FloatingPointData()
		for j := range wantFP[:520] {
			if gotFP[j] != wantFP[j] {
				t.Fatalf("iteration %d: FP state differs at byte %d: got %#x want %#x", i, j, gotFP[j], wantFP[j])
			}
		}
	}
}

func TestInterruptStormKeepsCountersConsistent(t *testing.T) {
	plat := newTestPlatform(t)
	// X1 counts loop iterations. Each interruption captures X1 from the
	// hardware: it can never go backwards.
	g := newGuest(t, plat, insnAddX1One, 0x17ffffff) // ADD X1,X1,#1; B .-4
	g.regs().Regs[1] = 0
	var prev uint64
	for i := range 200 {
		res := g.switchAsync()
		waitInGuest(t, g.ctx)
		g.ctx.Interrupt()
		got := receive(t, res)
		if !errors.Is(got.err, platform.ErrContextInterrupt) {
			t.Fatalf("iteration %d: Switch = (%v, %v)", i, got.sig, got.err)
		}
		cur := g.regs().Regs[1]
		if cur < prev {
			t.Fatalf("iteration %d: X1 went backwards: %d after %d", i, cur, prev)
		}
		prev = cur
	}
	if prev == 0 {
		t.Fatal("the guest never advanced the counter")
	}
}

// TestInterruptDuringSyscallExitIsNotReplayed interrupts a guest that makes
// system calls in a loop, then redirects it to a handler as signal delivery
// does. An interruption inside the EL1 stub must not leave the stub exit for a
// later entry to replay against the new state. A replayed exit skips the
// handler, so X2 keeps its old value.
func TestInterruptDuringSyscallExitIsNotReplayed(t *testing.T) {
	const handlerAddr = guestCodeAddr + 0x10
	plat := newTestPlatform(t)
	// The loop adds one to X1 and makes a system call. The handler sets X2 and
	// makes a system call.
	g := newGuest(t, plat,
		insnAddX1One, insnSVC0, 0x17fffffe, // ADD X1,X1,#1; SVC #0; B .-8
		0xd503201f,                         // NOP.
		movz(2, 0x77), insnSVC0, insnBSelf, // Handler: MOV X2,#0x77; SVC #0; B .
	)
	for i := range 300 {
		g.ac.SetIP(uintptr(guestCodeAddr))
		res := make(chan switchResult, 1)
		go func() {
			// Each system call of the loop returns to here. Only an interruption
			// or a signal ends the run.
			for {
				sig, at, err := g.switchOnce()
				if sig != nil || err != nil {
					res <- switchResult{sig, at, err}
					return
				}
			}
		}()
		waitInGuest(t, g.ctx)
		g.ctx.Interrupt()
		got := receive(t, res)
		if !errors.Is(got.err, platform.ErrContextInterrupt) {
			t.Fatalf("iteration %d: Switch = (%v, %v), want ErrContextInterrupt", i, got.sig, got.err)
		}
		g.regs().Regs[2] = 0
		g.ac.SetIP(uintptr(handlerAddr))
		if sig, _, err := g.switchOnce(); sig != nil || err != nil {
			t.Fatalf("iteration %d: Switch to the handler = (%v, %v), want a system call", i, sig, err)
		}
		if x2 := g.regs().Regs[2]; x2 != 0x77 {
			t.Fatalf("iteration %d: X2 = %#x, want 0x77: the handler did not run", i, x2)
		}
		if want := uintptr(handlerAddr) + 8; g.ac.IP() != want {
			t.Fatalf("iteration %d: IP = %#x, want %#x after the handler's system call", i, g.ac.IP(), want)
		}
	}
}

func TestFaultsReportSignalAndAccess(t *testing.T) {
	plat := newTestPlatform(t)
	cases := []struct {
		name    string
		program []uint32
		setup   func(g *guest)
		signo   linux.Signal
		code    int32
		addr    func(g *guest) uint64
		at      hostarch.AccessType
	}{
		{
			name: "execute unmapped", program: nil,
			setup: func(g *guest) { g.ac.SetIP(0xdead0000) },
			signo: linux.SIGSEGV, code: sigSegvMap, addr: func(*guest) uint64 { return 0xdead0000 },
			at: hostarch.Execute,
		},
		{
			name: "read unmapped", program: []uint32{insnLdrX1X0},
			setup: func(g *guest) { g.regs().Regs[0] = 0xbeef0000 },
			signo: linux.SIGSEGV, code: sigSegvMap, addr: func(*guest) uint64 { return 0xbeef0000 },
			at: hostarch.Read,
		},
		{
			name: "write read-only page", program: []uint32{insnStrX1X2},
			setup: func(g *guest) { g.regs().Regs[2] = uint64(guestCodeAddr) + 0x100 },
			signo: linux.SIGSEGV, code: sigSegvAcc, addr: func(*guest) uint64 { return uint64(guestCodeAddr) + 0x100 },
			at: hostarch.Write,
		},
		{
			name: "execute non-executable page", program: nil,
			setup: func(g *guest) { g.ac.SetIP(uintptr(guestDataAddr)) },
			signo: linux.SIGSEGV, code: sigSegvAcc, addr: func(*guest) uint64 { return uint64(guestDataAddr) },
			at: hostarch.Execute,
		},
		{
			name: "tagged pointer", program: []uint32{insnLdrX1X0},
			setup: func(g *guest) { g.regs().Regs[0] = 0x5a00_0000_beef_0000 },
			signo: linux.SIGSEGV, code: sigSegvMap, addr: func(*guest) uint64 { return 0xbeef0000 },
			at: hostarch.Read,
		},
		{
			name: "breakpoint", program: []uint32{insnBRK0},
			signo: linux.SIGTRAP, code: sigTrapBrkpt, addr: func(*guest) uint64 { return uint64(guestCodeAddr) },
		},
		{
			name: "undefined instruction", program: []uint32{insnUDF0},
			signo: linux.SIGILL, code: sigIllIllOpc, addr: func(*guest) uint64 { return uint64(guestCodeAddr) },
		},
		{
			name: "misaligned stack", program: []uint32{insnLdrX0SP},
			setup: func(g *guest) { g.ac.SetStack(uintptr(guestDataAddr) + 0x808) },
			signo: linux.SIGBUS, code: sigBusAdrAln, addr: func(*guest) uint64 { return uint64(guestDataAddr) + 0x808 },
		},
		{
			name: "write to a system register", program: []uint32{movz(0, 1), insnMsrMIDR},
			signo: linux.SIGILL, code: sigIllIllOpc, addr: func(*guest) uint64 { return uint64(guestCodeAddr) + 4 },
		},
		{
			name: "unknown system register", program: []uint32{insnMrsPMCR},
			signo: linux.SIGILL, code: sigIllIllOpc, addr: func(*guest) uint64 { return uint64(guestCodeAddr) },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newGuest(t, plat, tc.program...)
			if tc.setup != nil {
				tc.setup(g)
			}
			g.regs().Regs[5] = 0x5555
			sig, at, err := g.switchOnce()
			if !errors.Is(err, platform.ErrContextSignal) || sig == nil {
				t.Fatalf("Switch = (%v, %v), want ErrContextSignal", sig, err)
			}
			if sig.Signo != int32(tc.signo) || sig.Code != tc.code {
				t.Errorf("signal = %d code %d, want %d code %d", sig.Signo, sig.Code, tc.signo, tc.code)
			}
			if got, want := sig.Addr(), tc.addr(g); got != want {
				t.Errorf("si_addr = %#x, want %#x", got, want)
			}
			if tc.signo == linux.SIGSEGV && at != tc.at {
				t.Errorf("access type = %v, want %v", at, tc.at)
			}
			if g.regs().Regs[5] != 0x5555 {
				t.Errorf("X5 = %#x after the fault, want 0x5555", g.regs().Regs[5])
			}
		})
	}
}

func TestIDRegisterReadsAreEmulatedWithoutLeakingHiddenFeatures(t *testing.T) {
	plat := newTestPlatform(t)
	g := newGuest(t, plat, insnMrsMIDR, insnSVC0)
	if sig, _, err := g.switchOnce(); sig != nil || err != nil {
		t.Fatalf("MRS MIDR_EL1: Switch = (%v, %v), want a syscall", sig, err)
	}
	if got := g.regs().Regs[0]; got>>24 != 0x61 {
		t.Errorf("MIDR_EL1 = %#x, want the Apple implementer 0x61", got)
	}
	g.setProgram(insnMrsPFR0, insnSVC0)
	g.ac.SetIP(uintptr(guestCodeAddr))
	if sig, _, err := g.switchOnce(); sig != nil || err != nil {
		t.Fatalf("MRS ID_AA64PFR0_EL1: Switch = (%v, %v)", sig, err)
	}
	if got := g.regs().Regs[0]; got&(0xf<<32) != 0 {
		t.Errorf("ID_AA64PFR0_EL1 = %#x exposes SVE", got)
	}
}

func TestUserRegistersRunWithoutTraps(t *testing.T) {
	plat := newTestPlatform(t)
	for name, insn := range map[string]uint32{
		"CTR_EL0": insnMrsCTR, "DCZID_EL0": insnMrsDCZID,
		"CNTVCT_EL0": insnMrsCNTVC, "CNTPCT_EL0": insnMrsCNTPC, "TPIDRRO_EL0": insnMrsTPRO,
	} {
		t.Run(name, func(t *testing.T) {
			g := newGuest(t, plat, insn, insnSVC0)
			g.regs().Regs[0] = 0xdeadbeef
			sig, _, err := g.switchOnce()
			if sig != nil || err != nil {
				t.Fatalf("Switch = (%v, %v), want the register read to run natively", sig, err)
			}
			if g.regs().Regs[0] == 0xdeadbeef && name != "TPIDRRO_EL0" {
				t.Errorf("X0 unchanged: the guest did not read %s", name)
			}
		})
	}
}

func TestCacheMaintenanceAndWaitInstructionsRunWithoutTraps(t *testing.T) {
	plat := newTestPlatform(t)
	const (
		dcZVA  uint32 = 0xd50b7420 // DC ZVA, X0.
		icIVAU uint32 = 0xd50b7520 // IC IVAU, X0.
		dcCVAU uint32 = 0xd50b7b20 // DC CVAU, X0.
		dcCVAC uint32 = 0xd50b7a20 // DC CVAC, X0.
		dcCIVA uint32 = 0xd50b7e20 // DC CIVAC, X0.
		wfe    uint32 = 0xd503205f
		wfi    uint32 = 0xd503207f
		nop    uint32 = 0xd503201f
	)
	g := newGuest(t, plat, dcZVA, icIVAU, dcCVAU, dcCVAC, dcCIVA, wfe, wfi, nop, insnSVC0)
	// DC ZVA clears an aligned block: pre-fill the block and expect zeros.
	for i := range 64 {
		g.data[0x40+i] = 0xff
	}
	g.regs().Regs[0] = uint64(guestDataAddr) + 0x40
	sig, _, err := g.switchOnce()
	if sig != nil || err != nil {
		t.Fatalf("Switch = (%v, %v): cache maintenance or wait instructions trapped", sig, err)
	}
	if got, want := g.ac.IP(), uintptr(guestCodeAddr)+9*4; got != want {
		t.Errorf("IP() = %#x, want %#x: an instruction did not complete", got, want)
	}
	for i := range 64 {
		if g.data[0x40+i] != 0 {
			t.Fatalf("DC ZVA left byte %d of the block at %#x", i, g.data[0x40+i])
		}
	}
}

func TestCounterRegistersAdvance(t *testing.T) {
	plat := newTestPlatform(t)
	g := newGuest(t, plat, insnMrsCNTVC, insnSVC0)
	var last uint64
	for range 3 {
		g.ac.SetIP(uintptr(guestCodeAddr))
		if sig, _, err := g.switchOnce(); sig != nil || err != nil {
			t.Fatalf("Switch = (%v, %v)", sig, err)
		}
		cur := g.regs().Regs[0]
		if cur <= last {
			t.Fatalf("CNTVCT_EL0 = %d after %d: the counter did not advance", cur, last)
		}
		last = cur
	}
}
