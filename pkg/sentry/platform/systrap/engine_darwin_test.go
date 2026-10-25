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

//go:build darwin && arm64 && pagesize_16k

package systrap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/pkg/usermem"
)

// Instruction encodings of the hand-assembled guests.
const (
	insnSVC0  uint32 = 0xd4000001
	insnBRK   uint32 = 0xd4200000
	insnUDF   uint32 = 0x00000000
	insnNOP   uint32 = 0xd503201f
	insnBSelf uint32 = 0x14000000 // b .
	insnMRSTP uint32 = 0xd53bd040 // mrs x0, tpidr_el0
	insnMSRTP uint32 = 0xd51bd040 // msr tpidr_el0, x0
)

func movz(rd, imm uint32) uint32          { return 0xd2800000 | imm<<5 | rd }
func movk(rd, imm, shift uint32) uint32   { return 0xf2800000 | shift/16<<21 | imm<<5 | rd }
func addImm(rd, rn, imm uint32) uint32    { return 0x91000000 | imm<<10 | rn<<5 | rd }
func subsImm(rd, rn, imm uint32) uint32   { return 0xf1000000 | imm<<10 | rn<<5 | rd }
func addReg(rd, rn, rm uint32) uint32     { return 0x8b000000 | rm<<16 | rn<<5 | rd }
func cmpReg(rn, rm uint32) uint32         { return 0xeb00001f | rm<<16 | rn<<5 }
func ldrX(rt, rn uint32) uint32           { return 0xf9400000 | rn<<5 | rt }
func strX(rt, rn uint32) uint32           { return 0xf9000000 | rn<<5 | rt }
func mrsTPIDR(rt uint32) uint32           { return insnMRSTP&^0x1f | rt }
func msrTPIDR(rt uint32) uint32           { return insnMSRTP&^0x1f | rt }
func bCond(cond uint32, delta int) uint32 { return 0x54000000 | uint32(delta/4)&0x7ffff<<5 | cond }
func b(delta int) uint32                  { return 0x14000000 | uint32(delta/4)&0x3ffffff }
func movVec(rd, rn uint32) uint32         { return 0x4ea01c00 | rn<<16 | rn<<5 | rd } // mov vd.16b, vn.16b
func dupX(vd, xn uint32) uint32           { return 0x4e080c00 | xn<<5 | vd }          // dup vd.2d, xn
func umovX(xd, vn uint32) uint32          { return 0x4e083c00 | vn<<5 | xd }          // umov xd, vn.d[0]

const (
	condEQ = 0
	condNE = 1
	condLT = 11
)

// testMM is the MemoryManager of the engine tests. It records the VMAs that the
// address space creates for its islands, and it refuses overlapping ones the
// way mm.MMap does with NoReplace.
type testMM struct {
	usermem.IO
	mu   sync.Mutex
	as   platform.AddressSpace
	vmas []hostarch.AddrRange
	// pages maps the start of a guest page to the Sentry view of its frame.
	pages map[uint64][]byte
}

func (m *testMM) MMap(_ context.Context, opts memmap.MMapOpts) (hostarch.Addr, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ar := hostarch.AddrRange{Start: opts.Addr, End: opts.Addr + hostarch.Addr(opts.Length)}
	for _, v := range m.vmas {
		if v.Overlaps(ar) {
			return 0, unix.EEXIST
		}
	}
	m.vmas = append(m.vmas, ar)
	return opts.Addr, nil
}

func (m *testMM) AddressSpace() platform.AddressSpace { return m.as }

func (m *testMM) FindVMAByName(hostarch.AddrRange, string) (hostarch.Addr, uint64, error) {
	return 0, 0, unix.ENOENT
}

// reserve marks a range as a guest VMA so that islands avoid it.
func (m *testMM) reserve(start, length uint64) {
	m.mu.Lock()
	m.vmas = append(m.vmas, hostarch.AddrRange{Start: hostarch.Addr(start), End: hostarch.Addr(start + length)})
	m.mu.Unlock()
}

// record remembers the Sentry view of the frame that backs the page at va.
func (m *testMM) record(va uint64, mem []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pages == nil {
		m.pages = make(map[uint64][]byte)
	}
	m.pages[va] = mem
}

// CopyIn reads guest memory from the recorded frames. A read must stay inside
// one page.
func (m *testMM) CopyIn(_ context.Context, addr hostarch.Addr, dst []byte, _ usermem.IOOpts) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	base := blockRound(uint64(addr))
	page, ok := m.pages[base]
	off := uint64(addr) - base
	if !ok || off+uint64(len(dst)) > uint64(len(page)) {
		return 0, unix.EFAULT
	}
	return copy(dst, page[off:]), nil
}

const (
	codeVA  = 0x5555_0000_0000
	dataVA  = 0x5555_1000_0000
	stackVA = 0x7000_0000_0000
)

type rig struct {
	t      testing.TB
	p      *Platform
	mf     *pgalloc.MemoryFile
	as     *addressSpace
	mm     *testMM
	ctx    *Context
	ac     *arch.Context64
	rctx   context.Context
	stopCh chan struct{}
}

func newPlatform(t testing.TB) *Platform {
	t.Helper()
	// A developer can export the variable of the zone mode in a shell. The
	// tests of the default mode must not see it.
	t.Setenv(ZoneEnv, "")
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
	asI, err := p.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		t.Fatalf("NewAddressSpace: %v", err)
	}
	as := asI.(*addressSpace)
	r := &rig{t: t, p: p, mf: mf, as: as, mm: &testMM{as: as}, rctx: context.Background()}
	t.Cleanup(func() {
		r.ctx.Release()
		as.Release()
		mf.Destroy()
	})
	r.ctx = p.NewContext(r.rctx).(*Context)
	r.ac = arch.New(arch.Host)
	return r
}

// mapPage allocates one frame, fills it and maps it at va.
func (r *rig) mapPage(va uint64, at hostarch.AccessType, words ...uint32) []byte {
	r.t.Helper()
	fr, err := r.mf.Allocate(blockSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		r.t.Fatalf("Allocate: %v", err)
	}
	bs, err := r.mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		r.t.Fatalf("MapInternal: %v", err)
	}
	buf := make([]byte, 0)
	_ = buf
	b := bs.Head()
	mem := b.ToSlice()
	for i, w := range words {
		binary.LittleEndian.PutUint32(mem[i*4:], w)
	}
	r.mm.reserve(va, blockSize)
	r.mm.record(va, mem)
	if err := r.as.MapFile(hostarch.Addr(va), r.mf, fr, at, false); err != nil {
		r.t.Fatalf("MapFile %#x: %v", va, err)
	}
	return mem
}

// program maps code at codeVA and a stack, and points ac at the code.
func (r *rig) program(words ...uint32) {
	r.t.Helper()
	r.mapPage(codeVA, hostarch.AccessType{Read: true, Execute: true}, words...)
	r.mapPage(stackVA, hostarch.ReadWrite)
	r.ac.SetIP(codeVA)
	r.ac.SetStack(stackVA + blockSize - 0x100)
}

func (r *rig) run() (*linux.SignalInfo, hostarch.AccessType, error) {
	return r.ctx.Switch(r.rctx, r.mm, r.ac, -1)
}

func (r *rig) regs() *arch.Registers { return &r.ac.StateData().Regs }

func describe(si *linux.SignalInfo) string {
	if si == nil {
		return "nil"
	}
	return fmt.Sprintf("signal %d code %d addr %#x", si.Signo, si.Code, si.Addr())
}

func mustSyscall(t testing.TB, si *linux.SignalInfo, err error, wantNo uint64, ac *arch.Context64) {
	t.Helper()
	if si != nil || err != nil {
		t.Logf("regs: %+v", ac.StateData().Regs)
		t.Fatalf("Switch = (%s, %v), want a system call", describe(si), err)
	}
	if got := ac.StateData().Regs.Regs[8]; got != wantNo {
		t.Fatalf("system call number = %d, want %d", got, wantNo)
	}
}

func TestSyscallRoundTrip(t *testing.T) {
	p := newPlatform(t)
	r := newRig(t, p)
	r.program(movz(0, 42), movz(8, 93), insnSVC0, movz(1, 7), movz(8, 94), insnSVC0)
	si, _, err := r.run()
	mustSyscall(t, si, err, 93, r.ac)
	if got := r.regs().Regs[0]; got != 42 {
		t.Errorf("x0 = %d, want 42", got)
	}
	if got := r.regs().Pc; got != codeVA+12 {
		t.Errorf("pc = %#x, want %#x", got, codeVA+12)
	}
	r.regs().Regs[0] = 1000
	si, _, err = r.run()
	mustSyscall(t, si, err, 94, r.ac)
	if got := r.regs().Regs[0]; got != 1000 {
		t.Errorf("x0 after the second system call = %d, want 1000", got)
	}
	if got := r.regs().Regs[1]; got != 7 {
		t.Errorf("x1 = %d, want 7", got)
	}
}

func strW(rt, rn uint32) uint32 { return 0xb9000000 | rn<<5 | rt }
func brReg(rn uint32) uint32    { return 0xd61f0000 | rn<<5 }

// loadWord returns instructions that put a 32-bit constant in register rd.
func loadWord(rd, v uint32) []uint32 {
	return []uint32{movz(rd, v&0xffff), movk(rd, v>>16, 16)}
}

func TestNativeArithmetic(t *testing.T) {
	p := newPlatform(t)
	r := newRig(t, p)
	// x1 accumulates 3 for 100000 iterations, so the guest runs 300000 add
	// instructions on the host CPU before it reports the sum.
	r.program(
		movz(1, 0), movz(2, 0x86a0), movk(2, 1, 16),
		addImm(1, 1, 3), subsImm(2, 2, 1), bCond(condNE, -8),
		addImm(0, 1, 0), movz(8, 93), insnSVC0,
	)
	si, _, err := r.run()
	mustSyscall(t, si, err, 93, r.ac)
	if got := r.regs().Regs[0]; got != 300000 {
		t.Fatalf("sum = %d, want 300000", got)
	}
}

func TestLazyPatchOnce(t *testing.T) {
	p := newPlatform(t)
	r := newRig(t, p)
	// Five svc sites on one page. x30 holds a marker that the trampoline must keep.
	prog := []uint32{movz(30, 0x1234), movk(30, 0xbeef, 16)}
	siteIdx := []int{}
	for i := uint32(0); i < 5; i++ {
		prog = append(prog, movz(8, 100+i))
		siteIdx = append(siteIdx, len(prog))
		prog = append(prog, insnSVC0)
	}
	r.program(prog...)
	for i := 0; i < 5; i++ {
		si, _, err := r.run()
		mustSyscall(t, si, err, uint64(100+i), r.ac)
		if got := r.regs().Regs[30]; got != 0xbeef1234 {
			t.Fatalf("x30 = %#x after site %d, want 0xbeef1234", got, i)
		}
	}
	if got := r.as.PatchedBlocks(); got != 1 {
		t.Fatalf("patched blocks = %d, want 1", got)
	}
	// Every site now holds a B into an island, and each island slot decodes as a trap slot.
	r.as.mu.Lock()
	defer r.as.mu.Unlock()
	blk := r.as.blocks[codeVA]
	if blk == nil || blk.state != blockExec {
		t.Fatalf("code block state = %+v, want an executable copy", blk)
	}
	code := pageBytes(blk.priv)
	for _, idx := range siteIdx {
		word := binary.LittleEndian.Uint32(code[idx*4:])
		target, ok := decodeBranch(codeVA+uint64(idx)*4, word)
		if !ok {
			t.Fatalf("site %d holds %#x, want a B instruction", idx, word)
		}
		isl := r.as.islands[blockRound(target)]
		if isl == nil {
			t.Fatalf("site %d branches to %#x, outside every island", idx, target)
		}
		off := target - isl.base
		slot := pageBytes(isl.page)[off:]
		const wantPtr0 = arm64MRSTPIDRRO | arm64ScratchReg
		if got := binary.LittleEndian.Uint32(slot); got != wantPtr0 {
			t.Errorf("slot of site %d starts with %#x, want mrs x18, tpidrro_el0 (%#x)", idx, got, uint32(wantPtr0))
		}
		if got := binary.LittleEndian.Uint32(slot[trapSlotTailOffset:]); got != wantPtr0 {
			t.Errorf("slot tail of site %d starts with %#x, want mrs x18, tpidrro_el0 (%#x)", idx, got, uint32(wantPtr0))
		}
		back, ok := decodeBranch(target+trapSlotTailOffset+16, binary.LittleEndian.Uint32(slot[trapSlotTailOffset+16:]))
		if !ok || back != codeVA+uint64(idx)*4+4 {
			t.Errorf("slot of site %d returns to %#x, want %#x", idx, back, codeVA+uint64(idx)*4+4)
		}
		if d := absDiff(target, codeVA); d >= arm64BranchRange {
			t.Errorf("island distance %#x exceeds the B range", d)
		}
	}
}

func TestRegisterPreservation(t *testing.T) {
	p := newPlatform(t)
	r := newRig(t, p)
	// The kernel clears X18 on every return to user mode, including a handled
	// page fault, so no test can depend on X18. The loop below skips it.
	r.program(
		insnSVC0,
		umovX(20, 0), umovX(21, 31),
		addReg(22, 5, 5),
		insnSVC0,
	)
	regs := r.regs()
	for i := 1; i < 31; i++ {
		regs.Regs[i] = 0x1111_0000_0000_0000 + uint64(i)*0x0101_0101
	}
	regs.Regs[8] = 0x55 // keep a plain syscall number
	regs.Pstate = 0xa0000000
	fp := *r.ac.FloatingPointData()
	for v := 0; v < 32; v++ {
		binary.LittleEndian.PutUint64(fp[vregsOffset+16*v:], 0xfeed_0000_0000_0000|uint64(v)*0x1111)
		binary.LittleEndian.PutUint64(fp[vregsOffset+16*v+8:], 0xface_0000_0000_0000|uint64(v))
	}
	binary.LittleEndian.PutUint32(fp[fpcrOffset:], 0x0300_0000) // FZ and DN set
	want := regs.Regs

	si, _, err := r.run()
	mustSyscall(t, si, err, 0x55, r.ac)
	for i := 1; i < 31; i++ {
		if i == 18 {
			continue
		}
		if got := regs.Regs[i]; got != want[i] {
			t.Errorf("x%d = %#x after the first system call, want %#x", i, got, want[i])
		}
	}
	if regs.Pstate&nzcvMask != 0xa0000000 {
		t.Errorf("NZCV = %#x, want 0xa0000000", regs.Pstate&nzcvMask)
	}
	// Change one register through the Sentry, which forces a full reload.
	regs.Regs[5] = 0x2_0000_0001
	regs.Regs[0] = 0
	si, _, err = r.run()
	mustSyscall(t, si, err, 0x55, r.ac)
	if got := regs.Regs[22]; got != 0x4_0000_0002 {
		t.Errorf("x22 = %#x, want the doubled x5 that the Sentry wrote", got)
	}
	if got, w := regs.Regs[20], uint64(0xfeed_0000_0000_0000); got != w {
		t.Errorf("v0 low half = %#x, want %#x", got, w)
	}
	if got, w := regs.Regs[21], 0xfeed_0000_0000_0000|uint64(31)*0x1111; got != w {
		t.Errorf("v31 low half = %#x, want %#x", got, w)
	}
	if err := r.ctx.PullFullState(r.as, r.ac); err != nil {
		t.Fatal(err)
	}
	fp = *r.ac.FloatingPointData()
	for v := 0; v < 32; v++ {
		lo := binary.LittleEndian.Uint64(fp[vregsOffset+16*v:])
		hi := binary.LittleEndian.Uint64(fp[vregsOffset+16*v+8:])
		if lo != 0xfeed_0000_0000_0000|uint64(v)*0x1111 || hi != 0xface_0000_0000_0000|uint64(v) {
			t.Errorf("v%d = %#x:%#x after two system calls", v, hi, lo)
		}
	}
	if got := binary.LittleEndian.Uint32(fp[fpcrOffset:]); got != 0x0300_0000 {
		t.Errorf("FPCR = %#x, want 0x03000000", got)
	}
}

func TestTLSIsVirtual(t *testing.T) {
	p := newPlatform(t)
	r := newRig(t, p)
	// The guest reads the initial TLS, writes a new one, reads it back, traps,
	// then spins while it reads TPIDR_EL0 in a loop and compares the value.
	prog := []uint32{
		mrsTPIDR(2), // x2 = initial TLS
		movz(1, 0x4321), movk(1, 0xabcd, 16),
		msrTPIDR(1), // TLS = 0xabcd4321
		mrsTPIDR(3), // x3 = new TLS
		movz(8, 1), insnSVC0,
	}
	// Spin loop: 20 million iterations of mrs and cmp.
	spin := len(prog)
	prog = append(prog,
		movz(4, 0x2d00), movk(4, 0x131, 16), // x4 = 20000000
		movz(6, 0),
	)
	loop := len(prog)
	prog = append(prog,
		mrsTPIDR(5),
		cmpReg(5, 1),
		bCond(condNE, 16), // mismatch: jump to the failure marker
		addImm(6, 6, 1),
		subsImm(4, 4, 1),
		bCond(condNE, -(5*4)),
		movz(8, 2), insnSVC0,
		movz(7, 0xdead), insnSVC0, // failure marker
	)
	_ = spin
	_ = loop
	r.program(prog...)
	r.ac.SetTLS(0x7777_0000)
	si, _, err := r.run()
	mustSyscall(t, si, err, 1, r.ac)
	if got := r.regs().Regs[2]; got != 0x7777_0000 {
		t.Errorf("initial TLS read = %#x, want 0x77770000", got)
	}
	if got := r.regs().Regs[3]; got != 0xabcd4321 {
		t.Errorf("TLS read after msr = %#x, want 0xabcd4321", got)
	}
	if got := r.ac.TLS(); got != 0xabcd4321 {
		t.Errorf("Sentry TLS = %#x, want 0xabcd4321", got)
	}
	// Load every core so that the kernel preempts the guest during the spin.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2*runtimeCPUs(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			x := 0
			for {
				select {
				case <-stop:
					_ = x
					return
				default:
					x++
				}
			}
		}()
	}
	si, _, err = r.run()
	close(stop)
	wg.Wait()
	mustSyscall(t, si, err, 2, r.ac)
	if got := r.regs().Regs[6]; got != 20_000_000 {
		t.Errorf("the guest saw a changed TLS after %d iterations", got)
	}
}

func runtimeCPUs() int { return runtime.NumCPU() }

func wantSignal(t testing.TB, si *linux.SignalInfo, at hostarch.AccessType, err error, sig linux.Signal, code int32, addr uint64, wantAt hostarch.AccessType) {
	t.Helper()
	if !errors.Is(err, platform.ErrContextSignal) || si == nil {
		t.Fatalf("Switch = (%s, %v), want a signal", describe(si), err)
	}
	if linux.Signal(si.Signo) != sig || si.Code != code || si.Addr() != addr || at != wantAt {
		t.Fatalf("Switch = (%s, access %v), want signal %d code %d addr %#x access %v", describe(si), at, sig, code, addr, wantAt)
	}
}

func TestFaultsBecomeSegv(t *testing.T) {
	const (
		unmapped = 0x6666_0000_0000
		roVA     = 0x5555_2000_0000
	)
	cases := []struct {
		name  string
		prog  func() []uint32
		setup func(r *rig)
		sig   linux.Signal
		code  int32
		addr  uint64
		at    hostarch.AccessType
	}{
		{
			name: "read of an unmapped address",
			prog: func() []uint32 { return append(loadAddr(1, unmapped), ldrX(0, 1)) },
			sig:  linux.SIGSEGV, code: 1, addr: unmapped, at: hostarch.Read,
		},
		{
			name: "write to an unmapped address",
			prog: func() []uint32 { return append(loadAddr(1, unmapped+8), strX(0, 1)) },
			sig:  linux.SIGSEGV, code: 1, addr: unmapped + 8, at: hostarch.Write,
		},
		{
			name: "write to a read-only page",
			prog: func() []uint32 { return append(loadAddr(1, roVA+16), strX(0, 1)) },
			setup: func(r *rig) {
				r.mapPage(roVA, hostarch.Read)
			},
			sig: linux.SIGSEGV, code: 2, addr: roVA + 16, at: hostarch.Write,
		},
		{
			name: "jump to an unmapped address",
			prog: func() []uint32 { return append(loadAddr(1, unmapped+0x40), brReg(1)) },
			sig:  linux.SIGSEGV, code: 1, addr: unmapped + 0x40, at: hostarch.Execute,
		},
		{
			name: "jump to a data page",
			prog: func() []uint32 { return append(loadAddr(1, dataVA), brReg(1)) },
			setup: func(r *rig) {
				r.mapPage(dataVA, hostarch.ReadWrite)
			},
			sig: linux.SIGSEGV, code: 2, addr: dataVA, at: hostarch.Execute,
		},
		{
			name: "undefined instruction",
			prog: func() []uint32 { return []uint32{insnNOP, insnUDF} },
			sig:  linux.SIGILL, code: 1, addr: codeVA + 4, at: hostarch.NoAccess,
		},
		{
			name: "breakpoint",
			prog: func() []uint32 { return []uint32{insnNOP, insnNOP, insnBRK} },
			sig:  linux.SIGTRAP, code: linux.TRAP_BRKPT, addr: codeVA + 8, at: hostarch.NoAccess,
		},
	}
	p := newPlatform(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, p)
			r.program(tc.prog()...)
			if tc.setup != nil {
				tc.setup(r)
			}
			si, at, err := r.run()
			wantSignal(t, si, at, err, tc.sig, tc.code, tc.addr, tc.at)
		})
	}
}

// loadAddr returns instructions that load a 48-bit constant into rd.
func loadAddr(rd uint32, v uint64) []uint32 {
	return []uint32{movz(rd, uint32(v&0xffff)), movk(rd, uint32(v>>16&0xffff), 16), movk(rd, uint32(v>>32&0xffff), 32)}
}

func TestFaultThenMapRetries(t *testing.T) {
	// A fault reports the address, the Sentry maps memory, and the same
	// instruction succeeds on the next Switch. This is the path of demand paging.
	const addr = 0x6666_0000_0000
	p := newPlatform(t)
	r := newRig(t, p)
	prog := append(loadAddr(1, addr), movz(2, 0x77), strX(2, 1), ldrX(0, 1), movz(8, 9), insnSVC0)
	r.program(prog...)
	si, at, err := r.run()
	wantSignal(t, si, at, err, linux.SIGSEGV, 1, addr, hostarch.Write)
	mem := r.mapPage(addr, hostarch.ReadWrite)
	si, _, err = r.run()
	mustSyscall(t, si, err, 9, r.ac)
	if got := r.regs().Regs[0]; got != 0x77 {
		t.Errorf("x0 = %#x, want 0x77", got)
	}
	if got := binary.LittleEndian.Uint64(mem); got != 0x77 {
		t.Errorf("the store reached memory file bytes %#x, want 0x77", got)
	}
}

func TestExecuteAfterWrite(t *testing.T) {
	// A guest writes code into a page that does not allow execution. The
	// jump faults. The Sentry then maps the same frame as executable, which is
	// what mprotect does, and the written code runs patched.
	p := newPlatform(t)
	r := newRig(t, p)
	prog := []uint32{}
	prog = append(prog, loadAddr(1, dataVA)...)
	prog = append(prog, loadWord(2, movz(8, 77))...)
	prog = append(prog, strW(2, 1))
	prog = append(prog, loadWord(2, insnSVC0)...)
	prog = append(prog, movz(3, 4), addReg(3, 1, 3), strW(2, 3), brReg(1))
	r.program(prog...)
	// The data page is a frame that the test keeps to remap it later.
	fr, err := r.mf.Allocate(blockSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatal(err)
	}
	r.mm.reserve(dataVA, blockSize)
	if err := r.as.MapFile(dataVA, r.mf, fr, hostarch.ReadWrite, false); err != nil {
		t.Fatal(err)
	}
	si, at, err := r.run()
	wantSignal(t, si, at, err, linux.SIGSEGV, 2, dataVA, hostarch.Execute)
	if err := r.as.MapFile(dataVA, r.mf, fr, hostarch.AccessType{Read: true, Execute: true}, false); err != nil {
		t.Fatal(err)
	}
	si, _, err = r.run()
	mustSyscall(t, si, err, 77, r.ac)
	if got := r.regs().Pc; got != dataVA+8 {
		t.Errorf("pc = %#x after the written svc, want %#x", got, dataVA+8)
	}
}

func TestWritableExecutableBlock(t *testing.T) {
	// A block that allows read, write and execute alternates between the
	// writable frame and the patched copy. The guest runs code, rewrites it,
	// and runs the new code, which a stale patched copy would not show.
	p := newPlatform(t)
	r := newRig(t, p)
	prog := []uint32{}
	prog = append(prog, loadAddr(1, dataVA)...)
	prog = append(prog, loadWord(2, movz(8, 11))...)
	prog = append(prog, strW(2, 1))
	prog = append(prog, loadWord(2, insnSVC0)...)
	prog = append(prog, movz(3, 4), addReg(3, 1, 3), strW(2, 3))
	prog = append(prog, loadWord(2, 0xd65f03c0)...) // ret
	prog = append(prog, movz(3, 8), addReg(3, 1, 3), strW(2, 3))
	// Call the block; its ret returns here through x30.
	call := len(prog)
	prog = append(prog, 0xd63f0020) // blr x1
	prog = append(prog, loadWord(2, movz(8, 12))...)
	prog = append(prog, strW(2, 1)) // rewrite the first instruction while it is in the patched state
	prog = append(prog, 0xd63f0020) // blr x1
	prog = append(prog, movz(8, 13), insnSVC0)
	_ = call
	r.program(prog...)
	r.mapPage(dataVA, hostarch.AccessType{Read: true, Write: true, Execute: true})
	si, _, err := r.run()
	mustSyscall(t, si, err, 11, r.ac)
	si, _, err = r.run()
	mustSyscall(t, si, err, 12, r.ac)
	si, _, err = r.run()
	mustSyscall(t, si, err, 13, r.ac)
	// The code page, the data block before the rewrite and the data block after it.
	if got := r.as.PatchedBlocks(); got != 3 {
		t.Errorf("patched blocks = %d, want 3", got)
	}
}

func TestSyscallKeepsTheWordsBelowTheStackPointer(t *testing.T) {
	// Go assembly keeps live words just below the stack pointer across a
	// system call. runtime.clone leaves the g, m and fn of its child there. The
	// trap slot spills x16 and x17, and the spill must not touch those words.
	p := newPlatform(t)
	r := newRig(t, p)
	r.program(
		movz(9, 0x1234),
		0xf81f03e9, // stur x9, [sp, #-16]
		0xf81f83e9, // stur x9, [sp, #-8]
		movz(8, 1), insnSVC0,
		0xf85f03ea, // ldur x10, [sp, #-16]
		0xf85f83eb, // ldur x11, [sp, #-8]
		movz(8, 2), insnSVC0,
	)
	si, _, err := r.run()
	mustSyscall(t, si, err, 1, r.ac)
	si, _, err = r.run()
	mustSyscall(t, si, err, 2, r.ac)
	if x := &r.regs().Regs; x[10] != 0x1234 || x[11] != 0x1234 {
		t.Errorf("the words below the stack pointer read back %#x and %#x, want 0x1234 and 0x1234", x[10], x[11])
	}
}
func TestStoreIntoTheOwnBlockRunsInTheSentry(t *testing.T) {
	// A guest that stores to the block that it executes cannot run the store in
	// the stub, because the engine gives a block write access or execute
	// access, never both. The Sentry runs the store, writes both frames of the
	// block, and applies the writeback of the addressing mode.
	p := newPlatform(t)
	r := newRig(t, p)
	prog := append(loadAddr(1, codeVA+0x400),
		movz(2, 0x55), movz(3, 0x66),
		strX(2, 1),
		0xa9810c22, // stp x2, x3, [x1, #16]!
		0xf85f0020, // ldur x0, [x1, #-16]
		ldrX(4, 1),
		0xf9400425, // ldr x5, [x1, #8]
		movz(8, 9), insnSVC0)
	r.mapPage(codeVA, hostarch.AccessType{Read: true, Write: true, Execute: true}, prog...)
	r.mapPage(stackVA, hostarch.ReadWrite)
	r.ac.SetIP(codeVA)
	r.ac.SetStack(stackVA + blockSize - 0x100)
	si, _, err := r.run()
	mustSyscall(t, si, err, 9, r.ac)
	x := &r.regs().Regs
	for _, tc := range []struct {
		what      string
		got, want uint64
	}{
		{"x0, the word of the plain store", x[0], 0x55},
		{"x4, the first word of the pair store", x[4], 0x55},
		{"x5, the second word of the pair store", x[5], 0x66},
		{"x1, the base after the pre-index writeback", x[1], codeVA + 0x410},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %#x, want %#x", tc.what, tc.got, tc.want)
		}
	}
}

func TestStoreOverPatchedCodeOfTheOwnBlockFaults(t *testing.T) {
	// The patcher replaced the system call instruction in the executable copy.
	// A store over it would turn the patch into data, so the engine reports
	// SIGSEGV and does not run the store.
	p := newPlatform(t)
	r := newRig(t, p)
	prog := append(loadAddr(1, codeVA+24), movz(2, 1), strW(2, 1), movz(8, 9), insnSVC0)
	r.mapPage(codeVA, hostarch.AccessType{Read: true, Write: true, Execute: true}, prog...)
	r.mapPage(stackVA, hostarch.ReadWrite)
	r.ac.SetIP(codeVA)
	r.ac.SetStack(stackVA + blockSize - 0x100)
	si, at, err := r.run()
	wantSignal(t, si, at, err, linux.SIGSEGV, 2, codeVA+24, hostarch.Write)
}

func TestStoreFromAnotherBlockStillSucceeds(t *testing.T) {
	// The loop breaker must not stop the ordinary case: code in one block
	// writes to a writable and executable block that it does not run in.
	p := newPlatform(t)
	r := newRig(t, p)
	prog := append(loadAddr(1, dataVA+0x400), movz(2, 0x55), strW(2, 1), ldrX(0, 1), movz(8, 9), insnSVC0)
	r.program(prog...)
	r.mapPage(dataVA, hostarch.AccessType{Read: true, Write: true, Execute: true})
	si, _, err := r.run()
	mustSyscall(t, si, err, 9, r.ac)
	if got := r.regs().Regs[0]; got != 0x55 {
		t.Errorf("the load returned %#x, want 0x55", got)
	}
}

func TestMapFileOverAnIslandSkipsTheIsland(t *testing.T) {
	// A map unit of 256KB lets the memory manager hand over one pma that
	// spans the block of an island. The range must not replace the island, or
	// the next system call of the guest would jump into the new frame.
	p := newPlatform(t)
	r := newRig(t, p)
	r.program(movz(8, 9), insnSVC0, movz(8, 10), insnSVC0)
	si, _, err := r.run()
	mustSyscall(t, si, err, 9, r.ac)
	var island uint64
	r.as.mu.Lock()
	for base := range r.as.islands {
		island = base
	}
	r.as.mu.Unlock()
	if island == 0 {
		t.Fatal("the first system call created no island")
	}
	fr, err := r.mf.Allocate(4*blockSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if err := r.as.MapFile(hostarch.Addr(island-blockSize), r.mf, fr, hostarch.ReadWrite, false); err != nil {
		t.Fatalf("MapFile over an island: %v", err)
	}
	// The stub fetches the slots through its own mapping of the island. Map
	// that view into the Sentry and compare it with the page that holds the
	// slots. A hot resume does not prove anything here, because the Sentry
	// recovers a fault on the tail of a trap slot.
	view, err := vmRemapFrom(r.as.proc.task, island, blockSize)
	if err != nil {
		t.Fatalf("map the island of the stub task: %v", err)
	}
	defer vmDeallocate(selfTask(), view, blockSize)
	r.as.mu.Lock()
	want := pageBytes(r.as.islands[island].page)
	r.as.mu.Unlock()
	if got := unsafe.Slice((*byte)(addrPtr(view)), blockSize); !bytes.Equal(got, want) {
		t.Error("the stub sees other bytes in the island after MapFile covered it, so the range replaced the island")
	}
	if _, ok, err := vmRegion(r.as.proc.task, island-blockSize); err != nil || !ok {
		t.Errorf("vmRegion below the island = (%v, %v), want a mapping of the new frame", ok, err)
	}
}

// BenchmarkSyscallRoundTrip measures one guest system call from the trap of
// the guest thread to the next trap. The Sentry does no work for the call, so
// the time is the cost of the handoff between the stub and the Sentry.
func BenchmarkSyscallRoundTrip(b *testing.B) {
	p := newPlatform(b)
	r := newRig(b, p)
	r.program(movz(8, 9), insnSVC0, 0x17fffffe /* b -8 */)
	if si, _, err := r.run(); si != nil || err != nil {
		b.Fatalf("first run = (%s, %v), want a system call", describe(si), err)
	}
	for b.Loop() {
		if si, _, err := r.run(); si != nil || err != nil {
			b.Fatalf("run = (%s, %v), want a system call", describe(si), err)
		}
	}
}

func TestSyscallRestart(t *testing.T) {
	p := newPlatform(t)
	r := newRig(t, p)
	r.program(movz(0, 5), movz(8, 40), insnSVC0, addImm(0, 0, 1), movz(8, 41), insnSVC0)
	si, _, err := r.run()
	mustSyscall(t, si, err, 40, r.ac)
	// Restart the call, as the Sentry does for an interrupted blocking call.
	r.ac.RestartSyscall()
	r.regs().Regs[0] = 5
	si, _, err = r.run()
	mustSyscall(t, si, err, 40, r.ac)
	if got := r.ac.StateData().OrigR0; got != 5 {
		t.Errorf("OrigR0 = %d, want 5", got)
	}
	r.regs().Regs[0] = 99
	si, _, err = r.run()
	mustSyscall(t, si, err, 41, r.ac)
	if got := r.regs().Regs[0]; got != 100 {
		t.Errorf("x0 = %d, want 100", got)
	}
}

func TestColdResumeRedirectsExecution(t *testing.T) {
	// A signal handler call and rt_sigreturn change the PC and SP behind the
	// guest's back. The next Switch must run from the new state.
	p := newPlatform(t)
	r := newRig(t, p)
	r.program(movz(8, 1), insnSVC0, movz(8, 2), insnSVC0, movz(8, 3), insnSVC0)
	si, _, err := r.run()
	mustSyscall(t, si, err, 1, r.ac)
	r.regs().Pc = codeVA + 16 // skip to the third call
	r.regs().Regs[20] = 0x4040
	si, _, err = r.run()
	mustSyscall(t, si, err, 3, r.ac)
	if got := r.regs().Regs[20]; got != 0x4040 {
		t.Errorf("x20 = %#x, want 0x4040", got)
	}
}

func TestInterruptStopsRunningGuest(t *testing.T) {
	p := newPlatform(t)
	r := newRig(t, p)
	// The guest counts in x20 forever.
	r.program(addImm(20, 20, 1), bCond(condNE, -4)) // flags are zero, so b.ne is taken
	r.regs().Pstate = 0
	for i := 0; i < 50; i++ {
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			// Interrupt until Switch returns, because the first call can
			// arrive before the guest runs.
			for {
				r.ctx.Interrupt()
				select {
				case <-time.After(200 * time.Microsecond):
				case <-stop:
					return
				}
			}
		}()
		si, _, err := r.run()
		close(stop)
		<-done
		if si != nil || !errors.Is(err, platform.ErrContextInterrupt) {
			t.Fatalf("iteration %d: Switch = (%s, %v), want ErrContextInterrupt", i, describe(si), err)
		}
		pc := r.regs().Pc
		if pc != codeVA && pc != codeVA+4 {
			t.Fatalf("iteration %d: pc = %#x, want an address of the loop", i, pc)
		}
	}
}

func TestInterruptBeforeSwitch(t *testing.T) {
	p := newPlatform(t)
	r := newRig(t, p)
	r.program(movz(8, 3), insnSVC0)
	r.ctx.Interrupt()
	si, _, err := r.run()
	if si != nil || !errors.Is(err, platform.ErrContextInterrupt) {
		t.Fatalf("Switch = (%s, %v), want ErrContextInterrupt", describe(si), err)
	}
	si, _, err = r.run()
	mustSyscall(t, si, err, 3, r.ac)
}

func TestInterruptKeepsGuestState(t *testing.T) {
	// An interrupt lands between instructions. After it, the guest continues
	// from the saved registers and finishes the exact count.
	p := newPlatform(t)
	r := newRig(t, p)
	r.program(
		movz(2, 0x9680), movk(2, 0x98, 16), // x2 = 10,000,000
		addImm(1, 1, 1), subsImm(2, 2, 1), bCond(condNE, -8),
		addImm(0, 1, 0), movz(8, 7), insnSVC0,
	)
	interrupts := 0
	for {
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				r.ctx.Interrupt()
				select {
				case <-stop:
					return
				case <-time.After(100 * time.Microsecond):
				}
			}
		}()
		si, _, err := r.run()
		close(stop)
		<-done
		if errors.Is(err, platform.ErrContextInterrupt) {
			interrupts++
			continue
		}
		mustSyscall(t, si, err, 7, r.ac)
		break
	}
	if got := r.regs().Regs[0]; got != 10_000_000 {
		t.Fatalf("count = %d after %d interrupts, want 10000000", got, interrupts)
	}
}

func TestThreadsShareAddressSpace(t *testing.T) {
	p := newPlatform(t)
	r := newRig(t, p)
	// Each thread makes 2000 system calls and the Sentry adds one to x0 per call.
	r.program(
		movz(1, 2000), movz(8, 5),
		insnSVC0, subsImm(1, 1, 1), bCond(condNE, -8),
		movz(8, 6), insnSVC0,
	)
	const threads = 4
	var wg sync.WaitGroup
	errs := make(chan error, threads)
	for i := 0; i < threads; i++ {
		c := r.p.NewContext(r.rctx).(*Context)
		ac := arch.New(arch.Host)
		ac.SetIP(codeVA)
		ac.SetStack(uintptr(stackVA + blockSize - 0x100 - uint64(i)*0x400))
		ac.StateData().Regs.Regs[0] = uint64(i) * 1000
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer c.Release()
			calls := 0
			for {
				si, _, err := c.Switch(r.rctx, r.mm, ac, -1)
				if si != nil || err != nil {
					errs <- fmt.Errorf("thread %d: Switch = (%s, %v)", i, describe(si), err)
					return
				}
				regs := &ac.StateData().Regs
				if regs.Regs[8] == 6 {
					break
				}
				if regs.Regs[0] != uint64(i)*1000+uint64(calls) {
					errs <- fmt.Errorf("thread %d: x0 = %d at call %d, want %d", i, regs.Regs[0], calls, uint64(i)*1000+uint64(calls))
					return
				}
				calls++
				regs.Regs[0]++
			}
			if calls != 2000 {
				errs <- fmt.Errorf("thread %d made %d calls, want 2000", i, calls)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := r.as.PatchedBlocks(); got != 1 {
		t.Errorf("patched blocks = %d for %d threads, want 1", got, threads)
	}
}

func TestThreadReleaseAndReuse(t *testing.T) {
	p := newPlatform(t)
	r := newRig(t, p)
	r.program(movz(8, 1), insnSVC0, movz(8, 2), insnSVC0)
	for i := 0; i < 20; i++ {
		c := p.NewContext(r.rctx).(*Context)
		ac := arch.New(arch.Host)
		ac.SetIP(codeVA)
		ac.SetStack(stackVA + blockSize - 0x100)
		si, _, err := c.Switch(r.rctx, r.mm, ac, -1)
		mustSyscall(t, si, err, 1, ac)
		c.Release()
	}
	r.as.mu.Lock()
	defer r.as.mu.Unlock()
	if r.as.nextIdx > 2 {
		t.Errorf("the address space allocated %d thread slots for sequential threads, want reuse", r.as.nextIdx)
	}
}

func TestStubDeathReturnsError(t *testing.T) {
	p := newPlatform(t)
	r := newRig(t, p)
	// The first system call proves that the stub task runs the guest. The
	// guest then spins, and the test kills the task from the outside, as a
	// crash would.
	r.program(movz(8, 5), insnSVC0, insnBSelf)
	si, _, err := r.run()
	mustSyscall(t, si, err, 5, r.ac)
	done := make(chan error, 1)
	go func() {
		_, _, err := r.run()
		done <- err
	}()
	p.host.killProc(r.as.proc)
	err = <-done
	var ce *platform.ContextError
	if !errors.As(err, &ce) || !errors.Is(ce.Err, errDeadStub) {
		t.Fatalf("Switch error = %v, want a ContextError that wraps errDeadStub", err)
	}
	if _, _, err := r.run(); !errors.As(err, &ce) {
		t.Fatalf("second Switch error = %v, want a ContextError", err)
	}
	if _, err := p.NewAddressSpace(platform.AddressSpaceOptions{}); err != nil {
		t.Fatalf("a new address space must work after another stub died: %v", err)
	}
}

// waitProcessExit blocks until the process pid is gone. The kernel reports the
// exit through a kqueue event, so the wait needs no polling. A process that
// exited before the registration makes EVFILT_PROC fail with ESRCH.
func waitProcessExit(t testing.TB, pid int) {
	t.Helper()
	kq, err := unix.Kqueue()
	if err != nil {
		t.Fatalf("kqueue: %v", err)
	}
	defer unix.Close(kq)
	change := unix.Kevent_t{
		Ident:  uint64(pid),
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD | unix.EV_ONESHOT,
		Fflags: unix.NOTE_EXIT,
	}
	var out [1]unix.Kevent_t
	timeout := unix.NsecToTimespec(int64(10 * time.Second))
	n, err := unix.Kevent(kq, []unix.Kevent_t{change}, out[:], &timeout)
	switch {
	case errors.Is(err, unix.ESRCH):
		return
	case err != nil:
		t.Fatalf("kevent for process %d: %v", pid, err)
	case n == 0:
		t.Fatalf("process %d still runs after 10s", pid)
	}
}

func TestUnpatchedSyscallKillsStub(t *testing.T) {
	// A system call outside every patched site must never run on the host. The
	// test maps an unpatched copy as executable behind the patcher's back. The
	// strict sandbox profile then kills the stub on the host call, and the
	// Sentry reports a dead stub.
	p := newPlatform(t)
	r := newRig(t, p)
	page, err := p.pool.alloc()
	if err != nil {
		t.Fatal(err)
	}
	// getppid, which the sandbox filters, with the host system call convention.
	binary.LittleEndian.PutUint32(pageBytes(page), movz(16, 39))
	binary.LittleEndian.PutUint32(pageBytes(page)[4:], insnSVC0)
	flushCode(pageBytes(page)[:8])
	if err := r.as.mapPages(codeVA, blockSize, page, vmProtRead|vmProtExecute); err != nil {
		t.Fatal(err)
	}
	r.mapPage(stackVA, hostarch.ReadWrite)
	r.ac.SetIP(codeVA)
	r.ac.SetStack(stackVA + blockSize - 0x100)
	_, _, err = r.run()
	var ce *platform.ContextError
	if !errors.As(err, &ce) || !errors.Is(ce.Err, errDeadStub) {
		t.Fatalf("Switch error = %v, want a dead stub", err)
	}
}

func TestMapFileRejectsPartialHostPage(t *testing.T) {
	p := newPlatform(t)
	r := newRig(t, p)
	fr, err := r.mf.Allocate(blockSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatal(err)
	}
	var ae *AlignmentError
	if err := r.as.MapFile(codeVA+0x1000, r.mf, fr, hostarch.ReadWrite, false); !errors.As(err, &ae) {
		t.Errorf("MapFile at an unaligned address = %v, want an AlignmentError", err)
	}
	short := memmap.FileRange{Start: fr.Start, End: fr.Start + 0x1000}
	if err := r.as.MapFile(codeVA, r.mf, short, hostarch.ReadWrite, false); !errors.As(err, &ae) {
		t.Errorf("MapFile of a 4KB range = %v, want an AlignmentError", err)
	}
}

func TestUnmapRemovesAccess(t *testing.T) {
	p := newPlatform(t)
	r := newRig(t, p)
	prog := append(loadAddr(1, dataVA), movz(2, 5), strX(2, 1), movz(8, 1), insnSVC0, ldrX(3, 1), movz(8, 2), insnSVC0)
	r.program(prog...)
	r.mapPage(dataVA, hostarch.ReadWrite)
	si, _, err := r.run()
	mustSyscall(t, si, err, 1, r.ac)
	r.as.Unmap(dataVA, blockSize)
	si, at, err := r.run()
	wantSignal(t, si, at, err, linux.SIGSEGV, 1, dataVA, hostarch.Read)
}

func TestAddressSpaceLifecycle(t *testing.T) {
	p := newPlatform(t)
	for i := 0; i < 20; i++ {
		asI, err := p.NewAddressSpace(platform.AddressSpaceOptions{})
		if err != nil {
			t.Fatalf("iteration %d: NewAddressSpace: %v", i, err)
		}
		as := asI.(*addressSpace)
		pid := as.proc.pid
		as.Release()
		// The template reaps the stub, so the process ID disappears once the kill lands.
		waitProcessExit(t, pid)
	}
}

func TestSyscallWithUnusableStack(t *testing.T) {
	// The trampoline saves two registers below the guest stack pointer. With a
	// stack pointer that points nowhere, the store faults, and the Sentry must
	// still deliver the system call with the guest registers intact.
	p := newPlatform(t)
	r := newRig(t, p)
	r.program(movz(8, 30), insnSVC0, movz(8, 31), insnSVC0)
	const badSP = 0x6666_0000_0010
	r.ac.SetStack(badSP)
	r.regs().Regs[16] = 0x1616
	r.regs().Regs[17] = 0x1717
	si, _, err := r.run()
	mustSyscall(t, si, err, 30, r.ac)
	if got := r.regs().Sp; got != badSP {
		t.Errorf("sp = %#x, want %#x", got, uint64(badSP))
	}
	if got := r.regs().Pc; got != codeVA+8 {
		t.Errorf("pc = %#x, want %#x", got, uint64(codeVA+8))
	}
	if r.regs().Regs[16] != 0x1616 || r.regs().Regs[17] != 0x1717 {
		t.Errorf("x16, x17 = %#x, %#x, want 0x1616, 0x1717", r.regs().Regs[16], r.regs().Regs[17])
	}
	si, _, err = r.run()
	mustSyscall(t, si, err, 31, r.ac)
}

func TestProbeReportsStub(t *testing.T) {
	info, err := Probe()
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if info.Arch != "arm64" || info.PageSize != blockSize || info.StubPID <= 1 || info.ProtocolVersion != protocolVersion {
		t.Errorf("Probe info = %+v", info)
	}
	if info.RoundTrip <= 0 || info.RoundTrip > time.Second {
		t.Errorf("round trip = %v, want a positive time under one second", info.RoundTrip)
	}
	t.Logf("round trip %v", info.RoundTrip)
	if err := unix.Kill(info.StubPID, 0); !errors.Is(err, unix.ESRCH) {
		t.Errorf("the template stub %d still exists after Probe: %v", info.StubPID, err)
	}
}

// TestUserRangeFromRegions covers the pure walk over the template layout.
func TestUserRangeFromRegions(t *testing.T) {
	const gb = 1 << 30
	listerFor := func(regions []hostRegion) regionLister {
		return func(addr uint64) (hostRegion, bool, error) {
			for _, r := range regions {
				if r.start+r.size > addr {
					return r, true, nil
				}
			}
			return hostRegion{}, false, nil
		}
	}
	permanent := []hostRegion{{0xf_c000_0000, 1 * gb}, {0x10_0000_0000, 0x180 * gb}}
	for _, c := range []struct {
		name           string
		regions        []hostRegion
		wantLo, wantHi uint64
	}{
		{"no mapping", nil, userFloor, sysBase},
		{"stub image below the floor", []hostRegion{{0x1_0000_0000, 0x1000_0000}}, userFloor, sysBase},
		{"permanent reservation", permanent, 0x70_0000_0000, sysBase},
		{"removable reservations below a permanent one",
			append([]hostRegion{{0x9_3400_0000, 12 * gb}, {0xc_3540_0000, 12 * gb}}, permanent...),
			0x70_0000_0000, sysBase},
		{"a region that straddles the floor", []hostRegion{{0x3_c000_0000, 2 * gb}}, 0x4_4000_0000, sysBase},
		{"sysmsg blocks above sysBase do not count", []hostRegion{{sysBase, 0x1000_0000}}, userFloor, sysBase},
		{"unaligned end rounds up to a host page", []hostRegion{{0x8_0000_0000, 0x1000}}, 0x8_0000_4000, sysBase},
		// The libmalloc nano zone of a macOS 15 virtual machine: the larger gap
		// lies below it.
		{"a mapping near 0x600000000000 splits the range",
			append(append([]hostRegion{}, permanent...), hostRegion{0x6000_0000_0000, 0x2000_0000}),
			0x70_0000_0000, 0x6000_0000_0000},
		{"the larger gap wins above a mapping",
			append(append([]hostRegion{}, permanent...), hostRegion{0x1000_0000_0000, 0x2000_0000}),
			0x1000_2000_0000, sysBase},
		{"an ordinary mapping below the reservations is ignored",
			append([]hostRegion{{0x5_0000_0000, 0x10_0000}}, permanent...), 0x70_0000_0000, sysBase},
	} {
		lo, hi, err := userRangeFromRegions(listerFor(c.regions))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if lo != c.wantLo || hi != c.wantHi {
			t.Errorf("%s: range = [%#x, %#x), want [%#x, %#x)", c.name, lo, hi, c.wantLo, c.wantHi)
		}
	}

	if _, _, err := userRangeFromRegions(listerFor([]hostRegion{{userFloor, sysBase - userFloor}})); err == nil {
		t.Error("a mapping that spans the whole range must fail")
	}
	boom := errors.New("task is gone")
	if _, _, err := userRangeFromRegions(func(uint64) (hostRegion, bool, error) { return hostRegion{}, false, boom }); !errors.Is(err, boom) {
		t.Errorf("a lister error must propagate, got %v", err)
	}
	if _, _, err := userRangeFromRegions(func(addr uint64) (hostRegion, bool, error) { return hostRegion{start: addr}, true, nil }); err == nil {
		t.Error("an empty region must fail instead of looping")
	}
}

// TestGuestRangeHasNoHostHoles proves that the guest range works on this host.
// The test maps a page at addresses across [MinUserAddress, sysBase) and runs
// guest code that stores to and reloads from each of them. Before the Platform
// computed its minimum from the template layout, a store into the host
// reservation at 0x455e0c0000 ended a V8 guest with SIGBUS.
func TestGuestRangeHasNoHostHoles(t *testing.T) {
	p := newPlatform(t)
	lo := uint64(p.MinUserAddress())
	if lo < userFloor || lo%blockSize != 0 {
		t.Fatalf("MinUserAddress = %#x, want a host-page-aligned value at or above %#x", lo, uint64(userFloor))
	}
	// 0x455e0c0000 sits inside the macOS reservation on Apple silicon, so
	// the minimum must lie above it on that hardware.
	if lo <= 0x45_5e0c_0000 {
		t.Fatalf("MinUserAddress = %#x lies inside the host reservation at 0x455e0c0000", lo)
	}
	r := newRig(t, p)
	hi := uint64(p.MaxUserAddress())
	targets := []uint64{lo, lo + 0x1_0000_0000, (lo + hi) / 2 &^ (blockSize - 1), hi - blockSize}
	for _, va := range targets {
		r.mapPage(va, hostarch.ReadWrite)
	}
	// str x1, [x0]; ldr x2, [x0]; svc #0
	r.program(0xf9000001, 0xf9400002, 0xd4000001)
	for _, va := range targets {
		r.ac.SetIP(codeVA)
		r.regs().Regs[0] = va
		r.regs().Regs[1] = 0x1122_3344_5566_7788
		r.regs().Regs[8] = 93
		si, _, err := r.run()
		mustSyscall(t, si, err, 93, r.ac)
		if got := r.regs().Regs[2]; got != 0x1122_3344_5566_7788 {
			t.Errorf("va %#x: reloaded %#x", va, got)
		}
	}
}

// kindMM is a memory manager that describes every mapping as one kind.
type kindMM struct {
	*testMM
	kind platform.MappingKind
}

func (m *kindMM) ExecImageAt(context.Context, hostarch.Addr) platform.ExecImage {
	return platform.ExecImage{Kind: m.kind}
}

// TestScopeOfLeavesUnprovableMemoryAlone covers the kinds of mapping that
// hold no provable code.
func TestScopeOfLeavesUnprovableMemoryAlone(t *testing.T) {
	p := &Platform{}
	const base = 0x5555_0000_0000
	for _, kind := range []platform.MappingKind{platform.MappingUnmapped, platform.MappingAnonymous, platform.MappingSpecial} {
		scope := p.scopeOf(context.Background(), &kindMM{kind: kind}, base)
		if scope.contains(base) || scope.contains(base+blockSize-4) {
			t.Errorf("kind %d: the scope contains words of a block without provable code", kind)
		}
	}
	if scope := p.scopeOf(context.Background(), struct{ platform.MemoryManager }{}, base); !scope.contains(base) {
		t.Error("a memory manager that cannot describe mappings must get the whole-block scan")
	}
}

// TestAnonymousCodeKeepsItsDataWords runs a guest that loads a data word
// which decodes as `mov x3, x18`. The word sits in an executable page behind
// the code. With a memory manager that reports the mapping as anonymous, as
// it does for JIT output, the guest reads its own word. With no description
// of the mapping, the whole-block scan rewrites the word, and the guest reads
// a branch to a trampoline island. V8 object pointers broke that way.
func TestAnonymousCodeKeepsItsDataWords(t *testing.T) {
	const dataWord = 0xaa1203e3 // mov x3, x18
	prog := []uint32{
		0x10000060, // adr x0, .+12
		0xb9400001, // ldr w1, [x0]
		insnSVC0,
		dataWord,
	}
	runWith := func(t *testing.T, kind platform.MappingKind, described bool) uint64 {
		p := newPlatform(t)
		r := newRig(t, p)
		r.program(prog...)
		r.regs().Regs[8] = 93
		var mm platform.MemoryManager = r.mm
		if described {
			mm = &kindMM{testMM: r.mm, kind: kind}
		}
		si, _, err := r.ctx.Switch(r.rctx, mm, r.ac, -1)
		mustSyscall(t, si, err, 93, r.ac)
		return r.regs().Regs[1] & 0xffff_ffff
	}
	if got := runWith(t, platform.MappingAnonymous, true); got != dataWord {
		t.Errorf("anonymous mapping: the guest read %#x, want its own data word %#x", got, uint32(dataWord))
	}
	if got := runWith(t, 0, false); got == dataWord {
		t.Errorf("undescribed mapping: the guest read %#x, which means that the whole-block scan did not run", got)
	}
}

func TestIslandSlotsReclaimedOnRepatchAndUnmap(t *testing.T) {
	p := newPlatform(t)
	r := newRig(t, p)
	mem := r.mapPage(dataVA, hostarch.AccessType{Read: true, Write: true, Execute: true})
	words := []uint32{movz(8, 10), insnSVC0}
	for i := 0; i < 64; i++ {
		words = append(words, insnSVC0)
	}
	for i, w := range words {
		binary.LittleEndian.PutUint32(mem[i*4:], w)
	}
	r.regs().Pc = dataVA
	si, _, err := r.run()
	mustSyscall(t, si, err, 10, r.ac)

	// Each patch of dataVA allocates 65 trap slots (65 * 56 = 3640 bytes).
	// Ten repatches exceed a 16KB island (16384 bytes) unless restoreData
	// reclaims the block's slots.
	const rounds = 10
	for i := 0; i < rounds; i++ {
		if ok, err := r.as.restoreData(dataVA); !ok || err != nil {
			t.Fatalf("round %d: restoreData = (%v, %v), want (true, nil)", i, ok, err)
		}
		r.regs().Pc = dataVA
		si, _, err := r.run()
		mustSyscall(t, si, err, 10, r.ac)
	}

	r.as.mu.Lock()
	islandCount := len(r.as.islands)
	r.as.mu.Unlock()
	if islandCount != 1 {
		t.Fatalf("islands allocated after %d repatches = %d, want 1", rounds, islandCount)
	}

	r.as.Unmap(hostarch.Addr(dataVA), blockSize)
	r.as.mu.Lock()
	defer r.as.mu.Unlock()
	for base, isl := range r.as.islands {
		for wIdx, bits := range isl.usedBits {
			if bits != 0 {
				t.Errorf("island %#x word %d has usedBits %#x after Unmap, want 0", base, wIdx, bits)
			}
		}
	}
}
