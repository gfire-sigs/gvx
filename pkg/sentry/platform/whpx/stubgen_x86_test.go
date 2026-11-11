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

package whpx_test

import (
	"encoding/binary"
	"testing"

	"golang.org/x/arch/x86/x86asm"

	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
	"z.gfire.dev/gvx/pkg/sentry/platform/whpx"
)

// x86Inst is one decoded instruction with its offset in the code page.
type x86Inst struct {
	off  int
	inst x86asm.Inst
}

func decodeX86(t *testing.T, code []byte, start, end int) []x86Inst {
	t.Helper()
	var out []x86Inst
	for pc := start; pc < end; {
		inst, err := x86asm.Decode(code[pc:end], 64)
		if err != nil {
			t.Fatalf("decode at %#x: %v", pc, err)
		}
		out = append(out, x86Inst{off: pc, inst: inst})
		pc += inst.Len
	}
	return out
}

// gsStore reports whether in is MOV [gs:disp], reg and returns both.
func gsStore(in x86Inst) (disp int64, reg x86asm.Reg, ok bool) {
	if in.inst.Op != x86asm.MOV {
		return 0, 0, false
	}
	m, isMem := in.inst.Args[0].(x86asm.Mem)
	r, isReg := in.inst.Args[1].(x86asm.Reg)
	if !isMem || !isReg || m.Segment != x86asm.GS || m.Base != 0 || m.Index != 0 {
		return 0, 0, false
	}
	return m.Disp, r, true
}

// gsLoad reports whether in is MOV reg, [gs:disp].
func gsLoad(in x86Inst) (disp int64, reg x86asm.Reg, ok bool) {
	if in.inst.Op != x86asm.MOV {
		return 0, 0, false
	}
	r, isReg := in.inst.Args[0].(x86asm.Reg)
	m, isMem := in.inst.Args[1].(x86asm.Mem)
	if !isMem || !isReg || m.Segment != x86asm.GS || m.Base != 0 || m.Index != 0 {
		return 0, 0, false
	}
	return m.Disp, r, true
}

var x86Gprs = map[int]x86asm.Reg{
	0: x86asm.RAX, 1: x86asm.RCX, 2: x86asm.RDX, 3: x86asm.RBX, 5: x86asm.RBP, 6: x86asm.RSI, 7: x86asm.RDI,
	8: x86asm.R8, 9: x86asm.R9, 10: x86asm.R10, 11: x86asm.R11, 12: x86asm.R12, 13: x86asm.R13, 14: x86asm.R14, 15: x86asm.R15,
}

func TestX64EntrySpillsEveryRegister(t *testing.T) {
	s, err := whpx.BuildX64StubsForTest(whpx.KernelBaseX64ForTest)
	if err != nil {
		t.Fatal(err)
	}
	ins := decodeX86(t, s.Code, s.Entry, s.EntryEnd)
	if ins[0].inst.Op != x86asm.SWAPGS {
		t.Fatalf("entry starts with %v, want SWAPGS", ins[0].inst)
	}
	last := ins[len(ins)-1]
	if last.inst.Op != x86asm.HLT || last.off != s.HltSyscall {
		t.Fatalf("entry ends with %v at %#x, want HLT at %#x", last.inst, last.off, s.HltSyscall)
	}
	stored := map[x86asm.Reg]int64{}
	var spillRSP, loadStack bool
	for _, in := range ins[1 : len(ins)-2] {
		if d, r, ok := gsStore(in); ok {
			if r == x86asm.RSP {
				spillRSP = d == whpx.CommOffSPForTest
				continue
			}
			stored[r] = d
			continue
		}
		if d, r, ok := gsLoad(in); ok && r == x86asm.RSP {
			loadStack = d == whpx.CommOffRegsForTest+4*8
			continue
		}
		t.Errorf("unexpected instruction in the entry path: %v", in.inst)
	}
	if !spillRSP {
		t.Error("entry does not save the user RSP in CommPage.SP")
	}
	if !loadStack {
		t.Error("entry does not load the kernel stack from CommPage.Regs[4]")
	}
	for idx, reg := range x86Gprs {
		if got, ok := stored[reg]; !ok || got != int64(whpx.CommOffRegsForTest+idx*8) {
			t.Errorf("register %v is stored at %#x (present %v), want %#x", reg, got, ok, whpx.CommOffRegsForTest+idx*8)
		}
	}
	// SYSCALL clobbers RCX and R11 before the first instruction, so the
	// entry must keep them out of every scratch role.
	if _, ok := stored[x86asm.RCX]; !ok {
		t.Error("RCX is not spilled")
	}
	exit := ins[len(ins)-2]
	if exit.inst.Op != x86asm.MOV || exit.inst.Args[1] != x86asm.Imm(whpx.ExitSyscall) {
		t.Errorf("entry writes %v before HLT, want the syscall exit reason", exit.inst)
	}
	if m, ok := exit.inst.Args[0].(x86asm.Mem); !ok || m.Disp != whpx.CommOffExitReasonForTest || m.Segment != x86asm.GS {
		t.Errorf("exit reason is written to %v, want gs:[%#x]", exit.inst.Args[0], whpx.CommOffExitReasonForTest)
	}
}

func TestX64ReloadReturnPaths(t *testing.T) {
	s, err := whpx.BuildX64StubsForTest(whpx.KernelBaseX64ForTest)
	if err != nil {
		t.Fatal(err)
	}
	ins := decodeX86(t, s.Code, s.Reload, s.ReloadEnd)
	index := map[int]int{}
	for i, in := range ins {
		index[in.off] = i
	}
	target := func(in x86Inst) int {
		rel, ok := in.inst.Args[0].(x86asm.Rel)
		if !ok {
			t.Fatalf("%v has no relative target", in.inst)
		}
		i, ok := index[in.off+in.inst.Len+int(rel)]
		if !ok {
			t.Fatalf("%v jumps into the middle of an instruction", in.inst)
		}
		return i
	}

	// TEST flags,1; JZ over CR3 reload; MOV RAX,[root]; MOV CR3,RAX.
	if ins[0].inst.Op != x86asm.TEST || ins[1].inst.Op != x86asm.JE {
		t.Fatalf("reload starts with %v, %v", ins[0].inst, ins[1].inst)
	}
	if d, r, ok := gsLoad(ins[2]); !ok || r != x86asm.RAX || d != whpx.CommOffRootForTest {
		t.Errorf("root load is %v", ins[2].inst)
	}
	if ins[3].inst.Op != x86asm.MOV || ins[3].inst.Args[0] != x86asm.CR3 || ins[3].inst.Args[1] != x86asm.RAX {
		t.Errorf("CR3 write is %v", ins[3].inst)
	}
	if got := target(ins[1]); got != 4 {
		t.Errorf("JZ lands on instruction %d, want 4 (past the CR3 write)", got)
	}
	if ins[4].inst.Op != x86asm.TEST || ins[5].inst.Op != x86asm.JNE {
		t.Fatalf("mode test is %v, %v", ins[4].inst, ins[5].inst)
	}
	iret := target(ins[5])

	// SYSRET path: every register, then RSP, SWAPGS, SYSRET.
	loads := map[x86asm.Reg]int64{}
	i := 6
	for ; i < iret; i++ {
		if d, r, ok := gsLoad(ins[i]); ok {
			if r == x86asm.RSP {
				if d != whpx.CommOffSPForTest {
					t.Errorf("sysret path loads RSP from %#x", d)
				}
				continue
			}
			loads[r] = d
			continue
		}
		break
	}
	if ins[i].inst.Op != x86asm.SWAPGS || ins[i+1].inst.Op != x86asm.SYSRET || i+2 != iret {
		t.Fatalf("sysret path ends with %v, %v at %d (iret at %d)", ins[i].inst, ins[i+1].inst, i, iret)
	}
	for idx, reg := range x86Gprs {
		if loads[reg] != int64(whpx.CommOffRegsForTest+idx*8) {
			t.Errorf("sysret path loads %v from %#x, want %#x", reg, loads[reg], whpx.CommOffRegsForTest+idx*8)
		}
	}
	if sysret := s.Code[ins[i+1].off : ins[i+1].off+3]; sysret[0] != 0x48 || sysret[1] != 0x0F || sysret[2] != 0x07 {
		t.Errorf("sysret encoding is % x, want 48 0f 07 (64-bit return)", sysret)
	}

	// IRET path: kernel stack, five pushes in IRET order, registers, SWAPGS, IRETQ.
	if d, r, ok := gsLoad(ins[iret]); !ok || r != x86asm.RSP || d != whpx.CommOffRegsForTest+4*8 {
		t.Errorf("iret path starts with %v", ins[iret].inst)
	}
	wantPush := []int64{whpx.CommOffSSForTest, whpx.CommOffSPForTest, whpx.CommOffPstateForTest, whpx.CommOffCSForTest, whpx.CommOffPCForTest}
	for k, want := range wantPush {
		in := ins[iret+1+k].inst
		m, ok := in.Args[0].(x86asm.Mem)
		if in.Op != x86asm.PUSH || !ok || m.Segment != x86asm.GS || m.Disp != want {
			t.Errorf("iret push %d is %v, want PUSH gs:[%#x]", k, in, want)
		}
	}
	tail := ins[iret+1+len(wantPush):]
	if tail[len(tail)-2].inst.Op != x86asm.SWAPGS || tail[len(tail)-1].inst.Op != x86asm.IRETQ {
		t.Errorf("iret path ends with %v, %v", tail[len(tail)-2].inst, tail[len(tail)-1].inst)
	}
	if b := s.Code[tail[len(tail)-1].off : tail[len(tail)-1].off+2]; b[0] != 0x48 || b[1] != 0xCF {
		t.Errorf("iretq encoding is % x, want 48 cf", b)
	}
	iretLoads := map[x86asm.Reg]int64{}
	for _, in := range tail[:len(tail)-2] {
		d, r, ok := gsLoad(in)
		if !ok {
			t.Errorf("unexpected instruction in the iret path: %v", in.inst)
			continue
		}
		iretLoads[r] = d
	}
	for idx, reg := range x86Gprs {
		if iretLoads[reg] != int64(whpx.CommOffRegsForTest+idx*8) {
			t.Errorf("iret path loads %v from %#x, want %#x", reg, iretLoads[reg], whpx.CommOffRegsForTest+idx*8)
		}
	}
	if _, ok := iretLoads[x86asm.RCX]; !ok {
		t.Error("iret path does not restore RCX")
	}
}

func TestX64ExceptionStubsAndCommonPath(t *testing.T) {
	s, err := whpx.BuildX64StubsForTest(whpx.KernelBaseX64ForTest)
	if err != nil {
		t.Fatal(err)
	}
	for v := range whpx.X64IDTVectorsForTest {
		off := s.ExcStubs + v*whpx.X64ExcStubSizeForTest
		ins := decodeX86(t, s.Code, off, off+whpx.X64ExcStubSizeForTest)
		var pushes []int
		var jmp *x86Inst
		for k := range ins {
			in := ins[k]
			if in.inst.Op == x86asm.INT {
				break // padding
			}
			switch in.inst.Op {
			case x86asm.PUSH:
				pushes = append(pushes, int(in.inst.Args[0].(x86asm.Imm)))
			case x86asm.JMP:
				jmp = &ins[k]
			}
			if jmp != nil {
				break
			}
		}
		wantPushes := []int{v}
		if !hvcommon.VectorHasErrorCode(v) {
			wantPushes = []int{0, v}
		}
		if len(pushes) != len(wantPushes) || pushes[len(pushes)-1] != v || (len(pushes) == 2 && pushes[0] != 0) {
			t.Errorf("vector %d pushes %v, want %v", v, pushes, wantPushes)
		}
		if jmp == nil {
			t.Fatalf("vector %d has no jump", v)
		}
		if got := jmp.off + jmp.inst.Len + int(jmp.inst.Args[0].(x86asm.Rel)); got != s.Common {
			t.Errorf("vector %d jumps to %#x, want the common path at %#x", v, got, s.Common)
		}
	}

	ins := decodeX86(t, s.Code, s.Common, s.CommonEnd)
	if m, ok := ins[0].inst.Args[0].(x86asm.Mem); ins[0].inst.Op != x86asm.TEST || !ok || m.Base != x86asm.RSP || m.Disp != 24 {
		t.Errorf("common path starts with %v, want TEST [rsp+24], 3", ins[0].inst)
	}
	// The frame is popped in stack order into the CommPage fields.
	var pops []int64
	for k := 0; k < len(ins)-1; k++ {
		if ins[k].inst.Op != x86asm.POP {
			continue
		}
		d, r, ok := gsStore(ins[k+1])
		if !ok || r != x86asm.RAX {
			t.Fatalf("POP is followed by %v", ins[k+1].inst)
		}
		pops = append(pops, d)
	}
	want := []int64{
		whpx.CommOffVectorForTest,
		whpx.CommOffFaultCodeForTest,
		whpx.CommOffPCForTest,
		whpx.CommOffCSForTest,
		whpx.CommOffPstateForTest,
		whpx.CommOffSPForTest,
		whpx.CommOffSSForTest,
	}
	if len(pops) != len(want) {
		t.Fatalf("common path pops into %v, want %v", pops, want)
	}
	for i := range want {
		if pops[i] != want[i] {
			t.Errorf("pop %d stores to %#x, want %#x", i, pops[i], want[i])
		}
	}
	var sawCR2, hlts int
	for _, in := range ins {
		if in.inst.Op == x86asm.MOV && in.inst.Args[1] == x86asm.CR2 {
			sawCR2++
		}
		if in.inst.Op == x86asm.HLT {
			hlts++
		}
	}
	if sawCR2 != 1 || hlts != 2 {
		t.Errorf("common path reads CR2 %d times and has %d HLT instructions, want 1 and 2", sawCR2, hlts)
	}
	if s.Code[s.HltException] != 0xF4 || s.Code[s.HltKernel] != 0xF4 || s.Code[s.HltSyscall] != 0xF4 {
		t.Error("an HLT offset does not point at an HLT instruction")
	}
}

func TestX64DescriptorTables(t *testing.T) {
	const kb = whpx.KernelBaseX64ForTest
	s, err := whpx.BuildX64StubsForTest(kb)
	if err != nil {
		t.Fatal(err)
	}
	// The selectors must match the values that pkg/sentry/arch uses for user
	// mode (userCS 0x33, userDS 0x2b) and the SYSRET base rule.
	if whpx.X64SelUserCSForTest != 0x33 || whpx.X64SelUserSSForTest != 0x2B {
		t.Fatalf("user selectors are %#x, %#x", whpx.X64SelUserCSForTest, whpx.X64SelUserSSForTest)
	}
	if whpx.X64StarUserBaseForTest+16 != whpx.X64SelUserCSForTest || whpx.X64StarUserBaseForTest+8 != whpx.X64SelUserSSForTest {
		t.Errorf("SYSRET base %#x does not produce CS %#x and SS %#x", whpx.X64StarUserBaseForTest, whpx.X64SelUserCSForTest, whpx.X64SelUserSSForTest)
	}
	desc := func(sel int) uint64 { return binary.LittleEndian.Uint64(s.Sys[whpx.X64SysOffGDTForTest+sel&^7:]) }
	type segCheck struct {
		sel              int
		code, long, dpl3 bool
		accessed         bool
	}
	for _, c := range []segCheck{
		{whpx.X64SelKernelCSForTest, true, true, false, true},
		{whpx.X64SelKernelSSForTest, false, false, false, true},
		{whpx.X64SelUserCS32ForTest, true, false, true, true},
		{whpx.X64SelUserSSForTest, false, false, true, true},
		{whpx.X64SelUserCSForTest, true, true, true, true},
	} {
		d := desc(c.sel)
		access := byte(d >> 40)
		flags := byte(d >> 52)
		if access&0x80 == 0 || access&0x10 == 0 {
			t.Errorf("descriptor %#x is not present or not a code/data segment", c.sel)
		}
		if (access&0x08 != 0) != c.code {
			t.Errorf("descriptor %#x code bit is %v, want %v", c.sel, access&0x08 != 0, c.code)
		}
		if (access&0x60 == 0x60) != c.dpl3 || (access&0x60 == 0) == c.dpl3 {
			t.Errorf("descriptor %#x has DPL %d, want dpl3=%v", c.sel, access>>5&3, c.dpl3)
		}
		if (flags&0x2 != 0) != c.long {
			t.Errorf("descriptor %#x long bit is %v, want %v", c.sel, flags&0x2 != 0, c.long)
		}
		// The CPU writes the accessed bit when it loads a descriptor. The
		// page is read-only, so the bit must already be set.
		if access&1 == 0 {
			t.Errorf("descriptor %#x has no accessed bit", c.sel)
		}
	}
	// The segment attributes that bring-up writes must equal the descriptors.
	attr := func(sel int) uint16 {
		d := desc(sel)
		return uint16(d>>40&0xFF) | uint16(d>>52&0xF)<<12
	}
	for _, c := range []struct {
		sel  int
		want uint16
	}{
		{whpx.X64SelKernelCSForTest, whpx.X64AttrKernelCS64ForTest},
		{whpx.X64SelKernelSSForTest, whpx.X64AttrKernelSSForTest},
		{whpx.X64SelUserCS32ForTest, whpx.X64AttrUserCS32ForTest},
		{whpx.X64SelUserSSForTest, whpx.X64AttrUserDataForTest},
		{whpx.X64SelUserCSForTest, whpx.X64AttrUserCS64ForTest},
	} {
		if got := attr(c.sel); got != c.want {
			t.Errorf("attributes of selector %#x are %#x, descriptor says %#x", c.sel, c.want, got)
		}
	}
	if whpx.X64GDTLimitForTest != 7*8-1 {
		t.Errorf("GDT limit is %#x, want %#x", whpx.X64GDTLimitForTest, 7*8-1)
	}

	for v := range whpx.X64IDTVectorsForTest {
		g := s.Sys[whpx.X64SysOffIDTForTest+v*16:]
		target := uint64(binary.LittleEndian.Uint16(g[0:])) |
			uint64(binary.LittleEndian.Uint16(g[6:]))<<16 |
			uint64(binary.LittleEndian.Uint32(g[8:]))<<32
		want := kb + whpx.KernelCodeOffForTest + uint64(s.ExcStubs+v*whpx.X64ExcStubSizeForTest)
		if target != want {
			t.Errorf("IDT vector %d targets %#x, want %#x", v, target, want)
		}
		if sel := binary.LittleEndian.Uint16(g[2:]); sel != whpx.X64SelKernelCSForTest {
			t.Errorf("IDT vector %d uses selector %#x", v, sel)
		}
		if g[4] != 0 || g[5] != 0x8E {
			t.Errorf("IDT vector %d has IST %d and type %#x, want an interrupt gate with DPL 0", v, g[4], g[5])
		}
	}
	if whpx.X64IDTLimitForTest != whpx.X64IDTVectorsForTest*16-1 {
		t.Errorf("IDT limit is %#x", whpx.X64IDTLimitForTest)
	}
}

func TestX64StubsFitTheirRegions(t *testing.T) {
	s, err := whpx.BuildX64StubsForTest(whpx.KernelBaseX64ForTest)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct {
		name       string
		start, end int
		limit      int
	}{
		{"entry", s.Entry, s.EntryEnd, s.Reload},
		{"reload", s.Reload, s.ReloadEnd, s.ExcStubs},
		{"common", s.Common, s.CommonEnd, whpx.PageSizeForTest},
	} {
		if r.start >= r.end || r.end > r.limit {
			t.Errorf("%s spans [%#x, %#x) with limit %#x", r.name, r.start, r.end, r.limit)
		}
	}
}

func TestX64TSS(t *testing.T) {
	page := make([]byte, whpx.PageSizeForTest)
	c := whpx.OverlayCommPageForTest(page)
	const va = whpx.KernelBaseX64ForTest + whpx.KernelCommOffForTest
	whpx.X64InitTSSForTest(c, va)
	if got := binary.LittleEndian.Uint64(page[whpx.CommTSSOffForTest+4:]); got != va+whpx.CommStackTopForTest {
		t.Errorf("TSS.RSP0 is %#x, want %#x", got, uint64(va+whpx.CommStackTopForTest))
	}
	if got := binary.LittleEndian.Uint16(page[whpx.CommTSSOffForTest+102:]); got != whpx.CommTSSSizeForTest {
		t.Errorf("TSS I/O map base is %d, want %d so that no I/O bitmap exists", got, whpx.CommTSSSizeForTest)
	}
}
