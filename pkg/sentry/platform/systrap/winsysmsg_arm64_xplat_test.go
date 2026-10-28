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

//go:build (darwin || windows) && arm64

package systrap

import (
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/arch"
)

func newTrapContext() *arch.Context64 {
	ac := arch.New(arch.Host)
	regs := &ac.StateData().Regs
	for i := range regs.Regs {
		regs.Regs[i] = 0x100 + uint64(i)
	}
	regs.Sp = 0x7000_0000_1000
	regs.Pc = 0x5555_0000_0104
	regs.Pstate = 0xa000_0000
	return ac
}

func TestWinRegsCarryTheGuestStateAcrossTheSysmsg(t *testing.T) {
	src := newTrapContext()
	var r winRegs
	r.loadFrom(src)

	dst := arch.New(arch.Host)
	// The bits of PSTATE outside the condition flags belong to the Sentry.
	dst.StateData().Regs.Pstate = 0x5
	const ret = 0x5555_0000_0104
	r.storeTo(dst, ret)

	want, got := &src.StateData().Regs, &dst.StateData().Regs
	if got.Regs != want.Regs {
		t.Errorf("general registers differ after the round trip")
	}
	if got.Sp != want.Sp {
		t.Errorf("sp = %#x, want %#x", got.Sp, want.Sp)
	}
	if got.Pc != ret {
		t.Errorf("pc = %#x, want the return address %#x", got.Pc, uint64(ret))
	}
	if got.Pstate&pstateNZCV != want.Pstate&pstateNZCV {
		t.Errorf("condition flags = %#x, want %#x", got.Pstate&pstateNZCV, want.Pstate&pstateNZCV)
	}
	if got.Pstate&^pstateNZCV != 0x5 {
		t.Errorf("storeTo changed the PSTATE bits outside the condition flags: %#x", got.Pstate)
	}
	if orig := dst.StateData().OrigR0; orig != want.Regs[0] {
		t.Errorf("OrigR0 = %#x, want x0 %#x", orig, want.Regs[0])
	}
}

func TestWinTrapResumesHotOnlyAtTheSameProgramCounterAndStack(t *testing.T) {
	ac := newTrapContext()
	regs := &ac.StateData().Regs
	trap := winTrap{site: regs.Pc - winSiteLen, ret: regs.Pc, sp: regs.Sp}
	if got := trap.resumeState(ac); got != winStateRunHot {
		t.Fatalf("an unchanged context resumes with state %d, want RunHot", got)
	}
	// A system call result changes x0 and nothing else that the slot cares about.
	regs.Regs[0] = 1234
	if got := trap.resumeState(ac); got != winStateRunHot {
		t.Errorf("a changed return value resumes with state %d, want RunHot", got)
	}
	for name, change := range map[string]func(){
		"a changed program counter": func() { regs.Pc += 4 },
		"a changed stack pointer":   func() { regs.Sp -= 0x100 },
	} {
		saved := *regs
		change()
		if got := trap.resumeState(ac); got != winStateRunCold {
			t.Errorf("%s resumes with state %d, want RunCold", name, got)
		}
		*regs = saved
	}
}

func TestWinSiteReturnIsTheNextInstruction(t *testing.T) {
	if got := winSiteReturn(0x1000); got != 0x1004 {
		t.Fatalf("the return address of a site at 0x1000 is %#x, want 0x1004", got)
	}
}

func TestWinSysmsgLoadVectorMarksTheImageDirty(t *testing.T) {
	var sm winSysmsg
	if sm.FPDirty != 0 {
		t.Fatal("a new sysmsg is dirty")
	}
	sm.loadVector(newTrapContext())
	if sm.FPDirty != 1 {
		t.Errorf("FPDirty = %d after the Sentry wrote the image, want 1", sm.FPDirty)
	}
}
