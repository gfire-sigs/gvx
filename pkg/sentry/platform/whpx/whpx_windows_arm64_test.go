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

//go:build windows && arm64

package whpx

import (
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/sentry/arch"
)

func TestRealSecondaryProcessorSyscall(t *testing.T) {
	p := newRealPlatform(t)
	if p.vpCount < 2 {
		t.Skip("the partition has only one virtual processor")
	}
	c, mm, ac := realGuest(t, p, guestSyscallCode)
	v, err := newVP(p, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := v.destroy(); err != nil {
			t.Error(err)
		}
	})
	if result, done := c.prepareRun(v, mm.as.(*AddressSpace), ac); done {
		t.Fatal(result.err)
	}

	canceled := make(chan error, 1)
	timer := time.AfterFunc(5*time.Second, func() { canceled <- p.be.cancel(v.index) })
	err = p.be.run(v.index, v.exit)
	if !timer.Stop() {
		if cancelErr := <-canceled; cancelErr != nil {
			t.Errorf("cancel secondary processor: %v", cancelErr)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	exit, err := v.decodeExit()
	if err != nil || exit.kind != exitStub {
		t.Fatalf("secondary processor exit = %+v, %v; want a syscall trap", exit, err)
	}
	result, _ := c.onStubExit(v, exit, ac)
	if result.err != nil || result.sig != nil {
		t.Fatalf("secondary processor syscall = %+v", result)
	}
	checkSyscallExit(t, ac)
}

var (
	// svc #0
	guestSyscallCode = []byte{0x01, 0x00, 0x00, 0xD4}
	// b .
	guestLoopCode = []byte{0x00, 0x00, 0x00, 0x14}
	// ldr x0, [x1] with x1 pointing at unmapped memory.
	guestFaultCode = []byte{0x20, 0x00, 0x40, 0xF9}
)

func setGuestEntry(ac *arch.Context64, pc uintptr) {
	r := &ac.StateData().Regs
	r.Pc = uint64(pc)
	r.Sp = 0x7FFF0000
	r.Regs[8] = 172
	r.Regs[1] = 0x10000000
	r.Pstate = 0
}

func checkSyscallExit(t *testing.T, ac *arch.Context64) {
	t.Helper()
	r := &ac.StateData().Regs
	if r.Regs[8] != 172 || r.Pc != guestCodeAddr+4 {
		t.Errorf("after SVC: x8=%d pc=%#x", r.Regs[8], r.Pc)
	}
}
