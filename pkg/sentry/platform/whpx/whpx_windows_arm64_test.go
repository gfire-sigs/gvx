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
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

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

func TestRealUserCannotReadEL1Pages(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr uint64
	}{
		{"stub code", kernelBaseA64 + kernelCodeOff},
		{"exit notification", kernelBaseA64 + kernelSysOff},
		{"communication page", kernelBaseA64 + kernelCommOff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newRealPlatform(t)
			c, mm, ac := realGuest(t, p, guestFaultCode)
			ac.StateData().Regs.Regs[1] = tc.addr
			sig, at, err := c.Switch(context.Background(), mm, ac, -1)
			if !errors.Is(err, platform.ErrContextSignal) || sig == nil {
				t.Fatalf("read EL1 page %#x: signal %v, error %v", tc.addr, sig, err)
			}
			if sig.Signo != int32(linux.SIGSEGV) || sig.Code != hvcommon.SegvAccErr || !at.Read {
				t.Errorf("read EL1 page %#x: signal %d code %d access %v", tc.addr, sig.Signo, sig.Code, at)
			}
		})
	}
}

func TestRealSecondaryProcessorRunsWhileAnotherExecutes(t *testing.T) {
	p := newRealPlatform(t)
	if p.ConcurrencyCount() < 2 {
		t.Skip("two virtual processors are required")
	}
	// STR W2, [X1] publishes readiness before the guest loops in place.
	code := []byte{0x22, 0x00, 0x00, 0xB9, 0x00, 0x00, 0x00, 0x14}
	first, mm, ac := realGuest(t, p, code)
	mem, err := p.be.allocHost(ptSlabSize)
	if err != nil {
		t.Fatal(err)
	}
	realMemMu.Lock()
	realMem[p] = append(realMem[p], mem)
	realMemMu.Unlock()
	const dataAddr = 0x500000
	if err := mm.as.(*AddressSpace).mapHost(dataAddr, mem[:pageSize], hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	ac.StateData().Regs.Regs[1] = dataAddr
	ac.StateData().Regs.Regs[2] = 1
	finished := make(chan struct{})
	var firstErr error
	go func() {
		_, _, firstErr = first.Switch(context.Background(), mm, ac, -1)
		close(finished)
	}()
	defer func() {
		first.Interrupt()
		select {
		case <-finished:
			if !errors.Is(firstErr, platform.ErrContextInterrupt) {
				t.Errorf("first processor: %v", firstErr)
			}
		case <-time.After(5 * time.Second):
			t.Error("first processor did not stop")
		}
	}()
	readyDeadline := time.NewTimer(5 * time.Second)
	defer readyDeadline.Stop()
	for atomic.LoadUint32((*uint32)(unsafe.Pointer(&mem[0]))) == 0 {
		select {
		case <-finished:
			t.Fatalf("first processor stopped before readiness: %v", firstErr)
		case <-readyDeadline.C:
			t.Fatal("first processor did not publish readiness")
		default:
			runtime.Gosched()
		}
	}
	second, secondMM, secondAC := realGuest(t, p, guestSyscallCode)
	sig, _, err := second.Switch(context.Background(), secondMM, secondAC, -1)
	if err != nil || sig != nil {
		t.Fatalf("second processor: signal %v, error %v", sig, err)
	}
	checkSyscallExit(t, secondAC)
}
