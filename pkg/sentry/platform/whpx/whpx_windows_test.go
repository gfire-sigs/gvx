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

package whpx

import (
	"errors"
	"runtime"
	"sync"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/cpuid"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// These tests run guest code in a real partition. They skip when the host has
// no hypervisor. Other hosts never run them.

const guestCodeAddr = 0x400000

func init() {
	// arch.New builds the floating-point state of the host. On amd64 that
	// reads the CPUID feature set, which must exist before the first test.
	cpuid.Initialize()
}

// realMem holds the host memory that the guest of each real platform maps.
var (
	realMemMu sync.Mutex
	realMem   = map[*Platform][][]byte{}
)

func newRealPlatform(t *testing.T) *Platform {
	t.Helper()
	p, err := New()
	if errors.Is(err, ErrUnsupported) {
		t.Skipf("no Windows Hypervisor Platform: %v", err)
	}
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		realMemMu.Lock()
		defer realMemMu.Unlock()
		for _, mem := range realMem[p] {
			if err := p.be.freeHost(mem); err != nil {
				t.Error(err)
			}
		}
		delete(realMem, p)
	})
	return p
}

// realGuest maps code at guestCodeAddr and returns a context that runs it.
func realGuest(t *testing.T, p *Platform, code []byte) (*Context, *fakeMM, *arch.Context64) {
	t.Helper()
	as := newTestAS(t, p)
	mem, err := p.be.allocHost(ptSlabSize)
	if err != nil {
		t.Fatal(err)
	}
	// The partition keeps the mapping of mem until Close, so newRealPlatform
	// frees the memory after Close.
	realMemMu.Lock()
	realMem[p] = append(realMem[p], mem)
	realMemMu.Unlock()
	copy(mem, code)
	if err := as.mapHost(guestCodeAddr, mem[:pageSize], hostarch.AccessType{Read: true, Execute: true}); err != nil {
		t.Fatal(err)
	}
	c := p.NewContext(nil).(*Context)
	t.Cleanup(c.Release)
	ac := arch.New(arch.Host)
	setGuestEntry(ac, guestCodeAddr)
	return c, &fakeMM{as: as}, ac
}

func TestRealPlatformLifecycle(t *testing.T) {
	p := newRealPlatform(t)
	if p.ConcurrencyCount() < 1 || p.MapUnit() != 2<<20 {
		t.Errorf("concurrency %d, map unit %d", p.ConcurrencyCount(), p.MapUnit())
	}
	if runtime.GOARCH == "arm64" && !p.arm64 {
		t.Error("an arm64 build runs the amd64 path")
	}
}

func TestRealSyscallRoundTrip(t *testing.T) {
	p := newRealPlatform(t)
	c, mm, ac := realGuest(t, p, guestSyscallCode)
	for range 3 {
		sig, _, err := c.Switch(nil, mm, ac, -1)
		if err != nil || sig != nil {
			t.Fatalf("Switch returned %v, %v", sig, err)
		}
		checkSyscallExit(t, ac)
		// Run the same instruction again.
		setGuestEntry(ac, guestCodeAddr)
	}
}

func TestRealPageFault(t *testing.T) {
	p := newRealPlatform(t)
	c, mm, ac := realGuest(t, p, guestFaultCode)
	sig, at, err := c.Switch(nil, mm, ac, -1)
	if !errors.Is(err, platform.ErrContextSignal) || sig == nil {
		t.Fatalf("Switch returned %v, %v", sig, err)
	}
	if sig.Signo != int32(linux.SIGSEGV) || sig.Code != hvcommon.SegvMapErr || !at.Read {
		t.Errorf("signal %d code %d access %+v", sig.Signo, sig.Code, at)
	}
}

func TestRealInterruptStopsALoop(t *testing.T) {
	p := newRealPlatform(t)
	c, mm, ac := realGuest(t, p, guestLoopCode)
	done := make(chan error, 1)
	go func() {
		_, _, err := c.Switch(nil, mm, ac, -1)
		done <- err
	}()
	for {
		select {
		case err := <-done:
			if !errors.Is(err, platform.ErrContextInterrupt) {
				t.Fatalf("Switch returned %v", err)
			}
			return
		default:
			c.Interrupt()
			runtime.Gosched()
		}
	}
}
