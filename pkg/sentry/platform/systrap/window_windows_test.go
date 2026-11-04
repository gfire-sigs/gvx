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
	"errors"
	"fmt"
	"slices"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"z.gfire.dev/gvx/pkg/hostarch"
)

const memReserve = 0x2000

// stopPoolForTest ends the pool of p, so that the test can change the layout
// without a race with the goroutine that fills the pool.
func stopPoolForTest(p *Platform) {
	p.stopPool()
	p.pool = nil
}

func TestPlatformReservesEveryOptionalWindowOnTheCIHosts(t *testing.T) {
	p := newPlatform(t)
	want := append(windowLayout{
		{windowLow, lowBase, lowLimit},
		{windowMid, midBase, midLimit},
	}, hotSpotLayout()...)
	want = append(want, guestRange{windowHigh, winBase, winLimit})
	if !slices.Equal(p.layout, want) {
		t.Fatalf("layout = %v, want %v", p.layout, want)
	}
	if got, want := uint64(p.MinUserAddress()), lowBase; got != want {
		t.Errorf("MinUserAddress = %#x, want %#x", got, want)
	}
	// Only KUSER_SHARED_DATA separates the low and the middle windows.
	wantHoles := []hostarch.AddrRange{{Start: hostarch.Addr(lowLimit), End: hostarch.Addr(lowLimit + 0x10000)}}
	prev := midLimit
	for _, w := range hotSpotLayout() {
		wantHoles = append(wantHoles, hostarch.AddrRange{Start: hostarch.Addr(prev), End: hostarch.Addr(w.base)})
		prev = w.limit
	}
	wantHoles = append(wantHoles, hostarch.AddrRange{Start: hostarch.Addr(prev), End: hostarch.Addr(winBase)})
	if got := p.UserAddressHoles(); !slices.Equal(got, wantHoles) {
		t.Errorf("UserAddressHoles = %v, want %v", got, wantHoles)
	}
	// The memory manager asks for the holes on every mmap.
	if n := testing.AllocsPerRun(100, func() { _ = p.UserAddressHoles() }); n != 0 {
		t.Errorf("allocations per UserAddressHoles call = %v, want 0", n)
	}
}

// Each stub holds every window as one placeholder before its loader runs, and
// the kernel and the loader leave the windows alone.
func TestEveryStubHoldsEachWindowAsOnePlaceholder(t *testing.T) {
	p := newPlatform(t)
	for i := range 30 {
		sp, err := p.newStubProcFresh()
		if err != nil {
			t.Fatalf("stub %d: %v", i, err)
		}
		for _, w := range p.layout {
			var mbi windows.MemoryBasicInformation
			if err := windows.VirtualQueryEx(sp.proc, uintptr(w.base), &mbi, unsafe.Sizeof(mbi)); err != nil {
				t.Fatalf("stub %d: VirtualQueryEx(%s window): %v", i, w.name, err)
			}
			if mbi.State != memReserve || uint64(mbi.AllocationBase) != w.base || uint64(mbi.RegionSize) != w.limit-w.base {
				t.Errorf("stub %d: the %s window is state %#x, allocation base %#x, size %#x; want one reserved region of [%#x, %#x)",
					i, w.name, mbi.State, uint64(mbi.AllocationBase), uint64(mbi.RegionSize), w.base, w.limit)
			}
		}
		sp.destroy()
	}
}

// A guest runs code, and reads and writes data, in every window. Each window
// gets its own platform: the section cache keys a section by the handle value
// of the memory file, and Windows reuses that value after a memory file
// closes, so a second rig of one platform can map the section of the first.
func TestGuestRunsInEveryWindow(t *testing.T) {
	const value = 0x1122334455667788
	hs := hotSpotLayout()
	for _, w := range []guestRange{optionalWindows[0], optionalWindows[1], hs[0], hs[len(hs)-1], {windowHigh, winBase, winLimit}} {
		t.Run(fmt.Sprintf("%s@%#x", w.name, w.base), func(t *testing.T) {
			r := newRig(t, newPlatform(t))
			code, data, stack := w.base+0x200000, w.base+0x300000, w.base+0x400000
			r.mapPage(code, execAccess, gStoreTo(data, value), gLoadFrom(data), gSyscall(93))
			store := r.mapPage(data, hostarch.ReadWrite)
			r.mapPage(stack, hostarch.ReadWrite)
			r.ac.SetIP(uintptr(code))
			r.ac.SetStack(uintptr(stack + blockSize - 0x100))
			si, _, err := r.run()
			mustSyscall(t, si, err, 93, r.ac)
			if got := regAcc(r.ac); got != value {
				t.Errorf("the guest read %#x back, want %#x", got, uint64(value))
			}
			if got := load64(store); got != value {
				t.Errorf("the Sentry sees %#x in the page, want %#x", got, uint64(value))
			}
		})
	}
}

// HotSpot on arm64 tries the multiples of 4 GiB below 32 GiB for the class
// space, then multiples of 32 GiB below 1 TiB. The guest windows serve a page
// at each of the 38 places and at the last page of each HotSpot window. They
// serve nothing between the windows.
func TestGuestWindowsServeEveryHotSpotPlace(t *testing.T) {
	p := newPlatform(t)
	r := newRig(t, p)
	var places []uint64
	for a := uint64(4 << 30); a < 32<<30; a += 4 << 30 {
		places = append(places, a)
	}
	for a := uint64(32 << 30); a < 1<<40; a += 32 << 30 {
		places = append(places, a, a+hotSpotSize-blockSize)
	}

	code, stack := uint64(codeVA), uint64(stackVA)
	var prog []byte
	for i, a := range places {
		r.mapPage(a, hostarch.ReadWrite)[0] = byte(i + 1)
		prog = append(prog, gLoadFrom(a)...)
		prog = append(prog, gSyscall(93)...)
	}
	r.mapPage(code, execAccess, prog)
	r.mapPage(stack, hostarch.ReadWrite)
	r.ac.SetIP(uintptr(code))
	r.ac.SetStack(uintptr(stack + blockSize - 0x100))
	for i, a := range places {
		si, _, err := r.run()
		mustSyscall(t, si, err, 93, r.ac)
		if got := regAcc(r.ac) & 0xff; got != uint64(i+1) {
			t.Errorf("page at %#x: the guest read %d, want %d", a, got, i+1)
		}
	}
	for _, a := range []uint64{midLimit, midBase - blockSize, lowLimit, winBase - blockSize, 96<<30 + hotSpotSize, 96<<30 - blockSize} {
		fr, _ := r.allocFrames(1)
		if err := r.as.MapFile(hostarch.Addr(a), r.mf, fr, hostarch.ReadWrite, false); err == nil {
			t.Errorf("MapFile at %#x, in a hole, succeeded", a)
		}
	}
}

// A stub is thrown away when a window is taken, and the request reports the
// window after it ran out of attempts.
func TestTakenWindowIsReportedAfterTheAttempts(t *testing.T) {
	p := newPlatform(t)
	stopPoolForTest(p)
	// The kernel maps KUSER_SHARED_DATA at lowLimit in every process.
	p.setLayout([]guestRange{{"clash", lowLimit - 0x10000, lowLimit + 0x1000}})
	before := bringUpStats.discarded.Load()
	sp, err := p.newStubProcFresh()
	if err == nil {
		sp.destroy()
		t.Fatal("a stub came up although the window is taken")
	}
	var taken *windowTakenError
	if !errors.As(err, &taken) || taken.window != "clash" || !errors.Is(err, errWindowTaken) {
		t.Fatalf("error = %v, want a taken-window error for the clash window", err)
	}
	if got := bringUpStats.discarded.Load() - before; got != windowAttempts {
		t.Errorf("discarded stubs = %d, want %d", got, windowAttempts)
	}
}

// The platform drops every window of the name that no stub can reserve and
// keeps the windows of the other names. Only the first clash window covers
// KUSER_SHARED_DATA; the second one is free.
func TestSelectWindowsDropsEveryWindowOfTheTakenName(t *testing.T) {
	p := newPlatform(t)
	stopPoolForTest(p)
	optional := []guestRange{
		{windowLow, lowBase, lowLimit - 0x10000},
		{"clash", lowLimit - 0x10000, lowLimit + 0x1000},
		{windowMid, midBase, midLimit},
		{"clash", 96 << 30, 98 << 30},
	}
	sp := p.selectWindows(optional)
	if sp == nil {
		t.Fatal("selectWindows returned no stub")
	}
	defer sp.destroy()
	want := windowLayout{optional[0], optional[2], {windowHigh, winBase, winLimit}}
	if !slices.Equal(p.layout, want) {
		t.Errorf("layout = %v, want %v", p.layout, want)
	}
	if got := p.userMin; got != lowBase {
		t.Errorf("userMin = %#x, want %#x", got, lowBase)
	}
}

// A failure that no window caused leaves the high window only.
func TestSelectWindowsFallsBackToTheHighWindow(t *testing.T) {
	p := newPlatform(t)
	stopPoolForTest(p)
	// The high window is not optional. A window that overlaps it makes the
	// reservation of the high window fail, which no drop can repair.
	p.layout = nil
	bad := guestRange{"overlap", winBase + 0x10000, winBase + 0x20000}
	sp := p.selectWindows([]guestRange{bad})
	if sp != nil {
		sp.destroy()
		t.Fatal("selectWindows returned a stub although the high window cannot be reserved")
	}
	if want := (windowLayout{{windowHigh, winBase, winLimit}}); !slices.Equal(p.layout, want) {
		t.Errorf("layout = %v, want %v", p.layout, want)
	}
	if got := p.userMin; got != winBase {
		t.Errorf("userMin = %#x, want %#x", got, winBase)
	}
}

// hotSpotLayout returns the HotSpot windows of optionalWindows.
func hotSpotLayout() []guestRange {
	var out []guestRange
	for _, w := range optionalWindows {
		if w.name == windowHotSpot {
			out = append(out, w)
		}
	}
	return out
}
