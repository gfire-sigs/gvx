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
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type occupied struct{ base, end uint64 }

// walkStub returns the regions of the stub that are not free, merged when
// adjacent, within [lo, hi).
func walkStub(proc windows.Handle, lo, hi uint64) []occupied {
	var out []occupied
	addr := lo
	for addr < hi {
		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(proc, uintptr(addr), &mbi, unsafe.Sizeof(mbi)); err != nil {
			break
		}
		base := uint64(mbi.BaseAddress)
		end := base + uint64(mbi.RegionSize)
		if mbi.State != 0x10000 {
			if base < lo {
				base = lo
			}
			if n := len(out); n > 0 && out[n-1].end == base {
				out[n-1].end = end
			} else {
				out = append(out, occupied{base, end})
			}
		}
		if end <= addr {
			break
		}
		addr = end
	}
	return out
}

func freeAt(occ []occupied, base, size uint64) bool {
	for _, o := range occ {
		if o.base < base+size && base < o.end {
			return false
		}
	}
	return true
}

var procNtQueryVirtualMemory = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryVirtualMemory")

func mappedName(proc windows.Handle, addr uint64) string {
	var buf [1024]uint16
	var ret uintptr
	// MemoryMappedFilenameInformation = 2: a UNICODE_STRING, then its text.
	r, _, _ := procNtQueryVirtualMemory.Call(uintptr(proc), uintptr(addr), 2, uintptr(unsafe.Pointer(&buf[0])), unsafe.Sizeof(buf), uintptr(unsafe.Pointer(&ret)))
	if r != 0 {
		return ""
	}
	return windows.UTF16ToString(buf[8:])
}

// dumpStub prints every region of the stub in [lo, hi) with its attributes.
func dumpStub(proc windows.Handle, stub int, phase string, lo, hi uint64) {
	addr := lo
	for addr < hi {
		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(proc, uintptr(addr), &mbi, unsafe.Sizeof(mbi)); err != nil {
			return
		}
		base := uint64(mbi.BaseAddress)
		end := base + uint64(mbi.RegionSize)
		if mbi.State != 0x10000 {
			name := ""
			if mbi.Type != 0x20000 {
				name = mappedName(proc, base)
			}
			fmt.Printf("PROBEREGION stub=%d phase=%s %#x-%#x size=%#x alloc=%#x state=%#x prot=%#x allocprot=%#x type=%#x %s\n",
				stub, phase, base, end, end-base, uint64(mbi.AllocationBase), mbi.State, mbi.Protect, mbi.AllocationProtect, mbi.Type, name)
		}
		if end <= addr {
			return
		}
		addr = end
	}
}

// allocationOf returns the allocation that holds addr in proc.
func allocationOf(proc windows.Handle, addr uint64) (base, size uint64) {
	var mbi windows.MemoryBasicInformation
	if err := windows.VirtualQueryEx(proc, uintptr(addr), &mbi, unsafe.Sizeof(mbi)); err != nil {
		return 0, 0
	}
	base = uint64(mbi.AllocationBase)
	for a := base; ; {
		if err := windows.VirtualQueryEx(proc, uintptr(a), &mbi, unsafe.Sizeof(mbi)); err != nil || uint64(mbi.AllocationBase) != base {
			return base, a - base
		}
		a = uint64(mbi.BaseAddress) + uint64(mbi.RegionSize)
	}
}

// stubIdentity returns the allocations of the PEB, the TEB, and the initial
// stack of a suspended stub.
func stubIdentity(proc, thread windows.Handle) (peb, teb, stack occupied) {
	var pbi windows.PROCESS_BASIC_INFORMATION
	var n uint32
	if err := windows.NtQueryInformationProcess(proc, windows.ProcessBasicInformation, unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), &n); err != nil {
		return
	}
	var tbi [48]byte
	if r, _, _ := procNtQueryInformationThread.Call(uintptr(thread), 0, uintptr(unsafe.Pointer(&tbi[0])), unsafe.Sizeof(tbi), uintptr(unsafe.Pointer(&n))); r != 0 {
		return
	}
	tebAddr := *(*uint64)(unsafe.Pointer(&tbi[8]))
	// NT_TIB.StackLimit lies at offset 0x10 of the TEB on amd64 and arm64.
	var limit uint64
	var got uintptr
	if err := windows.ReadProcessMemory(proc, uintptr(tebAddr+0x10), (*byte)(unsafe.Pointer(&limit)), 8, &got); err != nil {
		return
	}
	span := func(addr uint64) occupied {
		b, s := allocationOf(proc, addr)
		return occupied{b, b + s}
	}
	return span(uint64(uintptr(unsafe.Pointer(pbi.PebBaseAddress)))), span(tebAddr), span(limit)
}

// TestProbeStubLayout prints which ranges between 4 GiB and 16 TiB hold
// something in new stub processes, before and after the loader runs. It also
// names the allocations that hold the PEB, the TEB, and the initial stack, and
// tries to release the PEB allocation. It is a measurement, not a check: it
// fails only when a stub cannot start.
func TestProbeStubLayout(t *testing.T) {
	if os.Getenv("GVX_PROBE_LAYOUT") == "" {
		t.Skip("set GVX_PROBE_LAYOUT=<count> to run the probe")
	}
	n, _ := strconv.Atoi(os.Getenv("GVX_PROBE_LAYOUT"))
	if n <= 0 {
		n = 40
	}
	const (
		g     = uint64(1) << 30
		lo    = uint64(4) * g
		hi    = uint64(0x100000000000)
		top   = uint64(0x7FFFFFFF0000)
		cdsSz = uint64(2) * g
	)
	p := newPlatform(t)
	var candidates []uint64
	for a := 4 * g; a < 32*g; a += 4 * g {
		candidates = append(candidates, a)
	}
	for a := 32 * g; a < 1024*g; a += 32 * g {
		candidates = append(candidates, a)
	}
	type phase struct {
		name         string
		free         map[uint64]int // candidate -> stubs with [a, a+1 GiB) free
		free2        map[uint64]int
		allFree      int // stubs where all of [4G,1T) is free
		allFreeTo16T int // stubs where all of [4G,16T) is free
		okAny        int // stubs with at least one free candidate
		gapLow       int // stubs where [0x7FFF0000, 4G) is free
		gapHigh      int // stubs where [3T, 16T) is free
	}
	identity := map[string]int{}
	phases := []*phase{
		{name: "suspended", free: map[uint64]int{}, free2: map[uint64]int{}},
		{name: "loaded", free: map[uint64]int{}, free2: map[uint64]int{}},
	}
	for i := range n {
		sh, err := p.host.newStub()
		if err != nil {
			t.Fatalf("newStub: %v", err)
		}
		sp := &stubProc{
			p: p, pid: sh.pid, proc: sh.proc, main: sh.thread, level: sh.level,
			threads: make(map[uint32]*thread),
			deadCh:  make(chan struct{}),
		}
		t.Cleanup(sp.destroy)
		th0 := newThread(sp, sh.thread, sh.tid)
		th0.ctx = nil
		sp.threads[sh.tid] = th0
		p.dbg.register(sp)

		record := func(ph *phase) {
			all := walkStub(sp.proc, 0x10000, top)
			for _, o := range all {
				if o.end > lo && o.base < hi {
					fmt.Printf("PROBELAYOUT stub=%d phase=%s %#x-%#x size=%#x\n", i, ph.name, o.base, o.end, o.end-o.base)
				}
			}
			any := false
			for _, a := range candidates {
				if freeAt(all, a, g) {
					ph.free[a]++
					any = true
				}
				if freeAt(all, a, cdsSz) {
					ph.free2[a]++
				}
			}
			if any {
				ph.okAny++
			}
			if freeAt(all, lo, 1024*g-lo) {
				ph.allFree++
			}
			if freeAt(all, lo, hi-lo) {
				ph.allFreeTo16T++
			}
			if freeAt(all, 0x7FFF0000, lo-0x7FFF0000) {
				ph.gapLow++
			}
			if freeAt(all, 3<<40, hi-3<<40) {
				ph.gapHigh++
			}
		}
		peb, teb, stack := stubIdentity(sp.proc, sp.main)
		identity[fmt.Sprintf("pebAlloc=%#x tebInPebAlloc=%v stackAlloc=%#x pebIn[4G,1T)=%v stackIn[4G,1T)=%v",
			peb.end-peb.base, teb == peb, stack.end-stack.base, peb.base >= lo && peb.end <= 1<<40, stack.base >= lo && stack.end <= 1<<40)]++
		if i < 3 {
			dumpStub(sp.proc, i, "suspended", 0x10000, 0x7FFFFFFF0000)
		}
		record(phases[0])
		if err := ntResumeThread(sp.main); err != nil {
			t.Fatal(err)
		}
		ev, err := th0.waitEventUntil(startTimeout, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := ntSuspendThread(sp.main); err != nil {
			t.Fatal(err)
		}
		if i < 3 {
			dumpStub(sp.proc, i, "loaded", 0x10000, 0x7FFFFFFF0000)
		}
		record(phases[1])
		if err := p.dbg.reply(ev); err != nil {
			t.Fatal(err)
		}
		sp.destroy()
		time.Sleep(time.Millisecond)
	}
	for k, c := range identity {
		fmt.Printf("PROBEIDENT %s count=%d\n", k, c)
	}
	// The kernel owns the PEB allocation: try to release it in one more stub.
	if sh, err := p.host.newStub(); err == nil {
		sp := &stubProc{p: p, pid: sh.pid, proc: sh.proc, main: sh.thread, level: sh.level, threads: make(map[uint32]*thread), deadCh: make(chan struct{})}
		th0 := newThread(sp, sh.thread, sh.tid)
		th0.ctx = nil
		sp.threads[sh.tid] = th0
		p.dbg.register(sp)
		peb, _, _ := stubIdentity(sp.proc, sp.main)
		r, _, e := procVirtualFreeEx.Call(uintptr(sp.proc), uintptr(peb.base), 0, windows.MEM_RELEASE)
		fmt.Printf("PROBEFREEPEB base=%#x released=%v err=%v\n", peb.base, r != 0, e)
		sp.destroy()
	}
	for _, ph := range phases {
		fmt.Printf("PROBESUMMARY phase=%s stubs=%d anyCandidateFree=%d all[4G,1T)free=%d all[4G,16T)free=%d [0x7FFF0000,4G)free=%d [3T,16T)free=%d\n", ph.name, n, ph.okAny, ph.allFree, ph.allFreeTo16T, ph.gapLow, ph.gapHigh)
		for _, a := range candidates {
			fmt.Printf("PROBECAND phase=%s cand=%#x free1G=%d free2G=%d\n", ph.name, a, ph.free[a], ph.free2[a])
		}
	}
}
