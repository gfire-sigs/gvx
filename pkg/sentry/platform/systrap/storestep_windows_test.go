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
	"bytes"
	"encoding/binary"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

var rwxAccess = hostarch.AccessType{Read: true, Write: true, Execute: true}

// mapStack maps the stack page that program maps, and points ac at the code.
func (r *rig) mapStack() {
	r.t.Helper()
	r.mapPage(stackVA, hostarch.ReadWrite)
	r.ac.SetIP(codeVA)
	r.ac.SetStack(stackVA + blockSize - 0x100)
}

func le64(v uint64) []byte { return binary.LittleEndian.AppendUint64(nil, v) }

func (r *rig) wantCall(nr uint64) {
	r.t.Helper()
	si, _, err := r.run()
	mustSyscall(r.t, si, err, nr, r.ac)
}

// TestSelfModifyingCodeRunsTheNewBytes runs a page that writes a system call
// into itself and jumps there. The engine must complete the store, patch the
// new bytes before they run, and keep the original bytes in the frame.
func TestSelfModifyingCodeRunsTheNewBytes(t *testing.T) {
	r := newRig(t, newPlatform(t))
	newCode := gSyscall(77)
	page := r.mapPage(codeVA, rwxAccess, storeCode(codeVA+0x800, newCode), gJump(codeVA+0x800))
	r.mapStack()
	r.wantCall(77)
	if got := page[0x800 : 0x800+len(newCode)]; !bytes.Equal(got, newCode) {
		t.Errorf("the frame holds % x at 0x800, want the unpatched code % x", got, newCode)
	}
}

// TestStoresIntoTheExecutingPageKeepEverySiteWorking runs a page that stores
// data into itself between system calls. Each store must reach the frame, and
// every system call after it must still trap, so the page is patched again
// after each store.
func TestStoresIntoTheExecutingPageKeepEverySiteWorking(t *testing.T) {
	r := newRig(t, newPlatform(t))
	page := r.mapPage(codeVA, rwxAccess,
		gSyscall(1),
		gStoreTo(codeVA+0x400, 0x1122334455667788),
		gSyscall(2),
		gStoreTo(codeVA+0x408, 0x99aabbccddeeff00),
		gSyscall(3),
		gStoreTo(codeVA+0x400, 0xfeedfacecafebeef),
		gSyscall(4))
	r.mapStack()
	r.wantCall(1)
	r.wantCall(2)
	if got := load64(page[0x400:]); got != 0x1122334455667788 {
		t.Errorf("after the first store the frame holds %#x at 0x400", got)
	}
	r.wantCall(3)
	r.wantCall(4)
	for off, want := range map[int]uint64{0x400: 0xfeedfacecafebeef, 0x408: 0x99aabbccddeeff00} {
		if got := load64(page[off:]); got != want {
			t.Errorf("the frame holds %#x at %#x, want %#x", got, off, want)
		}
	}
}

// TestStoreSpanningTwoExecutingPages runs a store that crosses from one
// executing page into the next. Both pages hold a copy when the store faults.
func TestStoreSpanningTwoExecutingPages(t *testing.T) {
	r := newRig(t, newPlatform(t))
	fr, mem := r.allocFrames(2, gSyscall(1), gJump(codeVA+blockSize+0x100))
	copy(mem[blockSize+0x100:], append(gSyscall(2), gJump(codeVA+0x200)...))
	copy(mem[0x200:], append(gStoreTo(codeVA+blockSize-4, 0xa1a2a3a4a5a6a7a8), gSyscall(3)...))
	r.mapRange(codeVA, fr, rwxAccess)
	r.mapStack()
	r.wantCall(1)
	r.wantCall(2)
	r.ac.SetIP(codeVA + 0x200)
	r.wantCall(3)
	want := le64(0xa1a2a3a4a5a6a7a8)
	if got := mem[blockSize-4 : blockSize+4]; !bytes.Equal(got, want) {
		t.Errorf("the frames hold % x across the page boundary, want % x", got, want)
	}
}

// TestStoreIntoTheExecutingReadOnlyPageStillFaults checks the case that no
// store step serves: the page does not allow writes.
func TestStoreIntoTheExecutingReadOnlyPageStillFaults(t *testing.T) {
	r := newRig(t, newPlatform(t))
	r.mapPage(codeVA, execAccess, gStoreTo(codeVA+0x400, 1))
	r.mapStack()
	si, at, err := r.run()
	wantSignal(t, si, err, linux.SIGSEGV)
	if at != hostarch.Write || si.Code != segvAccErr {
		t.Errorf("fault = access %v code %d, want a write that violates the permissions", at, si.Code)
	}
}

// TestStoreIntoTheExecutedFrameThroughAnotherView runs code through one view
// of a frame while it stores new code into the same frame through a second
// view. The store must complete, and the next run of the frame must execute
// the new bytes.
func TestStoreIntoTheExecutedFrameThroughAnotherView(t *testing.T) {
	r := newRig(t, newPlatform(t))
	newCode := gSyscall(42)
	fr, mem := r.allocFrames(1, storeCode(rwVA+0x800, newCode), gJump(rxVA+0x800))
	r.mapRange(rxVA, fr, execAccess)
	r.mapRange(rwVA, fr, hostarch.ReadWrite)
	r.program(gJump(rxVA))
	r.wantCall(42)
	if got := mem[0x800 : 0x800+len(newCode)]; !bytes.Equal(got, newCode) {
		t.Errorf("the frame holds % x at 0x800, want % x", got, newCode)
	}
}

// TestStoreIntoTheExecutedFrameDropsCopiesInOtherAddressSpaces stores into the
// executing frame through a second view while another address space holds a
// copy of the frame. That copy must go too.
func TestStoreIntoTheExecutedFrameDropsCopiesInOtherAddressSpaces(t *testing.T) {
	runner := newRig(t, newPlatform(t))
	writer := newRigOn(t, runner.p, runner.mf)
	fr, mem := runner.allocFrames(1, storeCode(rwVA+0x800, gSyscall(42)), gJump(rxVA+0x800))
	copy(mem[0x800:], gSyscall(41))
	runner.mapRange(rxVA, fr, execAccess)
	writer.mapRange(rxVA, fr, execAccess)
	writer.mapRange(rwVA, fr, hostarch.ReadWrite)
	runner.program(gJump(rxVA + 0x800))
	writer.program(gJump(rxVA))
	runner.wantCall(41)
	writer.wantCall(42)
	runner.ac.SetIP(codeVA)
	runner.wantCall(42)
}

// TestThreadsRunAPageWhileAnotherStoresIntoIt keeps one thread running in a
// page while another thread of the address space stores into that page. Every
// store step makes the copy writable for a short time and drops it afterwards.
// The running thread must see no fault from it and must still run afterwards.
func TestThreadsRunAPageWhileAnotherStoresIntoIt(t *testing.T) {
	r := newRig(t, newPlatform(t))
	const rounds = 16
	var writerCode []byte
	for i := range rounds {
		writerCode = append(writerCode, gStoreTo(codeVA+0xc00+8*uint64(i), uint64(i+1)*0x0101010101010101)...)
		writerCode = append(writerCode, gSyscall(9)...)
	}
	if len(writerCode) > 0x400 {
		t.Fatalf("the writer code has %d bytes, want at most 0x400", len(writerCode))
	}
	page := r.mapPage(codeVA, rwxAccess, gCountInMemory(dataVA))
	counter := r.mapPage(dataVA, hostarch.ReadWrite)
	copy(page[0x400:], writerCode)
	r.mapStack()
	writer := r.newThread()
	writer.ac.SetIP(codeVA + 0x400)
	writer.ac.SetStack(stackVA + blockSize/2)
	count := func() uint64 { return atomic.LoadUint64((*uint64)(unsafe.Pointer(&counter[0]))) }
	// waitAbove waits until the spinning thread has counted past n.
	waitAbove := func(n uint64, what string) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for count() <= n {
			if time.Now().After(deadline) {
				t.Fatalf("the spinning thread did not count past %d %s", n, what)
			}
			runtime.Gosched()
		}
	}

	type result struct {
		si  *linux.SignalInfo
		err error
	}
	done := make(chan result, 1)
	go func() {
		si, _, err := r.run()
		done <- result{si, err}
	}()
	waitAbove(0, "before the stores")
	for i := range rounds {
		writer.wantCall(9)
		if got, want := load64(page[0xc00+8*i:]), uint64(i+1)*0x0101010101010101; got != want {
			t.Fatalf("round %d: the frame holds %#x, want %#x", i, got, want)
		}
	}
	waitAbove(count(), "after the stores")
	r.ctx.Interrupt()
	select {
	case res := <-done:
		if !errors.Is(res.err, platform.ErrContextInterrupt) || res.si != nil {
			t.Fatalf("the spinning thread stopped with (%s, %v), want an interrupt", describe(res.si), res.err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("an interrupt did not stop the spinning thread")
	}
}
