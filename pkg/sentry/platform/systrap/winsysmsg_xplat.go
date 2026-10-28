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

//go:build darwin || windows

package systrap

import (
	"sync/atomic"
	"unsafe"
)

// The Windows fast path keeps one shared page for each guest thread: the
// winSysmsg. The Sentry and the stub thread map the page. A patched system
// call instruction jumps to a slot in a trampoline island. The slot jumps to
// the spill routine in the engine pages. The routine saves the guest
// registers in the winSysmsg, publishes winStateTrapped, and waits for the
// Sentry. The Sentry loads the registers, runs the system call, and publishes
// the resume state. No debug event and no thread context call is involved.
//
// This file holds the layout of the arena and of the shared page. The files
// with the suffix _amd64_xplat and _arm64_xplat hold the register block. The
// constants carry the prefix "win", because the macOS engine has its own
// sysmsg with other values under similar names.

const (
	// winEnginePagesSize is the size of the engine pages at the start of the
	// arena: the code pages, then the data pages.
	winEnginePagesSize = 0x10000
	// winCodeSize is the size of the executable part of the engine pages.
	winCodeSize = 0x8000
	// winSpillOffset is the offset of the spill routine in the engine pages.
	// The first part of the code pages holds the routines of the arch files:
	// the amd64 FS base trampolines and the arm64 TLS routine.
	winSpillOffset = 0x4000

	// winThreadAreaSize is the distance between the areas of two threads. One
	// area holds the winSysmsg page, then the page of the stub stack.
	winThreadAreaSize = 0x10000
	// winSysmsgSize is the size of the page that the Sentry and the stub share.
	winSysmsgSize = 0x1000
	// winStubStackSize is the size of the stack of the spill routine.
	winStubStackSize = 0x1000
	// winThreadMapSize is the part of one thread area that both sides map.
	winThreadMapSize = winSysmsgSize + winStubStackSize
	// winStubStackTop is the offset of the stack top of the spill routine from
	// the start of the area. The routine keeps 64 bytes below the top for the
	// shadow space of a call and for the alignment of the stack pointer.
	winStubStackTop = winThreadMapSize - 0x40

	// winMaxThreads is the number of guest threads with a fast slot in one
	// stub. One stub process holds at most this many guest threads.
	winMaxThreads = 512

	// winArenaSize is the part of the guest window that the engine keeps for
	// itself: the engine pages, then one area for each fast thread.
	winArenaSize = winEnginePagesSize + winMaxThreads*winThreadAreaSize
)

// Offsets of the thread-environment-block words that the amd64 slot and spill
// routine use. Every word lies in the NT_TIB part of the TEB. No code of the
// stub uses these words: the loader never runs in a guest thread, and the guest
// cannot write the GS base. The arm64 routine does not use the TEB, because the
// guest owns x18 and TPIDRRO_EL0 holds the CPU number.
const (
	// winTEBScratchA and winTEBScratchB are the scratch words of the amd64
	// slot and spill routine (SubSystemTib and FiberData).
	winTEBScratchA = 0x18
	winTEBScratchB = 0x20
	// winTEBSysmsg holds the address of the winSysmsg of the thread
	// (ArbitraryUserPointer).
	winTEBSysmsg = 0x28
)

// States of the handoff word.
const (
	// winStateIdle means that the thread runs guest code. The Sentry never
	// writes the state while the thread is Idle.
	winStateIdle uint32 = iota
	// winStateTrapped means that the stub saved the guest registers and waits
	// for the Sentry. The stub publishes it with release semantics.
	winStateTrapped
	// winStateRunHot means that the Sentry changed only registers that the
	// stub can reload. The stub reloads the registers from the winSysmsg and
	// jumps back to the slot.
	winStateRunHot
	// winStateRunCold means that the Sentry changed the program counter or
	// the stack. The stub loads the registers, then raises a trap with the
	// registers in place, and the Sentry continues the thread at Target.
	winStateRunCold
)

// winSysmsgHeader is the part of the winSysmsg that does not depend on the
// architecture. All fields have natural alignment.
//
// The Sentry writes State, with Trapped excepted, Target, and the register
// block while the state is Trapped. The stub writes the other fields. Each
// waiter flag has one writer, so no operation needs a read-modify-write.
type winSysmsgHeader struct {
	// State is the handoff word.
	State uint32
	// SentryWaiter is set by the Sentry before it sleeps on GuestEvent.
	SentryWaiter uint32
	// StubWaiter is set by the stub before it sleeps on HostEvent.
	StubWaiter uint32
	_          uint32
	// GuestEvent and HostEvent are handles in the stub process. The stub sets
	// GuestEvent to wake the Sentry and waits on HostEvent.
	GuestEvent uint64
	HostEvent  uint64
	// NtSetEvent and NtWaitForSingleObject are the addresses of the ntdll
	// functions in the stub process. System DLLs load at the same address in
	// every process of one boot.
	NtSetEvent            uint64
	NtWaitForSingleObject uint64
	// Tail is the address of the slot tail that the stub trapped from.
	Tail uint64
	// Target is the program counter of a RunCold resume.
	Target uint64
	// TLS is the thread pointer of the guest on arm64. The real TPIDR_EL0 of
	// the thread holds the address of this page, so the spill routine finds the
	// page without a free register. A patched `mrs xN, tpidr_el0` loads this word.
	TLS uint64
}

// Offsets inside the header. The spill routine encodes them.
const (
	winOffState        = 0x00
	winOffSentryWaiter = 0x04
	winOffStubWaiter   = 0x08
	winOffGuestEvent   = 0x10
	winOffHostEvent    = 0x18
	winOffNtSetEvent   = 0x20
	winOffNtWait       = 0x28
	winOffTail         = 0x30
	winOffTarget       = 0x38
	winOffTLS          = 0x40
	// winOffRegs is the offset of the register block.
	winOffRegs = 0x48
)

// winSpinStub and winSpinSentry are the numbers of polls before a side sleeps.
const (
	winSpinStub   = 1024
	winSpinSentry = 512
)

var _ = [1]struct{}{}[unsafe.Sizeof(winSysmsgHeader{})-winOffRegs]

func (h *winSysmsgHeader) state() *atomic.Uint32 {
	return (*atomic.Uint32)(unsafe.Pointer(&h.State))
}

func (h *winSysmsgHeader) sentryWaiter() *atomic.Uint32 {
	return (*atomic.Uint32)(unsafe.Pointer(&h.SentryWaiter))
}

func (h *winSysmsgHeader) stubWaiter() *atomic.Uint32 {
	return (*atomic.Uint32)(unsafe.Pointer(&h.StubWaiter))
}

// loadState reads the handoff word with acquire semantics.
func (h *winSysmsgHeader) loadState() uint32 { return h.state().Load() }

// spillOptions changes the spill routine for a measurement. The zero value is
// the routine that the engine runs.
type spillOptions struct {
	// noVector removes the save and the restore of the vector state. The routine
	// then breaks a guest that uses a vector register. Only
	// BenchmarkFastPathRoundTrip sets it, to measure what the vector state costs
	// in one round trip. No production path sets it.
	noVector bool
}

// winSignaler is the event pair behind one thread. The Windows engine backs
// it with the two auto-reset events. A test backs it with channels.
type winSignaler interface {
	// signalHost sets HostEvent, which wakes a stub that sleeps on it.
	signalHost() error
	// waitGuest blocks until the stub sets GuestEvent.
	waitGuest() error
}

// winAwait is the result of waiting for a trap.
type winAwait uint8

const (
	// winAwaitTrapped means that the stub published winStateTrapped.
	winAwaitTrapped winAwait = iota + 1
	// winAwaitPending means that another reason to wake came first: a debug
	// event or the death of the stub.
	winAwaitPending
)

// await waits until the stub publishes winStateTrapped or pending reports
// true. It polls spin times first, so a stub that answers within the window
// costs no kernel call. Then it sets SentryWaiter, tests both conditions
// again, and sleeps on GuestEvent. The test after the flag closes the race
// with a stub that published the state before it read the flag.
//
// pending runs on the polling path, so it must be cheap. A source of pending
// must wake the sleeping side by setting GuestEvent after it sets the condition,
// when it reads a non-zero SentryWaiter.
func (h *winSysmsgHeader) await(spin int, sig winSignaler, pending func() bool) (winAwait, error) {
	for range spin {
		if h.loadState() == winStateTrapped {
			return winAwaitTrapped, nil
		}
		if pending() {
			return winAwaitPending, nil
		}
	}
	waiter := h.sentryWaiter()
	for {
		waiter.Store(1)
		if h.loadState() == winStateTrapped {
			waiter.Store(0)
			return winAwaitTrapped, nil
		}
		if pending() {
			waiter.Store(0)
			return winAwaitPending, nil
		}
		err := sig.waitGuest()
		waiter.Store(0)
		if err != nil {
			return 0, err
		}
		// The event is auto-reset and a stale signal is possible, so the loop
		// tests both conditions again before it sleeps.
		if h.loadState() == winStateTrapped {
			return winAwaitTrapped, nil
		}
		if pending() {
			return winAwaitPending, nil
		}
	}
}

// release publishes state to the stub, which waits in winStateTrapped. It
// sets HostEvent only when the stub sleeps. The state is stored before the
// flag is read, so either the stub sees the state before it sleeps, or the
// Sentry sees the flag. It reports whether it woke the stub.
func (h *winSysmsgHeader) release(state uint32, sig winSignaler) (bool, error) {
	h.state().Store(state)
	if h.stubWaiter().Load() == 0 {
		return false, nil
	}
	return true, sig.signalHost()
}
