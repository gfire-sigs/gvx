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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.org/x/sys/windows"

	"z.gfire.dev/gvx/pkg/sentry/arch"
)

// The fast path replaces the debug stop of a patched system call. A patched
// instruction jumps to a slot in a trampoline island. The slot jumps to the
// spill routine, which saves the guest registers in the winSysmsg page of the
// thread, publishes winStateTrapped, and waits for the Sentry. The Sentry
// reads the registers, serves the system call, writes the registers back, and
// publishes a resume state. The thread stays alive in the stub the whole time,
// so a stop needs no NtSuspendThread, NtResumeThread, NtDebugContinue, or
// context call. Every other stop keeps the debug path of the engine.
//
// Section 6.8 of docs/systrap-windows.md describes the design and its limits.

// fastPathMode selects how New treats the fast path. GVX_SYSTRAP_FASTPATH=1
// requires it, and New fails when the self test fails. GVX_SYSTRAP_FASTPATH=0
// turns it off. Any other value, or no value, tries the fast path and falls
// back to the debug path when the host cannot run it.
var fastPathMode = parseFastPathMode(os.Getenv("GVX_SYSTRAP_FASTPATH"))

type fastPathSetting int

const (
	fastPathAuto fastPathSetting = iota
	fastPathRequired
	fastPathOff
)

func parseFastPathMode(v string) fastPathSetting {
	switch v {
	case "1":
		return fastPathRequired
	case "0":
		return fastPathOff
	}
	return fastPathAuto
}

var (
	procNtCreateEvent            = modNtdll.NewProc("NtCreateEvent")
	procNtSetEvent               = modNtdll.NewProc("NtSetEvent")
	procNtWaitForSingleObject    = modNtdll.NewProc("NtWaitForSingleObject")
	procNtQueryInformationThread = modNtdll.NewProc("NtQueryInformationThread")
)

const (
	eventAllAccess       = 0x1F0003
	synchronizationEvent = 1
	// threadBasicInformation is the information class that reports the TEB.
	threadBasicInformation = 0
)

// ntCreateAutoResetEvent creates an unnamed event that resets itself when a
// wait returns.
func ntCreateAutoResetEvent() (windows.Handle, error) {
	var h windows.Handle
	st, _, _ := procNtCreateEvent.Call(uintptr(unsafe.Pointer(&h)), eventAllAccess, 0, synchronizationEvent, 0)
	if err := ntCheck("NtCreateEvent", st); err != nil {
		return 0, err
	}
	return h, nil
}

// threadTEB returns the address of the TEB of a thread in its process.
func threadTEB(h windows.Handle) (uint64, error) {
	var info struct {
		ExitStatus     int32
		_              int32
		TebBaseAddress uintptr
		ClientID       [2]uintptr
		AffinityMask   uintptr
		Priority       int32
		BasePriority   int32
	}
	st, _, _ := procNtQueryInformationThread.Call(uintptr(h), threadBasicInformation, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info), 0)
	if err := ntCheck("NtQueryInformationThread", st); err != nil {
		return 0, err
	}
	return uint64(info.TebBaseAddress), nil
}

// writeEventsReply answers opNewEvents.
func writeEventsReply(out io.Writer, errno uint32, ev eventHandles) error {
	var rsp [hostRspSize]byte
	binary.LittleEndian.PutUint32(rsp[0:], hostMagic)
	binary.LittleEndian.PutUint32(rsp[4:], errno)
	binary.LittleEndian.PutUint64(rsp[8:], uint64(ev.stubGuest))
	binary.LittleEndian.PutUint64(rsp[16:], uint64(ev.stubHost))
	binary.LittleEndian.PutUint64(rsp[24:], uint64(ev.guest))
	binary.LittleEndian.PutUint64(rsp[32:], uint64(ev.host))
	_, err := out.Write(rsp[:])
	return err
}

// fastTraps counts the system calls that the fast path served, for the trace.
var fastTraps atomic.Uint64

// fastSentrySleeps counts the waits in which the Sentry polled spin times
// without seeing the trap and slept on the guest event. fastStubWakes counts
// the resumes that found the stub asleep and set the host event. Both cost a
// kernel call and a thread wake-up, so a high count means that a spin window is
// shorter than the time the other side needs to answer.
var fastSentrySleeps, fastStubWakes atomic.Uint64

// sentrySpin is the number of polls of the Sentry before it sleeps. Only
// the spin sweep benchmark changes it, and it does so while no guest runs.
var sentrySpin = winSpinSentry

// ---- platform --------------------------------------------------------------

// prepareFast builds the spill routine and finds the ntdll functions that it
// calls. It runs before the platform brings up an address space.
func (p *Platform) prepareFast() error {
	sc, err := buildSpill()
	if err != nil {
		return fmt.Errorf("generate the spill routine: %w", err)
	}
	if len(sc.code) > winCodeSize-winSpillOffset {
		return fmt.Errorf("the spill routine has %d bytes and the engine pages leave %d", len(sc.code), winCodeSize-winSpillOffset)
	}
	for _, proc := range []*windows.LazyProc{procNtSetEvent, procNtWaitForSingleObject} {
		if err := proc.Find(); err != nil {
			return err
		}
	}
	p.spill = sc
	p.ntSetEvent = uint64(procNtSetEvent.Addr())
	p.ntWait = uint64(procNtWaitForSingleObject.Addr())
	p.fast = true
	return nil
}

// spillVA is the address of the spill routine in every stub.
func (p *Platform) spillVA() uint64 { return internalBase + winSpillOffset }

// coldExitVA is the address of the trap that a cold resume executes.
func (p *Platform) coldExitVA() uint64 { return p.spillVA() + uint64(p.spill.coldExit()) }

// ntStubSize bounds the length of an ntdll system call stub. A thread that
// sleeps in NtWaitForSingleObject has its program counter inside the stub.
const ntStubSize = 0x40

// inSpillCode reports whether pc lies in the spill routine or in one of the
// two ntdll stubs that the routine calls.
func (p *Platform) inSpillCode(pc uint64) bool {
	if !p.fast {
		return false
	}
	switch {
	case pc >= p.spillVA() && pc < p.spillVA()+uint64(len(p.spill.code)):
		return true
	case pc >= p.ntSetEvent && pc < p.ntSetEvent+ntStubSize:
		return true
	case pc >= p.ntWait && pc < p.ntWait+ntStubSize:
		return true
	}
	return false
}

// ---- slots -----------------------------------------------------------------

// fastSlot is the winSysmsg page, the stub stack, and the event pair of one
// guest thread.
type fastSlot struct {
	index int
	// va is the address of the area in the stub.
	va  uint64
	sec *anonSection
	sm  *winSysmsg
	// guest and host are the events in the Sentry process.
	guest, host windows.Handle
	// sleeps counts the sleeps of the Sentry on guest, and wakes counts the
	// sets of host that woke the stub.
	sleeps, wakes atomic.Uint64
}

// signalHost implements winSignaler.
func (s *fastSlot) signalHost() error {
	s.wakes.Add(1)
	fastStubWakes.Add(1)
	return windows.SetEvent(s.host)
}

// waitGuest implements winSignaler.
func (s *fastSlot) waitGuest() error {
	s.sleeps.Add(1)
	fastSentrySleeps.Add(1)
	_, err := windows.WaitForSingleObject(s.guest, windows.INFINITE)
	return err
}

// wakeSentry sets the event that a sleeping Sentry waits on. The debug pump
// and the death of a stub use it.
func (s *fastSlot) wakeSentry() { _ = windows.SetEvent(s.guest) }

// fastSlots holds the slots of one stub. A slot is never unmapped from the
// stub before the stub dies, so a free slot keeps its mapping and its events.
type fastSlots struct {
	mu     sync.Mutex
	all    []*fastSlot
	free   []*fastSlot
	closed bool
}

// fastThread is the fast path state of one guest thread.
type fastThread struct {
	slot *fastSlot

	// inSpill is true while the thread waits in the spill routine for the
	// Sentry. The thread is not suspended then. Callers hold the mutex of the
	// thread.
	inSpill bool
	// trap describes the trap that put the thread in the spill routine.
	trap winTrap
	// resume is the state that the next run publishes.
	resume uint32
	// traps counts the system calls that the thread served through the fast
	// path.
	traps atomic.Uint64
	// colds counts the resumes that ended in a debug stop.
	colds atomic.Uint64
}

var errNoFastSlot = fmt.Errorf("the stub process already has %d fast threads", winMaxThreads)

// takeSlot returns a free slot or creates a new one.
func (as *addressSpace) takeSlot() (*fastSlot, error) {
	sp := as.sp
	sp.fast.mu.Lock()
	defer sp.fast.mu.Unlock()
	if sp.fast.closed {
		return nil, errStubReleased
	}
	if n := len(sp.fast.free); n > 0 {
		s := sp.fast.free[n-1]
		sp.fast.free = sp.fast.free[:n-1]
		return s, nil
	}
	idx := len(sp.fast.all)
	if idx >= winMaxThreads {
		return nil, errNoFastSlot
	}
	s, err := as.newSlot(idx)
	if err != nil {
		return nil, err
	}
	sp.fast.all = append(sp.fast.all, s)
	return s, nil
}

// newSlot creates the shared page and the events of slot idx and maps the page
// into the stub. The host creates the events, so the Sentry needs no process
// creation right and the stub gets only the handles that it uses.
func (as *addressSpace) newSlot(idx int) (*fastSlot, error) {
	sp := as.sp
	sec, err := newAnonSection(winThreadMapSize)
	if err != nil {
		return nil, err
	}
	ev, err := as.p.host.newEvents(sp.pid)
	if err != nil {
		sec.close()
		return nil, err
	}
	closeEvents := func() {
		_ = windows.CloseHandle(ev.guest)
		_ = windows.CloseHandle(ev.host)
	}
	va := internalBase + winEnginePagesSize + uint64(idx)*winThreadAreaSize
	as.mu.Lock()
	if as.released {
		as.mu.Unlock()
		closeEvents()
		sec.close()
		return nil, errAddressSpaceReleased
	}
	err = as.win.Map(va, winThreadMapSize, &sec.ref, 0, viewReadWrite)
	as.mu.Unlock()
	if err != nil {
		closeEvents()
		sec.close()
		return nil, as.mapErr(err)
	}
	s := &fastSlot{index: idx, va: va, sec: sec, sm: (*winSysmsg)(unsafe.Pointer(&sec.local[0])), guest: ev.guest, host: ev.host}
	s.sm.GuestEvent = uint64(ev.stubGuest)
	s.sm.HostEvent = uint64(ev.stubHost)
	s.sm.NtSetEvent = as.p.ntSetEvent
	s.sm.NtWaitForSingleObject = as.p.ntWait
	return s, nil
}

// putSlot takes back the slot of a thread that is gone, so nothing writes the
// page. The slot goes to the free list, or it closes when the stub is released.
func (sp *stubProc) putSlot(s *fastSlot) {
	sp.fast.mu.Lock()
	defer sp.fast.mu.Unlock()
	if sp.fast.closed {
		s.close()
		return
	}
	hdr := s.sm.winSysmsgHeader
	clear(s.sec.local[:winSysmsgSize])
	s.sm.GuestEvent, s.sm.HostEvent = hdr.GuestEvent, hdr.HostEvent
	s.sm.NtSetEvent, s.sm.NtWaitForSingleObject = hdr.NtSetEvent, hdr.NtWaitForSingleObject
	_ = windows.ResetEvent(s.guest)
	_ = windows.ResetEvent(s.host)
	sp.fast.free = append(sp.fast.free, s)
}

// close closes the events and unmaps the page of the slot.
func (s *fastSlot) close() {
	_ = windows.CloseHandle(s.guest)
	_ = windows.CloseHandle(s.host)
	s.sec.close()
}

// closeFast closes the free slots when the stub is released. A slot that a
// thread still holds stays open, because a Sentry goroutine can still read its
// page. The thread closes the slot when the context releases it.
func (sp *stubProc) closeFast() {
	sp.fast.mu.Lock()
	defer sp.fast.mu.Unlock()
	if sp.fast.closed {
		return
	}
	sp.fast.closed = true
	for _, s := range sp.fast.free {
		s.close()
	}
	sp.fast.all, sp.fast.free = nil, nil
}

// wakeFastThreads wakes the Sentry threads that sleep on the event of a fast
// thread, so that they see that the stub died.
func (sp *stubProc) wakeFastThreads() {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	for _, th := range sp.threads {
		if f := th.fast.Load(); f != nil {
			f.slot.wakeSentry()
		}
	}
}

// attachFast gives a new guest thread its slot and the register that names the
// slot to the spill routine. The arch file decides which register that is.
func (as *addressSpace) attachFast(th *thread) error {
	slot, err := as.takeSlot()
	if err != nil {
		return err
	}
	if err := th.archAttachFast(slot); err != nil {
		as.sp.putSlot(slot)
		return err
	}
	th.fast.Store(&fastThread{slot: slot})
	return nil
}

// writeTEBSysmsg stores the address of the winSysmsg in the TEB of the thread,
// where the amd64 spill routine finds it.
func (th *thread) writeTEBSysmsg(va uint64) error {
	teb, err := threadTEB(th.h)
	if err != nil {
		return err
	}
	th.teb = teb
	var written uintptr
	if err := windows.WriteProcessMemory(th.sp.proc, uintptr(teb+winTEBSysmsg), (*byte)(unsafe.Pointer(&va)), unsafe.Sizeof(va), &written); err != nil {
		return fmt.Errorf("WriteProcessMemory(TEB of thread %d): %w", th.tid, err)
	}
	return nil
}

// releaseFast detaches the slot of a thread that the engine terminated. The
// slot goes back to the free list only after the thread is gone, because a
// terminating thread can still write the page for a short time.
func (th *thread) releaseFast() {
	f := th.fast.Swap(nil)
	if f == nil {
		return
	}
	if !th.sp.dead.Load() {
		if ev, err := windows.WaitForSingleObject(th.h, 5000); err != nil || ev != windows.WAIT_OBJECT_0 {
			// The thread is still alive. The slot stays out of the free list.
			return
		}
	}
	th.sp.putSlot(f.slot)
}

// ---- Sentry side of the handoff --------------------------------------------

// waitNext waits for the next stop of the thread. A fast thread stops in one
// of two ways: the spill routine publishes a trap, or the debugger delivers an
// exception. The result tells which one came.
func (th *thread) waitNext() (ev debugEvent, trapped bool, err error) {
	f := th.fast.Load()
	if f == nil {
		ev, err = th.waitEvent(0)
		return ev, false, err
	}
	pending := func() bool { return th.evQueued.Load() > 0 || th.sp.dead.Load() }
	res, err := f.slot.sm.winSysmsgHeader.await(sentrySpin, f.slot, pending)
	if err != nil {
		if th.sp.dead.Load() {
			return debugEvent{}, false, th.sp.deathError()
		}
		return debugEvent{}, false, fmt.Errorf("wait for the trap of thread %d: %w", th.tid, err)
	}
	if res == winAwaitTrapped {
		return debugEvent{}, true, nil
	}
	ev, err = th.waitEvent(0)
	return ev, false, err
}

// fastTrapLocked reads the registers of a trap into ac. Callers hold mu.
func (th *thread) fastTrapLocked(as *addressSpace, f *fastThread, ac *arch.Context64) error {
	sm := f.slot.sm
	site, ok := as.slotAtTail(sm.Tail)
	if !ok {
		return fmt.Errorf("the stub trapped from unknown slot %#x", sm.Tail)
	}
	f.trap = newWinTrap(site, &sm.Regs)
	sm.Regs.storeTo(ac, f.trap.ret)
	th.archFastTrap(ac)
	f.inSpill = true
	f.traps.Add(1)
	fastTraps.Add(1)
	return nil
}

// fastStart loads ac into the winSysmsg of a thread that waits in the spill
// routine, and decides which resume state the next run publishes. Callers
// hold mu.
func (th *thread) fastStart(f *fastThread, ac *arch.Context64, loadFP bool) error {
	if loadFP {
		if err := th.archFastSetFP(f, ac); err != nil {
			return err
		}
	}
	sm := f.slot.sm
	f.resume = f.trap.resumeState(ac)
	if f.resume == winStateRunHot {
		as := th.sp.owner.Load()
		if as == nil {
			f.resume = winStateRunCold
		} else if site, ok := as.slotAtTail(sm.Tail); !ok || site != f.trap.site || !th.archFastHot(ac) {
			f.resume = winStateRunCold
		}
	}
	sm.Regs.loadFrom(ac)
	sm.Target = archPC(ac)
	th.stepping = false
	th.lastExecPC, th.execRepeats = 0, 0
	return nil
}

// fastRun releases a thread that waits in the spill routine. Callers hold mu.
func (th *thread) fastRun(f *fastThread) error {
	f.inSpill = false
	if _, err := f.slot.sm.winSysmsgHeader.release(f.resume, f.slot); err != nil {
		return th.ctxErr("SetEvent", err)
	}
	return nil
}

// fastExit serves the trap of a cold resume. The stub loaded every register of
// the Sentry and stopped at the trap instruction. The thread continues at the
// target with the state that a normal start loads. Callers hold mu.
func (th *thread) fastExit(ac *arch.Context64, ev debugEvent) outcome {
	f := th.fast.Load()
	f.colds.Add(1)
	th.ctx.setPC(f.slot.sm.Target)
	if err := th.park(ev); err != nil {
		return fatal(err, unix.EFAULT)
	}
	if err := th.archStart(ac); err != nil {
		return fatal(err, unix.EFAULT)
	}
	if err := th.resumeParked(); err != nil {
		return fatal(err, unix.EFAULT)
	}
	return running
}

// isFastExit reports whether ev is the trap of a cold resume.
func (th *thread) isFastExit(ev debugEvent) bool {
	f := th.fast.Load()
	return f != nil && ev.Addr == th.sp.p.coldExitVA()
}

// inFastCode reports whether pc lies in code that a trap runs: the spill
// routine or a trampoline island. A forced stop must not step there, because
// the trap publishes its own stop.
func (th *thread) inFastCode(pc uint64) bool {
	if th.fast.Load() == nil {
		return false
	}
	return th.sp.p.inSpillCode(pc) || th.inIslandPC(pc)
}

// inIslandPC reports whether pc lies in a trampoline island of the stub.
func (th *thread) inIslandPC(pc uint64) bool {
	if th.fast.Load() == nil {
		return false
	}
	as := th.sp.owner.Load()
	return as != nil && as.inIsland(pc)
}

// rewindToSite moves a thread that stopped at the first instruction of a slot
// back to the instruction that jumps to the slot. The slot has not run, so the
// registers are the guest registers, and the jump enters the slot again. For a
// pre-window slot that instruction lies in front of the SYSCALL.
func (th *thread) rewindToSite() bool {
	if th.fast.Load() == nil {
		return false
	}
	as := th.sp.owner.Load()
	if as == nil {
		return false
	}
	slot, ok := as.slotStart(th.ctx.pc())
	if !ok {
		return false
	}
	th.ctx.setPC(slot.jmpVA)
	return true
}

var errFastSelfTest = errors.New("the fast path self test failed")

// fastTrap serves a trap that the spill routine published.
func (c *Context) fastTrap(as *addressSpace, th *thread, ac *arch.Context64) outcome {
	th.mu.Lock()
	defer th.mu.Unlock()
	if err := th.fastTrapLocked(as, th.fast.Load(), ac); err != nil {
		return fatal(err, unix.EFAULT)
	}
	return outcome{done: true}
}

// wakeFast wakes a Sentry thread that sleeps on the event of the thread, after
// the debug pump queued an exception for it.
func (th *thread) wakeFast() {
	if f := th.fast.Load(); f != nil && f.slot.sm.sentryWaiter().Load() != 0 {
		f.slot.wakeSentry()
	}
}
