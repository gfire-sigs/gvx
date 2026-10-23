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
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This file binds the Windows calls of the engine. The names follow the
// Windows headers. Every wrapper returns a Go error with the call name.

var (
	modNtdll      = windows.NewLazySystemDLL("ntdll.dll")
	modKernel32   = windows.NewLazySystemDLL("kernel32.dll")
	modKernelBase = windows.NewLazySystemDLL("kernelbase.dll")

	procNtCreateDebugObject  = modNtdll.NewProc("NtCreateDebugObject")
	procNtDebugActiveProcess = modNtdll.NewProc("NtDebugActiveProcess")
	procNtRemoveProcessDebug = modNtdll.NewProc("NtRemoveProcessDebug")
	procNtWaitForDebugEvent  = modNtdll.NewProc("NtWaitForDebugEvent")
	procNtDebugContinue      = modNtdll.NewProc("NtDebugContinue")
	procNtCreateThreadEx     = modNtdll.NewProc("NtCreateThreadEx")
	procNtSuspendThread      = modNtdll.NewProc("NtSuspendThread")
	procNtResumeThread       = modNtdll.NewProc("NtResumeThread")
	procNtTerminateThread    = modNtdll.NewProc("NtTerminateThread")
	procNtTerminateProcess   = modNtdll.NewProc("NtTerminateProcess")

	procGetThreadContext      = modKernel32.NewProc("GetThreadContext")
	procSetThreadContext      = modKernel32.NewProc("SetThreadContext")
	procGetThreadID           = modKernel32.NewProc("GetThreadId")
	procVirtualFreeEx         = modKernel32.NewProc("VirtualFreeEx")
	procFlushInstructionCache = modKernel32.NewProc("FlushInstructionCache")
	procDebugBreakAddr        = modNtdll.NewProc("DbgBreakPoint")

	procVirtualAlloc2    = modKernelBase.NewProc("VirtualAlloc2")
	procMapViewOfFile3   = modKernelBase.NewProc("MapViewOfFile3")
	procUnmapViewOfFile2 = modKernelBase.NewProc("UnmapViewOfFile2")
)

// Windows constants that x/sys/windows does not define.
const (
	memReservePlaceholder   = 0x00040000
	memReplacePlaceholder   = 0x00004000
	memPreservePlaceholder  = 0x00000002
	memCoalescePlaceholders = 0x00000001

	debugKillOnClose   = 0x1
	debugAllAccess     = 0x1F000F
	dbgContinue        = 0x00010002
	dbgNotHandled      = 0x80010001
	statusTimeout      = 0x00000102
	statusAlerted      = 0x00000101
	statusUserAPC      = 0x000000C0
	statusBreakpoint   = 0x80000003
	statusSingleStep   = 0x80000004
	statusAccessViol   = 0xC0000005
	statusIllegalInsn  = 0xC000001D
	statusPrivInsn     = 0xC0000096
	statusIntDivZero   = 0xC0000094
	statusFltDivZero   = 0xC000008E
	statusFltInvalid   = 0xC0000090
	statusFltOverflow  = 0xC0000091
	statusFltUnderflow = 0xC0000093
	statusFltInexact   = 0xC000008F
	statusFltDenormal  = 0xC000008D
	statusFltStack     = 0xC0000092
	statusIntOverflow  = 0xC0000095
	statusInPageError  = 0xC0000006
	statusDatatypeMis  = 0x80000002
	statusGuardPage    = 0x80000001
	statusStackOverflw = 0xC00000FD

	threadAllAccess      = 0x1FFFFF
	threadCreateSuspend  = 0x00000001
	threadSkipAttach     = 0x00000002
	threadSkipLoaderInit = 0x00000020
)

// ntError is a failed NT call.
type ntError struct {
	Op     string
	Status uint32
}

func (e *ntError) Error() string {
	return fmt.Sprintf("%s: %s (status %#x)", e.Op, windows.NTStatus(e.Status).Error(), e.Status)
}

// ntCheck returns nil for a success or informational status.
func ntCheck(op string, status uintptr) error {
	if uint32(status)&0x80000000 == 0 {
		return nil
	}
	return &ntError{Op: op, Status: uint32(status)}
}

// ---- debug object ----------------------------------------------------------

func ntCreateDebugObject() (windows.Handle, error) {
	var h windows.Handle
	st, _, _ := procNtCreateDebugObject.Call(uintptr(unsafe.Pointer(&h)), debugAllAccess, 0, debugKillOnClose)
	if err := ntCheck("NtCreateDebugObject", st); err != nil {
		return 0, err
	}
	return h, nil
}

func ntDebugActiveProcess(proc, dbg windows.Handle) error {
	st, _, _ := procNtDebugActiveProcess.Call(uintptr(proc), uintptr(dbg))
	return ntCheck("NtDebugActiveProcess", st)
}

// ntRemoveProcessDebug detaches a process from a debug object.
func ntRemoveProcessDebug(proc, dbg windows.Handle) error {
	st, _, _ := procNtRemoveProcessDebug.Call(uintptr(proc), uintptr(dbg))
	return ntCheck("NtRemoveProcessDebug", st)
}

// Debug state values of DBGUI_WAIT_STATE_CHANGE.NewState.
const (
	dbgStateIdle         = 0
	dbgStateCreateThread = 2
	dbgStateCreateProc   = 3
	dbgStateExitThread   = 4
	dbgStateExitProc     = 5
	dbgStateException    = 6
	dbgStateBreakpoint   = 7
	dbgStateSingleStep   = 8
	dbgStateLoadDll      = 9
	dbgStateUnloadDll    = 10
)

// debugEvent is the parsed part of a DBGUI_WAIT_STATE_CHANGE record that the
// engine needs. The layout is the same on amd64 and arm64:
// NewState at 0, the client ID at 8, and the exception record at 24.
type debugEvent struct {
	State uint32
	PID   uint32
	TID   uint32
	// Code is the exception code of an exception state.
	Code uint32
	// Addr is ExceptionAddress.
	Addr uint64
	// Info holds the first three ExceptionInformation words. For an access
	// violation, Info[0] is the access kind (0 read, 1 write, 8 execute) and
	// Info[1] is the address.
	Info [3]uint64
	// FirstChance is the FirstChance word of the exception.
	FirstChance uint32
}

const debugRecordSize = 1024

func parseDebugEvent(b *[debugRecordSize]byte) debugEvent {
	u32 := func(o int) uint32 { return *(*uint32)(unsafe.Pointer(&b[o])) }
	u64 := func(o int) uint64 { return *(*uint64)(unsafe.Pointer(&b[o])) }
	ev := debugEvent{State: u32(0), PID: uint32(u64(8)), TID: uint32(u64(16))}
	if ev.State >= dbgStateException && ev.State <= dbgStateSingleStep {
		ev.Code = u32(24)
		ev.Addr = u64(40)
		ev.Info = [3]uint64{u64(56), u64(64), u64(72)}
		ev.FirstChance = u32(176)
	}
	return ev
}

// ntWaitForDebugEvent waits up to timeout for one event. It returns false on
// a timeout or an alert.
func ntWaitForDebugEvent(dbg windows.Handle, timeout time.Duration, buf *[debugRecordSize]byte) (bool, error) {
	// A negative value is a relative time in 100ns units.
	t := -int64(timeout / 100)
	st, _, _ := procNtWaitForDebugEvent.Call(uintptr(dbg), 0, uintptr(unsafe.Pointer(&t)), uintptr(unsafe.Pointer(buf)))
	switch uint32(st) {
	case 0:
		return true, nil
	case statusTimeout, statusAlerted, statusUserAPC:
		return false, nil
	}
	return false, ntCheck("NtWaitForDebugEvent", st)
}

func ntDebugContinue(dbg windows.Handle, pid, tid uint32, status uint32) error {
	cid := [2]uint64{uint64(pid), uint64(tid)}
	st, _, _ := procNtDebugContinue.Call(uintptr(dbg), uintptr(unsafe.Pointer(&cid[0])), uintptr(status))
	return ntCheck("NtDebugContinue", st)
}

// ---- threads and processes -------------------------------------------------

// ntCreateThreadEx creates a thread in proc without loader initialization.
// The thread starts suspended when suspended is set.
func ntCreateThreadEx(proc windows.Handle, start uintptr, suspended bool) (windows.Handle, error) {
	flags := uintptr(threadSkipAttach | threadSkipLoaderInit)
	if suspended {
		flags |= threadCreateSuspend
	}
	var h windows.Handle
	st, _, _ := procNtCreateThreadEx.Call(uintptr(unsafe.Pointer(&h)), threadAllAccess, 0, uintptr(proc), start, 0, flags, 0, 0, 0, 0)
	if err := ntCheck("NtCreateThreadEx", st); err != nil {
		return 0, err
	}
	return h, nil
}

func ntSuspendThread(h windows.Handle) error {
	var prev uint32
	st, _, _ := procNtSuspendThread.Call(uintptr(h), uintptr(unsafe.Pointer(&prev)))
	return ntCheck("NtSuspendThread", st)
}

func ntResumeThread(h windows.Handle) error {
	var prev uint32
	st, _, _ := procNtResumeThread.Call(uintptr(h), uintptr(unsafe.Pointer(&prev)))
	return ntCheck("NtResumeThread", st)
}

func ntTerminateThread(h windows.Handle) error {
	st, _, _ := procNtTerminateThread.Call(uintptr(h), 0)
	return ntCheck("NtTerminateThread", st)
}

func ntTerminateProcess(h windows.Handle) error {
	st, _, _ := procNtTerminateProcess.Call(uintptr(h), 0)
	return ntCheck("NtTerminateProcess", st)
}

func getThreadID(h windows.Handle) (uint32, error) {
	r, _, e := procGetThreadID.Call(uintptr(h))
	if r == 0 {
		return 0, fmt.Errorf("GetThreadId: %w", e)
	}
	return uint32(r), nil
}

// dbgBreakPointAddr returns the address of ntdll!DbgBreakPoint. System DLLs
// load at the same address in every process of one boot, so the stub runs
// the same function at the same address.
func dbgBreakPointAddr() (uintptr, error) {
	if err := procDebugBreakAddr.Find(); err != nil {
		return 0, err
	}
	return procDebugBreakAddr.Addr(), nil
}

// ---- memory ---------------------------------------------------------------

// virtualAlloc2 reserves size bytes at addr in proc as one placeholder.
func virtualAllocPlaceholder(proc windows.Handle, addr, size uintptr) error {
	r, _, e := procVirtualAlloc2.Call(uintptr(proc), addr, size, windows.MEM_RESERVE|memReservePlaceholder, windows.PAGE_NOACCESS, 0, 0)
	if r == 0 {
		return fmt.Errorf("VirtualAlloc2(placeholder %#x+%#x): %w", addr, size, e)
	}
	if r != addr {
		return fmt.Errorf("VirtualAlloc2(placeholder %#x+%#x) returned %#x", addr, size, r)
	}
	return nil
}

// splitPlaceholder makes [addr, addr+size) its own placeholder.
func splitPlaceholder(proc windows.Handle, addr, size uintptr) error {
	r, _, e := procVirtualFreeEx.Call(uintptr(proc), addr, size, windows.MEM_RELEASE|memPreservePlaceholder)
	if r == 0 {
		return fmt.Errorf("VirtualFreeEx(split %#x+%#x): %w", addr, size, e)
	}
	return nil
}

// coalescePlaceholders merges the adjacent placeholders that tile the range.
func coalescePlaceholders(proc windows.Handle, addr, size uintptr) error {
	r, _, e := procVirtualFreeEx.Call(uintptr(proc), addr, size, windows.MEM_RELEASE|memCoalescePlaceholders)
	if r == 0 {
		return fmt.Errorf("VirtualFreeEx(coalesce %#x+%#x): %w", addr, size, e)
	}
	return nil
}

// mapViewIntoPlaceholder replaces the placeholder [addr, addr+size) with a
// view of section at offset.
func mapViewIntoPlaceholder(section, proc windows.Handle, addr, size uintptr, offset uint64, prot uint32) error {
	r, _, e := procMapViewOfFile3.Call(uintptr(section), uintptr(proc), addr, uintptr(offset), size, memReplacePlaceholder, uintptr(prot), 0, 0)
	if r == 0 {
		return fmt.Errorf("MapViewOfFile3(%#x+%#x, offset %#x): %w", addr, size, offset, e)
	}
	return nil
}

// unmapViewToPlaceholder turns the whole view at addr into a placeholder.
func unmapViewToPlaceholder(proc windows.Handle, addr uintptr) error {
	r, _, e := procUnmapViewOfFile2.Call(uintptr(proc), addr, memPreservePlaceholder)
	if r == 0 {
		return fmt.Errorf("UnmapViewOfFile2(%#x): %w", addr, e)
	}
	return nil
}

func flushInstructionCache(proc windows.Handle, addr, size uintptr) error {
	r, _, e := procFlushInstructionCache.Call(uintptr(proc), addr, size)
	if r == 0 {
		return fmt.Errorf("FlushInstructionCache(%#x+%#x): %w", addr, size, e)
	}
	return nil
}
