// Throwaway research probe: can a debugger process act as a ptrace-like
// syscall trap for a Windows stub process?
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

var (
	k32                  = syscall.NewLazyDLL("kernel32.dll")
	pVirtualAlloc        = k32.NewProc("VirtualAlloc")
	pFlushICache         = k32.NewProc("FlushInstructionCache")
	pWaitForDebugEvent   = k32.NewProc("WaitForDebugEvent")
	pContinueDebugEvent  = k32.NewProc("ContinueDebugEvent")
	pGetThreadContext    = k32.NewProc("GetThreadContext")
	pSetThreadContext    = k32.NewProc("SetThreadContext")
	pDebugSetProcessKill = k32.NewProc("DebugSetProcessKillOnExit")
	pReadProcessMemory   = k32.NewProc("ReadProcessMemory")
)

func say(f string, a ...any) { fmt.Printf("DBG "+f+"\n", a...) }

func le32(ws ...uint32) []byte {
	b := make([]byte, 4*len(ws))
	for i, w := range ws {
		binary.LittleEndian.PutUint32(b[4*i:], w)
	}
	return b
}

func execMem(code []byte) uintptr {
	a, _, e := pVirtualAlloc.Call(0, 4096, 0x3000, 0x40)
	if a == 0 {
		say("VirtualAlloc failed: %v", e)
		os.Exit(3)
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(a)), len(code)), code)
	h, _ := syscall.GetCurrentProcess()
	pFlushICache.Call(uintptr(h), a, uintptr(len(code)))
	return a
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "debuggee" {
		debuggee(os.Args[2])
		return
	}
	for _, mode := range []string{"loop", "x18", "illegal"} {
		if runtime.GOARCH == "amd64" && mode == "x18" {
			continue
		}
		debugger(mode)
	}
}

// stubs returns the machine code that the debuggee runs. Every stub traps once
// and returns with the register that the debugger wrote.
func stubs(mode string) []byte {
	if runtime.GOARCH == "arm64" {
		const ret = 0xD65F03C0
		switch mode {
		case "loop":
			return le32(0xD4224680, ret) // brk #0x1234; ret
		case "x18":
			// mov x9,x18; mov x18,x0; brk #0x1234; mov x18,x9; ret
			return le32(0xAA1203E9, 0xAA0003F2, 0xD4224680, 0xAA0903F2, ret)
		case "illegal":
			return le32(0xD53B0020, ret) // mrs x0, ctr_el0 (illegal at EL0 on this host)
		}
	}
	switch mode {
	case "loop":
		return []byte{0xCC, 0xC3} // int3; ret
	case "illegal":
		return []byte{0x0F, 0x0B, 0xC3} // ud2; ret
	}
	return nil
}

func debuggee(mode string) {
	code := stubs(mode)
	a := execMem(code)
	n := 3000
	if mode == "illegal" {
		n = 200
	}
	var last uintptr
	for i := 0; i < n; i++ {
		arg := uintptr(0)
		if mode == "x18" {
			arg = 0x1234567890ABCDEF
		}
		last, _, _ = syscall.SyscallN(a, arg)
	}
	// Tell the debugger the final value through the exit code.
	os.Exit(int(last & 0xFF))
}

type debugEvent struct {
	Code  uint32
	Pid   uint32
	Tid   uint32
	_     uint32
	Union [160]byte
}

func debugger(mode string) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	exe, _ := os.Executable()
	argv, _ := syscall.UTF16PtrFromString(`"` + exe + `" debuggee ` + mode)
	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi syscall.ProcessInformation
	if err := syscall.CreateProcess(nil, argv, nil, nil, false, 0x2, nil, nil, &si, &pi); err != nil {
		say("%s: CreateProcess(DEBUG_ONLY_THIS_PROCESS) failed: %v", mode, err)
		return
	}
	pDebugSetProcessKill.Call(1)
	threads := map[uint32]syscall.Handle{pi.ThreadId: pi.Thread}
	ctxBuf := make([]byte, 4096+16)
	ctx := unsafe.Pointer(uintptr(unsafe.Pointer(&ctxBuf[0])) + (16-uintptr(unsafe.Pointer(&ctxBuf[0]))%16)%16)
	var flags uint32 = 0x100003
	pcOff, rax := uintptr(0), uintptr(0)
	if runtime.GOARCH == "arm64" {
		flags = 0x400003
		pcOff = 264
		rax = 8 // X0
	} else {
		rax = 120 // Rax in AMD64 CONTEXT
		pcOff = 248
	}
	events, traps, illegals, bad := 0, 0, 0, 0
	var firstTrap, lastTrap time.Time
	var ev debugEvent
	exit := -1
loop:
	for {
		r, _, e := pWaitForDebugEvent.Call(uintptr(unsafe.Pointer(&ev)), 15000)
		if r == 0 {
			say("%s: WaitForDebugEvent failed: %v", mode, e)
			break
		}
		events++
		cont := uint32(0x10002) // DBG_CONTINUE
		switch ev.Code {
		case 2: // CREATE_THREAD
			threads[ev.Tid] = syscall.Handle(binary.LittleEndian.Uint64(ev.Union[0:8]))
		case 5: // EXIT_PROCESS
			exit = int(binary.LittleEndian.Uint32(ev.Union[0:4]))
			pContinueDebugEvent.Call(uintptr(ev.Pid), uintptr(ev.Tid), uintptr(cont))
			break loop
		case 1: // EXCEPTION_DEBUG_EVENT
			code := binary.LittleEndian.Uint32(ev.Union[0:4])
			h := threads[ev.Tid]
			if code == 0x80000003 || code == 0xC000001D || code == 0xC000001E {
				if code == 0x80000003 && traps == 0 && mode != "illegal" && firstTrap.IsZero() {
					// The first breakpoint is the loader breakpoint unless the stub ran.
				}
				*(*uint32)(ctx) = flags
				if r, _, e := pGetThreadContext.Call(uintptr(h), uintptr(ctx)); r == 0 {
					say("%s: GetThreadContext failed: %v", mode, e)
					bad++
				}
				if code == 0x80000003 {
					traps++
				} else {
					illegals++
				}
				if firstTrap.IsZero() {
					firstTrap = time.Now()
				}
				lastTrap = time.Now()
				pc := (*uint64)(unsafe.Pointer(uintptr(ctx) + pcOff))
				if runtime.GOARCH == "arm64" {
					var ins [4]byte
					var n uintptr
					pReadProcessMemory.Call(uintptr(pi.Process), uintptr(*pc), uintptr(unsafe.Pointer(&ins[0])), 4, uintptr(unsafe.Pointer(&n)))
					w := binary.LittleEndian.Uint32(ins[:])
					if w&0xFFE0001F == 0xD4200000 || code == 0xC000001D {
						*pc += 4
					}
				} else if code == 0xC000001D {
					*pc += 2
				}
				*(*uint64)(unsafe.Pointer(uintptr(ctx) + rax)) = 0x42
				if r, _, e := pSetThreadContext.Call(uintptr(h), uintptr(ctx)); r == 0 {
					say("%s: SetThreadContext failed: %v", mode, e)
					bad++
				}
			} else {
				cont = 0x80010001 // DBG_EXCEPTION_NOT_HANDLED
				say("%s: unexpected exception %#x", mode, code)
			}
		}
		pContinueDebugEvent.Call(uintptr(ev.Pid), uintptr(ev.Tid), uintptr(cont))
	}
	span := lastTrap.Sub(firstTrap)
	per := 0.0
	if n := traps + illegals; n > 1 {
		per = float64(span.Nanoseconds()) / 1000 / float64(n-1)
	}
	say("%s: events=%d breakpoints=%d illegal=%d context errors=%d debuggee exit=%#x (0x42 means the written register came back) average per trap=%.1f us", mode, events, traps, illegals, bad, exit, per)
}
