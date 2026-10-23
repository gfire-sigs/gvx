// Throwaway research probe for Windows systrap feasibility. Not part of gvx.
package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

var (
	k32                 = syscall.NewLazyDLL("kernel32.dll")
	kb                  = syscall.NewLazyDLL("kernelbase.dll")
	ntd                 = syscall.NewLazyDLL("ntdll.dll")
	pVirtualAlloc       = k32.NewProc("VirtualAlloc")
	pVirtualProtect     = k32.NewProc("VirtualProtect")
	pVirtualProtectEx   = k32.NewProc("VirtualProtectEx")
	pFlushICache        = k32.NewProc("FlushInstructionCache")
	pWaitForDebugEvent  = k32.NewProc("WaitForDebugEvent")
	pContinueDebugEvent = k32.NewProc("ContinueDebugEvent")
	pGetThreadContext   = k32.NewProc("GetThreadContext")
	pSetThreadContext   = k32.NewProc("SetThreadContext")
	pDebugKill          = k32.NewProc("DebugSetProcessKillOnExit")
	pReadProcessMemory  = k32.NewProc("ReadProcessMemory")
	pWriteProcessMemory = k32.NewProc("WriteProcessMemory")
	pVirtualQueryEx     = k32.NewProc("VirtualQueryEx")
	pOpenThread         = k32.NewProc("OpenThread")
	pGetProcAddress     = k32.NewProc("GetProcAddress")
	pGetModuleHandle    = k32.NewProc("GetModuleHandleW")
	pSetMitigation      = k32.NewProc("SetProcessMitigationPolicy")
	pCreateFileMapping  = k32.NewProc("CreateFileMappingW")
	pMapViewOfFile      = k32.NewProc("MapViewOfFile")
	pMapViewOfFile3     = kb.NewProc("MapViewOfFile3")
	pVirtualAlloc2      = kb.NewProc("VirtualAlloc2")
	pNtCreateThreadEx   = ntd.NewProc("NtCreateThreadEx")
)

func say(f string, a ...any) { fmt.Printf("R2 "+f+"\n", a...) }

func le32(ws ...uint32) []byte {
	b := make([]byte, 4*len(ws))
	for i, w := range ws {
		binary.LittleEndian.PutUint32(b[4*i:], w)
	}
	return b
}

func allocAt(addr uintptr, size uintptr, prot uintptr) uintptr {
	a, _, e := pVirtualAlloc.Call(addr, size, 0x3000, prot)
	if a == 0 {
		say("VirtualAlloc(%#x) failed: %v", addr, e)
		os.Exit(3)
	}
	return a
}

func execMem(code []byte) uintptr {
	a := allocAt(0, 4096, 0x40)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(a)), len(code)), code)
	h, _ := syscall.GetCurrentProcess()
	pFlushICache.Call(uintptr(h), a, uintptr(len(code)))
	return a
}

func ntdllProc(name string) uintptr {
	h, _, _ := pGetModuleHandle.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("ntdll.dll"))))
	n, _ := syscall.BytePtrFromString(name)
	a, _, _ := pGetProcAddress.Call(h, uintptr(unsafe.Pointer(n)))
	return a
}

func ssnOf(name string) uint32 {
	a := ntdllProc(name)
	b := unsafe.Slice((*byte)(unsafe.Pointer(a)), 16)
	if runtime.GOARCH == "arm64" {
		return (binary.LittleEndian.Uint32(b[0:4]) >> 5) & 0xFFFF
	}
	for i := 0; i < 12; i++ {
		if b[i] == 0xB8 {
			return binary.LittleEndian.Uint32(b[i+1 : i+5])
		}
	}
	return 0xFFFFFFFF
}

func main() {
	mode := "main"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "main":
		runMain()
	case "fsbase-debuggee":
		fsbaseDebuggee()
	case "armsleep":
		armSleep(os.Args[2])
	case "mitig":
		mitig()
	case "idle":
		time.Sleep(time.Minute)
	}
}

func child(name string, args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, os.Args[0], args...).CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	fmt.Print(string(out))
	say("%s child exit=%#x", name, uint32(code))
}

func runMain() {
	say("arch=%s", runtime.GOARCH)
	child("mitig", "mitig")
	if runtime.GOARCH == "arm64" {
		child("armsleep x18", "armsleep", "x18")
		child("armsleep tpidr", "armsleep", "tpidr")
	}
	pePark()
	if runtime.GOARCH == "amd64" {
		fsbaseDebugger()
	}
}

// ---- amd64: lazy FS base recovery through a debugger -----------------------

const (
	tlsBase  = 0x31000000000
	trampVA  = 0x30000000000
	dataOff  = 0x100
	canary28 = 0xC0FFEE0000000028
	canary10 = 0xC0FFEE0000000010
)

func fsbaseDebuggee() {
	tls := allocAt(tlsBase, 0x10000, 0x04)
	fsb := tls + 0x8000
	*(*uint64)(unsafe.Pointer(fsb + 0x28)) = canary28
	*(*uint64)(unsafe.Pointer(fsb - 0x10)) = canary10
	t := allocAt(trampVA, 4096, 0x40)
	d := t + dataOff
	*(*uint64)(unsafe.Pointer(d)) = uint64(fsb)
	var code []byte
	imm := func(v uint64) []byte { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, v); return b }
	code = append(code, 0x48, 0xB8)
	code = append(code, imm(uint64(d))...)            // mov rax, D
	code = append(code, 0x48, 0x8B, 0x00)             // mov rax, [rax]
	code = append(code, 0xF3, 0x48, 0x0F, 0xAE, 0xD0) // wrfsbase rax
	code = append(code, 0x48, 0xB8)
	code = append(code, imm(uint64(d+8))...) // mov rax, D+8
	code = append(code, 0x48, 0x8B, 0x00)    // mov rax, [rax]
	code = append(code, 0xFF, 0x25)          // jmp [rip+rel32]
	next := int64(len(code) + 4)
	rel := int64(dataOff+16) - next
	var r4 [4]byte
	binary.LittleEndian.PutUint32(r4[:], uint32(int32(rel)))
	code = append(code, r4[:]...)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(t)), len(code)), code)

	setFS := execMem([]byte{0x48, 0x89, 0xC8, 0xF3, 0x48, 0x0F, 0xAE, 0xD0, 0xC3}) // mov rax,rcx; wrfsbase rax; ret
	rd28 := execMem([]byte{0x64, 0x48, 0x8B, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, 0xC3})
	rdNeg := execMem([]byte{0x64, 0x48, 0x8B, 0x04, 0x25, 0xF0, 0xFF, 0xFF, 0xFF, 0xC3})
	runtime.LockOSThread()
	syscall.SyscallN(setFS, fsb)
	bad := 0
	start := time.Now()
	n := 0
	for time.Since(start) < 1500*time.Millisecond {
		a, _, _ := syscall.SyscallN(rd28)
		b, _, _ := syscall.SyscallN(rdNeg)
		if a != canary28 || b != canary10 {
			bad++
		}
		n++
		if n%20 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	if bad > 200 {
		bad = 200
	}
	os.Exit(bad)
}

type debugEvent struct {
	Code  uint32
	Pid   uint32
	Tid   uint32
	_     uint32
	Union [160]byte
}

func fsbaseDebugger() {
	runtime.LockOSThread()
	exe, _ := os.Executable()
	argv, _ := syscall.UTF16PtrFromString(`"` + exe + `" fsbase-debuggee`)
	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi syscall.ProcessInformation
	if err := syscall.CreateProcess(nil, argv, nil, nil, false, 0x2, nil, nil, &si, &pi); err != nil {
		say("fsbase: CreateProcess failed: %v", err)
		return
	}
	pDebugKill.Call(1)
	threads := map[uint32]syscall.Handle{pi.ThreadId: pi.Thread}
	ctxBuf := make([]byte, 4096+16)
	ctx := unsafe.Pointer(uintptr(unsafe.Pointer(&ctxBuf[0])) + (16-uintptr(unsafe.Pointer(&ctxBuf[0]))%16)%16)
	var ev debugEvent
	avs, rec, loops := 0, 0, 0
	var lastRip uint64
	var lastTime time.Time
	exit := -1
	start := time.Now()
loop:
	for time.Since(start) < 60*time.Second {
		r, _, _ := pWaitForDebugEvent.Call(uintptr(unsafe.Pointer(&ev)), 10000)
		if r == 0 {
			say("fsbase: WaitForDebugEvent timeout or failure")
			break
		}
		cont := uint32(0x10002)
		switch ev.Code {
		case 2:
			threads[ev.Tid] = syscall.Handle(binary.LittleEndian.Uint64(ev.Union[0:8]))
		case 5:
			exit = int(binary.LittleEndian.Uint32(ev.Union[0:4]))
			pContinueDebugEvent.Call(uintptr(ev.Pid), uintptr(ev.Tid), uintptr(cont))
			break loop
		case 1:
			code := binary.LittleEndian.Uint32(ev.Union[0:4])
			if code == 0xC0000005 {
				avs++
				h := threads[ev.Tid]
				if h == 0 {
					oh, _, _ := pOpenThread.Call(0x1FFFFF, 0, uintptr(ev.Tid))
					h = syscall.Handle(oh)
					threads[ev.Tid] = h
				}
				*(*uint32)(unsafe.Pointer(uintptr(ctx) + 48)) = 0x100003 // CONTEXT.ContextFlags follows the six home slots on amd64
				gr, _, ge := pGetThreadContext.Call(uintptr(h), uintptr(ctx))
				rip := *(*uint64)(unsafe.Pointer(uintptr(ctx) + 248))
				rax := *(*uint64)(unsafe.Pointer(uintptr(ctx) + 120))
				rsp := *(*uint64)(unsafe.Pointer(uintptr(ctx) + 152))
				if avs <= 3 {
					say("fsbase: AV #%d tid=%d handle=%#x GetThreadContext ok=%d err=%v rip=%#x rsp=%#x rax=%#x", avs, ev.Tid, h, gr, ge, rip, rsp, rax)
				}
				if rip == lastRip && time.Since(lastTime) < 300*time.Microsecond {
					loops++
					info0 := binary.LittleEndian.Uint64(ev.Union[32:40])
					info1 := binary.LittleEndian.Uint64(ev.Union[40:48])
					var mbi [48]byte
					pVirtualQueryEx.Call(uintptr(pi.Process), uintptr(rip), uintptr(unsafe.Pointer(&mbi[0])), 48)
					say("fsbase: repeated AV at %#x: access=%d address=%#x region base=%#x state=%#x protect=%#x", rip, info0, info1,
						binary.LittleEndian.Uint64(mbi[0:8]), binary.LittleEndian.Uint32(mbi[32:36]), binary.LittleEndian.Uint32(mbi[36:40]))
				}
				if avs <= 3 {
					say("fsbase: AV #%d rip=%#x access=%d address=%#x", avs, rip, binary.LittleEndian.Uint64(ev.Union[32:40]), binary.LittleEndian.Uint64(ev.Union[40:48]))
				}
				lastRip = rip
				lastTime = time.Now()
				if loops > 3 {
					say("fsbase: the fault repeats at %#x after recovery; stopping", rip)
					cont = 0x80010001
				} else {
					var slots [2]uint64
					slots[0], slots[1] = rax, rip
					var n uintptr
					pWriteProcessMemory.Call(uintptr(pi.Process), trampVA+dataOff+8, uintptr(unsafe.Pointer(&slots[0])), 16, uintptr(unsafe.Pointer(&n)))
					*(*uint64)(unsafe.Pointer(uintptr(ctx) + 248)) = trampVA
					sr, _, se := pSetThreadContext.Call(uintptr(h), uintptr(ctx))
					if avs <= 3 {
						say("fsbase: SetThreadContext(rip=%#x) ok=%d err=%v", trampVA, sr, se)
					}
					rec++
				}
			} else if code != 0x80000003 {
				cont = 0x80010001
				say("fsbase: unexpected exception %#x", code)
			}
		}
		pContinueDebugEvent.Call(uintptr(ev.Pid), uintptr(ev.Tid), uintptr(cont))
	}
	say("fsbase: access violations=%d recovered=%d repeats=%d debuggee exit=%d (0 means every %%fs read returned the canary across 1.5 s of sleeps and context switches)", avs, rec, loops, exit)
}

// ---- arm64: register retention across a real kernel wait -------------------

func armSleep(which string) {
	ssn := ssnOf("NtDelayExecution")
	var code []byte
	switch which {
	case "x18":
		// str x18,[sp,#-16]!; mov x18,x0; mov x0,#0; svc; mov x0,x18; ldr x18,[sp],#16; ret
		code = le32(0xF81F0FF2, 0xAA0003F2, 0xD2800000, 0xD4000001|ssn<<5, 0xAA1203E0, 0xF84107F2, 0xD65F03C0)
	case "tpidr":
		// mrs x9,tpidr_el0; str x9,[sp,#-16]!; msr tpidr_el0,x0; mov x0,#0; svc; mrs x0,tpidr_el0; ldr x9,[sp],#16; msr tpidr_el0,x9; ret
		code = le32(0xD53BD049, 0xF81F0FE9, 0xD51BD040, 0xD2800000, 0xD4000001|ssn<<5, 0xD53BD040, 0xF84107E9, 0xD51BD049, 0xD65F03C0)
	}
	a := execMem(code)
	delay := int64(-50000) // 5 ms relative
	const junk = 0x1234567890ABCDEF
	ok := 0
	for i := 0; i < 200; i++ {
		r, _, _ := syscall.SyscallN(a, junk, uintptr(unsafe.Pointer(&delay)))
		if r == junk {
			ok++
		}
	}
	say("armsleep %s: junk value survived %d of 200 raw NtDelayExecution(5 ms) waits issued from a private stub", which, ok)
}

// ---- mitigation policy ------------------------------------------------------

func mitig() {
	for _, f := range []uint32{1, 4, 5} {
		flags := f
		ok, _, e := pSetMitigation.Call(4, uintptr(unsafe.Pointer(&flags)), 4)
		say("mitig: SetProcessMitigationPolicy(ProcessSystemCallDisablePolicy, flags=%#x) ok=%d err=%v", f, ok, e)
	}
}

// ---- minimal PE, parked stub, ntdll scrub, loader-less thread ---------------

func buildPE(code []byte) []byte {
	machine := uint16(0x8664)
	if runtime.GOARCH == "arm64" {
		machine = 0xAA64
	}
	img := make([]byte, 0x400)
	copy(img, "MZ")
	binary.LittleEndian.PutUint32(img[0x3C:], 0x40)
	nt := img[0x40:]
	copy(nt, "PE\x00\x00")
	binary.LittleEndian.PutUint16(nt[4:], machine)
	binary.LittleEndian.PutUint16(nt[6:], 1)     // sections
	binary.LittleEndian.PutUint16(nt[20:], 0xF0) // optional header size
	binary.LittleEndian.PutUint16(nt[22:], 0x22) // executable, large address aware
	opt := nt[24:]
	binary.LittleEndian.PutUint16(opt[0:], 0x20B)
	binary.LittleEndian.PutUint32(opt[4:], 0x200)   // size of code
	binary.LittleEndian.PutUint32(opt[16:], 0x1000) // entry
	binary.LittleEndian.PutUint32(opt[20:], 0x1000) // base of code
	binary.LittleEndian.PutUint64(opt[24:], 0x140000000)
	binary.LittleEndian.PutUint32(opt[32:], 0x1000) // section alignment
	binary.LittleEndian.PutUint32(opt[36:], 0x200)  // file alignment
	binary.LittleEndian.PutUint16(opt[40:], 10)
	binary.LittleEndian.PutUint16(opt[48:], 10)
	binary.LittleEndian.PutUint32(opt[56:], 0x2000) // size of image
	binary.LittleEndian.PutUint32(opt[60:], 0x200)  // size of headers
	binary.LittleEndian.PutUint16(opt[68:], 3)      // console subsystem
	binary.LittleEndian.PutUint16(opt[70:], 0x8160)
	binary.LittleEndian.PutUint64(opt[72:], 0x100000)
	binary.LittleEndian.PutUint64(opt[80:], 0x1000)
	binary.LittleEndian.PutUint64(opt[88:], 0x100000)
	binary.LittleEndian.PutUint64(opt[96:], 0x1000)
	binary.LittleEndian.PutUint32(opt[108:], 16) // data directories
	// Data directory 5 is the base relocation table: one empty block inside .text.
	binary.LittleEndian.PutUint32(opt[112+5*8:], 0x1100)
	binary.LittleEndian.PutUint32(opt[112+5*8+4:], 8)
	sec := nt[24+0xF0:]
	copy(sec, ".text")
	binary.LittleEndian.PutUint32(sec[8:], 0x200)
	binary.LittleEndian.PutUint32(sec[12:], 0x1000)
	binary.LittleEndian.PutUint32(sec[16:], 0x200)
	binary.LittleEndian.PutUint32(sec[20:], 0x200)
	binary.LittleEndian.PutUint32(sec[36:], 0x60000020)
	copy(img[0x200:], code)
	binary.LittleEndian.PutUint32(img[0x300:], 0x1000) // page RVA of the empty relocation block
	binary.LittleEndian.PutUint32(img[0x304:], 8)      // block size without entries
	return img
}

func exitCodeCode(v byte) []byte {
	if runtime.GOARCH == "arm64" {
		// mov w0, #v; ret
		return le32(0x52800000|uint32(v)<<5, 0xD65F03C0)
	}
	return []byte{0xB8, v, 0, 0, 0, 0xC3} // mov eax, v; ret
}

func parkCode() []byte {
	if runtime.GOARCH == "arm64" {
		return le32(0xD503203F, 0x17FFFFFF) // yield; b .-4
	}
	return []byte{0xF3, 0x90, 0xEB, 0xFC} // pause; jmp .-4
}

func pePark() {
	for _, kind := range []string{"baseline", "svcudf", "readonly"} {
		parkTest(kind)
	}
}

func patchSvc(proc syscall.Handle, textVA, textSize uintptr) (patched int) {
	for page := textVA; page < textVA+textSize; page += 0x1000 {
		buf := make([]byte, 0x1000)
		copy(buf, unsafe.Slice((*byte)(unsafe.Pointer(page)), 0x1000))
		n := 0
		if runtime.GOARCH == "arm64" {
			for o := 0; o+4 <= len(buf); o += 4 {
				w := binary.LittleEndian.Uint32(buf[o:])
				if w&0xFFE0001F == 0xD4000001 {
					binary.LittleEndian.PutUint32(buf[o:], 0)
					n++
				}
			}
		} else {
			for o := 0; o+2 <= len(buf); o++ {
				if buf[o] == 0x0F && buf[o+1] == 0x05 {
					buf[o+1] = 0x0B
					n++
				}
			}
		}
		if n == 0 {
			continue
		}
		var old uint32
		pVirtualProtectEx.Call(uintptr(proc), page, 0x1000, 0x40, uintptr(unsafe.Pointer(&old)))
		var w uintptr
		pWriteProcessMemory.Call(uintptr(proc), page, uintptr(unsafe.Pointer(&buf[0])), 0x1000, uintptr(unsafe.Pointer(&w)))
		pVirtualProtectEx.Call(uintptr(proc), page, 0x1000, 0x20, uintptr(unsafe.Pointer(&old)))
		patched += n
	}
	pFlushICache.Call(uintptr(proc), textVA, textSize)
	return
}

func parkTest(kind string) {
	argv, _ := syscall.UTF16PtrFromString(`C:\Windows\System32\PING.EXE -n 30 127.0.0.1`)
	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi syscall.ProcessInformation
	if err := syscall.CreateProcess(nil, argv, nil, nil, false, 0, nil, nil, &si, &pi); err != nil {
		say("park[%s]: CreateProcess failed: %v", kind, err)
		return
	}
	defer syscall.TerminateProcess(pi.Process, 0)
	time.Sleep(300 * time.Millisecond)
	h, _, _ := pGetModuleHandle.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("ntdll.dll"))))
	lfanew := *(*uint32)(unsafe.Pointer(h + 0x3C))
	nsec := *(*uint16)(unsafe.Pointer(h + uintptr(lfanew) + 6))
	optSize := *(*uint16)(unsafe.Pointer(h + uintptr(lfanew) + 20))
	secBase := h + uintptr(lfanew) + 24 + uintptr(optSize)
	var textVA, textSize uintptr
	for i := uintptr(0); i < uintptr(nsec); i++ {
		s := secBase + i*40
		if string(unsafe.Slice((*byte)(unsafe.Pointer(s)), 5)) == ".text" {
			textSize = uintptr(*(*uint32)(unsafe.Pointer(s + 8)))
			textVA = h + uintptr(*(*uint32)(unsafe.Pointer(s + 12)))
		}
	}
	textSize = (textSize + 0xFFF) &^ 0xFFF
	start := time.Now()
	switch kind {
	case "baseline":
		say("park[%s]: no change to the child", kind)
	case "readonly":
		var old uint32
		r, _, e := pVirtualProtectEx.Call(uintptr(pi.Process), textVA, textSize, 0x02, uintptr(unsafe.Pointer(&old)))
		say("park[%s]: ntdll .text -> PAGE_READONLY ok=%d err=%v", kind, r, e)
	case "svcudf":
		n := patchSvc(pi.Process, textVA, textSize)
		say("park[%s]: replaced %d syscall instructions in the ntdll text of the child in %d ms", kind, n, time.Since(start).Milliseconds())
	}
	sec, _, e := pCreateFileMapping.Call(^uintptr(0), 0, 0x40, 0, 0x10000, 0)
	if sec == 0 {
		say("park[%s]: CreateFileMapping failed: %v", kind, e)
		return
	}
	local, _, _ := pMapViewOfFile.Call(sec, 0xF001F, 0, 0, 0x10000)
	const dataVA, codeVA = 0x500000000000, 0x500000010000
	for _, m := range []struct{ va, off, prot uintptr }{{dataVA, 0, 0x04}, {codeVA, 0x1000, 0x20}} {
		ph, _, e := pVirtualAlloc2.Call(uintptr(pi.Process), m.va, 0x1000, 0x2000|0x40000, 0x01, 0, 0)
		if ph == 0 {
			say("park[%s]: placeholder at %#x failed: %v", kind, m.va, e)
			return
		}
		mv, _, e := pMapViewOfFile3.Call(sec, uintptr(pi.Process), m.va, m.off, 0x1000, 0x4000, 0x40, 0, 0)
		if mv == 0 {
			say("park[%s]: MapViewOfFile3 at %#x failed: %v", kind, m.va, e)
			return
		}
		if m.prot != 0x40 {
			var o uint32
			pVirtualProtectEx.Call(uintptr(pi.Process), m.va, 0x1000, m.prot, uintptr(unsafe.Pointer(&o)))
		}
	}
	var thr []byte
	if runtime.GOARCH == "arm64" {
		thr = le32(
			0xD2800001|uint32((dataVA&0xFFFF))<<5,
			0xF2A00001|uint32((dataVA>>16)&0xFFFF)<<5,
			0xF2C00001|uint32((dataVA>>32)&0xFFFF)<<5,
			0x52800840, // mov w0, #0x42
			0xB9000020, // str w0, [x1]
			0x14000000, // b .
		)
	} else {
		thr = []byte{0x48, 0xB9}
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, dataVA)
		thr = append(thr, b...)
		thr = append(thr, 0xC7, 0x01, 0x42, 0, 0, 0, 0xEB, 0xFE)
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(local+0x1000)), len(thr)), thr)
	pFlushICache.Call(uintptr(pi.Process), codeVA, uintptr(len(thr)))
	createThread := func(label string, start uintptr, flags uintptr) {
		var ht uintptr
		st, _, _ := pNtCreateThreadEx.Call(uintptr(unsafe.Pointer(&ht)), 0x1FFFFF, 0, uintptr(pi.Process), start, 0, flags, 0, 0, 0, 0)
		say("park[%s]: NtCreateThreadEx(%s, flags=%#x) status=%#x", kind, label, flags, uint32(st))
	}
	createThread("loader-less thread running guest-like code", codeVA, 0x20|0x2)
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) && *(*uint32)(unsafe.Pointer(local)) != 0x42 {
		time.Sleep(10 * time.Millisecond)
	}
	say("park[%s]: shared data word written by the new thread = %#x (0x42 means the thread ran)", kind, *(*uint32)(unsafe.Pointer(local)))
	alive, _ := syscall.WaitForSingleObject(pi.Process, 0)
	say("park[%s]: child still alive after the first thread: %v", kind, alive == 0x102)
	if alive == 0x102 {
		createThread("thread that starts inside the patched ntdll at NtClose", ntdllProc("NtClose"), 0x20|0x2)
		r2, _ := syscall.WaitForSingleObject(pi.Process, 3000)
		var ec uint32
		syscall.GetExitCodeProcess(pi.Process, &ec)
		say("park[%s]: after a thread entered NtClose in the patched ntdll: wait=%d exit code=%#x", kind, r2, ec)
	}
}
