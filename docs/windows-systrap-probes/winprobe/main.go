// Throwaway research probe. Not part of gvx. It measures Windows behavior that
// a Windows systrap engine would depend on.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	k32 = syscall.NewLazyDLL("kernel32.dll")
	kb  = syscall.NewLazyDLL("kernelbase.dll")
	nt  = syscall.NewLazyDLL("ntdll.dll")
	syn = syscall.NewLazyDLL("api-ms-win-core-synch-l1-2-0.dll")

	pVirtualAlloc            = k32.NewProc("VirtualAlloc")
	pVirtualAlloc2           = kb.NewProc("VirtualAlloc2")
	pVirtualFreeEx           = k32.NewProc("VirtualFreeEx")
	pVirtualProtectEx        = k32.NewProc("VirtualProtectEx")
	pMapViewOfFile3          = kb.NewProc("MapViewOfFile3")
	pMapViewOfFile           = k32.NewProc("MapViewOfFile")
	pOpenFileMapping         = k32.NewProc("OpenFileMappingW")
	pReadProcessMemory       = k32.NewProc("ReadProcessMemory")
	pFlushInstructionCache   = k32.NewProc("FlushInstructionCache")
	pGetSystemInfo           = k32.NewProc("GetSystemInfo")
	pSetProcessMitigationPol = k32.NewProc("SetProcessMitigationPolicy")
	pGetProcessMitigationPol = k32.NewProc("GetProcessMitigationPolicy")
	pWaitOnAddress           = kb.NewProc("WaitOnAddress")
	pWakeByAddressSingle     = kb.NewProc("WakeByAddressSingle")
	pGetProcAddress          = k32.NewProc("GetProcAddress")
	pGetModuleHandle         = k32.NewProc("GetModuleHandleW")
)

func say(format string, a ...any) { fmt.Printf("PROBE "+format+"\n", a...) }

func main() {
	mode := "main"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "main":
		runMain()
	case "idle":
		time.Sleep(time.Minute)
	case "waiter":
		runWaiter(os.Args[2])
	case "direct":
		runDirect()
	case "linuxnums":
		runLinuxNums()
	case "fsbase":
		runFSBase()
	case "filter":
		runFilter()
	case "fsbasekeep":
		runFSBaseKeep()
	case "spawn":
		runSpawn()
	case "arm":
		runARM(os.Args[2])
	case "pong":
		runPong(os.Args[2])
	}
}

func runMain() {
	var si [48]byte
	pGetSystemInfo.Call(uintptr(unsafe.Pointer(&si[0])))
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		say("sysinfo arch=%s pagesize=%d allocgranularity=%d", runtime.GOARCH,
			binary.LittleEndian.Uint32(si[4:8]), binary.LittleEndian.Uint32(si[40:44]))
	}
	for _, n := range []string{"VirtualAlloc2", "MapViewOfFile3", "VirtualFreeEx", "WaitOnAddress"} {
		say("export %s: kernel32=%v kernelbase=%v", n, k32.NewProc(n).Find() == nil, kb.NewProc(n).Find() == nil)
	}
	dumpStub("NtClose")
	dumpStub("NtAllocateVirtualMemory")
	child("direct")
	child("linuxnums")
	if runtime.GOARCH == "amd64" {
		child("fsbase")
	}
	child("filter")
	if runtime.GOARCH == "amd64" {
		child("fsbasekeep")
	}
	child("spawn")
	whpCheck()
	if runtime.GOARCH == "arm64" {
		for _, t := range []string{"x18", "tpidr", "ctr", "dczid", "icivau", "dccvau", "dczva"} {
			cmd := exec.Command(os.Args[0], "arm", t)
			out, err := cmd.CombinedOutput()
			code := 0
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			}
			fmt.Print(string(out))
			say("arm %s child exit=%#x", t, uint32(code))
		}
	}
	placeholders()
	waitCrossProcess()
	pingPong()
}

// child runs this binary in a mode and reports its output and exit code.
func child(mode string) {
	cmd := exec.Command(os.Args[0], mode)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		say("child %s start error: %v", mode, err)
		return
	}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			fmt.Println(l)
		}
	}
	say("child %s exit=%#x", mode, uint32(code))
}

func procAddr(name string) uintptr {
	h, _, _ := pGetModuleHandle.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("ntdll.dll"))))
	n, _ := syscall.BytePtrFromString(name)
	a, _, _ := pGetProcAddress.Call(h, uintptr(unsafe.Pointer(n)))
	return a
}

func dumpStub(name string) {
	a := procAddr(name)
	if a == 0 {
		say("stub %s not found", name)
		return
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(a)), 24)
	say("stub %s bytes=% x", name, b)
}

// ssnOf decodes the service number from the first bytes of an ntdll stub.
func ssnOf(name string) (uint32, bool) {
	a := procAddr(name)
	b := unsafe.Slice((*byte)(unsafe.Pointer(a)), 16)
	if runtime.GOARCH == "arm64" {
		w := binary.LittleEndian.Uint32(b[0:4])
		if w&0xFFE0001F == 0xD4000001 {
			return (w >> 5) & 0xFFFF, true
		}
		return 0, false
	}
	for i := 0; i < 12; i++ {
		if b[i] == 0xB8 {
			return binary.LittleEndian.Uint32(b[i+1 : i+5]), true
		}
	}
	return 0, false
}

func stubFor(ssn uint32) []byte {
	if runtime.GOARCH == "arm64" {
		var b [8]byte
		binary.LittleEndian.PutUint32(b[0:], 0xD4000001|(ssn&0xFFFF)<<5)
		binary.LittleEndian.PutUint32(b[4:], 0xD65F03C0)
		return b[:]
	}
	b := []byte{0x4C, 0x8B, 0xD1, 0xB8, 0, 0, 0, 0, 0x0F, 0x05, 0xC3}
	binary.LittleEndian.PutUint32(b[4:], ssn)
	return b
}

// execMem copies code into a fresh RWX page of this process.
func execMem(code []byte) uintptr {
	a, _, e := pVirtualAlloc.Call(0, 4096, 0x3000, 0x40)
	if a == 0 {
		say("VirtualAlloc RWX failed: %v", e)
		os.Exit(3)
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(a)), len(code)), code)
	h, _ := syscall.GetCurrentProcess()
	pFlushInstructionCache.Call(uintptr(h), a, uintptr(len(code)))
	return a
}

func runDirect() {
	ssn, ok := ssnOf("NtClose")
	if !ok {
		say("direct: cannot decode the NtClose service number")
		return
	}
	a := execMem(stubFor(ssn))
	r, _, _ := syscall.SyscallN(a, 0xBADBAD0)
	say("direct: NtClose(invalid handle) through a syscall stub in private memory ssn=%d status=%#x", ssn, uint32(r))
}

func runLinuxNums() {
	for n := uint32(0); n <= 3; n++ {
		a := execMem(stubFor(n))
		r, _, _ := syscall.SyscallN(a, 0, 0, 0, 0, 0, 0, 0, 0)
		say("linuxnums: syscall number %d with zero arguments returned status=%#x", n, uint32(r))
	}
}

func runFSBase() {
	// rdfsbase rax; ret
	a := execMem([]byte{0xF3, 0x48, 0x0F, 0xAE, 0xC0, 0xC3})
	r, _, _ := syscall.SyscallN(a)
	say("fsbase: RDFSBASE executed, fsbase=%#x", r)
}

func runFilter() {
	var flags uint32 = 1
	ok, _, e := pSetProcessMitigationPol.Call(11, uintptr(unsafe.Pointer(&flags)), 4)
	say("filter: SetProcessMitigationPolicy(ProcessSystemCallFilterPolicy, FilterId=1) ok=%d err=%v", ok, e)
	var got uint32
	h, _ := syscall.GetCurrentProcess()
	ok2, _, e2 := pGetProcessMitigationPol.Call(uintptr(h), 11, uintptr(unsafe.Pointer(&got)), 4)
	say("filter: GetProcessMitigationPolicy ok=%d value=%#x err=%v", ok2, got, e2)
	if ssn, ok := ssnOf("NtClose"); ok {
		a := execMem(stubFor(ssn))
		r, _, _ := syscall.SyscallN(a, 0xBADBAD0)
		say("filter: NtClose through a private stub after the policy status=%#x", uint32(r))
	}
}

const (
	memReserve    = 0x2000
	memReservePH  = 0x40000
	memReplacePH  = 0x4000
	memRelease    = 0x8000
	memPreservePH = 0x2
	pageNoAccess  = 0x01
	pageReadOnly  = 0x02
	pageReadWrite = 0x04
	pageExecRead  = 0x20
	pageExecRW    = 0x40
	fileMapAllAcc = 0xF001F
)

func spawnSuspended() (syscall.Handle, *syscall.ProcessInformation) {
	exe, _ := os.Executable()
	argv, _ := syscall.UTF16PtrFromString(`"` + exe + `" idle`)
	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi syscall.ProcessInformation
	err := syscall.CreateProcess(nil, argv, nil, nil, false, 0x4, nil, nil, &si, &pi)
	if err != nil {
		say("placeholders: CreateProcess suspended failed: %v", err)
		return 0, nil
	}
	return pi.Process, &pi
}

func placeholders() {
	proc, pi := spawnSuspended()
	if pi == nil {
		return
	}
	defer syscall.TerminateProcess(proc, 0)
	base, _, e := pVirtualAlloc2.Call(uintptr(proc), 0, 0x100000, memReserve|memReservePH, pageNoAccess, 0, 0)
	say("placeholders: reserve 1MiB placeholder in a remote process base=%#x err=%v", base, e)
	if base == 0 {
		return
	}
	split := func(addr uintptr, size uintptr) bool {
		r, _, e := pVirtualFreeEx.Call(uintptr(proc), addr, size, memRelease|memPreservePH)
		if r == 0 {
			say("placeholders: split at %#x size %#x failed: %v", addr, size, e)
			return false
		}
		return true
	}
	// Carve 4KiB placeholders at 0x1000 and 0x5000 from the 64KiB-aligned base.
	for _, off := range []uintptr{0, 0x1000, 0x2000, 0x5000, 0x6000} {
		if off == 0 {
			if !split(base, 0x1000) {
				return
			}
			continue
		}
		if !split(base+off, 0x1000) {
			return
		}
	}
	say("placeholders: split into 4KiB placeholders ok")

	secSize := uint32(0x10000)
	sec, err := syscall.CreateFileMapping(syscall.InvalidHandle, nil, pageExecRW, 0, secSize, nil)
	if err != nil {
		say("placeholders: CreateFileMapping failed: %v", err)
		return
	}
	mapAt := func(addr, off uintptr, prot uintptr) uintptr {
		r, _, e := pMapViewOfFile3.Call(uintptr(sec), uintptr(proc), addr, off, 0x1000, memReplacePH, prot, 0, 0)
		if r == 0 {
			say("placeholders: MapViewOfFile3(addr=%#x offset=%#x) failed: %v", addr, off, e)
		} else {
			say("placeholders: MapViewOfFile3(addr=%#x offset=%#x) mapped a 4KiB view at a non-64KiB address", addr, off)
		}
		return r
	}
	a1 := mapAt(base+0x1000, 0x3000, pageReadWrite)
	a2 := mapAt(base+0x5000, 0x3000, pageReadWrite)
	if a1 == 0 || a2 == 0 {
		return
	}
	// Write through a local 64KiB view and read both remote aliases.
	local, _, e := pMapViewOfFile.Call(uintptr(sec), fileMapAllAcc, 0, 0, 0x10000)
	if local == 0 {
		say("placeholders: local MapViewOfFile failed: %v", e)
		return
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(local+0x3000)), 8), "ALIAS-OK")
	for _, a := range []uintptr{a1, a2} {
		buf := make([]byte, 8)
		var n uintptr
		pReadProcessMemory.Call(uintptr(proc), a, uintptr(unsafe.Pointer(&buf[0])), 8, uintptr(unsafe.Pointer(&n)))
		say("placeholders: remote alias %#x reads %q", a, buf)
	}
	var old uint32
	execTests(proc, sec, base)
	addrProbes(proc)
	perf(proc, sec)
	r, _, e := pVirtualProtectEx.Call(uintptr(proc), a1, 0x1000, pageReadOnly, uintptr(unsafe.Pointer(&old)))
	say("placeholders: VirtualProtectEx one 4KiB view to read-only ok=%d err=%v", r, e)
	r, _, e = pVirtualProtectEx.Call(uintptr(proc), a2, 0x1000, pageExecRead, uintptr(unsafe.Pointer(&old)))
	say("placeholders: VirtualProtectEx the other 4KiB view to execute-read ok=%d err=%v", r, e)
}

func waitCrossProcess() {
	name := fmt.Sprintf("Local\\gvxprobe-%d", os.Getpid())
	n16, _ := syscall.UTF16PtrFromString(name)
	sec, err := syscall.CreateFileMapping(syscall.InvalidHandle, nil, pageReadWrite, 0, 4096, n16)
	if err != nil {
		say("waitaddr: CreateFileMapping failed: %v", err)
		return
	}
	v, _, e := pMapViewOfFile.Call(uintptr(sec), fileMapAllAcc, 0, 0, 4096)
	if v == 0 {
		say("waitaddr: MapViewOfFile failed: %v", e)
		return
	}
	*(*uint32)(unsafe.Pointer(v)) = 0
	cmd := exec.Command(os.Args[0], "waiter", name)
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		say("waitaddr: start waiter failed: %v", err)
		return
	}
	time.Sleep(700 * time.Millisecond)
	*(*uint32)(unsafe.Pointer(v)) = 1
	pWakeByAddressSingle.Call(v)
	buf := make([]byte, 512)
	n, _ := stdout.Read(buf)
	_ = cmd.Wait()
	fmt.Print(string(buf[:n]))
}

func runWaiter(name string) {
	n16, _ := syscall.UTF16PtrFromString(name)
	sec, _, e := pOpenFileMapping.Call(fileMapAllAcc, 0, uintptr(unsafe.Pointer(n16)))
	if sec == 0 {
		say("waiter: OpenFileMapping failed: %v", e)
		return
	}
	v, _, e := pMapViewOfFile.Call(sec, fileMapAllAcc, 0, 0, 4096)
	if v == 0 {
		say("waiter: MapViewOfFile failed: %v", e)
		return
	}
	var undesired uint32
	start := time.Now()
	r, _, e := pWaitOnAddress.Call(v, uintptr(unsafe.Pointer(&undesired)), 4, 4000)
	say("waitaddr: cross-process wake: WaitOnAddress returned ok=%d after %d ms (the waker stored 1 and called WakeByAddressSingle at about 700 ms; a 4000 ms result means no wake arrived) err=%v",
		r, time.Since(start).Milliseconds(), e)
}

func runFSBaseKeep() {
	runtime.LockOSThread()
	// mov rax, rcx; wrfsbase rax; rdfsbase rax; ret
	both := execMem([]byte{0x48, 0x89, 0xC8, 0xF3, 0x48, 0x0F, 0xAE, 0xD0, 0xF3, 0x48, 0x0F, 0xAE, 0xC0, 0xC3})
	rd := execMem([]byte{0xF3, 0x48, 0x0F, 0xAE, 0xC0, 0xC3}) // rdfsbase rax; ret
	const want = 0x00007ff112345678
	got, _, _ := syscall.SyscallN(both, want)
	say("fsbasekeep: WRFSBASE then RDFSBASE in one stub returned %#x (want %#x)", got, uintptr(want))
	got, _, _ = syscall.SyscallN(rd)
	say("fsbasekeep: RDFSBASE in a later call on the same thread returned %#x", got)
	start := time.Now()
	lost := uintptr(0)
	for time.Since(start) < 300*time.Millisecond {
		got, _, _ = syscall.SyscallN(rd)
		if got != want {
			lost = got
			break
		}
	}
	say("fsbasekeep: spinning 300 ms on the thread: base changed=%v last=%#x", lost != 0 || got != want, got)
	syscall.SyscallN(both, want)
	time.Sleep(1 * time.Millisecond)
	got, _, _ = syscall.SyscallN(rd)
	say("fsbasekeep: RDFSBASE after a 1 ms sleep returned %#x", got)
	syscall.SyscallN(both, want)
	runtime.Gosched()
	got, _, _ = syscall.SyscallN(rd)
	say("fsbasekeep: RDFSBASE after Gosched returned %#x", got)
}

func runSpawn() {
	exe, _ := os.Executable()
	const n = 30
	start := time.Now()
	for i := 0; i < n; i++ {
		argv, _ := syscall.UTF16PtrFromString(`"` + exe + `" idle`)
		var si syscall.StartupInfo
		si.Cb = uint32(unsafe.Sizeof(si))
		var pi syscall.ProcessInformation
		if err := syscall.CreateProcess(nil, argv, nil, nil, false, 0x4, nil, nil, &si, &pi); err != nil {
			say("spawn: CreateProcess failed: %v", err)
			return
		}
		syscall.TerminateProcess(pi.Process, 0)
		syscall.WaitForSingleObject(pi.Process, 5000)
		syscall.CloseHandle(pi.Thread)
		syscall.CloseHandle(pi.Process)
	}
	say("spawn: CreateProcess(suspended)+Terminate+Wait average=%.1f ms over %d runs", float64(time.Since(start).Microseconds())/1000/n, n)
}

var (
	pOpenEvent   = k32.NewProc("OpenEventW")
	pCreateEvent = k32.NewProc("CreateEventW")
	pSetEvent    = k32.NewProc("SetEvent")
)

func setEvent(h syscall.Handle) { pSetEvent.Call(uintptr(h)) }

func runPong(name string) {
	open := func(suffix string) syscall.Handle {
		n16, _ := syscall.UTF16PtrFromString(name + suffix)
		h, _, _ := pOpenEvent.Call(0x1F0003, 0, uintptr(unsafe.Pointer(n16)))
		return syscall.Handle(h)
	}
	a, b := open("A"), open("B")
	for i := 0; i < 20000; i++ {
		syscall.WaitForSingleObject(a, 10000)
		setEvent(b)
	}
}

func pingPong() {
	name := fmt.Sprintf("Local\\gvxpp-%d", os.Getpid())
	mk := func(suffix string) syscall.Handle {
		n16, _ := syscall.UTF16PtrFromString(name + suffix)
		h, _, e := pCreateEvent.Call(0, 0, 0, uintptr(unsafe.Pointer(n16)))
		if h == 0 {
			say("pingpong: CreateEvent failed: %v", e)
			os.Exit(0)
		}
		return syscall.Handle(h)
	}
	a, b := mk("A"), mk("B")
	cmd := exec.Command(os.Args[0], "pong", name)
	if err := cmd.Start(); err != nil {
		say("pingpong: start failed: %v", err)
		return
	}
	time.Sleep(500 * time.Millisecond)
	const n = 20000
	start := time.Now()
	for i := 0; i < n; i++ {
		setEvent(a)
		syscall.WaitForSingleObject(b, 10000)
	}
	say("pingpong: cross-process event round trip average=%.1f us over %d round trips", float64(time.Since(start).Nanoseconds())/1000/n, n)
	_ = cmd.Wait()
}

func execTests(proc syscall.Handle, sec syscall.Handle, base uintptr) {
	prot := func(label string, addr uintptr, p uintptr) {
		var old uint32
		r, _, e := pVirtualProtectEx.Call(uintptr(proc), addr, 0x1000, p, uintptr(unsafe.Pointer(&old)))
		say("exec: %s -> protect %#x ok=%d err=%v", label, p, r, e)
	}
	r, _, e := pMapViewOfFile3.Call(uintptr(sec), uintptr(proc), base+0x2000, 0x4000, 0x1000, memReplacePH, pageExecRW, 0, 0)
	say("exec: map a 4KiB view as PAGE_EXECUTE_READWRITE at %#x ok=%v err=%v", base+0x2000, r != 0, e)
	if r != 0 {
		prot("from execute-read-write", base+0x2000, pageExecRead)
		prot("from execute-read", base+0x2000, pageReadOnly)
		prot("from read-only", base+0x2000, pageExecRead)
		prot("from execute-read", base+0x2000, pageNoAccess)
		prot("from no-access", base+0x2000, pageExecRW)
	}
	r, _, e = pMapViewOfFile3.Call(uintptr(sec), uintptr(proc), base+0x6000, 0x5000, 0x1000, memReplacePH, pageExecRead, 0, 0)
	say("exec: map a 4KiB view as PAGE_EXECUTE_READ at %#x ok=%v err=%v", base+0x6000, r != 0, e)
}

func addrProbes(proc syscall.Handle) {
	for _, a := range []uintptr{0x10000, 0x400000, 0x10000000000, 0x100000000000} {
		r, _, e := pVirtualAlloc2.Call(uintptr(proc), a, 0x10000, memReserve|memReservePH, pageNoAccess, 0, 0)
		say("addr: reserve a 64KiB placeholder at %#x in a fresh remote process ok=%v err=%v", a, r != 0, e)
	}
}

var pUnmapViewOfFile2 = kb.NewProc("UnmapViewOfFile2")

func perf(proc syscall.Handle, sec syscall.Handle) {
	const n = 1500
	base, _, e := pVirtualAlloc2.Call(uintptr(proc), 0, n*0x1000, memReserve|memReservePH, pageNoAccess, 0, 0)
	if base == 0 {
		say("perf: reserve failed: %v", e)
		return
	}
	var tSplit, tMap, tProt, tUnmap time.Duration
	for i := uintptr(0); i < n; i++ {
		addr := base + i*0x1000
		t0 := time.Now()
		if i < n-1 {
			if r, _, _ := pVirtualFreeEx.Call(uintptr(proc), addr, 0x1000, memRelease|memPreservePH); r == 0 {
				say("perf: split failed at page %d", i)
				return
			}
		}
		t1 := time.Now()
		r, _, _ := pMapViewOfFile3.Call(uintptr(sec), uintptr(proc), addr, (i%16)*0x1000, 0x1000, memReplacePH, pageExecRW, 0, 0)
		t2 := time.Now()
		if r == 0 {
			say("perf: map failed at page %d", i)
			return
		}
		var old uint32
		pVirtualProtectEx.Call(uintptr(proc), addr, 0x1000, pageReadOnly, uintptr(unsafe.Pointer(&old)))
		t3 := time.Now()
		pUnmapViewOfFile2.Call(uintptr(proc), addr, memPreservePH)
		t4 := time.Now()
		tSplit += t1.Sub(t0)
		tMap += t2.Sub(t1)
		tProt += t3.Sub(t2)
		tUnmap += t4.Sub(t3)
	}
	us := func(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1000 / n }
	say("perf: remote 4KiB operations average split=%.1f us map=%.1f us protect=%.1f us unmap=%.1f us over %d pages", us(tSplit), us(tMap), us(tProt), us(tUnmap), n)
}

func whpCheck() {
	winhv := syscall.NewLazyDLL("WinHvPlatform.dll")
	p := winhv.NewProc("WHvGetCapability")
	if err := p.Find(); err != nil {
		say("whp: WinHvPlatform.dll not available: %v", err)
		return
	}
	var present uint32
	var written uint32
	hr, _, _ := p.Call(0, uintptr(unsafe.Pointer(&present)), 4, uintptr(unsafe.Pointer(&written)))
	say("whp: WHvGetCapability(CodeHypervisorPresent) hr=%#x present=%d", uint32(hr), present)
}

func le32(ws ...uint32) []byte {
	b := make([]byte, 4*len(ws))
	for i, w := range ws {
		binary.LittleEndian.PutUint32(b[4*i:], w)
	}
	return b
}

func runARM(which string) {
	const ret = 0xD65F03C0
	var code []byte
	var args []uintptr
	switch which {
	case "x18":
		// mov x9, x18; mov x18, x0; L: sub x1, x1, #1; cbnz x1, L; mov x0, x18; mov x18, x9; ret
		code = le32(0xAA1203E9, 0xAA0003F2, 0xD1000421, 0xB5FFFFE1, 0xAA1203E0, 0xAA0903F2, ret)
		args = []uintptr{0x1234567890ABCDEF, 400000000}
	case "tpidr":
		// mrs x9, tpidr_el0; msr tpidr_el0, x0; L: sub x1, x1, #1; cbnz x1, L; mrs x0, tpidr_el0; msr tpidr_el0, x9; ret
		code = le32(0xD53BD049, 0xD51BD040, 0xD1000421, 0xB5FFFFE1, 0xD53BD040, 0xD51BD049, ret)
		args = []uintptr{0x1234567890ABCDEF, 400000000}
	case "ctr":
		code = le32(0xD53B0020, ret) // mrs x0, ctr_el0
	case "dczid":
		code = le32(0xD53B00E0, ret) // mrs x0, dczid_el0
	case "icivau":
		code = le32(0xD50B7520, ret) // ic ivau, x0
		args = []uintptr{execMem([]byte{0, 0, 0, 0})}
	case "dccvau":
		code = le32(0xD50B7B20, ret) // dc cvau, x0
		args = []uintptr{execMem([]byte{0, 0, 0, 0})}
	case "dczva":
		code = le32(0xD50B7420, ret) // dc zva, x0
		args = []uintptr{execMem([]byte{0, 0, 0, 0})}
	}
	a := execMem(code)
	r, _, _ := syscall.SyscallN(a, args...)
	say("arm %s: executed, x0=%#x", which, r)
}
