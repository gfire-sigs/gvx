// Throwaway research probe for the Windows systrap design. Not part of gvx.
// It tests the "stub is a suspended process, guest threads are loader-less,
// the Sentry is the debugger" design on a real Windows host.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"syscall"
	"time"
	"unsafe"
)

var (
	ntd = syscall.NewLazyDLL("ntdll.dll")
	k32 = syscall.NewLazyDLL("kernel32.dll")
	kb  = syscall.NewLazyDLL("kernelbase.dll")
	adv = syscall.NewLazyDLL("advapi32.dll")

	pNtCreateDebugObject  = ntd.NewProc("NtCreateDebugObject")
	pNtDebugActiveProcess = ntd.NewProc("NtDebugActiveProcess")
	pNtWaitForDebugEvent  = ntd.NewProc("NtWaitForDebugEvent")
	pNtDebugContinue      = ntd.NewProc("NtDebugContinue")
	pNtCreateThreadEx     = ntd.NewProc("NtCreateThreadEx")
	pNtSuspendThread      = ntd.NewProc("NtSuspendThread")
	pNtResumeThread       = ntd.NewProc("NtResumeThread")
	pNtTerminateProcess   = ntd.NewProc("NtTerminateProcess")

	pGetThreadContext = k32.NewProc("GetThreadContext")
	pSetThreadContext = k32.NewProc("SetThreadContext")
	pGetThreadId      = k32.NewProc("GetThreadId")
	pVirtualFreeEx    = k32.NewProc("VirtualFreeEx")
	pVirtualQueryEx   = k32.NewProc("VirtualQueryEx")
	pMapViewOfFile    = k32.NewProc("MapViewOfFile")
	pCreateJob        = k32.NewProc("CreateJobObjectW")
	pSetJobInfo       = k32.NewProc("SetInformationJobObject")
	pAssignJob        = k32.NewProc("AssignProcessToJobObject")
	pFlushICache      = k32.NewProc("FlushInstructionCache")
	pVirtualProtectEx = k32.NewProc("VirtualProtectEx")
	pUnmapViewOfFile2 = kb.NewProc("UnmapViewOfFile2")
	pInitAttrList     = k32.NewProc("InitializeProcThreadAttributeList")
	pUpdateAttrList   = k32.NewProc("UpdateProcThreadAttribute")

	pVirtualAlloc2  = kb.NewProc("VirtualAlloc2")
	pMapViewOfFile3 = kb.NewProc("MapViewOfFile3")

	pCreateRestrictedToken = adv.NewProc("CreateRestrictedToken")
	pCreateProcessAsUserW  = adv.NewProc("CreateProcessAsUserW")
	pSetTokenInformation   = adv.NewProc("SetTokenInformation")
)

func say(f string, a ...any) { fmt.Printf("SP "+f+"\n", a...) }

const (
	memFree       = 0x10000
	memReserve    = 0x2000
	memReservePH  = 0x40000
	memReplacePH  = 0x4000
	memRelease    = 0x8000
	memPreservePH = 0x2
	pageNoAccess  = 0x01
	pageReadWrite = 0x04
	pageExecRW    = 0x40
	dbgContinue   = 0x00010002
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "idle" {
		time.Sleep(time.Hour)
		return
	}
	say("goos=%s goarch=%s numcpu=%d", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	go func() {
		time.Sleep(150 * time.Second)
		say("WATCHDOG: probe still running after 150 s, exiting")
		os.Exit(3)
	}()
	for _, mode := range []string{"plain", "locked"} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					say("%s: panic %v", mode, r)
				}
			}()
			runMode(mode)
		}()
	}
}

// ---- CONTEXT access -------------------------------------------------------

type layout struct {
	size, flagsOff, pc, sp, r0, r1, r3, r6, r18 int
	full, x18flag                                 uint32
	trapAdvance                                   uint64
}

var L = func() layout {
	if runtime.GOARCH == "arm64" {
		// x[i] at 8+8*i, sp 256, pc 264.
		return layout{size: 912, flagsOff: 0, pc: 264, sp: 256, r0: 8, r1: 16, r3: 32, r6: 56, r18: 152,
			full: 0x400007, x18flag: 0x10, trapAdvance: 4}
	}
	// amd64: rax 120, rbx 144 (data), rsi 168 (counter), rdi 176, rsp 152, rip 248.
	return layout{size: 1232, flagsOff: 48, pc: 248, sp: 152, r0: 120, r1: 176, r3: 144, r6: 168, r18: 0,
		full: 0x10000B, x18flag: 0, trapAdvance: 1}
}()

type cpuCtx struct {
	buf []byte
	p   uintptr
}

func newCtx() *cpuCtx {
	b := make([]byte, L.size+32)
	p := (uintptr(unsafe.Pointer(&b[0])) + 15) &^ 15
	return &cpuCtx{b, p}
}
func (c *cpuCtx) u64(off int) *uint64 { return (*uint64)(unsafe.Pointer(c.p + uintptr(off))) }
func (c *cpuCtx) u32(off int) *uint32 { return (*uint32)(unsafe.Pointer(c.p + uintptr(off))) }

func getCtx(th syscall.Handle, flags uint32) (*cpuCtx, error) {
	c := newCtx()
	*c.u32(L.flagsOff) = flags
	r, _, e := pGetThreadContext.Call(uintptr(th), c.p)
	if r == 0 {
		return nil, e
	}
	return c, nil
}

func setCtx(th syscall.Handle, c *cpuCtx, flags uint32) error {
	*c.u32(L.flagsOff) = flags
	r, _, e := pSetThreadContext.Call(uintptr(th), c.p)
	if r == 0 {
		return e
	}
	return nil
}

// ---- debug events ---------------------------------------------------------

type dbgEvent struct {
	state    uint32
	pid, tid uint64
	code     uint32
	addr     uint64
	info     [3]uint64
	at       time.Time
}

func parseEvent(b []byte) dbgEvent {
	le32 := func(o int) uint32 { return *(*uint32)(unsafe.Pointer(&b[o])) }
	le64 := func(o int) uint64 { return *(*uint64)(unsafe.Pointer(&b[o])) }
	ev := dbgEvent{state: le32(0), pid: le64(8), tid: le64(16), at: time.Now()}
	if ev.state >= 6 && ev.state <= 8 {
		ev.code = le32(24)
		ev.addr = le64(40)
		ev.info = [3]uint64{le64(56), le64(64), le64(72)}
	}
	return ev
}

func dbgCont(dbg uintptr, pid, tid uint64, status uint32) uint32 {
	cid := [2]uint64{pid, tid}
	r, _, _ := pNtDebugContinue.Call(dbg, uintptr(unsafe.Pointer(&cid[0])), uintptr(status))
	return uint32(r)
}

type pump struct {
	ch    chan dbgEvent
	stop  chan struct{}
	done  chan struct{}
	other map[uint32]int
}

func startPump(dbg uintptr) *pump {
	p := &pump{ch: make(chan dbgEvent, 256), stop: make(chan struct{}), done: make(chan struct{}), other: map[uint32]int{}}
	go func() {
		runtime.LockOSThread()
		defer close(p.done)
		buf := make([]byte, 2048)
		for {
			select {
			case <-p.stop:
				return
			default:
			}
			timeout := int64(-1_000_000) // 100 ms
			st, _, _ := pNtWaitForDebugEvent.Call(dbg, 0, uintptr(unsafe.Pointer(&timeout)), uintptr(unsafe.Pointer(&buf[0])))
			switch uint32(st) {
			case 0:
			case 0x102, 0x101, 0xC0:
				continue
			default:
				say("pump: NtWaitForDebugEvent status %#x", uint32(st))
				return
			}
			ev := parseEvent(buf)
			switch ev.state {
			case 6, 7, 8:
				p.ch <- ev
			default:
				p.other[ev.state]++
				dbgCont(dbg, ev.pid, ev.tid, dbgContinue)
			}
		}
	}()
	return p
}

func (p *pump) next(d time.Duration) (dbgEvent, bool) {
	select {
	case ev := <-p.ch:
		return ev, true
	case <-time.After(d):
		return dbgEvent{}, false
	}
}

// ---- stub process ---------------------------------------------------------

func u16(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }

func spawnStub(locked bool) (syscall.Handle, *syscall.ProcessInformation, error) {
	exe, _ := os.Executable()
	cmd := u16(`"` + exe + `" idle`)
	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi syscall.ProcessInformation
	if !locked {
		err := syscall.CreateProcess(nil, cmd, nil, nil, false, 0x4, nil, nil, &si, &pi)
		return pi.Process, &pi, err
	}
	self, _ := syscall.GetCurrentProcess()
	var tok syscall.Token
	if err := syscall.OpenProcessToken(self, 0x2|0x8|0x1|0x80|0x100, &tok); err != nil {
		return 0, nil, fmt.Errorf("OpenProcessToken: %w", err)
	}
	var rtok syscall.Token
	r, _, e := pCreateRestrictedToken.Call(uintptr(tok), 0x1, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&rtok)))
	if r == 0 {
		return 0, nil, fmt.Errorf("CreateRestrictedToken: %v", e)
	}
	sid, err := syscall.StringToSid("S-1-16-4096")
	if err != nil {
		return 0, nil, err
	}
	type mandatoryLabel struct {
		sid   *syscall.SID
		attrs uint32
	}
	lbl := mandatoryLabel{sid, 0x20}
	r, _, e = pSetTokenInformation.Call(uintptr(rtok), 25, uintptr(unsafe.Pointer(&lbl)), 16+12)
	if r == 0 {
		return 0, nil, fmt.Errorf("SetTokenInformation(IL): %v", e)
	}
	pip, err := createWithMitigation(uintptr(rtok), cmd)
	if err != nil {
		say("locked: %v; falling back to creation without the mitigation attribute", err)
		r, _, e = pCreateProcessAsUserW.Call(uintptr(rtok), 0, uintptr(unsafe.Pointer(cmd)), 0, 0, 0, 0x4, 0, 0,
			uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
		if r == 0 {
			return 0, nil, fmt.Errorf("CreateProcessAsUserW: %v", e)
		}
	} else {
		pi = *pip
		say("locked: Win32k system call disable applied at creation")
	}
	// A job with one active process and kill-on-close.
	job, _, _ := pCreateJob.Call(0, 0)
	var info [144]byte
	*(*uint32)(unsafe.Pointer(&info[16])) = 0x8 | 0x2000
	*(*uint32)(unsafe.Pointer(&info[40])) = 1
	r, _, e = pSetJobInfo.Call(job, 9, uintptr(unsafe.Pointer(&info[0])), 144)
	if r == 0 {
		say("locked: SetInformationJobObject failed: %v", e)
	}
	r, _, e = pAssignJob.Call(job, uintptr(pi.Process))
	if r == 0 {
		say("locked: AssignProcessToJobObject failed: %v", e)
	} else {
		say("locked: child is in a job with ActiveProcessLimit=1 and a restricted low-integrity token")
	}
	return pi.Process, &pi, nil
}

type region struct {
	base, size uint64
	state      uint32
	typ        uint32
}

func walk(proc syscall.Handle) []region {
	var out []region
	addr := uint64(0x10000)
	for addr < 0x7FFFFFFF0000 {
		var mbi [48]byte
		r, _, _ := pVirtualQueryEx.Call(uintptr(proc), uintptr(addr), uintptr(unsafe.Pointer(&mbi[0])), 48)
		if r == 0 {
			break
		}
		base := *(*uint64)(unsafe.Pointer(&mbi[0]))
		size := *(*uint64)(unsafe.Pointer(&mbi[24]))
		out = append(out, region{base, size, *(*uint32)(unsafe.Pointer(&mbi[32])), *(*uint32)(unsafe.Pointer(&mbi[40]))})
		addr = base + size
	}
	return out
}

func dumpMap(proc syscall.Handle) (gapBase, gapSize uint64) {
	rs := walk(proc)
	var gaps []region
	lines := 0
	var curStart, curEnd uint64
	flush := func() {
		if curEnd > curStart && lines < 40 {
			say("map: occupied %#x-%#x (%d KiB)", curStart, curEnd, (curEnd-curStart)/1024)
			lines++
		}
		curStart, curEnd = 0, 0
	}
	for _, r := range rs {
		if r.state == memFree {
			flush()
			gaps = append(gaps, r)
			continue
		}
		if curEnd == r.base {
			curEnd = r.base + r.size
		} else {
			flush()
			curStart, curEnd = r.base, r.base+r.size
		}
	}
	flush()
	sort.Slice(gaps, func(i, j int) bool { return gaps[i].size > gaps[j].size })
	for i := 0; i < 4 && i < len(gaps); i++ {
		say("map: free gap %#x size %d GiB", gaps[i].base, gaps[i].size>>30)
	}
	// lowest gap that is at least 1 GiB
	sort.Slice(gaps, func(i, j int) bool { return gaps[i].base < gaps[j].base })
	for _, g := range gaps {
		if g.size >= 1<<30 {
			return g.base, g.size
		}
	}
	return 0, 0
}

// ---- tests ----------------------------------------------------------------

func w32(b []byte, ws ...uint32) []byte {
	for _, w := range ws {
		b = append(b, byte(w), byte(w>>8), byte(w>>16), byte(w>>24))
	}
	return b
}

type guestCode struct {
	code     []byte
	trapOff  int // offset of the trap instruction
	trapSite int // for amd64, the int3 byte is at trapOff
}

func codeA() guestCode { // one trap, then stores results into [x3/rbx]
	if runtime.GOARCH == "arm64" {
		return guestCode{code: w32(nil, 0xD2800540, 0xD2824688, 0xD51BD048, 0xD420B800, 0xF9000060, 0xF9000472, 0xD53BD049, 0xF9000869, 0x14000000), trapOff: 0xC}
	}
	return guestCode{code: []byte{0xb8, 0x2a, 0, 0, 0, 0xcc, 0x90, 0x48, 0x89, 0x03, 0xeb, 0xfe}, trapOff: 5}
}
func codeB() guestCode { // spin counter at [x6/rsi]
	if runtime.GOARCH == "arm64" {
		return guestCode{code: w32(nil, 0xF94000C5, 0x910004A5, 0xF90000C5, 0x17FFFFFD)}
	}
	return guestCode{code: []byte{0x48, 0xff, 0x06, 0xeb, 0xfb}}
}
func codeC() guestCode { // trap loop
	if runtime.GOARCH == "arm64" {
		return guestCode{code: w32(nil, 0xD420B800, 0x17FFFFFF), trapOff: 0}
	}
	return guestCode{code: []byte{0xcc, 0x90, 0xeb, 0xfc}, trapOff: 0}
}
func codeD() guestCode { // load from [x1/rdi], store to [x3/rbx]
	if runtime.GOARCH == "arm64" {
		return guestCode{code: w32(nil, 0xF9400020, 0xF9000060, 0x14000000)}
	}
	return guestCode{code: []byte{0x48, 0x8b, 0x07, 0x48, 0x89, 0x03, 0xeb, 0xfe}}
}

type rig struct {
	proc      syscall.Handle
	dbg       uintptr
	p         *pump
	local     uintptr // Sentry view of the section
	remote    uint64  // stub address of page 0
	threads   map[uint64]syscall.Handle
	nextPage  int
	pageCodes map[int]bool
}

// mitigation: Win32k system call disable at creation through an attribute list.
func createWithMitigation(tok uintptr, cmd *uint16) (*syscall.ProcessInformation, error) {
	var size uintptr
	pInitAttrList.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))
	list := make([]byte, size)
	r, _, e := pInitAttrList.Call(uintptr(unsafe.Pointer(&list[0])), 1, 0, uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return nil, fmt.Errorf("InitializeProcThreadAttributeList: %v", e)
	}
	policy := uint64(0x1) << 28 // PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON
	r, _, e = pUpdateAttrList.Call(uintptr(unsafe.Pointer(&list[0])), 0, 0x20007, uintptr(unsafe.Pointer(&policy)), 8, 0, 0)
	if r == 0 {
		return nil, fmt.Errorf("UpdateProcThreadAttribute(mitigation): %v", e)
	}
	type siEx struct {
		si   syscall.StartupInfo
		attr uintptr
	}
	var ex siEx
	ex.si.Cb = uint32(unsafe.Sizeof(ex))
	ex.attr = uintptr(unsafe.Pointer(&list[0]))
	var pi syscall.ProcessInformation
	r, _, e = pCreateProcessAsUserW.Call(tok, 0, uintptr(unsafe.Pointer(cmd)), 0, 0, 0, 0x4|0x80000, 0, 0,
		uintptr(unsafe.Pointer(&ex)), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		return nil, fmt.Errorf("CreateProcessAsUserW with mitigation attribute: %v", e)
	}
	return &pi, nil
}

type stub struct {
	name     string
	proc     syscall.Handle
	pi       *syscall.ProcessInformation
	local    uintptr // Sentry view of the section
	win      uint64  // window base in the stub
	threads  map[uint64]syscall.Handle
	nextPage int
}

func (r *stub) pageAddr(i int) uint64 { return r.win + uint64(i)*0x1000 }
func (r *stub) pageLocal(i int) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(r.local+uintptr(i)*0x1000)), 0x1000)
}

type session struct {
	dbg     uintptr
	pm      *pump
	pending []dbgEvent
}

func (s *session) wait(pid, tid uint64, d time.Duration) (dbgEvent, bool) {
	for i, ev := range s.pending {
		if ev.tid == tid && ev.pid == pid {
			s.pending = append(s.pending[:i], s.pending[i+1:]...)
			return ev, true
		}
	}
	deadline := time.Now().Add(d)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return dbgEvent{}, false
		}
		ev, ok := s.pm.next(left)
		if !ok {
			return dbgEvent{}, false
		}
		if ev.tid == tid && ev.pid == pid {
			return ev, true
		}
		s.pending = append(s.pending, ev)
	}
}

func startCode() guestCode {
	if runtime.GOARCH == "arm64" {
		return guestCode{code: w32(nil, 0xD420B820)} // brk #0x5c1
	}
	return guestCode{code: []byte{0xcc, 0x90}}
}

// bringUp creates the stub, attaches the debug object, reserves the guest
// window, lets the loader finish, parks the initial thread and maps pages.
func bringUp(sess *session, name string, locked bool, file syscall.Handle, nPages int) *stub {
	proc, pi, err := spawnStub(locked)
	if err != nil {
		say("%s: spawn failed: %v", name, err)
		return nil
	}
	st := &stub{name: name, proc: proc, pi: pi, threads: map[uint64]syscall.Handle{}, nextPage: 4}
	say("%s: stub pid=%d initial tid=%d created suspended", name, pi.ProcessId, pi.ThreadId)
	r0, _, _ := pNtDebugActiveProcess.Call(uintptr(proc), sess.dbg)
	say("%s: NtDebugActiveProcess status %#x", name, uint32(r0))
	if uint32(r0) != 0 {
		return nil
	}
	// guest window before the loader runs
	const winBase = uint64(0x100000000000) // 16 TiB
	const winSize = uint64(0x6EE000000000) // up to 0x7EE000000000
	rr, _, e := pVirtualAlloc2.Call(uintptr(proc), uintptr(winBase), uintptr(winSize), memReserve|memReservePH, pageNoAccess, 0, 0)
	say("%s: reserve guest window %#x-%#x (%d TiB) -> %#x err=%v", name, winBase, winBase+winSize, winSize>>40, rr, e)
	if rr == 0 {
		return nil
	}
	st.win = winBase
	// let the loader run until the initial breakpoint
	var prev uint32
	pNtResumeThread.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&prev)))
	ev, ok := sess.wait(uint64(pi.ProcessId), uint64(pi.ThreadId), 5*time.Second)
	if !ok {
		say("%s: no initial event from the loader within 5 s", name)
		return nil
	}
	say("%s: first event state=%d code=%#x addr=%#x", name, ev.state, ev.code, ev.addr)
	pNtSuspendThread.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&prev)))
	cst := dbgCont(sess.dbg, ev.pid, ev.tid, dbgContinue)
	say("%s: initial thread parked (suspend count was %d), continue status %#x", name, prev, cst)
	dumpMap(proc)

	sec, err := syscall.CreateFileMapping(file, nil, pageExecRW, 0, 0, nil)
	if err != nil {
		say("%s: CreateFileMapping: %v", name, err)
		return nil
	}
	loc, _, e := pMapViewOfFile.Call(uintptr(sec), 0x1F|0x20, 0, 0, uintptr(nPages)*0x1000)
	if loc == 0 {
		say("%s: local MapViewOfFile failed: %v", name, e)
		return nil
	}
	st.local = loc
	// one multi-page view
	r1, _, e1 := pVirtualFreeEx.Call(uintptr(proc), uintptr(winBase), uintptr(nPages)*0x1000, memRelease|memPreservePH)
	if r1 == 0 {
		say("%s: split %d pages failed: %v", name, nPages, e1)
		return nil
	}
	mv, _, e2 := pMapViewOfFile3.Call(uintptr(sec), uintptr(proc), uintptr(winBase), 0, uintptr(nPages)*0x1000, memReplacePH, pageExecRW, 0, 0)
	if mv == 0 {
		say("%s: MapViewOfFile3 %d pages failed: %v", name, nPages, e2)
		return nil
	}
	say("%s: one %d-page RWX view mapped in the guest window", name, nPages)
	copy(st.pageLocal(2), startCode().code)
	pFlushICache.Call(uintptr(proc), uintptr(st.pageAddr(2)), 0x1000)
	return st
}

// newThread creates a running loader-less thread whose start routine is a
// trap page, waits for that first trap, loads the guest registers, and
// continues the thread into the guest code page.
func (s *stub) newThread(sess *session, code guestCode, setup func(c *cpuCtx)) (syscall.Handle, uint64) {
	page := s.nextPage
	s.nextPage++
	copy(s.pageLocal(page), code.code)
	pFlushICache.Call(uintptr(s.proc), uintptr(s.pageAddr(page)), 0x1000)
	var th syscall.Handle
	st, _, _ := pNtCreateThreadEx.Call(uintptr(unsafe.Pointer(&th)), 0x1FFFFF, 0, uintptr(s.proc), uintptr(s.pageAddr(2)), 0, 0x22, 0, 0, 0, 0)
	if uint32(st) != 0 {
		say("%s: NtCreateThreadEx status %#x", s.name, uint32(st))
		return 0, 0
	}
	tidr, _, _ := pGetThreadId.Call(uintptr(th))
	tid := uint64(tidr)
	s.threads[tid] = th
	ev, ok := sess.wait(uint64(s.pi.ProcessId), tid, 3*time.Second)
	if !ok {
		say("%s: thread %d never reached its start trap", s.name, tid)
		return 0, 0
	}
	c, err := getCtx(th, L.full|L.x18flag)
	if err != nil {
		say("%s: GetThreadContext at the start trap: %v", s.name, err)
		return 0, 0
	}
	say("%s: thread %d start trap code=%#x pc=%#x x18/r=%#x", s.name, tid, ev.code, *c.u64(L.pc), func() uint64 {
		if L.r18 != 0 {
			return *c.u64(L.r18)
		}
		return 0
	}())
	*c.u64(L.pc) = s.pageAddr(page)
	*c.u64(L.sp) = s.pageAddr(page) + 0xF00
	setup(c)
	if err := setCtx(th, c, L.full|L.x18flag); err != nil {
		say("%s: SetThreadContext failed: %v", s.name, err)
		return 0, 0
	}
	// verify the context took
	c2, _ := getCtx(th, L.full|L.x18flag)
	say("%s: after set, pc=%#x (want %#x)", s.name, *c2.u64(L.pc), s.pageAddr(page))
	dbgCont(sess.dbg, ev.pid, ev.tid, dbgContinue)
	return th, tid
}

func suspend(th syscall.Handle) uint32 {
	var prev uint32
	st, _, _ := pNtSuspendThread.Call(uintptr(th), uintptr(unsafe.Pointer(&prev)))
	return uint32(st)
}
func resume(th syscall.Handle) uint32 {
	var prev uint32
	st, _, _ := pNtResumeThread.Call(uintptr(th), uintptr(unsafe.Pointer(&prev)))
	return uint32(st)
}

func runMode(mode string) {
	say("==== mode %s ====", mode)
	var dbg uintptr
	st0, _, _ := pNtCreateDebugObject.Call(uintptr(unsafe.Pointer(&dbg)), 0x1F000F, 0, 1)
	if uint32(st0) != 0 {
		say("NtCreateDebugObject status %#x", uint32(st0))
		return
	}
	pm := startPump(dbg)
	defer func() { close(pm.stop); <-pm.done }()
	sess := &session{dbg: dbg, pm: pm}

	file := filepath.Join(os.TempDir(), fmt.Sprintf("gvx-stubprobe-%d", os.Getpid()))
	fh, err := syscall.CreateFile(u16(file), syscall.GENERIC_READ|syscall.GENERIC_WRITE|0x20000000, 7, nil, syscall.CREATE_ALWAYS, 0x100|0x04000000, 0)
	if err != nil {
		say("CreateFile: %v", err)
		return
	}
	defer syscall.CloseHandle(fh)
	const nPages = 32
	syscall.SetFilePointer(fh, nPages*0x1000, nil, 0)
	syscall.SetEndOfFile(fh)

	s1 := bringUp(sess, mode+"/stub1", mode == "locked", fh, nPages)
	if s1 == nil {
		return
	}
	defer func() { pNtTerminateProcess.Call(uintptr(s1.proc), 0) }()
	data := s1.pageLocal(0)
	dataVA := s1.pageAddr(0)
	counterVA := s1.pageAddr(1)
	counter := (*uint64)(unsafe.Pointer(&s1.pageLocal(1)[0]))
	rd := func(i int) uint64 { return *(*uint64)(unsafe.Pointer(&data[i*8])) }
	pid := uint64(s1.pi.ProcessId)

	say("---- T1 park and resume (x18 and tpidr)")
	thB, _ := s1.newThread(sess, codeB(), func(c *cpuCtx) { *c.u64(L.r6) = counterVA })
	thA, tidA := s1.newThread(sess, codeA(), func(c *cpuCtx) { *c.u64(L.r3) = dataVA })
	if thA == 0 || thB == 0 {
		return
	}
	ev, ok := sess.wait(pid, tidA, 3*time.Second)
	if !ok {
		say("T1: no guest trap event (data0=%d counter=%d)", rd(0), *counter)
		return
	}
	say("T1: event state=%d code=%#x addr=%#x", ev.state, ev.code, ev.addr)
	c, err := getCtx(thA, L.full|L.x18flag)
	if err != nil {
		say("T1: GetThreadContext failed: %v", err)
		return
	}
	say("T1: pc=%#x r0=%#x", *c.u64(L.pc), *c.u64(L.r0))
	say("T1: NtSuspendThread status %#x", suspend(thA))
	say("T1: NtDebugContinue status %#x", dbgCont(dbg, ev.pid, ev.tid, dbgContinue))
	c1 := *counter
	time.Sleep(150 * time.Millisecond)
	c2 := *counter
	say("T1: thread A parked: data0=%d (want 0); thread B counter %d -> %d (running=%v)", rd(0), c1, c2, c2 > c1)
	*c.u64(L.pc) += L.trapAdvance
	*c.u64(L.r0) = 7
	if L.r18 != 0 {
		*c.u64(L.r18) = 0xDEADBEEF12345678
	}
	if err := setCtx(thA, c, L.full|L.x18flag); err != nil {
		say("T1: SetThreadContext failed: %v", err)
	}
	resume(thA)
	time.Sleep(150 * time.Millisecond)
	say("T1: after resume data0=%d (want 7) x18=%#x (want 0xdeadbeef12345678 on arm64) tpidr=%#x (want 0x1234 on arm64)", rd(0), rd(1), rd(2))

	say("---- T4 fault and retry")
	*(*uint64)(unsafe.Pointer(&data[0x40])) = 0x77
	*(*uint64)(unsafe.Pointer(&data[0])) = 0
	thD, tidD := s1.newThread(sess, codeD(), func(c *cpuCtx) { *c.u64(L.r1) = 0x28; *c.u64(L.r3) = dataVA })
	if thD != 0 {
		ev, ok = sess.wait(pid, tidD, 3*time.Second)
		if !ok {
			say("T4: no event")
		} else {
			say("T4: event state=%d code=%#x addr=%#x info=%#x", ev.state, ev.code, ev.addr, ev.info)
			c, _ := getCtx(thD, L.full)
			*c.u64(L.r1) = dataVA + 0x40
			setCtx(thD, c, L.full)
			dbgCont(dbg, ev.pid, ev.tid, dbgContinue)
			time.Sleep(100 * time.Millisecond)
			say("T4: data0=%#x (want 0x77)", rd(0))
		}
	}

	say("---- T3 trap throughput")
	for _, variant := range []string{"cheap", "park"} {
		thC, tidC := s1.newThread(sess, codeC(), func(c *cpuCtx) {})
		if thC == 0 {
			continue
		}
		const n = 1000
		var t0 time.Time
		done := 0
		for done < n {
			ev, ok := sess.wait(pid, tidC, 3*time.Second)
			if !ok {
				say("T3 %s: stalled after %d events", variant, done)
				break
			}
			if done == 0 {
				t0 = time.Now()
			}
			c, err := getCtx(thC, L.full)
			if err != nil {
				say("T3: get failed %v", err)
				break
			}
			if variant == "cheap" {
				*c.u64(L.pc) += L.trapAdvance
				setCtx(thC, c, L.full)
				dbgCont(dbg, ev.pid, ev.tid, dbgContinue)
			} else {
				suspend(thC)
				dbgCont(dbg, ev.pid, ev.tid, dbgContinue)
				*c.u64(L.pc) += L.trapAdvance
				setCtx(thC, c, L.full)
				resume(thC)
			}
			done++
		}
		if done > 1 {
			say("T3 %s: %d traps, %.1f us per trap", variant, done, float64(time.Since(t0).Microseconds())/float64(done))
		}
		suspend(thC)
		for {
			ev, ok := pm.next(100 * time.Millisecond)
			if !ok {
				break
			}
			dbgCont(dbg, ev.pid, ev.tid, dbgContinue)
		}
	}

	say("---- T5 view operations")
	var old uint32
	r1, _, e1 := pVirtualProtectEx.Call(uintptr(s1.proc), uintptr(s1.pageAddr(10)), 0x1000, 0x20, uintptr(unsafe.Pointer(&old)))
	say("T5: partial VirtualProtectEx (1 page inside a %d-page view) to RX ok=%d err=%v", nPages, r1, e1)
	r1, _, e1 = pVirtualProtectEx.Call(uintptr(s1.proc), uintptr(s1.pageAddr(10)), 0x1000, 0x1, uintptr(unsafe.Pointer(&old)))
	say("T5: same page to NOACCESS ok=%d err=%v", r1, e1)
	r1, _, e1 = pUnmapViewOfFile2.Call(uintptr(s1.proc), uintptr(s1.pageAddr(12)), 0x2)
	say("T5: UnmapViewOfFile2(PRESERVE) at the middle of a view ok=%d err=%v", r1, e1)
	r1, _, e1 = pUnmapViewOfFile2.Call(uintptr(s1.proc), uintptr(s1.pageAddr(0)), 0x2)
	say("T5: UnmapViewOfFile2(PRESERVE) at the view base ok=%d err=%v (the whole view should become one placeholder)", r1, e1)

	say("---- T6 second stub on the same debug object")
	s2 := bringUp(sess, mode+"/stub2", mode == "locked", fh, nPages)
	if s2 != nil {
		defer func() { pNtTerminateProcess.Call(uintptr(s2.proc), 0) }()
		pid2 := uint64(s2.pi.ProcessId)
		data2 := s2.pageLocal(0)
		thE, tidE := s2.newThread(sess, codeA(), func(c *cpuCtx) { *c.u64(L.r3) = s2.pageAddr(0) })
		if thE != 0 {
			ev, ok := sess.wait(pid2, tidE, 3*time.Second)
			if ok {
				say("T6: stub2 trap event pid=%d (want %d) state=%d", ev.pid, pid2, ev.state)
				c, _ := getCtx(thE, L.full)
				*c.u64(L.pc) += L.trapAdvance
				*c.u64(L.r0) = 9
				setCtx(thE, c, L.full)
				dbgCont(dbg, ev.pid, ev.tid, dbgContinue)
				time.Sleep(100 * time.Millisecond)
				say("T6: stub2 data0=%d (want 9)", *(*uint64)(unsafe.Pointer(&data2[0])))
			} else {
				say("T6: no event from stub2")
			}
		}
	}
	say("%s: done", mode)
}
