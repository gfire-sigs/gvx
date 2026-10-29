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
	"os/exec"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Sentry cannot start a process after hostlockdown.Apply, because the
// lockdown job allows one process. A stub host starts before the lockdown. It
// is a second copy of the Sentry executable that runs only the loop in this
// file. It creates one confined stub process per request and duplicates the
// process and thread handles into the Sentry. The stub processes are not
// members of the job of the Sentry.
//
// The host trusts the Sentry and nothing else. A request names no path and no
// command line, so a compromised Sentry cannot start a program of its choice.

const (
	// hostEnv carries the Sentry process ID to the host. Its presence makes the
	// init function of this package run the host loop instead of main.
	hostEnv = "GVX_SYSTRAP_STUBHOST"

	hostMagic   = 0x31485347 // "GSH1"
	opNewStub   = 1
	opSetDebug  = 2
	opRelease   = 3
	opNewEvents = 4
	hostReqSize = 16
	// hostProtocolVersion is the version of the pipe protocol.
	hostProtocolVersion = 1
	hostRspSize         = 48
)

// confinement names how much of the stub confinement the host applied.
type confinement uint32

const (
	// confineToken is a Low-integrity token without privileges, in a job that
	// allows one process and kills the stub on close.
	confineToken confinement = 1 << iota
	// confineWin32k removes the Win32k system call table of the stub.
	confineWin32k
	// confineStrict adds strict handle checks and disables extension points.
	confineStrict
)

// stubHandles is the host reply for one stub.
type stubHandles struct {
	pid, tid uint32
	proc     windows.Handle
	thread   windows.Handle
	level    confinement
}

func init() {
	if v, ok := os.LookupEnv(hostEnv); ok {
		pid, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			os.Exit(2)
		}
		os.Exit(runStubHost(uint32(pid), os.Stdin, os.Stdout))
	}
}

// ---- host side -------------------------------------------------------------

type stubHostLoop struct {
	sentry windows.Handle
	token  windows.Token
	level  confinement
	exe    string
	// image is the locked file that the stubs run. It is nil when the host could
	// not write it. The stubs then run a copy of the executable of the host.
	image *stubImage
	jobs  map[uint32]windows.Handle
	// procs holds a handle to each live stub, to duplicate event handles into it.
	procs map[uint32]windows.Handle
	// debug is the debug object of the Sentry, in the handle table of the host.
	debug windows.Handle
}

// runStubHost serves requests until the Sentry closes the pipe. It returns the
// process exit code.
func runStubHost(sentryPID uint32, in io.Reader, out io.Writer) int {
	tStart := time.Now()
	h := &stubHostLoop{jobs: make(map[uint32]windows.Handle), procs: make(map[uint32]windows.Handle)}
	sentry, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, sentryPID)
	if err != nil {
		return 3
	}
	h.sentry = sentry
	h.exe, err = os.Executable()
	if err != nil {
		return 4
	}
	tToken := time.Now()
	h.token, h.level, err = buildStubToken()
	if err != nil {
		return 5
	}
	tImage := time.Now()
	h.image, err = createStubImage(os.TempDir())
	if err != nil && traceEvents {
		tracef("stub host: no stub image, the stubs run the executable of the host: %v", err)
	}
	defer h.image.close()
	if traceWatch {
		// The age is the time from the creation of the process to this point. It
		// covers the kernel, the loader, the Go runtime, and the package inits.
		var created, exited, kernel, user windows.Filetime
		age := float64(-1)
		if windows.GetProcessTimes(windows.CurrentProcess(), &created, &exited, &kernel, &user) == nil {
			age = float64(time.Now().UnixNano()-created.Nanoseconds()) / 1e6
		}
		fmt.Fprintf(os.Stderr, "systrap: stub host ms: age at start %.1f, token %.1f, image %.1f, setup %.1f\n",
			age, float64(tImage.Sub(tToken))/1e6, float64(time.Since(tImage))/1e6, float64(time.Since(tStart))/1e6)
	}
	// The first reply tells the Sentry that the host is ready.
	if err := writeHostReply(out, 0, nil, h.level); err != nil {
		return 6
	}
	for {
		var req [hostReqSize]byte
		if _, err := io.ReadFull(in, req[:]); err != nil {
			// EOF means that the Sentry is gone.
			h.shutdown()
			return 0
		}
		if binary.LittleEndian.Uint32(req[0:]) != hostMagic {
			return 7
		}
		switch binary.LittleEndian.Uint32(req[4:]) {
		case opSetDebug:
			h.debug = windows.Handle(binary.LittleEndian.Uint64(req[8:]))
			if err := writeHostReply(out, 0, nil, h.level); err != nil {
				return 6
			}
			continue
		case opRelease:
			h.release(uint32(binary.LittleEndian.Uint64(req[8:])))
			if err := writeHostReply(out, 0, nil, h.level); err != nil {
				return 6
			}
			continue
		case opNewEvents:
			ev, err := h.newEvents(uint32(binary.LittleEndian.Uint64(req[8:])))
			var errno uint32
			if err != nil {
				errno = uint32(windows.ERROR_GEN_FAILURE)
				var e windows.Errno
				if errors.As(err, &e) {
					errno = uint32(e)
				}
			}
			if err := writeEventsReply(out, errno, ev); err != nil {
				return 6
			}
			continue
		case opNewStub:
		default:
			return 7
		}
		sh, err := h.newStub()
		var errno uint32
		if err != nil {
			errno = uint32(windows.ERROR_GEN_FAILURE)
			var e windows.Errno
			if errors.As(err, &e) {
				errno = uint32(e)
			}
		}
		if err := writeHostReply(out, errno, sh, h.level); err != nil {
			return 6
		}
	}
}

func writeHostReply(out io.Writer, errno uint32, sh *stubHandles, level confinement) error {
	var rsp [hostRspSize]byte
	binary.LittleEndian.PutUint32(rsp[0:], hostMagic)
	binary.LittleEndian.PutUint32(rsp[4:], errno)
	if sh != nil {
		level = sh.level
		binary.LittleEndian.PutUint32(rsp[8:], sh.pid)
		binary.LittleEndian.PutUint32(rsp[12:], sh.tid)
		binary.LittleEndian.PutUint64(rsp[16:], uint64(sh.proc))
		binary.LittleEndian.PutUint64(rsp[24:], uint64(sh.thread))
	}
	binary.LittleEndian.PutUint32(rsp[32:], uint32(level))
	_, err := out.Write(rsp[:])
	return err
}

var (
	modAdvapi32               = windows.NewLazySystemDLL("advapi32.dll")
	procCreateRestrictedToken = modAdvapi32.NewProc("CreateRestrictedToken")
	procAdjustTokenPrivileges = modAdvapi32.NewProc("AdjustTokenPrivileges")
	procCreateProcessAsUserW  = modAdvapi32.NewProc("CreateProcessAsUserW")

	procInitializeProcThreadAttributeList = modKernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute         = modKernel32.NewProc("UpdateProcThreadAttribute")
)

const (
	disableMaxPrivilege = 0x1
	lowIntegritySID     = "S-1-16-4096"

	procThreadAttributeMitigationPolicy = 0x00020007
	mitigationWin32kSystemCallDisable   = uint64(1) << 28
	mitigationStrictHandleChecks        = uint64(1) << 24
	mitigationExtensionPointDisable     = uint64(1) << 32
)

// stubRestrictingSIDs are the restricting SIDs of the stub token: Everyone,
// BUILTIN\Users, and RESTRICTED. The system files that a process needs to start
// grant at least one of them.
var stubRestrictingSIDs = []string{"S-1-1-0", "S-1-5-32-545", "S-1-5-12"}

// buildStubToken returns the primary token of every stub: the token of the
// host with restricting SIDs, without privileges, at Low integrity.
//
// WHY: a Low-integrity token cannot write to Medium objects or open most
// processes. Dropping privileges removes SeDebugPrivilege and similar rights.
// The restricting SIDs keep the token from reading the private files of the
// user. The stub needs no handle at all, so the token is the only identity that
// a guest escape would inherit.
func buildStubToken() (windows.Token, confinement, error) {
	var self windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_SESSIONID|windows.TOKEN_ADJUST_PRIVILEGES, &self)
	if err != nil {
		return 0, 0, fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer self.Close()
	// The restricting SIDs make the kernel check each access a second time against
	// these SIDs only. A file that only the user can read then stays closed to a
	// stub that runs a system call of its own, because the user private files of
	// the profile grant none of these SIDs. A token with no restricting SID checks
	// the user and the groups of the user only, and Low integrity blocks writes
	// but not reads.
	var restrict []windows.SIDAndAttributes
	for _, sddl := range stubRestrictingSIDs {
		sid, err := windows.StringToSid(sddl)
		if err != nil {
			return 0, 0, fmt.Errorf("restricting SID %s: %w", sddl, err)
		}
		restrict = append(restrict, windows.SIDAndAttributes{Sid: sid})
	}
	var restricted windows.Token
	r, _, e := procCreateRestrictedToken.Call(uintptr(self), disableMaxPrivilege, 0, 0, 0, 0,
		uintptr(len(restrict)), uintptr(unsafe.Pointer(&restrict[0])), uintptr(unsafe.Pointer(&restricted)))
	if r == 0 {
		return 0, 0, fmt.Errorf("CreateRestrictedToken: %w", e)
	}
	if err := removeAllStubPrivileges(restricted); err != nil {
		restricted.Close()
		return 0, 0, err
	}
	sid, err := windows.StringToSid(lowIntegritySID)
	if err != nil {
		restricted.Close()
		return 0, 0, err
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: sid, Attributes: windows.SE_GROUP_INTEGRITY}}
	err = windows.SetTokenInformation(restricted, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)),
		uint32(unsafe.Sizeof(label))+windows.GetLengthSid(sid))
	if err != nil {
		restricted.Close()
		return 0, 0, fmt.Errorf("SetTokenInformation(TokenIntegrityLevel): %w", err)
	}
	return restricted, confineToken, nil
}

// removeAllStubPrivileges deletes every privilege from token with
// SE_PRIVILEGE_REMOVED so a stub process can never re-enable a privilege.
func removeAllStubPrivileges(token windows.Token) error {
	var needed uint32
	err := windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &needed)
	if err != nil && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return fmt.Errorf("GetTokenInformation(TokenPrivileges size): %w", err)
	}
	if needed == 0 {
		return nil
	}
	buf := make([]byte, needed)
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, &buf[0], needed, &needed); err != nil {
		return fmt.Errorf("GetTokenInformation(TokenPrivileges): %w", err)
	}
	tp := (*windows.Tokenprivileges)(unsafe.Pointer(&buf[0]))
	if tp.PrivilegeCount == 0 {
		return nil
	}
	entries := unsafe.Slice(&tp.Privileges[0], tp.PrivilegeCount)
	for i := range entries {
		entries[i].Attributes = windows.SE_PRIVILEGE_REMOVED
	}
	r, _, callErr := procAdjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(needed),
		0,
		0,
	)
	if r == 0 {
		return fmt.Errorf("AdjustTokenPrivileges: %w", callErr)
	}
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, &buf[0], uint32(len(buf)), &needed); err != nil {
		return fmt.Errorf("GetTokenInformation(TokenPrivileges verify): %w", err)
	}
	if tp.PrivilegeCount != 0 {
		return fmt.Errorf("stub token retained %d privileges after removal", tp.PrivilegeCount)
	}
	return nil
}

// release closes the job and the process handle of a stub that the Sentry
// destroyed.
func (h *stubHostLoop) release(pid uint32) {
	if job, ok := h.jobs[pid]; ok {
		_ = windows.CloseHandle(job)
		delete(h.jobs, pid)
	}
	if proc, ok := h.procs[pid]; ok {
		_ = windows.CloseHandle(proc)
		delete(h.procs, pid)
	}
}

// shutdown ends every stub. Closing the last handle of a job kills its stub.
// The host then waits for each stub to exit, because a stub that still maps the
// image keeps the file of the image on disk.
func (h *stubHostLoop) shutdown() {
	for pid, job := range h.jobs {
		_ = windows.CloseHandle(job)
		delete(h.jobs, pid)
	}
	for pid, proc := range h.procs {
		_, _ = windows.WaitForSingleObject(proc, 1000)
		_ = windows.CloseHandle(proc)
		delete(h.procs, pid)
	}
}

// eventStubAccess is the right of a stub on an event: it sets and waits.
const eventStubAccess = 0x100002 // EVENT_MODIFY_STATE | SYNCHRONIZE

// newEvents creates one auto-reset event pair and duplicates it into the stub
// with the given process ID and into the Sentry.
func (h *stubHostLoop) newEvents(pid uint32) (out eventHandles, err error) {
	proc, ok := h.procs[pid]
	if !ok {
		return eventHandles{}, windows.ERROR_NOT_FOUND
	}
	var inSentry []windows.Handle
	defer func() {
		if err != nil {
			// Close the events that already reached the Sentry. The stub copies
			// die with the stub.
			for _, ev := range inSentry {
				_ = windows.DuplicateHandle(h.sentry, ev, 0, nil, 0, false, windows.DUPLICATE_CLOSE_SOURCE)
			}
			out = eventHandles{}
		}
	}()
	self := windows.CurrentProcess()
	for _, d := range []struct{ stub, sentry *windows.Handle }{
		{&out.stubGuest, &out.guest},
		{&out.stubHost, &out.host},
	} {
		ev, err := ntCreateAutoResetEvent()
		if err != nil {
			return out, err
		}
		defer windows.CloseHandle(ev)
		if err := windows.DuplicateHandle(self, ev, proc, d.stub, eventStubAccess, false, 0); err != nil {
			return out, fmt.Errorf("DuplicateHandle(event to the stub): %w", err)
		}
		if err := windows.DuplicateHandle(self, ev, h.sentry, d.sentry, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
			return out, fmt.Errorf("DuplicateHandle(event to the Sentry): %w", err)
		}
		inSentry = append(inSentry, *d.sentry)
	}
	return out, nil
}

// newStub creates one confined, suspended stub process and returns handles in
// the Sentry process.
func (h *stubHostLoop) newStub() (*stubHandles, error) {
	pi, level, err := h.startStubProcess()
	if err != nil {
		return nil, err
	}
	keepProc := false
	defer func() {
		if !keepProc {
			_ = windows.CloseHandle(pi.Process)
		}
	}()
	defer windows.CloseHandle(pi.Thread)

	job, err := createStubJob()
	if err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		return nil, err
	}
	if err := windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		_ = windows.CloseHandle(job)
		_ = windows.TerminateProcess(pi.Process, 1)
		return nil, fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	h.jobs[pi.ProcessId] = job

	// The host attaches the stub to the debug object of the Sentry. The Sentry
	// then needs no right to debug a process, which a lockdown can remove.
	if h.debug == 0 {
		_ = windows.TerminateProcess(pi.Process, 1)
		return nil, errors.New("the Sentry sent no debug object")
	}
	if err := ntDebugActiveProcess(pi.Process, h.debug); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		return nil, err
	}

	var proc, thread windows.Handle
	self := windows.CurrentProcess()
	if err := windows.DuplicateHandle(self, pi.Process, h.sentry, &proc, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		return nil, fmt.Errorf("DuplicateHandle(process): %w", err)
	}
	if err := windows.DuplicateHandle(self, pi.Thread, h.sentry, &thread, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		return nil, fmt.Errorf("DuplicateHandle(thread): %w", err)
	}
	h.procs[pi.ProcessId] = pi.Process
	keepProc = true
	return &stubHandles{pid: pi.ProcessId, tid: pi.ThreadId, proc: proc, thread: thread, level: level}, nil
}

// startStubProcess creates the suspended process of one stub. It runs the small
// stub image. A policy of the machine can refuse that image: AppLocker, Windows
// Defender Application Control, or an endpoint product can block a small
// executable that nobody signed. When the creation fails, the host drops the
// image and runs a copy of its own executable for this stub and for every later
// one.
func (h *stubHostLoop) startStubProcess() (*windows.ProcessInformation, confinement, error) {
	if h.image == nil {
		return h.createProcessFor(h.exe)
	}
	pi, level, err := h.createProcessFor(h.image.path)
	if err == nil {
		return pi, level, nil
	}
	if traceEvents {
		tracef("stub host: the stub image %s did not start, the stubs run the executable of the host: %v", h.image.path, err)
	}
	h.image.close()
	h.image = nil
	pi, level, exeErr := h.createProcessFor(h.exe)
	if exeErr != nil {
		return nil, 0, fmt.Errorf("%w (the stub image failed first: %v)", exeErr, err)
	}
	return pi, level, nil
}

// createProcessFor starts the suspended stub from the executable at path.
func (h *stubHostLoop) createProcessFor(path string) (*windows.ProcessInformation, confinement, error) {
	cmd, err := windows.UTF16PtrFromString(`"` + path + `" stub`)
	if err != nil {
		return nil, 0, err
	}
	return h.createProcess(cmd)
}

// createProcess starts the suspended stub with the strongest mitigation set
// that the host accepts.
func (h *stubHostLoop) createProcess(cmd *uint16) (*windows.ProcessInformation, confinement, error) {
	policies := []struct {
		bits  uint64
		level confinement
	}{
		{mitigationWin32kSystemCallDisable | mitigationStrictHandleChecks | mitigationExtensionPointDisable, confineToken | confineWin32k | confineStrict},
		{mitigationWin32kSystemCallDisable, confineToken | confineWin32k},
		{0, confineToken},
	}
	var lastErr error
	for _, p := range policies {
		pi, err := h.createWithPolicy(cmd, p.bits)
		if err == nil {
			return pi, p.level, nil
		}
		if traceEvents {
			tracef("stub host: policy %#x failed: %v", p.bits, err)
		}
		lastErr = err
	}
	return nil, 0, lastErr
}

func (h *stubHostLoop) createWithPolicy(cmd *uint16, policy uint64) (*windows.ProcessInformation, error) {
	type startupInfoEx struct {
		windows.StartupInfo
		attrs uintptr
	}
	var si startupInfoEx
	si.Cb = uint32(unsafe.Sizeof(si))
	flags := uintptr(windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW)
	var list []byte
	if policy != 0 {
		var size uintptr
		_, _, _ = procInitializeProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))
		list = make([]byte, size)
		if r, _, e := procInitializeProcThreadAttributeList.Call(uintptr(unsafe.Pointer(&list[0])), 1, 0, uintptr(unsafe.Pointer(&size))); r == 0 {
			return nil, fmt.Errorf("InitializeProcThreadAttributeList: %w", e)
		}
		if r, _, e := procUpdateProcThreadAttribute.Call(uintptr(unsafe.Pointer(&list[0])), 0, procThreadAttributeMitigationPolicy,
			uintptr(unsafe.Pointer(&policy)), 8, 0, 0); r == 0 {
			return nil, fmt.Errorf("UpdateProcThreadAttribute(mitigation policy): %w", e)
		}
		si.attrs = uintptr(unsafe.Pointer(&list[0]))
		flags |= windows.EXTENDED_STARTUPINFO_PRESENT
	}
	var pi windows.ProcessInformation
	r, _, e := procCreateProcessAsUserW.Call(uintptr(h.token), 0, uintptr(unsafe.Pointer(cmd)), 0, 0, 0, flags, 0, 0,
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		return nil, fmt.Errorf("CreateProcessAsUser: %w", e)
	}
	return &pi, nil
}

// createStubJob returns a job that allows one process, kills it when the host
// closes the last handle, and blocks every window and clipboard operation.
func createStubJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("CreateJobObject: %w", err)
	}
	ext := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	ext.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	ext.BasicLimitInformation.ActiveProcessLimit = 1
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&ext)), uint32(unsafe.Sizeof(ext))); err != nil {
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("SetInformationJobObject(limits): %w", err)
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: 0xFF}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui))); err != nil {
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("SetInformationJobObject(UI restrictions): %w", err)
	}
	return job, nil
}

// ---- Sentry side -----------------------------------------------------------

// stubHost is the Sentry end of the host pipe.
type stubHost struct {
	mu  sync.Mutex
	cmd *exec.Cmd
	in  io.WriteCloser
	out io.ReadCloser
	// wait is a handle to the host that grants no more than the wait on its exit
	// and the read of its exit code. spawnStubHost releases the full access
	// handle of cmd when the host is ready, so a compromised Sentry cannot write
	// the memory of the host, which runs outside the lockdown.
	wait windows.Handle
	// level is the confinement that the host reported for its last stub.
	level confinement
}

// hostExitTimeoutMs is the time that close waits for the host to exit after the
// pipe closes. The host kills its stubs first, and that takes a few milliseconds.
const hostExitTimeoutMs = 10000

// spawnStubHost starts the host process, waits until it is ready, and gives it
// a handle to the debug object.
func spawnStubHost(debug windows.Handle) (*stubHost, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("find the Sentry executable: %w", err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), hostEnv+"="+strconv.Itoa(os.Getpid()))
	if traceEvents {
		cmd.Stderr = os.Stderr
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	tStart := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start the stub host: %w", err)
	}
	tStarted := time.Now()
	h := &stubHost{cmd: cmd, in: in, out: out}
	var rsp [hostRspSize]byte
	if _, err := io.ReadFull(out, rsp[:]); err != nil {
		_ = h.close()
		return nil, fmt.Errorf("the stub host did not report ready: %w", err)
	}
	if traceWatch {
		fmt.Fprintf(os.Stderr, "systrap: spawn ms: CreateProcess %.1f, wait for ready %.1f\n",
			float64(tStarted.Sub(tStart))/1e6, float64(time.Since(tStarted))/1e6)
	}
	if binary.LittleEndian.Uint32(rsp[0:]) != hostMagic || binary.LittleEndian.Uint32(rsp[4:]) != 0 {
		_ = h.close()
		return nil, errors.New("the stub host sent a malformed ready message")
	}
	h.level = confinement(binary.LittleEndian.Uint32(rsp[32:]))

	// Duplicate the debug object into the host.
	hostProc, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, uint32(cmd.Process.Pid))
	if err != nil {
		_ = h.close()
		return nil, fmt.Errorf("open the stub host: %w", err)
	}
	defer windows.CloseHandle(hostProc)
	var dup windows.Handle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), debug, hostProc, &dup, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		_ = h.close()
		return nil, fmt.Errorf("give the debug object to the stub host: %w", err)
	}
	var req [hostReqSize]byte
	binary.LittleEndian.PutUint32(req[0:], hostMagic)
	binary.LittleEndian.PutUint32(req[4:], opSetDebug)
	binary.LittleEndian.PutUint64(req[8:], uint64(dup))
	if _, err := in.Write(req[:]); err != nil {
		_ = h.close()
		return nil, fmt.Errorf("send the debug object to the stub host: %w", err)
	}
	if _, err := io.ReadFull(out, rsp[:]); err != nil {
		_ = h.close()
		return nil, fmt.Errorf("the stub host did not accept the debug object: %w", err)
	}
	if err := h.dropFullAccess(); err != nil {
		_ = h.close()
		return nil, err
	}
	return h, nil
}

// dropFullAccess replaces the full access handle of the host process with a
// handle that can wait for the exit. The host starts before the lockdown, so it
// has the user token and the user rights. Any handle with write access to its
// memory would let a compromised Sentry run code outside the lockdown.
func (h *stubHost) dropFullAccess() error {
	wait, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(h.cmd.Process.Pid))
	if err != nil {
		return fmt.Errorf("open the stub host for waiting: %w", err)
	}
	if err := h.cmd.Process.Release(); err != nil {
		_ = windows.CloseHandle(wait)
		return fmt.Errorf("release the stub host handle: %w", err)
	}
	h.wait = wait
	return nil
}

// newStub asks the host for one suspended stub process.
func (h *stubHost) newStub() (*stubHandles, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var req [hostReqSize]byte
	binary.LittleEndian.PutUint32(req[0:], hostMagic)
	binary.LittleEndian.PutUint32(req[4:], opNewStub)
	if _, err := h.in.Write(req[:]); err != nil {
		return nil, fmt.Errorf("send to the stub host: %w", err)
	}
	var rsp [hostRspSize]byte
	if _, err := io.ReadFull(h.out, rsp[:]); err != nil {
		return nil, fmt.Errorf("read from the stub host: %w", err)
	}
	if binary.LittleEndian.Uint32(rsp[0:]) != hostMagic {
		return nil, errors.New("the stub host sent a malformed reply")
	}
	if errno := binary.LittleEndian.Uint32(rsp[4:]); errno != 0 {
		return nil, fmt.Errorf("the stub host could not create a stub: %w", windows.Errno(errno))
	}
	sh := &stubHandles{
		pid:    binary.LittleEndian.Uint32(rsp[8:]),
		tid:    binary.LittleEndian.Uint32(rsp[12:]),
		proc:   windows.Handle(binary.LittleEndian.Uint64(rsp[16:])),
		thread: windows.Handle(binary.LittleEndian.Uint64(rsp[24:])),
		level:  confinement(binary.LittleEndian.Uint32(rsp[32:])),
	}
	h.level = sh.level
	return sh, nil
}

// eventHandles holds one auto-reset event pair in the Sentry and in a stub.
type eventHandles struct {
	// stubGuest and stubHost are handle values in the stub process. The stub
	// sets the guest event to wake the Sentry and waits on the host event.
	stubGuest, stubHost windows.Handle
	// guest and host are the same two events in the Sentry process.
	guest, host windows.Handle
}

// newEvents asks the host for one event pair that the stub with the given
// process ID can use. The host creates the events and duplicates them into the
// stub and into the Sentry, so the Sentry needs no right to a stub handle table.
func (h *stubHost) newEvents(pid uint32) (eventHandles, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var req [hostReqSize]byte
	binary.LittleEndian.PutUint32(req[0:], hostMagic)
	binary.LittleEndian.PutUint32(req[4:], opNewEvents)
	binary.LittleEndian.PutUint64(req[8:], uint64(pid))
	if _, err := h.in.Write(req[:]); err != nil {
		return eventHandles{}, fmt.Errorf("send to the stub host: %w", err)
	}
	var rsp [hostRspSize]byte
	if _, err := io.ReadFull(h.out, rsp[:]); err != nil {
		return eventHandles{}, fmt.Errorf("read from the stub host: %w", err)
	}
	if binary.LittleEndian.Uint32(rsp[0:]) != hostMagic {
		return eventHandles{}, errors.New("the stub host sent a malformed reply")
	}
	if errno := binary.LittleEndian.Uint32(rsp[4:]); errno != 0 {
		return eventHandles{}, fmt.Errorf("the stub host could not create events: %w", windows.Errno(errno))
	}
	return eventHandles{
		stubGuest: windows.Handle(binary.LittleEndian.Uint64(rsp[8:])),
		stubHost:  windows.Handle(binary.LittleEndian.Uint64(rsp[16:])),
		guest:     windows.Handle(binary.LittleEndian.Uint64(rsp[24:])),
		host:      windows.Handle(binary.LittleEndian.Uint64(rsp[32:])),
	}, nil
}

// release tells the host that the stub with the given process ID is gone.
func (h *stubHost) release(pid uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var req [hostReqSize]byte
	binary.LittleEndian.PutUint32(req[0:], hostMagic)
	binary.LittleEndian.PutUint32(req[4:], opRelease)
	binary.LittleEndian.PutUint64(req[8:], uint64(pid))
	if _, err := h.in.Write(req[:]); err != nil {
		return
	}
	var rsp [hostRspSize]byte
	_, _ = io.ReadFull(h.out, rsp[:])
}

// close stops the host. The host exits when the pipe closes, and the kernel
// kills every stub that is still alive.
func (h *stubHost) close() error {
	_ = h.in.Close()
	defer h.out.Close()
	if h.wait == 0 {
		// The host did not finish its start, so the full access handle is still open.
		err := h.cmd.Wait()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil
		}
		return err
	}
	defer func() {
		_ = windows.CloseHandle(h.wait)
		h.wait = 0
	}()
	ev, err := windows.WaitForSingleObject(h.wait, hostExitTimeoutMs)
	if err != nil {
		return fmt.Errorf("wait for the stub host: %w", err)
	}
	if ev != windows.WAIT_OBJECT_0 {
		return errors.New("the stub host did not exit after its pipe closed")
	}
	return nil
}
