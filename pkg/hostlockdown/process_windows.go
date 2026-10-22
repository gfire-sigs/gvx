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

package hostlockdown

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProcessOptions supplies the trusted program and its inherited resources.
// StartProcess borrows each file until it returns. The child receives duplicates.
type ProcessOptions struct {
	Executable            string
	Arguments             []string
	Stdin, Stdout, Stderr *os.File
	Files                 []*os.File
	WorkspacePath         string
	WorkspaceReadOnly     bool
}

// Process owns one AppContainer, its child, and a job that kills the child on close.
// The AppContainer has no network capabilities. A broker must supply permitted network I/O.
type Process struct {
	mu        sync.Mutex
	process   windows.Handle
	job       windows.Handle
	profile   string
	directory string
	workspace string
	sid       *windows.SID
	closed    bool
	waiters   sync.WaitGroup
}

type securityCapabilities struct {
	SID          *windows.SID
	Capabilities *windows.SIDAndAttributes
	Count        uint32
	Reserved     uint32
}

var (
	modUserenv                    = windows.NewLazySystemDLL("userenv.dll")
	procCreateAppContainerProfile = modUserenv.NewProc("CreateAppContainerProfile")
	procDeleteAppContainerProfile = modUserenv.NewProc("DeleteAppContainerProfile")
)

// StartProcess starts a trusted worker inside a new AppContainer without elevation.
// The executable must implement the caller's worker protocol. It cannot create a WHPX partition.
// Close the returned Process after Wait, including when initialization fails.
func StartProcess(opts ProcessOptions) (_ *Process, err error) {
	if opts.Executable == "" || opts.Stdin == nil || opts.Stdout == nil || opts.Stderr == nil {
		return nil, errors.New("hostlockdown: an executable and three standard files are required")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, fmt.Errorf("hostlockdown: generate AppContainer name: %w", err)
	}
	p := &Process{profile: "gvx-" + hex.EncodeToString(random[:])}
	defer func() {
		if err != nil {
			err = errors.Join(err, p.Close())
		}
	}()
	name, err := windows.UTF16PtrFromString(p.profile)
	if err != nil {
		return nil, err
	}
	hr, _, _ := procCreateAppContainerProfile.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(name)), 0, 0, uintptr(unsafe.Pointer(&p.sid)))
	if int32(hr) < 0 {
		p.profile = ""
		return nil, fmt.Errorf("hostlockdown: CreateAppContainerProfile: HRESULT %#08x", uint32(hr))
	}

	p.directory, err = os.MkdirTemp("", "gvx-worker-")
	if err != nil {
		return nil, fmt.Errorf("hostlockdown: create worker directory: %w", err)
	}
	executable := filepath.Join(p.directory, "worker.exe")
	if err := copyProgram(executable, opts.Executable); err != nil {
		return nil, err
	}
	if err := prepareWorkspace(p.directory, p.sid, true); err != nil {
		return nil, err
	}
	if opts.WorkspacePath != "" {
		p.workspace, err = resolveWorkspace(opts.WorkspacePath)
		if err != nil {
			return nil, err
		}
		if err := prepareWorkspace(p.workspace, p.sid, opts.WorkspaceReadOnly); err != nil {
			return nil, err
		}
	}

	// Duplicate only the supplied files. No unrelated inheritable handle enters the worker.
	var inherited []windows.Handle
	defer func() {
		for _, h := range inherited {
			_ = windows.CloseHandle(h)
		}
	}()
	for _, file := range append([]*os.File{opts.Stdin, opts.Stdout, opts.Stderr}, opts.Files...) {
		if file == nil {
			return nil, errors.New("hostlockdown: inherited file is nil")
		}
		var duplicate windows.Handle
		if err := windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(file.Fd()), windows.CurrentProcess(), &duplicate, 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
			return nil, fmt.Errorf("hostlockdown: duplicate inherited file: %w", err)
		}
		inherited = append(inherited, duplicate)
	}
	attrs, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return nil, err
	}
	defer attrs.Delete()
	caps := securityCapabilities{SID: p.sid}
	if err := attrs.Update(0x20009, unsafe.Pointer(&caps), unsafe.Sizeof(caps)); err != nil {
		return nil, fmt.Errorf("hostlockdown: set AppContainer capabilities: %w", err)
	}
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&inherited[0]), uintptr(len(inherited))*unsafe.Sizeof(inherited[0])); err != nil {
		return nil, fmt.Errorf("hostlockdown: set inherited files: %w", err)
	}
	args := append([]string{executable}, opts.Arguments...)
	command, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(args))
	if err != nil {
		return nil, err
	}
	// The protocol refers to each extra file by its index, not its parent's handle value.
	var environment []string
	for _, key := range []string{"SystemRoot", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "TEMP", "TMP"} {
		if value := os.Getenv(key); value != "" {
			environment = append(environment, key+"="+value)
		}
	}
	for i, h := range inherited[3:] {
		environment = append(environment, fmt.Sprintf("GVX_WORKER_FD_%d=%d", i, h))
	}
	if os.Getenv("GVX_DEBUG_LOG") == "1" {
		environment = append(environment, "GVX_DEBUG_LOG=1")
	}
	sort.Strings(environment)
	block := utf16.Encode([]rune(strings.Join(environment, "\x00") + "\x00\x00"))
	directory, err := windows.UTF16PtrFromString(p.directory)
	if err != nil {
		return nil, err
	}
	si := windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESTDHANDLES
	si.StdInput, si.StdOutput, si.StdErr = inherited[0], inherited[1], inherited[2]
	var pi windows.ProcessInformation
	flags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NO_WINDOW | windows.CREATE_SUSPENDED)
	if err := windows.CreateProcess(nil, command, nil, nil, true, flags, &block[0], directory, &si.StartupInfo, &pi); err != nil {
		return nil, fmt.Errorf("hostlockdown: start AppContainer worker: %w", err)
	}
	p.process = pi.Process
	defer windows.CloseHandle(pi.Thread)
	runtime.KeepAlive(inherited)
	p.job, err = windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("hostlockdown: create worker job: %w", err)
	}
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
	limits.BasicLimitInformation.ActiveProcessLimit = 1
	if err := setJobInformation(p.job, windows.JobObjectExtendedLimitInformation, unsafe.Pointer(&limits), unsafe.Sizeof(limits)); err != nil {
		return nil, fmt.Errorf("hostlockdown: limit worker job: %w", err)
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: jobUILimits}
	if err := setJobInformation(p.job, windows.JobObjectBasicUIRestrictions, unsafe.Pointer(&ui), unsafe.Sizeof(ui)); err != nil {
		return nil, fmt.Errorf("hostlockdown: restrict worker UI: %w", err)
	}
	if err := windows.AssignProcessToJobObject(p.job, p.process); err != nil {
		return nil, fmt.Errorf("hostlockdown: assign worker job: %w", err)
	}
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		return nil, fmt.Errorf("hostlockdown: resume worker: %w", err)
	}
	return p, nil
}

func copyProgram(destination, source string) (err error) {
	in, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("hostlockdown: open worker executable: %w", err)
	}
	defer func() { err = errors.Join(err, in.Close()) }()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return fmt.Errorf("hostlockdown: copy worker executable: %w", err)
	}
	defer func() { err = errors.Join(err, out.Close()) }()
	_, err = io.Copy(out, in)
	return err
}

// Handle borrows the process object until Close. Only the trusted broker may use it.
func (p *Process) Handle() uintptr { return uintptr(p.process) }

// Wait waits for child exit. Close can interrupt Wait by terminating the child.
func (p *Process) Wait() (uint32, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0, errors.New("hostlockdown: worker is closed")
	}
	handle := p.process
	p.waiters.Add(1)
	p.mu.Unlock()
	defer p.waiters.Done()
	event, err := windows.WaitForSingleObject(handle, windows.INFINITE)
	if err != nil {
		return 0, fmt.Errorf("hostlockdown: wait for worker: %w", err)
	}
	if event != windows.WAIT_OBJECT_0 {
		return 0, fmt.Errorf("hostlockdown: unexpected worker wait result %#x", event)
	}
	var code uint32
	if err := windows.GetExitCodeProcess(handle, &code); err != nil {
		return 0, err
	}
	return code, nil
}

// Terminate stops execution without closing the process object or its mapped pages.
// Close releases those resources after the broker unmaps them.
func (p *Process) Terminate() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.terminate()
}

func (p *Process) terminate() error {
	if p.process == 0 {
		return nil
	}
	var code uint32
	if err := windows.GetExitCodeProcess(p.process, &code); err != nil {
		return err
	}
	if code != uint32(windows.STATUS_PENDING) {
		return nil
	}
	if err := windows.TerminateProcess(p.process, 1); err != nil {
		if queryErr := windows.GetExitCodeProcess(p.process, &code); queryErr == nil && code != uint32(windows.STATUS_PENDING) {
			return nil
		}
		return err
	}
	return nil
}

// Close terminates the child and releases its profile, files, and workspace entries.
// Do not call Close while another operation uses a borrowed Handle.
func (p *Process) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	var errs []error
	if p.process != 0 {
		errs = append(errs, p.terminate())
		if _, err := windows.WaitForSingleObject(p.process, windows.INFINITE); err != nil {
			errs = append(errs, err)
		}
		p.waiters.Wait()
		errs = append(errs, windows.CloseHandle(p.process))
		p.process = 0
	}
	if p.job != 0 {
		errs = append(errs, windows.CloseHandle(p.job))
		p.job = 0
	}
	if p.workspace != "" && p.sid != nil {
		errs = append(errs, revokeWorkspaceSID(p.workspace, p.sid))
	}
	if p.profile != "" {
		name, err := windows.UTF16PtrFromString(p.profile)
		if err == nil {
			hr, _, _ := procDeleteAppContainerProfile.Call(uintptr(unsafe.Pointer(name)))
			if int32(hr) < 0 {
				err = fmt.Errorf("hostlockdown: DeleteAppContainerProfile: HRESULT %#08x", uint32(hr))
			}
		}
		errs = append(errs, err)
	}
	if p.sid != nil {
		err := windows.FreeSid(p.sid)
		errs = append(errs, err)
		p.sid = nil
	}
	if p.directory != "" {
		temporary, temporaryErr := filepath.Abs(os.TempDir())
		target, targetErr := filepath.Abs(p.directory)
		if temporaryErr != nil || targetErr != nil {
			errs = append(errs, errors.Join(temporaryErr, targetErr))
		} else if !strings.EqualFold(filepath.Dir(target), temporary) || !strings.HasPrefix(filepath.Base(target), "gvx-worker-") {
			errs = append(errs, errors.New("hostlockdown: worker directory is outside its temporary root"))
		} else {
			errs = append(errs, os.RemoveAll(target))
		}
	}
	return errors.Join(errs...)
}
