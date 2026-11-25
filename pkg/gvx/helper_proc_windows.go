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

package gvx

import (
	"context"
	"fmt"
	"os"
	"sync"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"z.gfire.dev/gvx/pkg/hostlockdown"
)

const (
	helperDisableMaxPrivilege = 0x1
	helperLowIntegritySID     = "S-1-16-4096"
	helperJobLimitFlags       = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
	helperJobUILimits         = windows.JOB_OBJECT_UILIMIT_HANDLES | windows.JOB_OBJECT_UILIMIT_READCLIPBOARD | windows.JOB_OBJECT_UILIMIT_WRITECLIPBOARD
)

var (
	helperModKernel32             = windows.NewLazySystemDLL("kernel32.dll")
	helperModAdvapi32             = windows.NewLazySystemDLL("advapi32.dll")
	helperProcSetInfoJobObject    = helperModKernel32.NewProc("SetInformationJobObject")
	helperProcCreateRestrictedTok = helperModAdvapi32.NewProc("CreateRestrictedToken")
)

// HelperProcess owns one Windows host worker process confined inside a
// dedicated Job Object with UI restrictions and a Low-integrity restricted
// token. Sentry retains PROCESS_DUP_HANDLE on the child handle; the child holds
// no handle to Sentry.
type HelperProcess struct {
	name string
	pid  int

	mu      sync.Mutex
	proc    windows.Handle
	job     windows.Handle
	closed  bool
	doneCh  chan struct{}
	waitErr error
}

func spawnHelperProcess(ctx context.Context, spec HelperSpec) (*HelperProcess, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if hostlockdown.IsLockedDown() {
		return nil, ErrLockdownActive
	}
	if spec.Path == "" {
		return nil, fmt.Errorf("%w: helper spec path is empty", ErrInvalidConfig)
	}

	job, err := createHelperJob()
	if err != nil {
		return nil, fmt.Errorf("gvx: create helper job for %q: %w", spec.Name, err)
	}
	keepJob := false
	defer func() {
		if !keepJob {
			_ = windows.CloseHandle(job)
		}
	}()

	tok, err := createHelperRestrictedToken()
	if err != nil {
		return nil, fmt.Errorf("gvx: create restricted token for helper %q: %w", spec.Name, err)
	}
	defer tok.Close()

	appName, err := windows.UTF16PtrFromString(spec.Path)
	if err != nil {
		return nil, fmt.Errorf("gvx: encode helper path %q: %w", spec.Path, err)
	}
	cmdArgs := make([]string, 0, 1+len(spec.Args))
	cmdArgs = append(cmdArgs, spec.Path)
	cmdArgs = append(cmdArgs, spec.Args...)
	cmdLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(cmdArgs))
	if err != nil {
		return nil, fmt.Errorf("gvx: encode helper command line: %w", err)
	}
	var dirPtr *uint16
	if spec.Dir != "" {
		dirPtr, err = windows.UTF16PtrFromString(spec.Dir)
		if err != nil {
			return nil, fmt.Errorf("gvx: encode helper dir %q: %w", spec.Dir, err)
		}
	}
	envSlice := spec.Env
	if envSlice == nil {
		envSlice = os.Environ()
	}
	envBlock := buildUTF16EnvBlock(envSlice)

	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW | windows.CREATE_UNICODE_ENVIRONMENT)
	var envPtr *uint16
	if len(envBlock) > 0 {
		envPtr = &envBlock[0]
	}
	if err := windows.CreateProcessAsUser(
		tok,
		appName,
		cmdLine,
		nil,
		nil,
		false,
		flags,
		envPtr,
		dirPtr,
		&si,
		&pi,
	); err != nil {
		return nil, fmt.Errorf("gvx: CreateProcessAsUser helper %q (%s): %w", spec.Name, spec.Path, err)
	}

	if err := windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		_ = windows.CloseHandle(pi.Thread)
		_ = windows.CloseHandle(pi.Process)
		return nil, fmt.Errorf("gvx: AssignProcessToJobObject helper %q: %w", spec.Name, err)
	}
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		_ = windows.TerminateJobObject(job, 1)
		_ = windows.CloseHandle(pi.Thread)
		_ = windows.CloseHandle(pi.Process)
		return nil, fmt.Errorf("gvx: ResumeThread helper %q: %w", spec.Name, err)
	}
	_ = windows.CloseHandle(pi.Thread)

	keepJob = true
	hp := &HelperProcess{
		name:   spec.Name,
		pid:    int(pi.ProcessId),
		proc:   pi.Process,
		job:    job,
		doneCh: make(chan struct{}),
	}
	go func(procHandle windows.Handle) {
		_, waitErr := windows.WaitForSingleObject(procHandle, windows.INFINITE)
		if waitErr != nil {
			hp.waitErr = waitErr
		} else {
			var code uint32
			if err := windows.GetExitCodeProcess(procHandle, &code); err != nil {
				hp.waitErr = err
			} else if code != 0 {
				hp.waitErr = fmt.Errorf("helper %q exited with status %d", hp.name, code)
			}
		}
		close(hp.doneCh)
	}(pi.Process)
	return hp, nil
}

func createHelperJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = helperJobLimitFlags
	r1, _, callErr := helperProcSetInfoJobObject.Call(
		uintptr(job),
		uintptr(windows.JobObjectExtendedLimitInformation),
		uintptr(unsafe.Pointer(&limits)),
		unsafe.Sizeof(limits),
	)
	if r1 == 0 {
		_ = windows.CloseHandle(job)
		return 0, callErr
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: helperJobUILimits}
	r1, _, callErr = helperProcSetInfoJobObject.Call(
		uintptr(job),
		uintptr(windows.JobObjectBasicUIRestrictions),
		uintptr(unsafe.Pointer(&ui)),
		unsafe.Sizeof(ui),
	)
	if r1 == 0 {
		_ = windows.CloseHandle(job)
		return 0, callErr
	}
	return job, nil
}

func createHelperRestrictedToken() (windows.Token, error) {
	var primary windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT,
		&primary,
	); err != nil {
		return 0, err
	}
	defer primary.Close()

	var restricted windows.Token
	r1, _, callErr := helperProcCreateRestrictedTok.Call(
		uintptr(primary),
		uintptr(helperDisableMaxPrivilege),
		0, 0,
		0, 0,
		0, 0,
		uintptr(unsafe.Pointer(&restricted)),
	)
	if r1 == 0 {
		return 0, callErr
	}
	lowSID, err := windows.StringToSid(helperLowIntegritySID)
	if err != nil {
		_ = restricted.Close()
		return 0, err
	}
	tml := windows.Tokenmandatorylabel{
		Label: windows.SIDAndAttributes{
			Sid:        lowSID,
			Attributes: windows.SE_GROUP_INTEGRITY,
		},
	}
	if err := windows.SetTokenInformation(
		restricted,
		windows.TokenIntegrityLevel,
		(*byte)(unsafe.Pointer(&tml)),
		uint32(unsafe.Sizeof(tml))+uint32(lowSID.Len()),
	); err != nil {
		_ = restricted.Close()
		return 0, err
	}
	return restricted, nil
}

func buildUTF16EnvBlock(env []string) []uint16 {
	var out []uint16
	for _, kv := range env {
		if kv == "" {
			continue
		}
		out = append(out, utf16.Encode([]rune(kv))...)
		out = append(out, 0)
	}
	if len(out) == 0 {
		out = append(out, 0)
	}
	out = append(out, 0)
	return out
}

// Name returns the diagnostic name of the helper process.
func (h *HelperProcess) Name() string {
	if h == nil {
		return ""
	}
	return h.name
}

// PID returns the OS process identifier of the helper.
func (h *HelperProcess) PID() int {
	if h == nil {
		return 0
	}
	return h.pid
}

// Done returns a channel closed once the helper process exits.
func (h *HelperProcess) Done() <-chan struct{} {
	if h == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return h.doneCh
}

// Wait blocks until the helper exits and returns its exit error, if any.
func (h *HelperProcess) Wait() error {
	if h == nil {
		return nil
	}
	<-h.doneCh
	return h.waitErr
}

// Kill terminates the helper job object and worker process. It is idempotent.
func (h *HelperProcess) Kill() error {
	if h == nil {
		return nil
	}
	select {
	case <-h.doneCh:
		return nil
	default:
	}
	h.mu.Lock()
	job := h.job
	proc := h.proc
	h.mu.Unlock()
	if job != 0 {
		if err := windows.TerminateJobObject(job, 1); err == nil {
			return nil
		}
	}
	if proc != 0 {
		return windows.TerminateProcess(proc, 1)
	}
	return nil
}

// Close terminates the helper if still running, waits until exit, and closes
// its Windows Job Object and process handles.
func (h *HelperProcess) Close() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		<-h.doneCh
		return nil
	}
	h.closed = true
	h.mu.Unlock()

	killErr := h.Kill()
	<-h.doneCh

	h.mu.Lock()
	job := h.job
	proc := h.proc
	h.job = 0
	h.proc = 0
	h.mu.Unlock()

	if job != 0 {
		_ = windows.CloseHandle(job)
	}
	if proc != 0 {
		_ = windows.CloseHandle(proc)
	}
	return killErr
}
