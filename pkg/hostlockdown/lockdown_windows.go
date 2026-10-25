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

package hostlockdown

import (
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// OS handles that live for the whole process. The restricted token stays open so
// BindThread can attach it to any thread later. The job handle stays open so
// the containment job outlives every other reference to it.
var (
	handlesMu       sync.RWMutex
	restrictedToken windows.Token
	containmentJob  windows.Handle
)

// applyOSLockdown runs the SPEC 3.8 Windows steps in order. Each step returns
// its error. Status fields change only after the step succeeded and its effect
// was read back from the OS.
func applyOSLockdown(opts Options) (st Status, err error) {
	if opts.AllowOutboundNet {
		prewarmWinsock()
	}
	primary, err := openPrimaryToken()
	if err != nil {
		return Status{}, err
	}
	defer primary.Close()
	id, err := readTokenIdentity(primary)
	if err != nil {
		return Status{}, err
	}
	if err := grantLogonInDefaultDACL(primary, id.logon); err != nil {
		return Status{}, err
	}

	// Step 1: Low-Integrity label and logon SID entry on every mount. A
	// directory that two mounts name, or that lies below another mount, gets
	// the rights of each mount. A file mount gets the label and the entry on
	// that one file. Each grant only adds access, so the order of the mounts
	// does not matter.
	mountsReal := make([]string, 0, len(opts.Mounts))
	for _, m := range opts.Mounts {
		real, err := resolveMount(m.Path)
		if err != nil {
			return Status{}, err
		}
		if err := prepareWorkspace(real, id.logon, m.ReadOnly, m.File); err != nil {
			return Status{}, err
		}
		mountsReal = append(mountsReal, real)
	}

	// Step 2: remove every privilege from the live primary token.
	if err := removeAllTokenPrivileges(primary); err != nil {
		return Status{}, err
	}

	// Step 3: lower the live primary token to Low integrity.
	if err := lowerTokenIntegrityToLow(primary); err != nil {
		return Status{}, err
	}
	st.IntegrityDowngraded = true

	// Step 4: restricted impersonation token for the process threads and BindThread.
	restricted, err := createRestrictedImpersonationToken(primary, id, opts.AllowOutboundNet)
	if err != nil {
		return Status{}, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = restricted.Close()
		}
	}()
	if err := probeRestrictedOpenBlocked(restricted, mountsReal); err != nil {
		return Status{}, err
	}
	if !opts.AllowOutboundNet {
		if err := probeRestrictedSocketBlocked(restricted); err != nil {
			return Status{}, err
		}
		st.NetworkOutboundBlocked = true
	}

	// Steps 5 to 7: containment job.
	job, err := createContainmentJob(opts.CPUQuotaMillis)
	if err != nil {
		return Status{}, err
	}
	st.SubprocessBlocked = true
	st.CPUQuotaEnforced = opts.CPUQuotaMillis > 0

	// Step 8: disallow win32k system calls.
	if err := disableWin32kSystemCalls(); err != nil {
		_ = windows.CloseHandle(job)
		return Status{}, err
	}
	st.Win32kBlocked = true

	// Step 9: attach the restricted impersonation token to every existing
	// thread in the process so unbound file opens and disallowed socket
	// creations fail across the process.
	if err := bindProcessThreads(restricted); err != nil {
		_ = windows.CloseHandle(job)
		return Status{}, err
	}
	st.UnboundFileOpenBlocked = true

	handlesMu.Lock()
	restrictedToken = restricted
	containmentJob = job
	handlesMu.Unlock()
	keep = true
	return st, nil
}

// prewarmWinsock initializes Winsock DLLs, ConnectEx, and the Go runtime IOCP
// netpoller before the restricted token blocks DLL file opens in System32.
func prewarmWinsock() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		done := make(chan struct{})
		go func() {
			defer close(done)
			if c, acceptErr := ln.Accept(); acceptErr == nil {
				_ = c.Close()
			}
		}()
		if c, dialErr := net.DialTimeout("tcp", ln.Addr().String(), time.Second); dialErr == nil {
			_ = c.Close()
		}
		_ = ln.Close()
		<-done
	}
	if pc, err := net.ListenPacket("udp", "127.0.0.1:0"); err == nil {
		_ = pc.Close()
	}
}

func prewarmOSThreads(n int) {
	var ready sync.WaitGroup
	var done sync.WaitGroup
	ready.Add(n)
	done.Add(n)
	release := make(chan struct{})
	for range n {
		go func() {
			runtime.LockOSThread()
			ready.Done()
			<-release
			runtime.UnlockOSThread()
			done.Done()
		}()
	}
	ready.Wait()
	close(release)
	done.Wait()
}

func bindProcessThreads(token windows.Token) error {
	prewarmOSThreads(max(runtime.GOMAXPROCS(0)*8, 64))
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pid := windows.GetCurrentProcessId()
	selfTID := windows.GetCurrentThreadId()
	for range 3 {
		if err := bindPeerThreadsOnce(pid, selfTID, token); err != nil {
			return err
		}
		runtime.Gosched()
	}
	if err := windows.SetThreadToken(nil, token); err != nil {
		return fmt.Errorf("hostlockdown: SetThreadToken(current thread): %w", err)
	}
	return nil
}

func bindPeerThreadsOnce(pid, selfTID uint32, token windows.Token) error {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("hostlockdown: CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	var handles []windows.Handle
	defer func() {
		for _, h := range handles {
			_ = windows.CloseHandle(h)
		}
	}()
	for err := windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		if te.OwnerProcessID != pid || te.ThreadID == selfTID {
			continue
		}
		h, openErr := windows.OpenThread(windows.THREAD_SET_THREAD_TOKEN, false, te.ThreadID)
		if openErr != nil {
			continue
		}
		handles = append(handles, h)
	}
	for _, h := range handles {
		if err := windows.SetThreadToken(&h, token); err != nil {
			return fmt.Errorf("hostlockdown: SetThreadToken(peer thread): %w", err)
		}
	}
	return nil
}

func openPrimaryToken() (windows.Token, error) {
	var token windows.Token
	err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE,
		&token,
	)
	if err != nil {
		return 0, fmt.Errorf("hostlockdown: OpenProcessToken: %w", err)
	}
	return token, nil
}

func resolveMount(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("hostlockdown: resolve mount %q: %w", path, err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("hostlockdown: resolve mount symlinks %q: %w", abs, err)
	}
	if filepath.Dir(real) == real {
		return "", fmt.Errorf("hostlockdown: mount %q resolves to the volume root %q and would allow every file on it", path, real)
	}
	return real, nil
}

// BindThread attaches the process-lifetime restricted token to the calling OS
// thread. Call it right after runtime.LockOSThread on every vCPU thread, and
// keep the thread locked until the goroutine exits.
//
// The token lets the thread reach only the workspace, so a compromised vCPU
// thread cannot read other user files. BindThread returns ErrNotLockedDown
// before a successful Apply.
func BindThread() error {
	handlesMu.RLock()
	token := restrictedToken
	handlesMu.RUnlock()
	if token == 0 {
		return ErrNotLockedDown
	}
	if err := windows.SetThreadToken(nil, token); err != nil {
		return fmt.Errorf("hostlockdown: SetThreadToken: %w", err)
	}
	return nil
}
