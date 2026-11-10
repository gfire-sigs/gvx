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
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const tlsOutOfIndexes = 0xffffffff

var (
	procTlsAlloc    = modKernel32.NewProc("TlsAlloc")
	procTlsGetValue = modKernel32.NewProc("TlsGetValue")
	procTlsSetValue = modKernel32.NewProc("TlsSetValue")
)

// OS handles that live for the whole process. The restricted token stays open so
// BindThread can attach it to any thread later. The job handle stays open so
// the containment job outlives every other reference to it.
//
// boundTLSSlotPlusOne holds the process-wide Windows TLS slot index plus one
// (zero means unallocated). Each OS thread that attaches the restricted token
// stores the token handle in its own TLS slot. Because the Windows kernel
// zeroes TLS slots on every new thread, an exited OS thread whose numeric TID
// is later reused by a new OS thread never causes BindThread to skip
// SetThreadToken.
var (
	handlesMu           sync.RWMutex
	restrictedToken     atomic.Uintptr
	containmentJob      windows.Handle
	boundTLSSlotOnce    sync.Once
	boundTLSSlotErr     error
	boundTLSSlotPlusOne atomic.Uint32
)

func initBoundTLSSlot() error {
	boundTLSSlotOnce.Do(func() {
		for _, p := range []*windows.LazyProc{procTlsAlloc, procTlsGetValue, procTlsSetValue} {
			if err := p.Find(); err != nil {
				boundTLSSlotErr = fmt.Errorf("hostlockdown: resolve TLS proc: %w", err)
				return
			}
		}
		r1, _, callErr := syscall.SyscallN(procTlsAlloc.Addr())
		slot := uint32(r1)
		if slot == tlsOutOfIndexes {
			boundTLSSlotErr = fmt.Errorf("hostlockdown: TlsAlloc: %w", callErr)
			return
		}
		boundTLSSlotPlusOne.Store(slot + 1)
	})
	return boundTLSSlotErr
}

func markCurrentThreadBound(token windows.Token) {
	slotPlusOne := boundTLSSlotPlusOne.Load()
	if slotPlusOne == 0 || token == 0 {
		return
	}
	_, _, _ = syscall.SyscallN(procTlsSetValue.Addr(), uintptr(slotPlusOne-1), uintptr(token))
}

func isCurrentThreadBound(token windows.Token) bool {
	slotPlusOne := boundTLSSlotPlusOne.Load()
	if slotPlusOne == 0 || token == 0 {
		return false
	}
	v, _, _ := syscall.SyscallN(procTlsGetValue.Addr(), uintptr(slotPlusOne-1))
	return v == uintptr(token)
}

// applyOSLockdown runs the SPEC 3.8 Windows steps in order. Each step returns
// its error. Status fields change only after the step succeeded and its effect
// was read back from the OS.
func applyOSLockdown(opts Options) (st Status, err error) {
	if err := initBoundTLSSlot(); err != nil {
		return Status{}, err
	}
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

	// Step 3: restricted impersonation token (already lowered to Low integrity)
	// for the process threads and BindThread. The live primary token stays at
	// its original integrity until Step 9 binds all pre-existing peer threads
	// so OpenThread(THREAD_SET_THREAD_TOKEN) does not fail MIC NO_WRITE_UP on
	// threads spawned before Apply.
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
	// thread in the process and lower the live primary token to Low integrity.
	if err := bindProcessThreads(primary, restricted); err != nil {
		_ = windows.CloseHandle(job)
		return Status{}, err
	}
	st.IntegrityDowngraded = true
	st.UnboundFileOpenBlocked = true

	handlesMu.Lock()
	restrictedToken.Store(uintptr(restricted))
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

func prewarmOSThreads(n int, onParked func() error) error {
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
	err := onParked()
	close(release)
	done.Wait()
	return err
}

func bindProcessThreads(primary, token windows.Token) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pid := windows.GetCurrentProcessId()
	selfTID := windows.GetCurrentThreadId()
	if err := prewarmOSThreads(max(runtime.GOMAXPROCS(0)*8, 64), func() error {
		return bindPeerThreadsOnce(pid, selfTID, token)
	}); err != nil {
		return err
	}
	if err := bindPeerThreadsOnce(pid, selfTID, token); err != nil {
		return err
	}
	if err := lowerTokenIntegrityToLow(primary); err != nil {
		return err
	}
	if err := bindPeerThreadsOnce(pid, selfTID, token); err != nil {
		return err
	}
	if err := windows.SetThreadToken(nil, token); err != nil {
		return fmt.Errorf("hostlockdown: SetThreadToken(current thread): %w", err)
	}
	markCurrentThreadBound(token)
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
	var peers []windows.Handle
	defer func() {
		for _, h := range peers {
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
		peers = append(peers, h)
	}
	for _, h := range peers {
		peer := h
		if err := windows.SetThreadToken(&peer, token); err != nil {
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
	_, real, err := resolveMountPath(path)
	return real, err
}

// BindThread attaches the process-lifetime restricted token to the calling OS
// thread. Call it right after runtime.LockOSThread on every vCPU thread, and
// keep the thread locked until the goroutine exits.
//
// The token lets the thread reach only the workspace, so a compromised vCPU
// thread cannot read other user files. BindThread returns ErrNotLockedDown
// before a successful Apply.
func BindThread() error {
	token := windows.Token(restrictedToken.Load())
	if token == 0 {
		return ErrNotLockedDown
	}
	if isCurrentThreadBound(token) {
		return nil
	}
	if err := windows.SetThreadToken(nil, token); err != nil {
		return fmt.Errorf("hostlockdown: SetThreadToken: %w", err)
	}
	markCurrentThreadBound(token)
	return nil
}
