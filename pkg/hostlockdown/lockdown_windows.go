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
	"errors"
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

const (
	tlsOutOfIndexes      = 0xffffffff
	minPrewarmedThreads  = 128
	prewarmThreadsPerCPU = 16
	threadSweepInterval  = 2 * time.Millisecond
)

var (
	modNtdll            = windows.NewLazySystemDLL("ntdll.dll")
	procNtGetNextThread = modNtdll.NewProc("NtGetNextThread")
	procGetThreadId     = modKernel32.NewProc("GetThreadId")
	procTlsAlloc        = modKernel32.NewProc("TlsAlloc")
	procTlsGetValue     = modKernel32.NewProc("TlsGetValue")
	procTlsSetValue     = modKernel32.NewProc("TlsSetValue")
)

// OS handles and state that live for the whole process after Apply succeeds.
var (
	handlesMu           sync.RWMutex
	restrictedToken     atomic.Uintptr
	containmentJob      windows.Handle
	boundTLSSlotOnce    sync.Once
	boundTLSSlotErr     error
	boundTLSSlotPlusOne atomic.Uint32
	hasNtGetNextThread  bool

	// threadBindMu serializes initial peer-thread token binding with background
	// thread sweeps.
	threadBindMu sync.Mutex

	excludedTIDsMu sync.RWMutex
	excludedTIDs   = make(map[uint32]struct{})

	wakeThreadSweep = make(chan struct{}, 1)
)

func excludeCurrentThread() uint32 {
	tid := windows.GetCurrentThreadId()
	excludedTIDsMu.Lock()
	excludedTIDs[tid] = struct{}{}
	excludedTIDsMu.Unlock()
	return tid
}

func unexcludeThread(tid uint32) {
	excludedTIDsMu.Lock()
	delete(excludedTIDs, tid)
	excludedTIDsMu.Unlock()
}

func isExcludedThread(tid uint32) bool {
	excludedTIDsMu.RLock()
	_, ok := excludedTIDs[tid]
	excludedTIDsMu.RUnlock()
	return ok
}

func initBoundTLSSlot() error {
	boundTLSSlotOnce.Do(func() {
		for _, p := range []*windows.LazyProc{procTlsAlloc, procTlsGetValue, procTlsSetValue} {
			if err := p.Find(); err != nil {
				boundTLSSlotErr = fmt.Errorf("hostlockdown: resolve TLS proc: %w", err)
				return
			}
		}
		if procNtGetNextThread.Find() == nil && procGetThreadId.Find() == nil {
			hasNtGetNextThread = true
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

// applyOSLockdown runs the Windows host lockdown sequence in order without
// modifying any DACL or mandatory label on the host filesystem.
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
	if err := grantDefaultDACL(primary, id); err != nil {
		return Status{}, err
	}

	// Step 1: resolve and pin mount handles in memory without changing NTFS ACLs.
	sealedMounts, mountsReal, err := pinHostMounts(opts.Mounts)
	if err != nil {
		return Status{}, err
	}
	keep := false
	defer func() {
		if !keep {
			sealedMounts.close()
		}
	}()

	// Step 2: remove every privilege from the live primary token with SE_PRIVILEGE_REMOVED.
	if err := removeAllTokenPrivileges(primary); err != nil {
		return Status{}, err
	}

	// Step 3: start the pinned-root file broker, the thread-sweeper OS thread,
	// and the optional Low-integrity NAT socket-broker pool before Apply lowers
	// primary to Untrusted integrity.
	fileBroker, _, err := startFileBroker(primary, sealedMounts)
	if err != nil {
		return Status{}, err
	}
	defer func() {
		if !keep {
			fileBroker.stop()
		}
	}()

	sweeper, err := prepareThreadSweeper(primary, id)
	if err != nil {
		return Status{}, err
	}
	defer func() {
		if !keep {
			sweeper.stop()
		}
	}()

	var netBroker *winNetBroker
	if opts.AllowOutboundNet || opts.PreboundListeners > 0 {
		netBroker, err = startNetBroker(primary, id, opts.AllowOutboundNet, opts.PreboundListeners)
		if err != nil {
			return Status{}, err
		}
		defer func() {
			if !keep {
				netBroker.stop()
			}
		}()
	}

	// Step 4: build the Untrusted NULL_SID restricted impersonation token and
	// verify that both unlisted file opens and raw WSASocket calls fail on
	// restricted threads.
	restricted, err := createRestrictedImpersonationToken(primary, id)
	if err != nil {
		return Status{}, err
	}
	defer func() {
		if !keep {
			_ = restricted.Close()
		}
	}()
	if err := probeRestrictedOpenBlocked(restricted, mountsReal); err != nil {
		return Status{}, err
	}
	if err := probeRestrictedSocketBlocked(restricted); err != nil {
		return Status{}, err
	}
	st.NetworkOutboundBlocked = !opts.AllowOutboundNet

	// Steps 5 to 7: create and assign the containment job object.
	job, err := createContainmentJob(opts.CPUQuotaMillis)
	if err != nil {
		return Status{}, err
	}
	defer func() {
		if !keep {
			_ = windows.CloseHandle(job)
		}
	}()
	st.SubprocessBlocked = true
	st.CPUQuotaEnforced = opts.CPUQuotaMillis > 0

	// Step 8: disallow win32k system calls.
	if err := disableWin32kSystemCalls(); err != nil {
		return Status{}, err
	}
	st.Win32kBlocked = true

	// Step 9: pre-warm Go runtime OS threads, bind all non-broker threads to
	// restricted, and lower primary to Untrusted integrity.
	if err := bindProcessThreads(primary, restricted); err != nil {
		return Status{}, err
	}
	st.IntegrityDowngraded = true
	st.UnboundFileOpenBlocked = true

	if netBroker != nil {
		activeNetBroker.Store(netBroker)
	}
	activeFileBroker.Store(fileBroker)

	handlesMu.Lock()
	restrictedToken.Store(uintptr(restricted))
	containmentJob = job
	handlesMu.Unlock()

	sweeper.activate(restricted)
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
	targetThreads := max(runtime.GOMAXPROCS(0)*prewarmThreadsPerCPU, minPrewarmedThreads)
	if err := prewarmOSThreads(targetThreads, func() error {
		return bindPeerThreadsOnce(pid, selfTID, token)
	}); err != nil {
		return err
	}
	if err := bindPeerThreadsOnce(pid, selfTID, token); err != nil {
		return err
	}
	if err := lowerTokenIntegrityToUntrusted(primary); err != nil {
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
	threadBindMu.Lock()
	defer threadBindMu.Unlock()

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
		if te.OwnerProcessID != pid || te.ThreadID == selfTID || isExcludedThread(te.ThreadID) {
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

type winThreadSweeper struct {
	activateCh chan windows.Token
	stopCh     chan struct{}
}

// prepareThreadSweeper locks one dedicated OS thread before Apply lowers
// primary, attaches a Low-integrity NULL_SID restricted token, and closes the
// sweeper token handle immediately. Activate starts periodic sweeping with the
// Untrusted restricted token after bindProcessThreads finishes.
func prepareThreadSweeper(primary windows.Token, id *tokenIdentity) (*winThreadSweeper, error) {
	sweeperTok, err := createSweeperImpersonationToken(primary, id)
	if err != nil {
		return nil, err
	}
	s := &winThreadSweeper{
		activateCh: make(chan windows.Token, 1),
		stopCh:     make(chan struct{}),
	}
	pid := windows.GetCurrentProcessId()
	ready := make(chan error, 1)
	go func(tok windows.Token) {
		runtime.LockOSThread()
		tid := excludeCurrentThread()
		setErr := windows.SetThreadToken(nil, tok)
		_ = tok.Close()
		if setErr != nil {
			unexcludeThread(tid)
			ready <- fmt.Errorf("hostlockdown: SetThreadToken(thread sweeper): %w", setErr)
			return
		}
		ready <- nil

		var restricted windows.Token
		select {
		case <-s.stopCh:
			unexcludeThread(tid)
			return
		case restricted = <-s.activateCh:
		}

		ticker := time.NewTicker(threadSweepInterval)
		defer ticker.Stop()
		for {
			sweepUnboundPeerThreads(pid, tid, restricted)
			select {
			case <-s.stopCh:
				unexcludeThread(tid)
				return
			case <-wakeThreadSweep:
			case <-ticker.C:
			}
		}
	}(sweeperTok)

	if err := <-ready; err != nil {
		return nil, err
	}
	return s, nil
}

func (s *winThreadSweeper) activate(restricted windows.Token) {
	if s != nil {
		s.activateCh <- restricted
	}
}

func (s *winThreadSweeper) stop() {
	if s != nil {
		close(s.stopCh)
	}
}

func sweepUnboundPeerThreads(pid, selfTID uint32, token windows.Token) {
	threadBindMu.Lock()
	defer threadBindMu.Unlock()

	if hasNtGetNextThread && sweepViaNtGetNextThread(selfTID, token) {
		return
	}
	sweepViaToolhelp(pid, selfTID, token)
}

func sweepViaNtGetNextThread(selfTID uint32, token windows.Token) bool {
	const desiredAccess = windows.THREAD_SET_THREAD_TOKEN | windows.THREAD_QUERY_INFORMATION
	proc := windows.CurrentProcess()
	var prev windows.Handle
	visited := 0
	for {
		var next windows.Handle
		r1, _, _ := syscall.SyscallN(
			procNtGetNextThread.Addr(),
			uintptr(proc),
			uintptr(prev),
			uintptr(desiredAccess),
			0,
			0,
			uintptr(unsafe.Pointer(&next)),
		)
		if prev != 0 {
			_ = windows.CloseHandle(prev)
			prev = 0
		}
		if r1 != 0 || next == 0 {
			return visited > 0
		}
		visited++
		tidR1, _, _ := syscall.SyscallN(procGetThreadId.Addr(), uintptr(next))
		tid := uint32(tidR1)
		if tid != 0 && tid != selfTID && !isExcludedThread(tid) {
			attachIfUnbound(next, token)
		}
		prev = next
	}
}

func sweepViaToolhelp(pid, selfTID uint32, token windows.Token) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snap)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	const desiredAccess = windows.THREAD_SET_THREAD_TOKEN | windows.THREAD_QUERY_INFORMATION
	for err := windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		if te.OwnerProcessID != pid || te.ThreadID == selfTID || isExcludedThread(te.ThreadID) {
			continue
		}
		h, openErr := windows.OpenThread(desiredAccess, false, te.ThreadID)
		if openErr != nil {
			continue
		}
		attachIfUnbound(h, token)
		_ = windows.CloseHandle(h)
	}
}

func attachIfUnbound(thread windows.Handle, token windows.Token) {
	var existing windows.Token
	err := windows.OpenThreadToken(thread, windows.TOKEN_QUERY, true, &existing)
	if err == nil {
		_ = existing.Close()
		return
	}
	if !errors.Is(err, windows.ERROR_NO_TOKEN) {
		return
	}
	peer := thread
	_ = windows.SetThreadToken(&peer, token)
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
// BindThread returns ErrNotLockedDown before a successful Apply.
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
	select {
	case wakeThreadSweep <- struct{}{}:
	default:
	}
	return nil
}
