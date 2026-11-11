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

//go:build linux

package systrap

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/cpuid"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

const landlockPtraceChildModeEnv = "GVX_SYSTRAP_LANDLOCK_PTRACE_MODE"

type landlockRulesetAttr struct {
	handledAccessFS uint64
}

type landlockTestMM struct {
	platform.MemoryManager
	as platform.AddressSpace
}

func (m landlockTestMM) AddressSpace() platform.AddressSpace {
	return m.as
}

func (landlockTestMM) PopulateSubBlock(context.Context, hostarch.Addr) bool {
	return false
}

// TestAddressSpaceAndSysmsgThreadsWorkAcrossDistinctLandlockDomains verifies
// that NewAddressSpace, Context.Switch, and createSysmsgThread succeed when
// caller OS threads hold Landlock hierarchy nodes distinct from the ptrace
// worker thread. Landlock confinement is irreversible, so each case runs in a
// dedicated child process of the test binary.
func TestAddressSpaceAndSysmsgThreadsWorkAcrossDistinctLandlockDomains(t *testing.T) {
	if os.Getenv(landlockPtraceChildModeEnv) != "" {
		t.Skip("running inside Landlock child subprocess")
	}

	for _, mode := range []string{"perthread", "allthreads"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestLandlockPtraceChild$", "-test.v")
			cmd.Env = append(os.Environ(), landlockPtraceChildModeEnv+"="+mode)
			out, err := cmd.CombinedOutput()
			if bytes.Contains(out, []byte("--- SKIP: TestLandlockPtraceChild")) {
				t.Skipf("child skipped:\n%s", out)
			}
			if err != nil {
				t.Fatalf("Landlock child (%s) failed: %v\n%s", mode, err, out)
			}
			if !bytes.Contains(out, []byte("--- PASS: TestLandlockPtraceChild")) {
				t.Fatalf("Landlock child (%s) did not complete:\n%s", mode, out)
			}
		})
	}
}

func TestLandlockPtraceChild(t *testing.T) {
	mode := os.Getenv(landlockPtraceChildModeEnv)
	if mode == "" {
		t.Skip("runs only as a child of TestAddressSpaceAndSysmsgThreadsWorkAcrossDistinctLandlockDomains")
	}
	if runtime.GOOS == "android" {
		t.Skip("Android Zygote seccomp blocks Landlock syscalls")
	}

	rulesetFD := openMakeFifoLandlockRuleset(t)
	defer unix.Close(rulesetFD)

	cpuid.Initialize()
	p, err := New(platform.Options{})
	if err != nil {
		t.Skipf("systrap engine unavailable: %v", err)
	}

	// Populate globalPool.available with one pre-lockdown stub so
	// RefreshSourceForLockdown must drain it rather than returning a stale stub.
	preLockdownAS, err := p.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		t.Fatalf("pre-lockdown NewAddressSpace: %v", err)
	}
	preLockdownAS.Release()

	switch mode {
	case "allthreads":
		if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno == unix.ENOTSUP {
			t.Skip("AllThreadsSyscall unavailable under cgo; covered by perthread mode")
		} else if errno != 0 {
			t.Fatalf("AllThreadsSyscall(PR_SET_NO_NEW_PRIVS): %v", errno)
		}
		if _, _, errno := syscall.AllThreadsSyscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFD), 0, 0); errno != 0 {
			t.Fatalf("AllThreadsSyscall(LANDLOCK_RESTRICT_SELF): %v", errno)
		}
		if err := p.RefreshSourceForLockdown(); err != nil {
			t.Fatalf("RefreshSourceForLockdown: %v", err)
		}
	case "perthread":
		if err := p.refreshSourceForLockdown(func() error {
			return restrictCurrentThreadLandlock(rulesetFD)
		}); err != nil {
			t.Fatalf("refreshSourceForLockdown: %v", err)
		}
	default:
		t.Fatalf("unknown mode %q", mode)
	}

	probeDir := t.TempDir()
	var workerTID int
	var workerFifoErr error
	runOnPtraceThread(func() {
		workerTID = unix.Gettid()
		workerFifoErr = unix.Mkfifo(filepath.Join(probeDir, "worker.fifo"), 0o600)
	})
	if !errors.Is(workerFifoErr, unix.EACCES) {
		t.Fatalf("mkfifo on ptrace worker returned %v, want EACCES", workerFifoErr)
	}

	// Run from a separate locked OS thread confined to its own Landlock
	// hierarchy node (flags=0 allocates a fresh node in security/landlock).
	callerErr := runOnSeparateRestrictedThread(rulesetFD, probeDir, workerTID, func() error {
		sourceTID := globalPool.source.syscallThread.thread.tid
		_, _, attachErrno := unix.RawSyscall6(unix.SYS_PTRACE, unix.PTRACE_ATTACH, uintptr(sourceTID), 0, 0, 0, 0)
		if attachErrno != unix.EPERM {
			if attachErrno == 0 {
				unix.RawSyscall6(unix.SYS_PTRACE, unix.PTRACE_DETACH, uintptr(sourceTID), 0, 0, 0, 0)
			}
			return fmt.Errorf("direct PTRACE_ATTACH from sibling Landlock domain returned %v, want EPERM", attachErrno)
		}

		asIface, err := p.NewAddressSpace(platform.AddressSpaceOptions{DisableSyscallPatching: true})
		if err != nil {
			return fmt.Errorf("NewAddressSpace from sibling Landlock domain: %w", err)
		}
		sp := asIface.(*subprocess)
		defer sp.Release()

		if err := mapAndUnmapPage(p, sp); err != nil {
			return fmt.Errorf("mapAndUnmapPage: %w", err)
		}
		if err := runGuestSyscallOnce(p, sp); err != nil {
			return fmt.Errorf("runGuestSyscallOnce: %w", err)
		}
		if err := addTestSysmsgThread(sp); err != nil {
			return fmt.Errorf("createSysmsgThread from sibling Landlock domain: %w", err)
		}
		return nil
	})
	if callerErr != nil {
		t.Fatal(callerErr)
	}

	// Exercise concurrent NewAddressSpace and createSysmsgThread calls from
	// distinct Landlock-restricted OS threads to verify deadlock freedom.
	const workers = 4
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subDir := filepath.Join(probeDir, fmt.Sprintf("concurrent-%d", i))
			if err := os.MkdirAll(subDir, 0o700); err != nil {
				errCh <- err
				return
			}
			err := runOnSeparateRestrictedThread(rulesetFD, subDir, workerTID, func() error {
				sp, err := newTestAddressSpace(p)
				if err != nil {
					return fmt.Errorf("worker %d NewAddressSpace: %w", i, err)
				}
				defer sp.Release()
				if err := mapAndUnmapPage(p, sp); err != nil {
					return fmt.Errorf("worker %d mapAndUnmapPage: %w", i, err)
				}
				if err := addTestSysmsgThread(sp); err != nil {
					return fmt.Errorf("worker %d createSysmsgThread: %w", i, err)
				}
				return nil
			})
			if err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

func addTestSysmsgThread(sp *subprocess) error {
	sp.kickSysmsgMu.Lock()
	sp.numSysmsgThreads++
	sp.kickSysmsgMu.Unlock()
	atomic.AddUint32(&sp.contextQueue.numThreadsToWakeup, 1)
	if err := sp.createSysmsgThread(); err != nil {
		atomic.AddUint32(&sp.contextQueue.numThreadsToWakeup, ^uint32(0))
		sp.kickSysmsgMu.Lock()
		sp.numSysmsgThreads--
		sp.kickSysmsgMu.Unlock()
		return err
	}
	return nil
}

func openMakeFifoLandlockRuleset(t *testing.T) int {
	t.Helper()
	_, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		0,
		0,
		unix.LANDLOCK_CREATE_RULESET_VERSION,
	)
	if errno == unix.ENOSYS || errno == unix.EOPNOTSUPP {
		t.Skipf("Landlock unsupported by host kernel: %v", errno)
	}
	if errno != 0 {
		t.Fatalf("query Landlock ABI version: %v", errno)
	}

	// Confine only MAKE_FIFO so normal /proc, /tmp, and memfd operations keep
	// working while the kernel still allocates a real Landlock domain per call.
	attr := landlockRulesetAttr{handledAccessFS: unix.LANDLOCK_ACCESS_FS_MAKE_FIFO}
	fd, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
		0,
	)
	runtime.KeepAlive(&attr)
	if errno != 0 {
		t.Fatalf("create Landlock ruleset: %v", errno)
	}
	return int(fd)
}

func restrictCurrentThreadLandlock(rulesetFD int) error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", err)
	}
	_, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFD), 0, 0)
	if errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %w", errno)
	}
	return nil
}

func runOnSeparateRestrictedThread(rulesetFD int, probeDir string, workerTID int, fn func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// Leave this OS thread locked on return so the runtime terminates it.
		if got := unix.Gettid(); got == workerTID {
			done <- fmt.Errorf("caller goroutine ran on ptrace worker tid %d", got)
			return
		}
		if err := restrictCurrentThreadLandlock(rulesetFD); err != nil {
			done <- err
			return
		}
		fifoErr := unix.Mkfifo(filepath.Join(probeDir, "caller.fifo"), 0o600)
		if !errors.Is(fifoErr, unix.EACCES) {
			done <- fmt.Errorf("mkfifo on caller thread returned %v, want EACCES", fifoErr)
			return
		}
		done <- fn()
	}()
	return <-done
}

func guestExitSyscallCode() (code []byte, wantSysno uintptr, wantArg0 uintptr) {
	const exitCode = 42
	switch runtime.GOARCH {
	case "amd64":
		// mov eax, 60; mov edi, 42; syscall
		return []byte{
			0xb8, 60, 0x00, 0x00, 0x00,
			0xbf, exitCode, 0x00, 0x00, 0x00,
			0x0f, 0x05,
		}, 60, exitCode
	case "arm64":
		// movz x8, #93; movz x0, #42; svc #0
		return []byte{
			0xa8, 0x0b, 0x80, 0xd2,
			0x40, 0x05, 0x80, 0xd2,
			0x01, 0x00, 0x00, 0xd4,
		}, 93, exitCode
	default:
		panic("unsupported architecture: " + runtime.GOARCH)
	}
}

func runGuestSyscallOnce(p *Systrap, sp *subprocess) error {
	unit := max(uint64(hostarch.PageSize), uint64(os.Getpagesize()))
	codeAddr := hostarch.Addr(0x10000000)
	stackAddr := codeAddr + hostarch.Addr(2*unit)

	codeFR, err := p.memoryFile.Allocate(unit, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		return fmt.Errorf("allocate code page: %w", err)
	}
	defer p.memoryFile.DecRef(codeFR)

	stackFR, err := p.memoryFile.Allocate(unit, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		return fmt.Errorf("allocate stack page: %w", err)
	}
	defer p.memoryFile.DecRef(stackFR)

	bs, err := p.memoryFile.MapInternal(codeFR, hostarch.ReadWrite)
	if err != nil {
		return fmt.Errorf("MapInternal code page: %w", err)
	}
	code, wantSysno, wantArg0 := guestExitSyscallCode()
	copy(bs.Head().ToSlice(), code)

	execPerm := hostarch.AccessType{Read: true, Execute: true}
	if err := sp.MapFile(codeAddr, p.memoryFile, codeFR, execPerm, false); err != nil {
		return fmt.Errorf("MapFile code: %w", err)
	}
	defer sp.Unmap(codeAddr, unit)

	if err := sp.MapFile(stackAddr, p.memoryFile, stackFR, hostarch.ReadWrite, false); err != nil {
		return fmt.Errorf("MapFile stack: %w", err)
	}
	defer sp.Unmap(stackAddr, unit)

	guestArch := arch.AMD64
	if runtime.GOARCH == "arm64" {
		guestArch = arch.ARM64
	}
	ac := arch.New(guestArch)
	ac.SetIP(uintptr(codeAddr))
	ac.SetStack(uintptr(stackAddr) + uintptr(unit) - 0x100)

	ctx := p.NewContext(nil)
	defer ctx.Release()

	si, _, switchErr := ctx.Switch(nil, landlockTestMM{as: sp}, ac, -1)
	if switchErr != nil || si != nil {
		return fmt.Errorf("Switch = (si=%v, err=%v), want guest syscall trap", si, switchErr)
	}
	ac.SyscallSaveOrig()
	if got := ac.SyscallNo(); got != wantSysno {
		return fmt.Errorf("guest syscall number = %d, want %d", got, wantSysno)
	}
	if got := ac.SyscallArgs()[0].Value; got != wantArg0 {
		return fmt.Errorf("guest syscall arg0 = %d, want %d", got, wantArg0)
	}
	return nil
}
