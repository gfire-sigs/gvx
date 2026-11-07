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

//go:build linux && (amd64 || arm64)

package guestcpu

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// Event is the moment at which Run lets the kernel act on the thread.
type Event int

const (
	// EventSyscall executes one system call with the number and the arguments
	// that the State holds. Linux changes only the result register and, on
	// amd64, RCX and R11.
	EventSyscall Event = iota
	// EventSpin loops in user code until ReleaseSpin runs. A signal that
	// arrives in the meantime interrupts the loop. On arm64 the loop uses X0 as
	// its only scratch register, and X0 is 1 when the loop ends.
	EventSpin
	// EventFault stores zero to the address in the fault register (RSI on
	// amd64, X1 on arm64). The store faults when the page is not present or not
	// writable.
	EventFault
)

// Run loads in into the CPU, lets ev happen, and stores the CPU state that the
// thread has afterwards in out. Run stores the stack pointer of the event in in
// and in out. Run restores the FP control state that the caller had.
//
// The caller must lock the OS thread and block SIGURG and SIGCHLD on it. On
// arm64 the Go handler of a signal reads the g register, and in holds a test
// value there. On every architecture, a signal that the Go runtime sends to a
// thread that is busy in Run has no use.
func Run(ev Event, in, out *State) {
	switch ev {
	case EventSyscall:
		runSyscall(in, out)
	case EventSpin:
		runSpin(in, out)
	case EventFault:
		runFault(in, out)
	default:
		panic(fmt.Sprintf("guestcpu: unknown event %d", ev))
	}
}

func runSyscall(in, out *State)
func runSpin(in, out *State)
func runFault(in, out *State)

// evilHandler is the signal handler that destroys the state. It counts the
// signal, records the spin flag, follows handlerMode, makes the page of a
// SIGSEGV writable unless handlerMode says to skip the faulting instruction,
// loads trashState into every register, and returns to the restorer.
func evilHandler()

// handlerPC returns the address of evilHandler.
func handlerPC() uintptr

// Variables that the assembly reads and writes.
var (
	// spinFlag ends EventSpin when it is not zero.
	spinFlag uint32
	// sigCount is the number of signals that evilHandler received.
	sigCount uint32
	// flagSeen is the value of spinFlag that evilHandler saw at its last call.
	flagSeen uint32
	// pageMask and pageSize describe the page that evilHandler makes writable
	// after a SIGSEGV.
	pageMask uint64
	pageSize uint64
	// trashState is the content of every register while evilHandler runs.
	trashState State
	// handlerMode holds the Mode bits that evilHandler obeys.
	handlerMode uint32
	// captured is the copy of the last signal frame that evilHandler saw.
	captured capture
	// editState is the register state that evilHandler writes into the frame
	// in ModeEdit.
	editState State
)

// Mode selects what evilHandler does in addition to its destruction of the
// registers.
type Mode uint32

const (
	// ModeCapture copies the siginfo, the ucontext, and the FP record of the
	// frame, so that CapturedFrame can decode them.
	ModeCapture Mode = 1 << iota
	// ModeEdit overwrites the registers in the frame with the State that
	// SetEdit sets. After the sigreturn, the thread has these values. On arm64
	// the handler leaves X0 alone, because EventSpin uses it as scratch.
	ModeEdit
	// ModeSkipFault moves the program counter in the frame over the faulting
	// instruction of EventFault, at the first SIGSEGV. A kernel that ignores
	// the edit delivers a second SIGSEGV, and the handler ends the program.
	ModeSkipFault
)

// SetMode sets the Mode bits that evilHandler obeys.
func SetMode(m Mode) { handlerMode = uint32(m) }

// SetEdit makes evilHandler write s into the frame. The mode must include
// ModeEdit.
func SetEdit(s *State) { editState = *s }

const (
	saSigInfo = 0x4
	saOnStack = 0x08000000
	saRestart = 0x10000000
)

// sigaction is the kernel layout of the argument of rt_sigaction on amd64 and
// arm64. The kernel of arm64 ignores restorer.
type sigaction struct {
	handler  uintptr
	flags    uint64
	restorer uintptr
	mask     uint64
}

// Install makes evilHandler the handler of sig and returns a function that
// puts the old handler back. The handler runs on the signal stack of the
// thread. With restart, a blocking system call that the signal interrupts
// restarts after the handler returns.
func Install(sig syscall.Signal, restart bool) (restore func(), err error) {
	pageSize = uint64(syscall.Getpagesize())
	pageMask = ^(pageSize - 1)
	trashState = trashPattern()
	flags := uint64(saSigInfo | saOnStack | restorerFlag)
	if restart {
		flags |= saRestart
	}
	act := sigaction{handler: handlerPC(), flags: flags, restorer: restorerPC()}
	var old sigaction
	if err := rtSigaction(sig, &act, &old); err != nil {
		return nil, fmt.Errorf("install the handler of %v: %w", sig, err)
	}
	return func() { _ = rtSigaction(sig, &old, nil) }, nil
}

func rtSigaction(sig syscall.Signal, act, old *sigaction) error {
	_, _, errno := syscall.RawSyscall6(syscall.SYS_RT_SIGACTION, uintptr(sig),
		uintptr(unsafe.Pointer(act)), uintptr(unsafe.Pointer(old)), 8, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// BlockSignals blocks sigs on the calling thread. The Go runtime sends SIGURG
// to a thread that runs for a long time. The caller must lock the OS thread.
// The caller must call the returned function before it unlocks the thread.
func BlockSignals(sigs ...syscall.Signal) (unblock func(), err error) {
	var set uint64
	for _, s := range sigs {
		set |= 1 << (uint(s) - 1)
	}
	var old uint64
	const sigBlock = 0
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_RT_SIGPROCMASK, sigBlock,
		uintptr(unsafe.Pointer(&set)), uintptr(unsafe.Pointer(&old)), 8, 0, 0); errno != 0 {
		return nil, fmt.Errorf("block signals: %w", errno)
	}
	return func() {
		const sigSetMask = 2
		syscall.RawSyscall6(syscall.SYS_RT_SIGPROCMASK, sigSetMask,
			uintptr(unsafe.Pointer(&old)), 0, 8, 0, 0)
	}, nil
}

// ResetHandler clears the counters of evilHandler, the spin flag, the mode, and
// the captured frame.
func ResetHandler() {
	handlerMode = 0
	captured = capture{}
	atomic.StoreUint32(&sigCount, 0)
	atomic.StoreUint32(&flagSeen, 0)
	atomic.StoreUint32(&spinFlag, 0)
}

// HandlerCalls returns the number of signals that evilHandler received since
// ResetHandler.
func HandlerCalls() int { return int(atomic.LoadUint32(&sigCount)) }

// SpinFlagAtHandler returns the value of the spin flag at the last call of
// evilHandler. The value is 0 when the handler ran before ReleaseSpin.
func SpinFlagAtHandler() uint32 { return atomic.LoadUint32(&flagSeen) }

// ReleaseSpin ends the loop of EventSpin.
func ReleaseSpin() { atomic.StoreUint32(&spinFlag, 1) }

// splitmix returns the next value of the SplitMix64 sequence of *x. Each value
// differs from the next. A register that takes the value of another register
// shows up as a mismatch.
func splitmix(x *uint64) uint64 {
	*x += 0x9e3779b97f4a7c15
	z := *x
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// maxDiffs is the number of register mismatches that Compare lists.
const maxDiffs = 6

// Compare returns an error that lists the registers of got that differ from
// want. It ignores the registers in skip. It compares the stack pointer only
// when want has one: Run stores it in its input State, so a copy of that State
// has one.
func Compare(want, got *State, skip ...int) error {
	d := diffs(want, got, skip...)
	if len(d) == 0 {
		return nil
	}
	more := ""
	if len(d) > maxDiffs {
		more = fmt.Sprintf(" (and %d more)", len(d)-maxDiffs)
		d = d[:maxDiffs]
	}
	return errors.New(strings.Join(d, "; ") + more)
}

// SignalDelay is the time that SignalLater waits before it sends the signal,
// and then before it calls release. It gives the thread time to enter its
// blocking call or its loop.
const SignalDelay = 30 * time.Millisecond

// SignalLater sends sig to the calling thread after SignalDelay. When release is
// not nil, it calls release after a second delay. The returned function waits
// for both actions. The caller must lock its OS thread. The process needs two
// or more Ps, so that the goroutine runs while the thread is busy in Run.
func SignalLater(sig syscall.Signal, release func()) (wait func()) {
	tid := syscall.Gettid()
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(SignalDelay)
		if err := syscall.Tgkill(os.Getpid(), tid, sig); err != nil {
			fmt.Println("tgkill:", err)
		}
		if release != nil {
			time.Sleep(SignalDelay)
			release()
		}
	}()
	return func() { <-done }
}

// Watchdog ends the program with a failure message when it still runs after d.
// A guest kernel that loses a signal or a wakeup then fails the probe and does
// not hang it. The process needs two or more Ps, so that the timer fires while
// a thread is busy in Run.
func Watchdog(d time.Duration) *time.Timer {
	return time.AfterFunc(d, func() {
		fmt.Printf("FAIL watchdog: the probe did not end within %v\n", d)
		os.Exit(1)
	})
}

// ReadMemory returns n bytes of the guest memory at addr. The kernel copies the
// bytes through a pipe, so a wrong address returns EFAULT and does not crash.
func ReadMemory(addr uintptr, n int) ([]byte, error) {
	var fds [2]int
	if err := syscall.Pipe(fds[:]); err != nil {
		return nil, err
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])
	if _, _, errno := syscall.RawSyscall(syscall.SYS_WRITE, uintptr(fds[1]), addr, uintptr(n)); errno != 0 {
		return nil, errno
	}
	buf := make([]byte, n)
	if _, err := syscall.Read(fds[0], buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// NegErrno returns the value that a system call leaves in its result register
// when it fails with e.
func NegErrno(e syscall.Errno) uint64 { return -uint64(e) }
