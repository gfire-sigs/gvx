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

// Command eintrprobe checks that a blocking socket call survives a signal in a
// guest. Linux restarts a blocked call after a signal with a handler that has
// SA_RESTART and after a signal that the process ignores. It returns EINTR only
// for a handler without SA_RESTART. Each check prints "PASS name" or
// "FAIL name: reason".
//
// Usage:
//
//	eintrprobe checks [signals]   block in each call, send the given number of
//	                              signals (default 100) to the blocked thread,
//	                              release the call, then print DONE
package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	defaultSignals = 100
	// enterWait is the time that the receiver thread gets to block in its call
	// before the first signal.
	enterWait = 50 * time.Millisecond
	// signalGap is the time between two signals.
	signalGap = time.Millisecond
	// releaseWait is the time that a released call gets to return.
	releaseWait = 20 * time.Second
	// eintrWait is the time that a call without SA_RESTART gets to return EINTR.
	eintrWait = 20 * time.Second
	watchdog  = 5 * time.Minute
	payload   = "hello"
)

// outcome is the result of one blocking call.
type outcome struct {
	n   int
	err error
}

// call is one blocking socket call. open makes the sockets and returns the
// call, a function that lets the call finish, and a function that closes the
// sockets. The call returns the number of bytes that it moved. The release
// function makes that number want.
type call struct {
	name string
	open func() (block func() (int, error), release func() error, closeAll func(), want int, err error)
}

// signalSource is a signal that the checks send with tgkill(2).
type signalSource struct {
	name string
	sig  syscall.Signal
}

func main() {
	if len(os.Args) < 2 || os.Args[1] != "checks" {
		fmt.Fprintln(os.Stderr, "usage: eintrprobe checks [signals]")
		os.Exit(2)
	}
	count := defaultSignals
	if len(os.Args) > 2 {
		n, err := strconv.Atoi(os.Args[2])
		if err != nil || n < 1 {
			fmt.Fprintln(os.Stderr, "invalid signal count", os.Args[2])
			os.Exit(2)
		}
		count = n
	}
	go func() {
		time.Sleep(watchdog)
		fmt.Println("FAIL watchdog: the checks did not finish in time")
		os.Exit(1)
	}()
	ok := runChecks(count)
	fmt.Println("DONE")
	if !ok {
		os.Exit(1)
	}
}

// report prints the result of one check and returns whether it passed.
func report(name string, err error) bool {
	if err != nil {
		fmt.Printf("FAIL %s: %v\n", name, err)
		return false
	}
	fmt.Printf("PASS %s\n", name)
	return true
}

func runChecks(count int) bool {
	// The Go runtime installs a handler with SA_RESTART for every signal that
	// it does not ignore. SIGURG is the signal of its preemption. A channel
	// for SIGUSR1 keeps the signal away from the default action. SIGUSR2 is
	// ignored.
	usr1 := make(chan os.Signal, 1)
	signal.Notify(usr1, syscall.SIGUSR1)
	go func() {
		for range usr1 {
		}
	}()
	signal.Ignore(syscall.SIGUSR2)

	calls := []call{
		{"recvfrom-peek-trunc-seqpacket", openRecvfromPeek},
		{"recvmsg-stream", openRecvmsg},
		{"accept-stream", openAccept},
		{"sendmsg-full-stream", openSendmsg},
	}
	sources := []signalSource{
		{"handler-restart-sigurg", syscall.SIGURG},
		{"handler-restart-sigusr1", syscall.SIGUSR1},
		{"handler-restart-sigchld", syscall.SIGCHLD},
		{"ignored-sigusr2", syscall.SIGUSR2},
	}
	ok := true
	for _, src := range sources {
		for _, c := range calls {
			name := c.name + "-" + src.name
			ok = report(name, checkRestarts(c, src.sig, count)) && ok
		}
	}
	// The negative control: without SA_RESTART the call must fail with EINTR.
	// A probe that never sees EINTR would pass every check above for any kernel.
	if err := clearRestartFlag(syscall.SIGUSR1); err != nil {
		return report("handler-without-restart-sigusr1", err) && ok
	}
	ok = report("recvfrom-peek-trunc-seqpacket-handler-without-restart-sigusr1",
		checkInterrupts(calls[0], syscall.SIGUSR1)) && ok
	return ok
}

// startCall runs the call on a locked thread and returns the thread ID and the
// channel of the result.
func startCall(block func() (int, error)) (int, <-chan outcome) {
	tidCh := make(chan int, 1)
	done := make(chan outcome, 1)
	go func() {
		runtime.LockOSThread()
		tidCh <- unix.Gettid()
		n, err := block()
		done <- outcome{n, err}
	}()
	return <-tidCh, done
}

// checkRestarts blocks a thread in the call and sends it count signals. The call
// must stay blocked until the release, then return the expected count of bytes.
func checkRestarts(c call, sig syscall.Signal, count int) error {
	block, release, closeAll, want, err := c.open()
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer closeAll()
	tid, done := startCall(block)
	time.Sleep(enterWait)
	pid := os.Getpid()
	for i := range count {
		if err := unix.Tgkill(pid, tid, sig); err != nil {
			if errors.Is(err, unix.ESRCH) {
				// The thread ended, so the call returned before the release.
				r := <-done
				return fmt.Errorf("the call returned before signal %d of %d, before the release: n=%d, %w",
					i+1, count, r.n, orNone(r.err))
			}
			return fmt.Errorf("tgkill: %w", err)
		}
		time.Sleep(signalGap)
		select {
		case r := <-done:
			return fmt.Errorf("the call returned after signal %d of %d, before the release: n=%d, %w",
				i+1, count, r.n, orNone(r.err))
		default:
		}
	}
	if err := release(); err != nil {
		return fmt.Errorf("release: %w", err)
	}
	select {
	case r := <-done:
		if r.err != nil {
			return fmt.Errorf("the call failed after the release: %w", r.err)
		}
		if r.n != want {
			return fmt.Errorf("the call moved %d bytes, want %d", r.n, want)
		}
		return nil
	case <-time.After(releaseWait):
		return errors.New("the call did not return after the release")
	}
}

// checkInterrupts blocks a thread in the call and sends signals until the call
// returns. The call must return EINTR.
func checkInterrupts(c call, sig syscall.Signal) error {
	block, release, closeAll, _, err := c.open()
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer closeAll()
	tid, done := startCall(block)
	time.Sleep(enterWait)
	pid := os.Getpid()
	deadline := time.After(eintrWait)
	result := func(r outcome) error {
		if !errors.Is(r.err, syscall.EINTR) {
			return fmt.Errorf("the call returned n=%d, %w, want EINTR", r.n, orNone(r.err))
		}
		return nil
	}
	for {
		if err := unix.Tgkill(pid, tid, sig); err != nil {
			// The thread ends when its goroutine returns, because the goroutine
			// keeps the thread locked. A signal that arrives after the call
			// returned finds no thread, so the result is already in done.
			if errors.Is(err, unix.ESRCH) {
				return result(<-done)
			}
			return fmt.Errorf("tgkill: %w", err)
		}
		select {
		case r := <-done:
			return result(r)
		case <-deadline:
			_ = release()
			return errors.New("the call did not return EINTR for a handler without SA_RESTART")
		case <-time.After(signalGap):
		}
	}
}

func orNone(err error) error {
	if err == nil {
		return errors.New("no error")
	}
	return err
}

// kernelSigaction is struct sigaction of the rt_sigaction(2) system call on
// the 64-bit Linux architectures.
type kernelSigaction struct {
	handler  uintptr
	flags    uint64
	restorer uintptr
	mask     uint64
}

const saRestart = 0x10000000

// clearRestartFlag removes SA_RESTART from the handler that the Go runtime
// installed for sig. The handler address stays the same.
func clearRestartFlag(sig syscall.Signal) error {
	var act kernelSigaction
	if _, _, e := syscall.RawSyscall6(syscall.SYS_RT_SIGACTION, uintptr(sig), 0, uintptr(unsafe.Pointer(&act)), 8, 0, 0); e != 0 {
		return fmt.Errorf("rt_sigaction read: %w", e)
	}
	if act.flags&saRestart == 0 {
		return errors.New("the handler of the Go runtime has no SA_RESTART")
	}
	act.flags &^= saRestart
	if _, _, e := syscall.RawSyscall6(syscall.SYS_RT_SIGACTION, uintptr(sig), uintptr(unsafe.Pointer(&act)), 0, 8, 0, 0); e != 0 {
		return fmt.Errorf("rt_sigaction write: %w", e)
	}
	return nil
}

func closeFDs(fds ...int) {
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
}

// openRecvfromPeek is the call of runc when it reads a packet of its sync
// socket: the length of the next packet, without a buffer.
func openRecvfromPeek() (func() (int, error), func() error, func(), int, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	block := func() (int, error) {
		n, _, err := unix.Recvfrom(fds[0], nil, unix.MSG_TRUNC|unix.MSG_PEEK)
		return n, err
	}
	release := func() error {
		_, err := unix.Write(fds[1], []byte(payload))
		return err
	}
	return block, release, func() { closeFDs(fds[0], fds[1]) }, len(payload), nil
}

func openRecvmsg() (func() (int, error), func() error, func(), int, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	block := func() (int, error) {
		buf := make([]byte, 64)
		n, _, _, _, err := unix.Recvmsg(fds[0], buf, nil, 0)
		return n, err
	}
	release := func() error {
		_, err := unix.Write(fds[1], []byte(payload))
		return err
	}
	return block, release, func() { closeFDs(fds[0], fds[1]) }, len(payload), nil
}

func openAccept() (func() (int, error), func() error, func(), int, error) {
	lfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	addr := &unix.SockaddrUnix{Name: "@gvx-eintrprobe-" + strconv.Itoa(os.Getpid())}
	if err := unix.Bind(lfd, addr); err != nil {
		closeFDs(lfd)
		return nil, nil, nil, 0, fmt.Errorf("bind: %w", err)
	}
	if err := unix.Listen(lfd, 1); err != nil {
		closeFDs(lfd)
		return nil, nil, nil, 0, fmt.Errorf("listen: %w", err)
	}
	accepted := make(chan int, 1)
	var client int
	block := func() (int, error) {
		fd, _, err := unix.Accept(lfd)
		if err != nil {
			return 0, err
		}
		accepted <- fd
		return 1, nil
	}
	release := func() error {
		var err error
		client, err = unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			return err
		}
		return unix.Connect(client, addr)
	}
	closeAll := func() {
		closeFDs(lfd)
		if client != 0 {
			closeFDs(client)
		}
		select {
		case fd := <-accepted:
			closeFDs(fd)
		default:
		}
	}
	return block, release, closeAll, 1, nil
}

// openSendmsg fills the send buffer of a stream socket, so that the next
// blocking send waits for the reader.
func openSendmsg() (func() (int, error), func() error, func(), int, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	if err := unix.SetNonblock(fds[0], true); err != nil {
		closeFDs(fds[0], fds[1])
		return nil, nil, nil, 0, err
	}
	chunk := make([]byte, 64<<10)
	for {
		if _, err := unix.Write(fds[0], chunk); err != nil {
			if errors.Is(err, syscall.EAGAIN) {
				break
			}
			closeFDs(fds[0], fds[1])
			return nil, nil, nil, 0, fmt.Errorf("fill: %w", err)
		}
	}
	if err := unix.SetNonblock(fds[0], false); err != nil {
		closeFDs(fds[0], fds[1])
		return nil, nil, nil, 0, err
	}
	msg := make([]byte, 4096)
	block := func() (int, error) {
		return unix.SendmsgN(fds[0], msg, nil, nil, 0)
	}
	release := func() error {
		buf := make([]byte, 1<<20)
		_, err := unix.Read(fds[1], buf)
		return err
	}
	return block, release, func() { closeFDs(fds[0], fds[1]) }, len(msg), nil
}
