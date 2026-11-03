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

// Command membarrierprobe checks membarrier(2) in a guest. Each check prints
// "PASS name" or "FAIL name: reason".
//
// Usage:
//
//	membarrierprobe checks   run the command checks on the main thread and on
//	                         several other threads, then print DONE
//	membarrierprobe stress   call membarrier from several threads while other
//	                         threads make system calls or compute without any,
//	                         then print DONE
package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Command values from include/uapi/linux/membarrier.h.
const (
	cmdQuery                = 0
	cmdGlobal               = 1 << 0
	cmdGlobalExpedited      = 1 << 1
	cmdRegisterGlobalExped  = 1 << 2
	cmdPrivateExpedited     = 1 << 3
	cmdRegisterPrivateExped = 1 << 4
	unknownCmd              = 1 << 30
	flagsNotAllowed         = 1

	// supportedRequired is the set of commands that QUERY must report.
	supportedRequired = cmdGlobal | cmdGlobalExpedited | cmdRegisterGlobalExped |
		cmdPrivateExpedited | cmdRegisterPrivateExped
)

// Sizes of the checks and of the stress run.
const (
	threadCount             = 6
	checkRepeatsPerThread   = 40
	stressCallers           = 3
	stressBarriersPerCaller = 300
	stressSyscallPairs      = 3
	stressSpinners          = 2
	stressWatchdog          = 2 * time.Minute
)

func membarrier(cmd, flags int) (int, error) {
	r, _, e := syscall.Syscall(unix.SYS_MEMBARRIER, uintptr(cmd), uintptr(flags), 0)
	if e != 0 {
		return -1, e
	}
	return int(r), nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: membarrierprobe checks|stress")
		os.Exit(2)
	}
	var ok bool
	switch os.Args[1] {
	case "checks":
		ok = runChecks()
	case "stress":
		ok = runStress()
	default:
		fmt.Fprintln(os.Stderr, "unknown command", os.Args[1])
		os.Exit(2)
	}
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

// expectErrno returns an error unless err is the errno want.
func expectErrno(op string, err error, want syscall.Errno) error {
	if errors.Is(err, want) {
		return nil
	}
	return fmt.Errorf("%s returned %v, want %v", op, err, want)
}

// expectOK runs command cmd and returns an error unless it succeeds.
func expectOK(op string, cmd int) error {
	if _, err := membarrier(cmd, 0); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func runChecks() bool {
	ok := true
	ok = report("query-reports-expedited-commands", checkQuery()) && ok
	ok = report("unknown-arguments-fail", checkInvalid()) && ok
	ok = report("private-expedited-needs-registration", checkPrivateNeedsRegistration()) && ok
	ok = report("register-private-expedited", expectOK("REGISTER_PRIVATE_EXPEDITED", cmdRegisterPrivateExped)) && ok
	ok = report("register-global-expedited", expectOK("REGISTER_GLOBAL_EXPEDITED", cmdRegisterGlobalExped)) && ok
	ok = report("commands-from-several-threads", checkThreads()) && ok
	return ok
}

func checkQuery() error {
	mask, err := membarrier(cmdQuery, 0)
	if err != nil {
		return fmt.Errorf("QUERY: %w", err)
	}
	if missing := supportedRequired &^ mask; missing != 0 {
		return fmt.Errorf("QUERY returned %#x, missing bits %#x", mask, missing)
	}
	return nil
}

func checkInvalid() error {
	if _, err := membarrier(cmdQuery, flagsNotAllowed); !errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("QUERY with flags returned %v, want EINVAL", err)
	}
	if _, err := membarrier(cmdGlobal, flagsNotAllowed); !errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("GLOBAL with flags returned %v, want EINVAL", err)
	}
	_, err := membarrier(unknownCmd, 0)
	return expectErrno("unknown command", err, syscall.EINVAL)
}

func checkPrivateNeedsRegistration() error {
	_, err := membarrier(cmdPrivateExpedited, 0)
	return expectErrno("PRIVATE_EXPEDITED before registration", err, syscall.EPERM)
}

// checkThreads calls every barrier command from threadCount threads at the same
// time. Each goroutine locks its OS thread, so each call comes from its own
// guest thread.
func checkThreads() error {
	var wg sync.WaitGroup
	errs := make(chan error, threadCount)
	for i := range threadCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			for range checkRepeatsPerThread {
				for _, cmd := range []int{cmdPrivateExpedited, cmdGlobal, cmdGlobalExpedited} {
					if _, err := membarrier(cmd, 0); err != nil {
						errs <- fmt.Errorf("thread %d: command %#x: %w", i, cmd, err)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	var all []error
	for err := range errs {
		all = append(all, err)
	}
	return errors.Join(all...)
}

// runStress runs the barrier commands against threads that trap often and
// threads that never trap. A barrier must wait for the first kind to leave the
// guest and must kick the second kind.
func runStress() bool {
	runtime.GOMAXPROCS(32)
	if _, err := membarrier(cmdRegisterPrivateExped, 0); err != nil {
		return report("stress", fmt.Errorf("REGISTER_PRIVATE_EXPEDITED: %w", err))
	}
	go func() {
		time.Sleep(stressWatchdog)
		fmt.Println("FAIL stress: the barriers did not finish in time")
		os.Exit(1)
	}()

	var stop atomic.Bool
	var background sync.WaitGroup
	// wake lists the write ends of the pipes. After stop is set, one byte on
	// each end releases a thread that waits in read(2) for its peer.
	var wake []int
	for range stressSyscallPairs {
		var ping, pong [2]int
		if err := syscall.Pipe(ping[:]); err != nil {
			return report("stress", fmt.Errorf("pipe: %w", err))
		}
		if err := syscall.Pipe(pong[:]); err != nil {
			return report("stress", fmt.Errorf("pipe: %w", err))
		}
		wake = append(wake, ping[1], pong[1])
		background.Add(2)
		go func() {
			defer background.Done()
			runtime.LockOSThread()
			pingPong(&stop, ping[1], pong[0], true)
		}()
		go func() {
			defer background.Done()
			runtime.LockOSThread()
			pingPong(&stop, pong[1], ping[0], false)
		}()
	}
	var counter atomic.Uint64
	for range stressSpinners {
		background.Add(1)
		go func() {
			defer background.Done()
			runtime.LockOSThread()
			for !stop.Load() {
				counter.Add(1)
			}
		}()
	}

	var callers sync.WaitGroup
	errs := make(chan error, stressCallers)
	for i := range stressCallers {
		callers.Add(1)
		go func() {
			defer callers.Done()
			runtime.LockOSThread()
			cmds := []int{cmdPrivateExpedited, cmdGlobal, cmdGlobalExpedited}
			for n := range stressBarriersPerCaller {
				if _, err := membarrier(cmds[(i+n)%len(cmds)], 0); err != nil {
					errs <- fmt.Errorf("caller %d barrier %d: %w", i, n, err)
					return
				}
			}
		}()
	}
	callers.Wait()
	close(errs)
	var all []error
	for err := range errs {
		all = append(all, err)
	}
	stop.Store(true)
	for _, fd := range wake {
		_, _ = syscall.Write(fd, []byte{0})
	}
	background.Wait()
	if len(all) == 0 && counter.Load() == 0 {
		all = append(all, errors.New("the threads that never trap made no progress"))
	}
	return report("stress", errors.Join(all...))
}

// pingPong writes one byte to out and reads one byte from in until stop is set.
// The side that starts writes first, so the pair never waits on itself.
func pingPong(stop *atomic.Bool, out, in int, first bool) {
	var b [1]byte
	if !first {
		if _, err := syscall.Read(in, b[:]); err != nil {
			return
		}
	}
	for !stop.Load() {
		if _, err := syscall.Write(out, b[:]); err != nil {
			return
		}
		if _, err := syscall.Read(in, b[:]); err != nil {
			return
		}
	}
}
