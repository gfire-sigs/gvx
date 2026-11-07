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

package main

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"slices"
	"sync"
	"syscall"
	"time"
)

const (
	// toggleCallers is the number of threads that run the text of the program
	// while a toggler changes its protection.
	toggleCallers = 4
	// toggleRounds is the number of RWX and RX changes of the toggler.
	toggleRounds = 400
	// toggleWatchdog is the time after which the check reports a failure.
	toggleWatchdog = time.Minute
	// toggleName is the name of the check in the messages of the program.
	toggleName = "code-text-toggle"
)

// textPages returns the pages that hold the system call functions of the
// program: the pages that its threads run all the time.
func textPages() []uintptr {
	size := uintptr(syscall.Getpagesize())
	var pages []uintptr
	for _, fn := range []any{syscall.Syscall, syscall.RawSyscall, syscall.Getpid} {
		page := reflect.ValueOf(fn).Pointer() &^ (size - 1)
		if !slices.Contains(pages, page) {
			pages = append(pages, page)
		}
	}
	return pages
}

// fileBytes returns the bytes that the executable file holds for the pages of
// pages, in the same order. A thread that stores them back into the pages
// writes the value that is there, whatever a read of the page returns. A
// guest kernel that runs patched copies of the code can return patched bytes
// to a load, so the check does not load the bytes from the pages.
func fileBytes(pages []uintptr) ([][]byte, error) {
	f, err := elf.Open("/proc/self/exe")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	size := uintptr(syscall.Getpagesize())
	out := make([][]byte, len(pages))
	for i, page := range pages {
		for _, p := range f.Progs {
			if p.Type != elf.PT_LOAD || uint64(page) < p.Vaddr || uint64(page)+uint64(size) > p.Vaddr+p.Filesz {
				continue
			}
			out[i] = make([]byte, size)
			if _, err := p.ReadAt(out[i], int64(uint64(page)-p.Vaddr)); err != nil {
				return nil, fmt.Errorf("read the file bytes of page %#x: %w", page, err)
			}
			break
		}
		if out[i] == nil {
			return nil, fmt.Errorf("no loaded segment of the executable holds page %#x", page)
		}
	}
	return out, nil
}

// textToggler makes each page of pages writable and executable, stores one
// byte into the page, and makes the page executable only, toggleRounds times.
// The stored value is the byte that the file holds, which equals the byte of
// the page, so Linux leaves the memory as it was. The position of the byte
// moves through the page from round to round. It returns the number of rounds
// that ran.
func textToggler(pages []uintptr, files [][]byte, stop <-chan struct{}) (int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	size := uintptr(syscall.Getpagesize())
	for round := range toggleRounds {
		select {
		case <-stop:
			return round, nil
		default:
		}
		off := uintptr(round) * 61 % size
		for i, page := range pages {
			if _, _, errno := syscall.Syscall(syscall.SYS_MPROTECT, page, size, protRWX); errno != 0 {
				return round, fmt.Errorf("toggler: mprotect %#x RWX: %w", page, errno)
			}
			storeByte(page+off, files[i][off])
			if _, _, errno := syscall.Syscall(syscall.SYS_MPROTECT, page, size, protRX); errno != 0 {
				return round, fmt.Errorf("toggler: mprotect %#x RX: %w", page, errno)
			}
		}
	}
	return toggleRounds, nil
}

// textCaller runs system calls through the functions of the program until stop
// closes, and it verifies each result against the process ID. It returns the
// number of calls.
func textCaller(pid int, stop <-chan struct{}) (int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	calls := 0
	for {
		select {
		case <-stop:
			return calls, nil
		default:
		}
		if got := syscall.Getpid(); got != pid {
			return calls, fmt.Errorf("Getpid returned %d, want %d", got, pid)
		}
		if got, _, errno := syscall.RawSyscall(syscall.SYS_GETPID, 0, 0, 0); errno != 0 || int(got) != pid {
			return calls, fmt.Errorf("RawSyscall(getpid) returned %d, errno %v, want %d", got, errno, pid)
		}
		if got, _, errno := syscall.Syscall(syscall.SYS_GETPID, 0, 0, 0); errno != 0 || int(got) != pid {
			return calls, fmt.Errorf("Syscall(getpid) returned %d, errno %v, want %d", got, errno, pid)
		}
		calls++
	}
}

// checkTextToggle makes the pages that hold the system call functions of the
// program writable and executable, writes a byte back to itself, and makes the
// pages executable only, while other threads call those functions. Linux
// leaves the code as it was, so every call must return the process ID. An
// engine that patches system call instructions must keep the threads that run
// the patched code safe when it drops and patches the code again.
func checkTextToggle() error {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(toggleCallers + 3))
	watchdog := time.AfterFunc(toggleWatchdog, func() {
		fmt.Printf("FAIL %s: the threads did not end within %v\n", toggleName, toggleWatchdog)
		os.Exit(1)
	})
	defer watchdog.Stop()
	pid := os.Getpid()
	pages := textPages()
	files, err := fileBytes(pages)
	if err != nil {
		return err
	}
	stop := make(chan struct{})
	var callers sync.WaitGroup
	errs := make([]error, toggleCallers+1)
	calls := make([]int, toggleCallers)
	for c := range toggleCallers {
		callers.Add(1)
		go func() {
			defer callers.Done()
			calls[c], errs[c] = textCaller(pid, stop)
		}()
	}
	start := time.Now()
	rounds, err := textToggler(pages, files, stop)
	errs[toggleCallers] = err
	close(stop)
	callers.Wait()
	total := 0
	for _, n := range calls {
		total += n
	}
	fmt.Printf("INFO %s: %d rounds on %d pages, %d calls, in %v\n", toggleName, rounds, len(pages), total, time.Since(start).Round(time.Millisecond))
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if total == 0 {
		return errors.New("no thread called a function while the toggler ran")
	}
	return nil
}
