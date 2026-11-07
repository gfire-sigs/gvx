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
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// churnWorkers is the number of threads that rewrite and run code. Each
	// owns one code page between two neighbor pages.
	churnWorkers = 4
	// churnRounds is the number of rewrites of each worker.
	churnRounds = 50
	// churnRemapEvery is the number of rounds between two rounds in which a
	// worker unmaps its code page and maps a new one at the same address.
	churnRemapEvery = 4
	// churnSwaps is the number of times that the swapper replaces the page that
	// the runner executes.
	churnSwaps = 60
	// churnRunnerVersion is the version of the code that the runner executes.
	// Both frames that the swapper maps hold this version.
	churnRunnerVersion = 5
	// churnWatchdog is the time after which the check reports a failure.
	churnWatchdog = time.Minute
	// maxCodeVersion is the largest version that codeSyscall accepts on every
	// architecture. The immediate of the arm64 instruction ADD sets the limit.
	maxCodeVersion = 4095
	// churnName is the name of the check in the messages of the program.
	churnName = "code-churn-threads"
	// churnThreads is the number of threads of the check: the workers, two
	// churners, the runner, and the swapper.
	churnThreads = churnWorkers + 4
)

// churnRegion is an address range with 3 pages for each worker (a neighbor
// page, the code page of the worker, and a neighbor page) and a last page that
// the runner executes.
type churnRegion struct {
	mem      []byte
	pageSize int
}

func newChurnRegion() (*churnRegion, error) {
	ps := syscall.Getpagesize()
	mem, err := syscall.Mmap(-1, 0, (3*churnWorkers+1)*ps, syscall.PROT_NONE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		return nil, fmt.Errorf("mmap the region: %w", err)
	}
	return &churnRegion{mem: mem, pageSize: ps}, nil
}

// runnerPage is the index of the page that the runner executes.
const runnerPage = 3 * churnWorkers

// page returns page i of the region.
func (r *churnRegion) page(i int) []byte {
	return r.mem[i*r.pageSize : (i+1)*r.pageSize : (i+1)*r.pageSize]
}

// prot sets the protection of page i.
func (r *churnRegion) prot(i, prot int) error {
	return syscall.Mprotect(r.page(i), prot)
}

// mapFixed maps a page at the address of page i, over what is there. With
// fd -1 the page is anonymous and private. Otherwise it is page 0 of the file.
// The call goes to the kernel directly. The syscall package has no call for a
// fixed address, and its Munmap accepts only a whole mapping.
func (r *churnRegion) mapFixed(i, prot, fd int) error {
	p := r.page(i)
	flags := syscall.MAP_PRIVATE | syscall.MAP_ANON | syscall.MAP_FIXED
	if fd >= 0 {
		flags = syscall.MAP_SHARED | syscall.MAP_FIXED
	}
	got, _, errno := syscall.Syscall6(syscall.SYS_MMAP, addr(p), uintptr(len(p)), uintptr(prot),
		uintptr(flags), uintptr(fd), 0)
	if errno != 0 {
		return fmt.Errorf("mmap at the address of page %d: %w", i, errno)
	}
	if got != addr(p) {
		return fmt.Errorf("mmap with MAP_FIXED returned %#x, want %#x", got, addr(p))
	}
	return nil
}

// remap replaces page i with a new anonymous page at the same address, after it
// unmaps the old page.
func (r *churnRegion) remap(i, prot int) error {
	p := r.page(i)
	if _, _, errno := syscall.Syscall(syscall.SYS_MUNMAP, addr(p), uintptr(len(p)), 0); errno != 0 {
		return fmt.Errorf("munmap: %w", errno)
	}
	return r.mapFixed(i, prot, -1)
}

// store writes the code for version v into page i, which must be writable, and
// makes the instruction fetches see it.
func (r *churnRegion) store(i int, v uint32) {
	p := r.page(i)
	code := codeSyscall(v)
	copy(p, code)
	syncICache(addr(p), len(code))
}

// call runs the code of page i, which must be executable, and verifies the
// result. The expected result comes from the kernel of the program, not from the
// code that runs.
func (r *churnRegion) call(i int, v uint32, what string) error {
	got := callCode(addr(r.page(i)), 0)
	if wantResult := uint32(os.Getpid()) + v; got != wantResult {
		return fmt.Errorf("%s: the code of version %d returned %d, want %d", what, v, got, wantResult)
	}
	return nil
}

// worker rewrites and runs the code page of worker w. It toggles the page
// between writable and executable, and it maps a new page at the same address
// in every churnRemapEvery rounds.
func (r *churnRegion) worker(w int, ready <-chan struct{}) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	<-ready
	code := 3*w + 1
	for round := range churnRounds {
		v := uint32(100*w + round + 1)
		what := fmt.Sprintf("worker %d round %d", w, round)
		if round%churnRemapEvery == churnRemapEvery-1 {
			if err := r.remap(code, protRW); err != nil {
				return fmt.Errorf("%s: %w", what, err)
			}
		} else if err := r.prot(code, protRW); err != nil {
			return fmt.Errorf("%s: mprotect RW: %w", what, err)
		}
		r.store(code, v)
		if err := r.prot(code, protRX); err != nil {
			return fmt.Errorf("%s: mprotect RX: %w", what, err)
		}
		if err := r.call(code, v, what); err != nil {
			return err
		}
	}
	return nil
}

// churner changes the neighbor pages of the code pages until stop closes, and
// returns the number of passes. It calls warm after its first pass. Each pass
// of kind 0 makes the lower neighbor of each worker writable, runs code in it,
// and takes its permissions away. Each pass of kind 1 unmaps the upper neighbor
// of each worker, maps a new page at its address, and runs code in it.
func (r *churnRegion) churner(kind int, stop <-chan struct{}, warm func()) (int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for pass := uint32(0); ; pass++ {
		version := pass%maxCodeVersion + 1
		for w := range churnWorkers {
			select {
			case <-stop:
				return int(pass), nil
			default:
			}
			page := 3*w + 2*kind
			what := fmt.Sprintf("churner %d page %d pass %d", kind, page, pass)
			if kind == 0 {
				if err := r.prot(page, protRW); err != nil {
					return int(pass), fmt.Errorf("%s: mprotect RW: %w", what, err)
				}
				r.store(page, version)
				if err := r.prot(page, protRX); err != nil {
					return int(pass), fmt.Errorf("%s: mprotect RX: %w", what, err)
				}
				if err := r.call(page, version, what); err != nil {
					return int(pass), err
				}
				if err := r.prot(page, syscall.PROT_NONE); err != nil {
					return int(pass), fmt.Errorf("%s: mprotect NONE: %w", what, err)
				}
				continue
			}
			if err := r.remap(page, protRW); err != nil {
				return int(pass), fmt.Errorf("%s: %w", what, err)
			}
			r.store(page, version)
			if err := r.prot(page, protRX); err != nil {
				return int(pass), fmt.Errorf("%s: mprotect RX: %w", what, err)
			}
			if err := r.call(page, version, what); err != nil {
				return int(pass), err
			}
		}
		if pass == 0 {
			warm()
		}
	}
}

// codeFrame is a page of a memfd that holds the code of the runner.
type codeFrame struct {
	rw, rx []byte
	fd     int
}

func newCodeFrame() (*codeFrame, error) {
	rw, rx, fd, err := sharedViews()
	if err != nil {
		return nil, err
	}
	copy(rw, codeSyscall(churnRunnerVersion))
	syncICache(addr(rx), len(rx))
	return &codeFrame{rw, rx, fd}, nil
}

func (f *codeFrame) close() { unmapViews(f.rw, f.rx, f.fd) }

// swapper replaces the page that the runner executes, churnSwaps times, with a
// mapping of one of two frames that hold the same code. The runner executes the
// page all the time, so every replacement happens under a running thread, as
// the replacement of the mapping of a program does. Linux replaces the mapping
// at once, so the runner always sees one of the two copies of the code.
func (r *churnRegion) swapper(frames [2]*codeFrame, running <-chan struct{}, done *atomic.Bool) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer done.Store(true)
	<-running
	for i := range churnSwaps {
		if err := r.mapFixed(runnerPage, protRX, frames[i%2].fd); err != nil {
			return fmt.Errorf("swapper pass %d: %w", i, err)
		}
		if err := r.prot(runnerPage, protRX); err != nil {
			return fmt.Errorf("swapper pass %d: mprotect RX: %w", i, err)
		}
	}
	return nil
}

// runner executes the code of the runner page until done is set, and returns
// the number of runs. It closes running after its first run, or when it fails.
func (r *churnRegion) runner(running chan<- struct{}, done *atomic.Bool) (int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var once sync.Once
	defer once.Do(func() { close(running) })
	runs := 0
	for !done.Load() {
		if err := r.call(runnerPage, churnRunnerVersion, "runner"); err != nil {
			return runs, err
		}
		runs++
		once.Do(func() { close(running) })
	}
	return runs, nil
}

// checkCodeChurn rewrites and runs code from several threads at once. Two
// churners change the pages beside the code pages. A swapper replaces the page
// that a runner executes. The code calls getpid, so an engine that patches
// system call instructions has to patch and unpatch them while neighbors change
// permissions and addresses, and while a mapping goes away under a running
// thread. Every run must return the result of the latest version of the code.
func checkCodeChurn() error {
	// A thread that waits for a lock or runs generated code holds a P. Keep
	// free Ps for the watchdog and for the goroutines that have not started.
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(churnThreads + 2))
	r, err := newChurnRegion()
	if err != nil {
		return err
	}
	defer syscall.Munmap(r.mem)
	var frames [2]*codeFrame
	for i := range frames {
		if frames[i], err = newCodeFrame(); err != nil {
			return err
		}
		defer frames[i].close()
	}
	if err := r.mapFixed(runnerPage, protRX, frames[0].fd); err != nil {
		return err
	}
	watchdog := time.AfterFunc(churnWatchdog, func() {
		fmt.Printf("FAIL %s: the threads did not end within %v\n", churnName, churnWatchdog)
		os.Exit(1)
	})
	defer watchdog.Stop()

	start := time.Now()
	stop := make(chan struct{})
	ready := make(chan struct{})
	var warm sync.WaitGroup
	warm.Add(2)
	var done atomic.Bool
	running := make(chan struct{})
	var workers, others sync.WaitGroup
	errs := make([]error, churnThreads)
	passes := make([]int, 2)
	var runs int
	for w := range churnWorkers {
		workers.Add(1)
		go func() {
			defer workers.Done()
			errs[w] = r.worker(w, ready)
		}()
	}
	for kind := range 2 {
		others.Add(1)
		go func() {
			defer others.Done()
			var once sync.Once
			// A churner that fails before its first pass still releases the
			// workers, so that the check ends.
			warmUp := func() { once.Do(warm.Done) }
			defer warmUp()
			passes[kind], errs[churnWorkers+kind] = r.churner(kind, stop, warmUp)
		}()
	}
	others.Add(2)
	go func() {
		defer others.Done()
		runs, errs[churnWorkers+2] = r.runner(running, &done)
	}()
	go func() {
		defer others.Done()
		errs[churnWorkers+3] = r.swapper(frames, running, &done)
	}()
	// The workers start when both churners finished a pass, so that the
	// threads overlap.
	warm.Wait()
	close(ready)
	workers.Wait()
	close(stop)
	others.Wait()
	fmt.Printf("INFO %s: %d rewrites, %d and %d churner passes, %d runs, in %v\n", churnName,
		churnWorkers*churnRounds, passes[0], passes[1], runs, time.Since(start).Round(time.Millisecond))
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if runs == 0 || passes[0] == 0 || passes[1] == 0 {
		return fmt.Errorf("the threads did not overlap: %d runs, %d and %d churner passes", runs, passes[0], passes[1])
	}
	return nil
}
