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

// Command microbench is a static guest program that measures the cost of the
// operations that decide how fast a backend feels: a cheap system call, a file
// open and close, a pipe round trip between two threads, a futex round trip
// between two threads, a fork, and a fork with exec. It prints one JSON line for
// each benchmark. The e2e test TestE2EMicroBench runs it on every backend and
// prints the results, so the backends can be compared with one program.
//
// The program uses raw system calls and locked threads, so each number counts
// the backend and not the Go scheduler.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// result is one line of output.
type result struct {
	Name    string  `json:"name"`
	Iters   int     `json:"iters"`
	TotalNs int64   `json:"total_ns"`
	NsPerOp float64 `json:"ns_per_op"`
}

// measure runs op with a growing count until one run takes at least minDur or
// reaches maxIters, and reports the last run. The runs before it warm the
// caches of the backend.
func measure(name string, minDur time.Duration, maxIters int, op func(n int) error) {
	n := 1
	for {
		start := time.Now()
		if err := op(n); err != nil {
			fmt.Printf("MICROBENCH_ERR %s: %v\n", name, err)
			return
		}
		elapsed := time.Since(start)
		if elapsed >= minDur || n >= maxIters {
			r := result{Name: name, Iters: n, TotalNs: elapsed.Nanoseconds(), NsPerOp: float64(elapsed.Nanoseconds()) / float64(n)}
			line, _ := json.Marshal(r)
			fmt.Printf("MICROBENCH %s\n", line)
			return
		}
		// Aim for minDur in the next run, with a factor of two at least and 16 at most.
		next := n * 2
		if elapsed > 0 {
			if want := int(float64(n) * float64(minDur) / float64(elapsed) * 1.2); want > next {
				next = min(want, n*16)
			}
		}
		n = min(next, maxIters)
	}
}

func getpid(n int) error {
	for range n {
		syscall.RawSyscall(syscall.SYS_GETPID, 0, 0, 0)
	}
	return nil
}

// openClose opens and closes one file. Each iteration makes two system calls.
func openClose(path string) func(n int) error {
	return func(n int) error {
		for range n {
			fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
			if err != nil {
				return err
			}
			if err := syscall.Close(fd); err != nil {
				return err
			}
		}
		return nil
	}
}

// pingPong runs fn on two threads that each own an OS thread, and waits for
// both.
func pingPong(a, b func() error) error {
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, fn := range []func() error{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			errs[i] = fn()
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// pipePingPong sends 64 bytes through one pipe and gets them back through
// another. One iteration is one round trip: two writes, two reads, and two
// switches between the threads.
func pipePingPong(n int) error {
	var p1, p2 [2]int
	if err := syscall.Pipe(p1[:]); err != nil {
		return err
	}
	if err := syscall.Pipe(p2[:]); err != nil {
		return err
	}
	defer func() {
		for _, fd := range append(p1[:], p2[:]...) {
			syscall.Close(fd)
		}
	}()
	msg := make([]byte, 64)
	return pingPong(
		func() error {
			buf := make([]byte, 64)
			for range n {
				if _, err := syscall.Write(p1[1], msg); err != nil {
					return err
				}
				if _, err := syscall.Read(p2[0], buf); err != nil {
					return err
				}
			}
			return nil
		},
		func() error {
			buf := make([]byte, 64)
			for range n {
				if _, err := syscall.Read(p1[0], buf); err != nil {
					return err
				}
				if _, err := syscall.Write(p2[1], buf); err != nil {
					return err
				}
			}
			return nil
		},
	)
}

const (
	futexWait = 128 // FUTEX_WAIT | FUTEX_PRIVATE_FLAG
	futexWake = 129 // FUTEX_WAKE | FUTEX_PRIVATE_FLAG
)

func futex(addr *uint32, op int, val uint32) {
	syscall.Syscall6(syscall.SYS_FUTEX, uintptr(unsafe.Pointer(addr)), uintptr(op), uintptr(val), 0, 0, 0)
}

// futexPingPong wakes a thread with FUTEX_WAKE, waits for the answer with
// FUTEX_WAIT, and repeats. One iteration is one round trip.
func futexPingPong(n int) error {
	var w [2]uint32
	return pingPong(
		func() error {
			for range n {
				atomic.StoreUint32(&w[0], 1)
				futex(&w[0], futexWake, 1)
				for atomic.LoadUint32(&w[1]) == 0 {
					futex(&w[1], futexWait, 0)
				}
				atomic.StoreUint32(&w[1], 0)
			}
			return nil
		},
		func() error {
			for range n {
				for atomic.LoadUint32(&w[0]) == 0 {
					futex(&w[0], futexWait, 0)
				}
				atomic.StoreUint32(&w[0], 0)
				atomic.StoreUint32(&w[1], 1)
				futex(&w[1], futexWake, 1)
			}
			return nil
		},
	)
}

// forkExit makes a copy of the process that exits at once. The child runs no
// Go code beyond the return of the system call, so it needs neither the
// scheduler nor the garbage collector.
//
//go:nosplit
func forkExit() (pid uintptr, errno syscall.Errno) {
	pid, _, errno = syscall.RawSyscall(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD), 0, 0)
	if errno == 0 && pid == 0 {
		for {
			syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 0, 0, 0)
		}
	}
	return pid, errno
}

func wait(pid int) error {
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		return err
	}
	if !ws.Exited() || ws.ExitStatus() != 0 {
		return fmt.Errorf("child status %v", ws)
	}
	return nil
}

// forkWait forks a child that exits and waits for it.
func forkWait(n int) error {
	for range n {
		pid, errno := forkExit()
		if errno != 0 {
			return errno
		}
		if err := wait(int(pid)); err != nil {
			return err
		}
	}
	return nil
}

// forkExecTrue starts the executable at path, which exits with status 0 at
// once, and waits for it.
func forkExecTrue(path string) func(n int) error {
	return func(n int) error {
		for range n {
			pid, err := syscall.ForkExec(path, []string{path}, &syscall.ProcAttr{})
			if err != nil {
				return err
			}
			if err := wait(pid); err != nil {
				return err
			}
		}
		return nil
	}
}

// scratchDir returns a directory that the guest can write.
func scratchDir() string {
	for _, d := range []string{"/tmp", "/dev/shm", "/workspace"} {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			probe := d + "/mb.probe"
			if f, err := os.Create(probe); err == nil {
				f.Close()
				os.Remove(probe)
				return d
			}
		}
	}
	return ""
}

func main() {
	fmt.Printf("MICROBENCH_INFO {\"gomaxprocs\":%d,\"numcpu\":%d,\"arch\":%q,\"args\":%q}\n", runtime.GOMAXPROCS(0), runtime.NumCPU(), runtime.GOARCH, os.Args)
	want := map[string]bool{}
	for _, a := range os.Args[1:] {
		want[a] = true
	}
	run := func(name string) bool { return len(want) == 0 || want[name] }

	dir := scratchDir()
	var dataFile, trueFile string
	if dir != "" {
		dataFile = dir + "/mb.dat"
		trueFile = dir + "/mbtrue"
		if err := os.WriteFile(dataFile, []byte("x"), 0o644); err != nil {
			fmt.Printf("MICROBENCH_ERR setup: %v\n", err)
			dataFile = ""
		}
		if err := os.WriteFile(trueFile, trueELF(), 0o755); err != nil {
			fmt.Printf("MICROBENCH_ERR setup: %v\n", err)
			trueFile = ""
		}
	}

	if run("getpid") {
		measure("getpid", 400*time.Millisecond, 5_000_000, getpid)
	}
	if run("open_close") && dataFile != "" {
		measure("open_close", 400*time.Millisecond, 1_000_000, openClose(dataFile))
	}
	if run("pipe_pingpong") {
		measure("pipe_pingpong", 600*time.Millisecond, 500_000, pipePingPong)
	}
	if run("futex_pingpong") {
		measure("futex_pingpong", 600*time.Millisecond, 500_000, futexPingPong)
	}
	if run("fork_wait") {
		measure("fork_wait", 1500*time.Millisecond, 400, forkWait)
	}
	if run("fork_exec_true") && trueFile != "" {
		measure("fork_exec_true", 1500*time.Millisecond, 400, forkExecTrue(trueFile))
	}
}
