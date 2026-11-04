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

// Command cpumaxprobe checks the enforcement of cgroup v2 cpu.max in a guest.
// The program is the only process of the sandbox. It makes cgroups, starts
// busy-loop children in them, and compares the CPU time of the cgroup with the
// wall time. Each check prints "PASS name" or "FAIL name: reason".
//
// Usage:
//
//	cpumaxprobe checks   run the checks, then print DONE
//	cpumaxprobe spin     the busy-loop child: wait for a line on stdin, then
//	                     loop until the parent kills the process
package main

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	rootDir      = "/sys/fs/cgroup"
	probeDir     = rootDir + "/cpumaxprobe"
	childName    = "child"
	quotaWindow  = 5 * time.Second
	shortWindow  = 3 * time.Second
	tinyWindow   = 2 * time.Second
	resumeWindow = time.Second
	settle       = 300 * time.Millisecond
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: cpumaxprobe checks|spin")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "checks":
		ok := runChecks()
		fmt.Println("DONE")
		if !ok {
			os.Exit(1)
		}
	case "spin":
		spin()
	default:
		fmt.Fprintln(os.Stderr, "unknown command", os.Args[1])
		os.Exit(2)
	}
}

// spin waits for one line on stdin, so that the parent can move the process
// into a cgroup first, and then loops without a system call.
func spin() {
	var b [1]byte
	for {
		if _, err := os.Stdin.Read(b[:]); err != nil || b[0] == '\n' {
			break
		}
	}
	n := 0
	for {
		n++
	}
}

func runChecks() bool {
	checks := []struct {
		name string
		fn   func() error
	}{
		{"cpu-max-limits-busy-loop-to-half-cpu", checkHalfCPU},
		{"cpu-max-max-gives-full-cpu", checkUnlimited},
		{"cpu-max-of-parent-limits-child", checkParentLimit},
		{"cpu-max-quota-is-shared-by-all-tasks", checkSharedQuota},
		{"cpu-max-raised-to-max-resumes-task", checkRaisedToMax},
	}
	// The sandbox does not enable controllers for the children of the root
	// cgroup. The init script of docker:dind and of k3s does it, and so does
	// this write.
	if err := os.WriteFile(rootDir+"/cgroup.subtree_control", []byte("+cpu"), 0o644); err != nil {
		fmt.Printf("FAIL cpu-enable-controller: %v\n", err)
		return false
	}
	ok := true
	for _, c := range checks {
		if err := c.fn(); err != nil {
			fmt.Printf("FAIL %s: %v\n", c.name, err)
			ok = false
			continue
		}
		fmt.Printf("PASS %s\n", c.name)
	}
	return ok
}

// stat is one reading of cpu.stat.
type stat struct {
	usageUSec, nrPeriods, nrThrottled, throttledUSec uint64
	at                                               time.Time
}

func readStat(dir string) (stat, error) {
	data, err := os.ReadFile(dir + "/cpu.stat")
	if err != nil {
		return stat{}, err
	}
	s := stat{at: time.Now()}
	fields := map[string]*uint64{
		"usage_usec": &s.usageUSec, "nr_periods": &s.nrPeriods,
		"nr_throttled": &s.nrThrottled, "throttled_usec": &s.throttledUSec,
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, " ")
		dst := fields[key]
		if !ok || dst == nil {
			continue
		}
		if *dst, err = strconv.ParseUint(value, 10, 64); err != nil {
			return stat{}, fmt.Errorf("cpu.stat line %q: %w", line, err)
		}
		delete(fields, key)
	}
	if len(fields) != 0 {
		return stat{}, fmt.Errorf("cpu.stat lacks keys in:\n%s", data)
	}
	return s, nil
}

// window is the result of one measurement.
type window struct {
	// cpus is the CPU time of the cgroup divided by the wall time.
	cpus float64

	throttled, periods uint64
	throttledUSec      uint64
}

// measure reads cpu.stat of dir, waits for d, and reads it again.
func measure(dir string, d time.Duration) (window, error) {
	before, err := readStat(dir)
	if err != nil {
		return window{}, err
	}
	time.Sleep(d)
	after, err := readStat(dir)
	if err != nil {
		return window{}, err
	}
	wallUSec := float64(after.at.Sub(before.at).Microseconds())
	w := window{
		cpus:          float64(after.usageUSec-before.usageUSec) / wallUSec,
		throttled:     after.nrThrottled - before.nrThrottled,
		periods:       after.nrPeriods - before.nrPeriods,
		throttledUSec: after.throttledUSec - before.throttledUSec,
	}
	fmt.Printf("INFO %s: %.3f CPU over %.2f s, %d periods, %d throttles, %d us throttled\n",
		dir, w.cpus, wallUSec/1e6, w.periods, w.throttled, w.throttledUSec)
	return w, nil
}

// spinner is a busy-loop child process.
type spinner struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	done  chan struct{}
}

// startSpinner starts a busy-loop child, moves it into the cgroup dir, and
// lets it run.
func startSpinner(dir string) (*spinner, error) {
	cmd := exec.Command("/proc/self/exe", "spin")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	s := &spinner{cmd: cmd, stdin: stdin, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(s.done)
	}()
	procs := dir + "/cgroup.procs"
	if err := os.WriteFile(procs, []byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil {
		s.stop()
		return nil, fmt.Errorf("move the child into %s: %w", dir, err)
	}
	if _, err := io.WriteString(stdin, "\n"); err != nil {
		s.stop()
		return nil, err
	}
	return s, nil
}

// stop kills the child and waits until it ended.
func (s *spinner) stop() {
	_ = s.stdin.Close()
	_ = s.cmd.Process.Kill()
	select {
	case <-s.done:
	case <-time.After(30 * time.Second):
	}
}

// withCgroup makes the cgroup dir, runs fn, and removes the cgroup.
func withCgroup(dir string, fn func() error) error {
	if err := os.Mkdir(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	err := fn()
	if rmErr := os.Remove(dir); rmErr != nil {
		err = errors.Join(err, fmt.Errorf("remove %s: %w", dir, rmErr))
	}
	return err
}

func writeFile(dir, name, value string) error {
	if err := os.WriteFile(dir+"/"+name, []byte(value), 0o644); err != nil {
		return fmt.Errorf("write %q to %s/%s: %w", value, dir, name, err)
	}
	return nil
}

// runSpinners starts n children in dir, lets them settle, and measures dir over
// d. It stops the children before it returns.
func runSpinners(dir string, n int, d time.Duration) (window, error) {
	var started []*spinner
	defer func() {
		for _, s := range started {
			s.stop()
		}
	}()
	for range n {
		s, err := startSpinner(dir)
		if err != nil {
			return window{}, err
		}
		started = append(started, s)
	}
	time.Sleep(settle)
	return measure(dir, d)
}

func expectCPUs(w window, lo, hi float64) error {
	if w.cpus < lo || w.cpus > hi {
		return fmt.Errorf("the cgroup used %.3f CPU, want %.2f to %.2f (%d periods, %d throttles)", w.cpus, lo, hi, w.periods, w.throttled)
	}
	return nil
}

// checkHalfCPU is the check A14 of GVXIP-005: with cpu.max at 50000 100000,
// a busy loop uses 0.5 +- 0.1 CPU over 5 seconds, and nr_throttled grows.
func checkHalfCPU() error {
	return withCgroup(probeDir, func() error {
		if err := writeFile(probeDir, "cpu.max", "50000 100000"); err != nil {
			return err
		}
		w, err := runSpinners(probeDir, 1, quotaWindow)
		if err != nil {
			return err
		}
		if err := expectCPUs(w, 0.4, 0.6); err != nil {
			return err
		}
		if w.throttled == 0 || w.throttledUSec == 0 {
			return fmt.Errorf("nr_throttled grew by %d and throttled_usec by %d, want both to grow", w.throttled, w.throttledUSec)
		}
		return nil
	})
}

func checkUnlimited() error {
	return withCgroup(probeDir, func() error {
		if err := writeFile(probeDir, "cpu.max", "max 100000"); err != nil {
			return err
		}
		w, err := runSpinners(probeDir, 1, shortWindow)
		if err != nil {
			return err
		}
		// The Sentry bills a clock tick to each running thread that it samples,
		// so a Go child that has a second, mostly idle thread can pass 1.0.
		if err := expectCPUs(w, 0.8, math.Inf(1)); err != nil {
			return err
		}
		if w.throttled != 0 {
			return fmt.Errorf("nr_throttled grew by %d without a limit", w.throttled)
		}
		return nil
	})
}

// checkParentLimit limits the parent and leaves the child at max. A child
// obeys the limit of every ancestor, and only the parent counts the throttles.
func checkParentLimit() error {
	return withCgroup(probeDir, func() error {
		if err := writeFile(probeDir, "cpu.max", "50000 100000"); err != nil {
			return err
		}
		if err := writeFile(probeDir, "cgroup.subtree_control", "+cpu"); err != nil {
			return err
		}
		childDir := probeDir + "/" + childName
		err := withCgroup(childDir, func() error {
			if err := writeFile(childDir, "cpu.max", "max 100000"); err != nil {
				return err
			}
			before, err := readStat(probeDir)
			if err != nil {
				return err
			}
			w, err := runSpinners(childDir, 1, quotaWindow)
			if err != nil {
				return err
			}
			if err := expectCPUs(w, 0.4, 0.6); err != nil {
				return err
			}
			if w.throttled != 0 {
				return fmt.Errorf("the child counted %d throttles, but only its parent has a limit", w.throttled)
			}
			after, err := readStat(probeDir)
			if err != nil {
				return err
			}
			if after.nrThrottled == before.nrThrottled {
				return errors.New("nr_throttled of the parent did not grow")
			}
			return nil
		})
		return err
	})
}

// checkSharedQuota runs three loops in one cgroup with a quota of one CPU. The
// tasks use the quota together, so the cgroup uses one CPU and not three.
func checkSharedQuota() error {
	return withCgroup(probeDir, func() error {
		if err := writeFile(probeDir, "cpu.max", "100000 100000"); err != nil {
			return err
		}
		w, err := runSpinners(probeDir, 3, shortWindow)
		if err != nil {
			return err
		}
		return expectCPUs(w, 0.8, 1.2)
	})
}

// checkRaisedToMax holds a loop at 1% of a CPU, then writes max to cpu.max.
// The throttled loop must resume at once.
func checkRaisedToMax() error {
	return withCgroup(probeDir, func() error {
		if err := writeFile(probeDir, "cpu.max", "1000 100000"); err != nil {
			return err
		}
		s, err := startSpinner(probeDir)
		if err != nil {
			return err
		}
		defer s.stop()
		time.Sleep(settle)
		w, err := measure(probeDir, tinyWindow)
		if err != nil {
			return err
		}
		if err := expectCPUs(w, 0, 0.1); err != nil {
			return fmt.Errorf("with a quota of 1 ms: %w", err)
		}
		if err := writeFile(probeDir, "cpu.max", "max 100000"); err != nil {
			return err
		}
		// A task that the old limit held back must run again. A stall of
		// the host can lower one window, so the check passes when any of three
		// windows shows a full CPU. A task that stays held back fails all three.
		var last window
		for range 3 {
			time.Sleep(settle)
			if last, err = measure(probeDir, resumeWindow); err != nil {
				return err
			}
			if last.cpus >= 0.8 {
				return nil
			}
		}
		return fmt.Errorf("after the quota was lifted: %w", expectCPUs(last, 0.8, math.Inf(1)))
	})
}
