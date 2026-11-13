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
//	cpumaxprobe checks [NAME...]
//	                     run the checks, then print DONE. With names, the
//	                     program runs only the checks of those names.
//	cpumaxprobe spin [clock]
//	                     the busy-loop child: wait for a line on stdin, then
//	                     loop until the parent kills the process. The child
//	                     prints its loop count on stdout after each 2^24 turns.
//	                     With clock, the child prints instead the time in
//	                     microseconds in which it ran, after each 2 ms of it.
//	                     A gap of 2 ms or more between two readings of the
//	                     clock is time in which the child did not run.
package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	rootDir     = "/sys/fs/cgroup"
	probeDir    = rootDir + "/cpumaxprobe"
	siblingDir  = rootDir + "/cpumaxprobe2"
	childName   = "child"
	quotaWindow = 5 * time.Second
	shortWindow = 3 * time.Second
	settle      = 300 * time.Millisecond

	// clockGap is the gap between two readings of the clock that a running
	// clock loop never reaches. A longer gap is time without a run.
	clockGap = 2 * time.Millisecond

	// clockReport is the running time between two reports of a clock loop.
	clockReport = 2 * time.Millisecond

	// minRanShare and maxRanShare bound the time in which a throttled clock
	// loop runs, as a share of the time that the cgroup bills for it.
	minRanShare = 0.75
	maxRanShare = 1.2

	// startLimit is the time that a busy-loop child has to report its first
	// loop count after it started.
	startLimit = 30 * time.Second

	// resumeLimit bounds how long a released task may take to accumulate resumeCPU.
	// A task still throttled at 1 ms/s uses at most ~5 ms across 5 seconds.
	resumeLimit = 5 * time.Second
	// resumeCPU is the CPU time that proves the task was unthrottled.
	resumeCPU = 30 * time.Millisecond
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: cpumaxprobe checks|spin")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "checks":
		ok := runChecks(os.Args[2:])
		fmt.Println("DONE")
		if !ok {
			os.Exit(1)
		}
	case "spin":
		switch {
		case len(os.Args) == 2:
			spin()
		case len(os.Args) == 3 && os.Args[2] == "clock":
			spinClock()
		default:
			fmt.Fprintln(os.Stderr, "unknown arguments", os.Args[2:])
			os.Exit(2)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown command", os.Args[1])
		os.Exit(2)
	}
}

// spin waits for one line on stdin, so that the parent can move the process
// into a cgroup first. It then counts without a system call, and it reports the
// count on stdout after each 2^24 turns. The count measures the progress of the
// process independently of the CPU time that the Sentry bills.
func spin() {
	waitStart()
	var n uint64
	for {
		n++
		if n&(1<<24-1) == 0 {
			os.Stdout.WriteString(strconv.FormatUint(n, 10) + "\n")
		}
	}
}

// spinClock waits for the start line, like spin. It then reads the clock after
// each 2^16 turns and adds each gap below clockGap to its running time. It
// prints the running time in microseconds after each clockReport. The running
// time uses the clock of the guest, so it does not depend on the speed of the
// host CPU. A task that the Sentry holds back reads one long gap.
func spinClock() {
	waitStart()
	var n uint64
	var ran, reported time.Duration
	last := time.Now()
	for {
		n++
		if n&(1<<16-1) != 0 {
			continue
		}
		now := time.Now()
		if gap := now.Sub(last); gap < clockGap {
			ran += gap
		}
		last = now
		if ran-reported >= clockReport {
			reported = ran
			os.Stdout.WriteString(strconv.FormatInt(ran.Microseconds(), 10) + "\n")
		}
	}
}

// waitStart waits for one line on stdin, so that the parent can move the
// process into a cgroup first.
func waitStart() {
	var b [1]byte
	for {
		if _, err := os.Stdin.Read(b[:]); err != nil || b[0] == '\n' {
			return
		}
	}
}

// check is one named check.
type check struct {
	name string
	fn   func() error
}

func runChecks(only []string) bool {
	checks := []check{
		{"cpu-max-limits-busy-loop-to-half-cpu", checkHalfCPU},
		{"cpu-max-max-gives-one-cpu-to-one-thread", checkUnlimited},
		{"cpu-max-of-parent-limits-child", checkParentLimit},
		{"cpu-max-quota-is-shared-by-all-tasks", checkSharedQuota},
		{"cpu-max-above-demand-never-throttles-one-thread", checkQuotaAboveDemand},
		{"cpu-max-small-quota-bills-and-delivers-the-same-time", checkSmallQuota},
		{"cpu-max-raised-to-max-resumes-task", checkRaisedToMax},
		{"cpu-max-moving-task-to-free-cgroup-resumes-it", checkMigration},
		{"cpu-max-disabling-controller-resumes-task", checkDisableController},
		{"cpu-max-limits-loop-without-system-calls", checkNoSyscallLoop},
		{"cpu-stat-usage-of-parent-includes-children", checkHierarchicalUsage},
		{"cpu-stat-usage-of-parent-keeps-removed-children", checkRemovedChildUsage},
		{"memory-stat-exists-at-root", checkRootMemoryStat},
	}
	// The sandbox does not enable controllers for the children of the root
	// cgroup. The init script of docker:dind and of k3s does it, and so does
	// this write.
	if err := os.WriteFile(rootDir+"/cgroup.subtree_control", []byte("+cpu"), 0o644); err != nil {
		fmt.Printf("FAIL cpu-enable-controller: %v\n", err)
		return false
	}
	for _, name := range only {
		if !slices.ContainsFunc(checks, func(c check) bool { return c.name == name }) {
			fmt.Printf("FAIL unknown-check: no check named %q\n", name)
			return false
		}
	}
	ok := true
	for _, c := range checks {
		if len(only) > 0 && !slices.Contains(only, c.name) {
			continue
		}
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
	var (
		data []byte
		err  error
		at   time.Time
	)
	for attempt := range 5 {
		t0 := time.Now()
		data, err = os.ReadFile(dir + "/cpu.stat")
		t1 := time.Now()
		if err != nil {
			return stat{}, err
		}
		at = t0.Add(t1.Sub(t0) / 2)
		if t1.Sub(t0) <= 20*time.Millisecond || attempt == 4 {
			break
		}
	}
	s := stat{at: at}
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

	// progress is the growth of the count that the spinner reports, for each
	// second. A plain spinner reports loop counts, and a clock spinner reports
	// microseconds of running time.
	progress float64

	throttled, periods uint64
	throttledUSec      uint64

	// wall is the length of the window.
	wall time.Duration
}

// measure reads cpu.stat of dir and the loop count of sp, waits for d, and
// reads both again. The spinner sp can be nil.
func measure(dir string, sp *spinner, d time.Duration) (window, error) {
	before, err := readStat(dir)
	if err != nil {
		return window{}, err
	}
	var count0 uint64
	if sp != nil {
		count0 = sp.count.Load()
	}
	time.Sleep(d)
	after, err := readStat(dir)
	if err != nil {
		return window{}, err
	}
	wall := after.at.Sub(before.at)
	w := window{
		wall:          wall,
		cpus:          float64(after.usageUSec-before.usageUSec) / float64(wall.Microseconds()),
		throttled:     after.nrThrottled - before.nrThrottled,
		periods:       after.nrPeriods - before.nrPeriods,
		throttledUSec: after.throttledUSec - before.throttledUSec,
	}
	if sp != nil {
		w.progress = float64(sp.count.Load()-count0) / wall.Seconds()
	}
	fmt.Printf("INFO %s: %.3f CPU over %.2f s, %.0f progress/s, %d periods, %d throttles, %d us throttled\n",
		dir, w.cpus, wall.Seconds(), w.progress, w.periods, w.throttled, w.throttledUSec)
	return w, nil
}

// waitCPU polls cpu.stat of dir until the cgroup used want more CPU time than
// at the call, and it fails after limit.
func waitCPU(dir string, want, limit time.Duration) error {
	before, err := readStat(dir)
	if err != nil {
		return err
	}
	for {
		time.Sleep(10 * time.Millisecond)
		now, err := readStat(dir)
		if err != nil {
			return err
		}
		if used := time.Duration(now.usageUSec-before.usageUSec) * time.Microsecond; used >= want {
			fmt.Printf("INFO %s: %v of CPU after %v\n", dir, used, now.at.Sub(before.at).Round(time.Millisecond))
			return nil
		}
		if now.at.Sub(before.at) > limit {
			return fmt.Errorf("%s used %v of CPU in %v, want %v", dir,
				time.Duration(now.usageUSec-before.usageUSec)*time.Microsecond, limit, want)
		}
	}
}

// spinner is a busy-loop child process.
type spinner struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	done  chan struct{}

	// count is the last count that the child reported.
	count atomic.Uint64
}

// startSpinner starts a busy-loop child, moves it into the cgroup dir, and
// lets it run. The arguments follow "spin" on the command line of the child.
func startSpinner(dir string, args ...string) (*spinner, error) {
	cmd := exec.Command("/proc/self/exe", append([]string{"spin"}, args...)...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	s := &spinner{cmd: cmd, stdin: stdin, done: make(chan struct{})}
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if n, err := strconv.ParseUint(sc.Text(), 10, 64); err == nil {
				s.count.Store(n)
			}
		}
		_ = cmd.Wait()
		close(s.done)
	}()
	if err := moveTo(dir, cmd.Process.Pid); err != nil {
		s.stop()
		return nil, err
	}
	if _, err := io.WriteString(stdin, "\n"); err != nil {
		s.stop()
		return nil, err
	}
	return s, nil
}

func moveTo(dir string, pid int) error {
	if err := os.WriteFile(dir+"/cgroup.procs", []byte(strconv.Itoa(pid)), 0o644); err != nil {
		return fmt.Errorf("move process %d into %s: %w", pid, dir, err)
	}
	return nil
}

// waitProgress waits until the child reported a count, and it fails after
// limit.
func (s *spinner) waitProgress(limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for s.count.Load() == 0 {
		if time.Now().After(deadline) {
			return fmt.Errorf("a child made no progress in %v after it started", limit)
		}
		time.Sleep(5 * time.Millisecond)
	}
	return nil
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
	// A child can take seconds to start on a loaded host. The window opens
	// only after each child has reported its first loop count.
	for _, s := range started {
		if err := s.waitProgress(startLimit); err != nil {
			return window{}, err
		}
	}
	time.Sleep(settle)
	var first *spinner
	if n == 1 {
		first = started[0]
	}
	return measure(dir, first, d)
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

// checkUnlimited runs one busy thread without a limit. The thread is alone in
// the cgroup, because the loop program has no runtime and no helper threads.
// The Sentry bills the wall time of each run of a task. One thread therefore
// cannot read more than the wall time.
//
// A Go child has a monitor thread that wakes many times each second. The Sentry
// bills each wake-up for the time that the host takes to run it. That sum read
// 1.15 CPU on a Windows runner and 1.5 CPU on a loaded macOS host. It is not
// the usage of the busy thread.
func checkUnlimited() error {
	return withCgroup(probeDir, func() error {
		if err := writeFile(probeDir, "cpu.max", "max 100000"); err != nil {
			return err
		}
		w, err := runLoop(probeDir, shortWindow)
		if err != nil {
			return err
		}
		if err := expectCPUs(w, 0.95, 1.02); err != nil {
			return err
		}
		if w.throttled != 0 {
			return fmt.Errorf("nr_throttled grew by %d without a limit", w.throttled)
		}
		return nil
	})
}

// checkQuotaAboveDemand gives one busy thread 1.3 CPUs. The thread is alone in
// the cgroup, so its usage cannot pass 1 CPU and the cgroup never throttles. A
// charge above 1.4 CPU in each period would throttle it, so a double charge
// fails this check. The 0.1 CPU is the debt that the Sentry tolerates.
//
// A Go program has helper threads, and the Sentry bills each wake-up of those
// threads for the time that the host takes to run it. A stall of a Windows
// runner billed such a program 1.17 CPU in 3 seconds. One period then ended in
// debt of more than 10 ms. A Go program cannot show the rule of this check.
func checkQuotaAboveDemand() error {
	return withCgroup(probeDir, func() error {
		if err := writeFile(probeDir, "cpu.max", "130000 100000"); err != nil {
			return err
		}
		w, err := runLoop(probeDir, shortWindow)
		if err != nil {
			return err
		}
		if err := expectCPUs(w, 0.95, 1.02); err != nil {
			return err
		}
		if w.throttled != 0 {
			return fmt.Errorf("nr_throttled grew by %d for one thread below its quota", w.throttled)
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
		return withCgroup(childDir, func() error {
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

// checkSmallQuota gives one thread a tenth of a CPU. The Sentry must bill a
// tenth of a CPU, hold the thread back for the rest of each period, and run the
// thread for the time that it bills.
//
// The thread is a clock loop. It measures the time in which it runs with the
// clock of the guest, so the result does not depend on the speed of the host
// CPU. A comparison of loop counts did: a native loop that runs 10 ms and
// sleeps 90 ms makes 0.02 of the iterations of a loop that never sleeps on an
// Apple CPU. A reference loop with the same duty cycle made about half of the
// expected progress in two Windows runs. The cause is probably a change in the
// speed of the runner between two windows.
func checkSmallQuota() error {
	return withCgroup(probeDir, func() error {
		if err := writeFile(probeDir, "cpu.max", "10000 100000"); err != nil {
			return err
		}
		s, err := startSpinner(probeDir, "clock")
		if err != nil {
			return err
		}
		defer s.stop()
		if err := s.waitProgress(startLimit); err != nil {
			return err
		}
		time.Sleep(time.Second)
		var lastErr error
		for attempt := range 3 {
			w, err := measure(probeDir, s, quotaWindow)
			if err != nil {
				return err
			}
			// The clock loop reports microseconds, so the progress is microseconds
			// of running time for each second of wall time.
			ran := w.progress / 1e6
			fmt.Printf("INFO attempt %d: the clock loop ran %.3f of the wall time, %.3f of the billed time\n",
				attempt+1, ran, ran/w.cpus)
			if err := expectCPUs(w, 0.07, 0.13); err != nil {
				lastErr = fmt.Errorf("billed time: %w", err)
				continue
			}
			if w.periods == 0 || float64(w.throttled) < 0.8*float64(w.periods) {
				lastErr = fmt.Errorf("the cgroup throttled %d of %d periods, want at least 0.8", w.throttled, w.periods)
				continue
			}
			if held := float64(w.throttledUSec) / (w.wall.Seconds() * 1e6); held < 0.8 || held > 0.97 {
				lastErr = fmt.Errorf("the cgroup held its thread back for %.3f of the wall time, want 0.80 to 0.97", held)
				continue
			}
			if share := ran / w.cpus; share < minRanShare || share > maxRanShare {
				lastErr = fmt.Errorf("the thread ran for %.3f of the billed time, want %.2f to %.2f", share, minRanShare, maxRanShare)
				continue
			}
			return nil
		}
		return lastErr
	})
}

// holdBack starts an active loop in dir, applies a 1 ms per second limit, and
// waits until cpu.stat records at least one throttle event.
func holdBack(dir string) (*spinner, error) {
	if err := writeFile(dir, "cpu.max", "max 1000000"); err != nil {
		return nil, err
	}
	s, err := startSpinner(dir)
	if err != nil {
		return nil, err
	}
	if err := s.waitProgress(startLimit); err != nil {
		s.stop()
		return nil, err
	}
	before, err := readStat(dir)
	if err != nil {
		s.stop()
		return nil, err
	}
	if err := writeFile(dir, "cpu.max", "1000 1000000"); err != nil {
		s.stop()
		return nil, err
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		now, err := readStat(dir)
		if err != nil {
			s.stop()
			return nil, err
		}
		if now.nrThrottled > before.nrThrottled {
			return s, nil
		}
		if time.Now().After(deadline) {
			s.stop()
			return nil, fmt.Errorf("%s did not throttle within 10s (nr_throttled=%d)", dir, now.nrThrottled)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// checkRaisedToMax holds a loop back, then writes max to cpu.max. The loop must
// use resumeCPU within resumeLimit.
func checkRaisedToMax() error {
	return withCgroup(probeDir, func() error {
		s, err := holdBack(probeDir)
		if err != nil {
			return err
		}
		defer s.stop()
		if err := writeFile(probeDir, "cpu.max", "max 1000000"); err != nil {
			return err
		}
		return waitCPU(probeDir, resumeCPU, resumeLimit)
	})
}

// checkMigration moves a held-back loop into a sibling without a limit. The loop
// must unthrottle and accumulate resumeCPU within resumeLimit.
func checkMigration() error {
	return withCgroup(probeDir, func() error {
		return withCgroup(siblingDir, func() error {
			s, err := holdBack(probeDir)
			if err != nil {
				return err
			}
			defer s.stop()
			if err := moveTo(siblingDir, s.cmd.Process.Pid); err != nil {
				return err
			}
			return waitCPU(siblingDir, resumeCPU, resumeLimit)
		})
	})
}

// checkDisableController holds a loop back in a child cgroup, then removes the cpu
// controller from the subtree of the parent. The child loses its limit, and the
// loop must run again.
func checkDisableController() error {
	return withCgroup(probeDir, func() error {
		if err := writeFile(probeDir, "cgroup.subtree_control", "+cpu"); err != nil {
			return err
		}
		childDir := probeDir + "/" + childName
		return withCgroup(childDir, func() error {
			s, err := holdBack(childDir)
			if err != nil {
				return err
			}
			defer s.stop()
			if err := writeFile(probeDir, "cgroup.subtree_control", "-cpu"); err != nil {
				return err
			}
			return waitCPU(probeDir, resumeCPU, resumeLimit)
		})
	})
}

// usageTolerance is the difference that two readings of cpu.stat can have,
// because the cgroups are read one after the other while the loops run.
const usageTolerance = 150 * time.Millisecond

// checkHierarchicalUsage runs one loop in each of two children and reads
// usage_usec of the parent and of the children. The usage of the parent
// includes its descendants, as in Linux. The probe reads the parent last, so the
// parent can only read more than the sum.
func checkHierarchicalUsage() error {
	return withCgroup(probeDir, func() error {
		if err := writeFile(probeDir, "cgroup.subtree_control", "+cpu"); err != nil {
			return err
		}
		dirs := []string{probeDir + "/a", probeDir + "/b"}
		return withCgroups(dirs, func() error {
			var spinners []*spinner
			defer func() {
				for _, s := range spinners {
					s.stop()
				}
			}()
			for _, d := range dirs {
				s, err := startSpinner(d)
				if err != nil {
					return err
				}
				spinners = append(spinners, s)
			}
			time.Sleep(2 * time.Second)
			var sum uint64
			for _, d := range dirs {
				st, err := readStat(d)
				if err != nil {
					return err
				}
				sum += st.usageUSec
			}
			parent, err := readStat(probeDir)
			if err != nil {
				return err
			}
			fmt.Printf("INFO parent usage %d us, children %d us\n", parent.usageUSec, sum)
			if parent.usageUSec+uint64(usageTolerance.Microseconds()) < sum {
				return fmt.Errorf("usage_usec of the parent is %d, below the %d of its children", parent.usageUSec, sum)
			}
			if parent.usageUSec < 2*uint64(time.Second.Microseconds()) {
				return fmt.Errorf("usage_usec of the parent is %d, want at least 2 s from two busy loops in 2 s", parent.usageUSec)
			}
			return nil
		})
	})
}

// checkRemovedChildUsage removes a child cgroup that used CPU time. Linux keeps
// the time in the usage of the parent.
func checkRemovedChildUsage() error {
	return withCgroup(probeDir, func() error {
		if err := writeFile(probeDir, "cgroup.subtree_control", "+cpu"); err != nil {
			return err
		}
		childDir := probeDir + "/" + childName
		var before uint64
		err := withCgroup(childDir, func() error {
			s, err := startSpinner(childDir)
			if err != nil {
				return err
			}
			time.Sleep(time.Second)
			s.stop()
			st, err := readStat(probeDir)
			if err != nil {
				return err
			}
			before = st.usageUSec
			return nil
		})
		if err != nil {
			return err
		}
		after, err := readStat(probeDir)
		if err != nil {
			return err
		}
		fmt.Printf("INFO parent usage %d us before and %d us after the removal of its child\n", before, after.usageUSec)
		if before < 800_000 {
			return fmt.Errorf("the parent showed %d us for a loop that ran 1 s", before)
		}
		if after.usageUSec+uint64(usageTolerance.Microseconds()) < before {
			return fmt.Errorf("usage_usec of the parent fell from %d to %d when its child was removed", before, after.usageUSec)
		}
		return nil
	})
}

// withCgroups makes the cgroups dirs, runs fn, and removes them.
func withCgroups(dirs []string, fn func() error) error {
	if len(dirs) == 0 {
		return fn()
	}
	return withCgroup(dirs[0], func() error { return withCgroups(dirs[1:], fn) })
}

// checkRootMemoryStat reads memory.stat of the root cgroup, which the cAdvisor
// of the kubelet reads for the memory of the node. The root accounts all memory,
// so a running guest has anonymous and file memory.
func checkRootMemoryStat() error {
	data, err := os.ReadFile(rootDir + "/memory.stat")
	if err != nil {
		return err
	}
	fields := map[string]uint64{}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(line, " "); ok {
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				fields[k] = n
			}
		}
	}
	for _, k := range []string{"anon", "file", "kernel", "shmem", "file_mapped", "inactive_file", "active_file"} {
		if _, ok := fields[k]; !ok {
			return fmt.Errorf("memory.stat of the root has no key %s:\n%s", k, data)
		}
	}
	fmt.Printf("INFO root memory.stat: anon %d file %d kernel %d\n", fields["anon"], fields["file"], fields["kernel"])
	if fields["anon"]+fields["file"] == 0 {
		return fmt.Errorf("anon + file of the root is 0:\n%s", data)
	}
	for _, name := range []string{"memory.current", "memory.max"} {
		if _, err := os.Stat(rootDir + "/" + name); err == nil {
			return fmt.Errorf("the root cgroup has %s, which Linux does not create", name)
		}
	}
	return nil
}

// loopELF returns a static executable that jumps to itself. It makes no system
// call and uses no runtime, so only the interrupt of the engine can stop it.
func loopELF() []byte {
	const hdr = 64 + 56
	const base = 0x400000
	var code []byte
	var machine uint16
	switch runtime.GOARCH {
	case "amd64":
		machine, code = 62, []byte{0xeb, 0xfe} // jmp .
	default:
		machine, code = 183, []byte{0x00, 0x00, 0x00, 0x14} // b .
	}
	size := hdr + len(code)
	b := make([]byte, size)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	le := binary.LittleEndian
	le.PutUint16(b[16:], 2) // ET_EXEC
	le.PutUint16(b[18:], machine)
	le.PutUint32(b[20:], 1)
	le.PutUint64(b[24:], base+hdr)
	le.PutUint64(b[32:], 64)
	le.PutUint16(b[52:], 64)
	le.PutUint16(b[54:], 56)
	le.PutUint16(b[56:], 1)
	ph := b[64:]
	le.PutUint32(ph[0:], 1) // PT_LOAD
	le.PutUint32(ph[4:], 5) // R+X
	le.PutUint64(ph[16:], base)
	le.PutUint64(ph[24:], base)
	le.PutUint64(ph[32:], uint64(size))
	le.PutUint64(ph[40:], uint64(size))
	le.PutUint64(ph[48:], 0x1000)
	copy(b[hdr:], code)
	return b
}

// startLoop starts the loop program and moves it into the cgroup dir. The
// program runs from its start, so the cgroup counts only the time after the move.
func startLoop(dir string) (*exec.Cmd, error) {
	f, err := os.CreateTemp("", "loop-*")
	if err != nil {
		return nil, err
	}
	path := f.Name()
	defer os.Remove(path)
	if _, err := f.Write(loopELF()); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Chmod(0o755); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	cmd := exec.Command(path)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if err := moveTo(dir, cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		return nil, err
	}
	return cmd, nil
}

// runLoop starts the loop program in dir, lets it settle, and measures dir over
// d. It stops the program before it returns.
func runLoop(dir string, d time.Duration) (window, error) {
	cmd, err := startLoop(dir)
	if err != nil {
		return window{}, err
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	time.Sleep(settle)
	return measure(dir, nil, d)
}

// checkNoSyscallLoop limits a program that makes no system call. The Sentry never
// sees such a program, so the engine must interrupt it to throttle it.
func checkNoSyscallLoop() error {
	return withCgroup(probeDir, func() error {
		if err := writeFile(probeDir, "cpu.max", "50000 100000"); err != nil {
			return err
		}
		w, err := runLoop(probeDir, quotaWindow)
		if err != nil {
			return err
		}
		if err := expectCPUs(w, 0.4, 0.6); err != nil {
			return err
		}
		if w.throttled == 0 {
			return errors.New("nr_throttled did not grow")
		}
		return nil
	})
}
