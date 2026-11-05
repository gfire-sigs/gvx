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

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The memory cgroup checks run the probe as a parent that makes a cgroup with a
// memory limit and as hog children that allocate memory inside it.

const (
	memcgDir     = "/sys/fs/cgroup/memcgprobe"
	memcgTimeout = 30 * time.Second
	mib          = 1 << 20
)

// runMemcgChecks runs every memory cgroup check and prints one line for each.
// It returns false if any check failed.
func runMemcgChecks() bool {
	checks := []struct {
		name string
		fn   func() error
	}{
		{"memcg-stat-counts-anonymous-memory", checkMemcgStat},
		{"memcg-under-limit-keeps-task", checkMemcgUnderLimit},
		{"memcg-over-limit-kills-task", checkMemcgOverLimitKills},
		{"memcg-over-limit-kills-largest-task-only", checkMemcgKillsLargestOnly},
		{"memcg-oom-group-kills-every-task", checkMemcgOOMGroup},
		{"memcg-kill-counts-in-cgroup-of-victim", checkMemcgKillCountsInVictimCgroup},
	}
	// The sandbox does not enable controllers for the children of the root
	// cgroup. The init script of docker:dind does it, and so does this write.
	if err := os.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte("+memory"), 0o644); err != nil {
		fmt.Printf("FAIL memcg-enable-controller: %v\n", err)
		return false
	}
	ok := true
	for _, c := range checks {
		if err := withMemcg(c.fn); err != nil {
			fmt.Printf("FAIL %s: %v\n", c.name, err)
			ok = false
			continue
		}
		fmt.Printf("PASS %s\n", c.name)
	}
	return ok
}

// withMemcg runs fn with a fresh cgroup at memcgDir and removes the cgroup.
func withMemcg(fn func() error) error {
	if err := os.Mkdir(memcgDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", memcgDir, err)
	}
	err := fn()
	if rmErr := os.Remove(memcgDir); rmErr != nil {
		err = errors.Join(err, fmt.Errorf("remove %s: %w", memcgDir, rmErr))
	}
	return err
}

func writeControl(name, value string) error {
	return os.WriteFile(memcgDir+"/"+name, []byte(value), 0o644)
}

// controlValue returns the value of key in a flat-keyed control file.
func controlValue(file, key string) (uint64, error) {
	return controlValueIn(memcgDir, file, key)
}

// controlValueIn returns the value of key in a flat-keyed control file of the
// cgroup at dir.
func controlValueIn(dir, file, key string) (uint64, error) {
	data, err := os.ReadFile(dir + "/" + file)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(line, " "); ok && k == key {
			return strconv.ParseUint(v, 10, 64)
		}
	}
	return 0, fmt.Errorf("%s has no key %s:\n%s", file, key, data)
}

// hog is a child process in the cgroup that holds memory.
type hog struct {
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	allocated chan error

	// done closes when the process ended. status is valid after that.
	done   chan struct{}
	status syscall.WaitStatus
}

// startHog starts a child that allocates size bytes after it joined the cgroup.
// With hold set, the child then waits until stdin closes. Otherwise it exits.
func startHog(size int, hold bool) (*hog, error) {
	return startHogIn(memcgDir, size, hold)
}

// startHogIn is startHog for the cgroup at dir.
func startHogIn(dir string, size int, hold bool) (*hog, error) {
	mode := "exit"
	if hold {
		mode = "hold"
	}
	cmd := exec.Command("/proc/self/exe", "memcg-hog", strconv.Itoa(size/mib), mode)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	// The parent reads the pipe while Wait runs, so the pipe cannot be the one
	// that StdoutPipe makes. Wait closes that one.
	stdout, childOut, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout = childOut
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	_ = childOut.Close()
	if err != nil {
		_ = stdout.Close()
		return nil, err
	}
	h := &hog{cmd: cmd, stdin: stdin, allocated: make(chan error, 1), done: make(chan struct{})}
	go func() {
		defer stdout.Close()
		line, err := bufio.NewReader(stdout).ReadString('\n')
		if err != nil {
			h.allocated <- fmt.Errorf("the hog ended before it allocated: %w", err)
			return
		}
		if line != "ALLOCATED\n" {
			h.allocated <- fmt.Errorf("the hog printed %q", line)
			return
		}
		h.allocated <- nil
	}()
	go func() {
		_ = cmd.Wait()
		h.status = cmd.ProcessState.Sys().(syscall.WaitStatus)
		close(h.done)
	}()
	if err := os.WriteFile(dir+"/cgroup.procs", []byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil {
		h.stop()
		return nil, fmt.Errorf("move the hog into the cgroup: %w", err)
	}
	if _, err := io.WriteString(stdin, "go\n"); err != nil {
		h.stop()
		return nil, err
	}
	return h, nil
}

// stop ends the hog and waits for it. A hog that already ended stays ended.
func (h *hog) stop() syscall.WaitStatus {
	_ = h.stdin.Close()
	select {
	case <-h.done:
	case <-time.After(memcgTimeout):
		_ = h.cmd.Process.Kill()
		<-h.done
	}
	return h.status
}

// waitAllocated waits until the hog reports that it holds its memory.
func (h *hog) waitAllocated() error {
	select {
	case err := <-h.allocated:
		return err
	case <-time.After(memcgTimeout):
		return errors.New("the hog did not report its allocation")
	}
}

// waitKilled waits until the hog ends and reports whether SIGKILL ended it.
func (h *hog) waitKilled() (bool, error) {
	select {
	case <-h.done:
		return h.status.Signaled() && h.status.Signal() == syscall.SIGKILL, nil
	case <-time.After(memcgTimeout):
		return false, fmt.Errorf("the hog still runs after %v", memcgTimeout)
	}
}

// hogMain is the child side of startHog.
func hogMain(size int, hold bool) {
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		os.Exit(2)
	}
	mem, err := syscall.Mmap(-1, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mmap:", err)
		os.Exit(3)
	}
	for i := 0; i < len(mem); i += os.Getpagesize() {
		mem[i] = 1
	}
	fmt.Println("ALLOCATED")
	if hold {
		_, _ = io.Copy(io.Discard, os.Stdin)
	}
	os.Exit(0)
}

// idleUnreclaimable returns the anonymous and tmpfs memory that memory.stat
// shows for a probe process that holds 1 MiB. The enforcer compares the same
// sum with memory.max. The Sentry charges whole allocation units, so a Go
// process counts more than the 1 MiB that it holds.
func idleUnreclaimable() (uint64, error) {
	h, err := startHog(mib, true)
	if err != nil {
		return 0, err
	}
	defer h.stop()
	if err := h.waitAllocated(); err != nil {
		return 0, err
	}
	var sum uint64
	for deadline := time.Now().Add(memcgTimeout); sum == 0 && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		anon, err := controlValue("memory.stat", "anon")
		if err != nil {
			return 0, err
		}
		shmem, err := controlValue("memory.stat", "shmem")
		if err != nil {
			return 0, err
		}
		sum = anon + shmem
	}
	return sum, nil
}

// limitAbove sets memory.max to the idle usage of n probe processes plus extra
// bytes.
func limitAbove(n int, extra uint64) error {
	idle, err := idleUnreclaimable()
	if err != nil {
		return err
	}
	return writeControl("memory.max", strconv.FormatUint(uint64(n)*idle+extra, 10))
}

// printIdleUsage prints the usage that memory.stat shows for an idle probe
// process, so a test run records the numbers of the host.
func printIdleUsage() bool {
	if err := os.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte("+memory"), 0o644); err != nil {
		fmt.Println("FAIL memcg-idle:", err)
		return false
	}
	err := withMemcg(func() error {
		h, err := startHog(mib, true)
		if err != nil {
			return err
		}
		defer h.stop()
		if err := h.waitAllocated(); err != nil {
			return err
		}
		time.Sleep(200 * time.Millisecond)
		out := "IDLE"
		for _, k := range []string{"anon", "shmem", "file", "kernel"} {
			v, err := controlValue("memory.stat", k)
			if err != nil {
				return err
			}
			out += fmt.Sprintf(" %s=%d", k, v)
		}
		cur, err := os.ReadFile(memcgDir + "/memory.current")
		if err != nil {
			return err
		}
		fmt.Printf("%s current=%s\n", out, strings.TrimSpace(string(cur)))
		return nil
	})
	if err != nil {
		fmt.Println("FAIL memcg-idle:", err)
		return false
	}
	return true
}

func checkMemcgStat() error {
	h, err := startHog(16*mib, true)
	if err != nil {
		return err
	}
	defer h.stop()
	if err := h.waitAllocated(); err != nil {
		return err
	}
	// The Sentry counts a page after it scans the memory file, so the counters
	// can trail the allocation. Read until they show it.
	var anon, cur uint64
	for deadline := time.Now().Add(memcgTimeout); ; time.Sleep(10 * time.Millisecond) {
		if anon, err = controlValue("memory.stat", "anon"); err != nil {
			return err
		}
		current, err := os.ReadFile(memcgDir + "/memory.current")
		if err != nil {
			return err
		}
		if cur, err = strconv.ParseUint(strings.TrimSpace(string(current)), 10, 64); err != nil {
			return err
		}
		if anon >= 16*mib || time.Now().After(deadline) {
			break
		}
	}
	if anon < 16*mib || cur < 16*mib {
		return fmt.Errorf("a hog holds 16 MiB; memory.stat anon = %d, memory.current = %d", anon, cur)
	}
	return nil
}

func checkMemcgUnderLimit() error {
	if err := limitAbove(1, 64*mib); err != nil {
		return err
	}
	h, err := startHog(8*mib, false)
	if err != nil {
		return err
	}
	if ws := h.stop(); !ws.Exited() || ws.ExitStatus() != 0 {
		return fmt.Errorf("a hog under its limit ended with status %v", ws)
	}
	if kills, err := controlValue("memory.events", "oom_kill"); err != nil || kills != 0 {
		return fmt.Errorf("oom_kill = %d, %v; want 0", kills, err)
	}
	return nil
}

// watchEvents returns a channel that receives when the kernel reports a change
// of memory.events.
func watchEvents() (<-chan error, func(), error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), "inotify")
	if _, err := syscall.InotifyAddWatch(fd, memcgDir+"/memory.events", syscall.IN_MODIFY); err != nil {
		f.Close()
		return nil, nil, err
	}
	changed := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		_ = f.SetReadDeadline(time.Now().Add(memcgTimeout))
		_, err := f.Read(buf)
		changed <- err
	}()
	return changed, func() { f.Close() }, nil
}

func checkMemcgOverLimitKills() error {
	if err := limitAbove(1, 32*mib); err != nil {
		return err
	}
	changed, closeWatch, err := watchEvents()
	if err != nil {
		return fmt.Errorf("watch memory.events: %w", err)
	}
	defer closeWatch()
	h, err := startHog(128*mib, true)
	if err != nil {
		return err
	}
	defer h.stop()
	killed, err := h.waitKilled()
	if err != nil {
		return err
	}
	if !killed {
		return errors.New("a hog 96 MiB over its limit did not end with SIGKILL")
	}
	if err := <-changed; err != nil {
		return fmt.Errorf("no inotify event for memory.events after the kill: %w", err)
	}
	for _, key := range []string{"oom", "oom_kill"} {
		if n, err := controlValue("memory.events", key); err != nil || n == 0 {
			return fmt.Errorf("memory.events %s = %d, %v; want at least 1", key, n, err)
		}
	}
	return nil
}

func checkMemcgKillsLargestOnly() error {
	if err := limitAbove(2, 24*mib); err != nil {
		return err
	}
	small, err := startHog(8*mib, true)
	if err != nil {
		return err
	}
	defer small.stop()
	if err := small.waitAllocated(); err != nil {
		return err
	}
	large, err := startHog(40*mib, true)
	if err != nil {
		return err
	}
	defer large.stop()
	killed, err := large.waitKilled()
	if err != nil {
		return err
	}
	if !killed {
		return errors.New("the largest hog did not end with SIGKILL")
	}
	select {
	case <-small.done:
		return fmt.Errorf("the smaller hog ended too: %v", small.status)
	default:
	}
	if n, err := controlValue("memory.events", "oom_kill"); err != nil || n != 1 {
		return fmt.Errorf("memory.events oom_kill = %d, %v; want 1", n, err)
	}
	return nil
}

func checkMemcgOOMGroup() error {
	if err := limitAbove(2, 24*mib); err != nil {
		return err
	}
	if err := writeControl("memory.oom.group", "1"); err != nil {
		return err
	}
	first, err := startHog(8*mib, true)
	if err != nil {
		return err
	}
	defer first.stop()
	if err := first.waitAllocated(); err != nil {
		return err
	}
	second, err := startHog(40*mib, true)
	if err != nil {
		return err
	}
	defer second.stop()
	for name, h := range map[string]*hog{"smaller": first, "larger": second} {
		killed, err := h.waitKilled()
		if err != nil {
			return fmt.Errorf("%s hog: %w", name, err)
		}
		if !killed {
			return fmt.Errorf("the %s hog did not end with SIGKILL", name)
		}
	}
	if n, err := controlValue("memory.events", "oom_group_kill"); err != nil || n != 1 {
		return fmt.Errorf("memory.events oom_group_kill = %d, %v; want 1", n, err)
	}
	return nil
}

// checkMemcgKillCountsInVictimCgroup passes the limit of a parent cgroup with
// a hog in a child cgroup without a limit. Linux counts the OOM event in the
// parent and the kill in the child and its ancestors. The OOM monitor of
// containerd reads the cgroup of the container, which is such a child when
// the limit of the pod cgroup is reached first.
func checkMemcgKillCountsInVictimCgroup() error {
	// limitAbove runs a probe process in the parent, so it comes before the
	// parent gets a child with the memory controller.
	if err := limitAbove(1, 32*mib); err != nil {
		return err
	}
	child := memcgDir + "/victim"
	if err := writeControl("cgroup.subtree_control", "+memory"); err != nil {
		return err
	}
	if err := os.Mkdir(child, 0o755); err != nil {
		return err
	}
	defer os.Remove(child)
	h, err := startHogIn(child, 128*mib, true)
	if err != nil {
		return err
	}
	defer h.stop()
	killed, err := h.waitKilled()
	if err != nil {
		return err
	}
	if !killed {
		return errors.New("a hog 96 MiB over the limit of its parent did not end with SIGKILL")
	}
	// The parent can count more than one OOM event before the kill takes
	// effect, so its oom count needs only to be positive.
	if n, err := controlValueIn(memcgDir, "memory.events", "oom"); err != nil || n == 0 {
		return fmt.Errorf("%s memory.events oom = %d, %v; want at least 1", memcgDir, n, err)
	}
	for _, want := range []struct {
		dir, key string
		n        uint64
	}{
		{memcgDir, "oom_kill", 1}, {child, "oom", 0}, {child, "oom_kill", 1},
	} {
		if n, err := controlValueIn(want.dir, "memory.events", want.key); err != nil || n != want.n {
			return fmt.Errorf("%s memory.events %s = %d, %v; want %d", want.dir, want.key, n, err, want.n)
		}
	}
	return nil
}
