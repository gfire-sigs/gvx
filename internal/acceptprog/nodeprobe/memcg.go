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
	"time"

	"golang.org/x/sys/unix"
)

const (
	memcgRoot = "/sys/fs/cgroup"
	memcgPath = memcgRoot + "/nodeprobe-memcg"

	// memcgSlack is the memory above the held memory that a reading may show:
	// the Go runtime of the probe and of the child, and the memory of the guest
	// kernel. Another sandbox that holds more than this is visible.
	memcgSlack = 64 << 20
)

// memcgHog is the child of memcgChecks. It joins the memory cgroup, commits
// memory, and holds it until the probe ends.
type memcgHog struct {
	cmd  *exec.Cmd
	in   io.WriteCloser
	done chan struct{}
}

// memcgState is the state that the checks of memcgChecks share.
type memcgState struct {
	holdMiB  int
	limitMiB int
	hog      *memcgHog

	current, cgroupAnon, rootAnon, meminfoAnon uint64
	oomKills                                   uint64
	hogAlive                                   bool
}

// memcgChecks makes a memory cgroup, starts a child in it that commits holdMiB
// MiB, and prints HOLDING. When the input ends, it reads what the guest shows
// for its own memory: memory.current and memory.stat of the cgroup, memory.stat
// of the root cgroup, and AnonPages of /proc/meminfo. Another sandbox of the
// same process that holds more memory must change none of them. With limitMiB
// above 0, the cgroup has that memory.max, and the child must stay alive.
func memcgChecks(holdMiB, limitMiB int) []check {
	s := &memcgState{holdMiB: holdMiB, limitMiB: limitMiB}
	held := uint64(holdMiB) << 20
	checks := []check{
		{"memcg-child-holds-its-memory", s.start},
		{"memcg-readings-after-the-input-ends", s.read},
		{"memcg-current-excludes-other-sandboxes", func() error {
			return atMostHeld("memory.current", s.current, held)
		}},
		{"memcg-stat-excludes-other-sandboxes", func() error {
			return atMostHeld("memory.stat anon", s.cgroupAnon, held)
		}},
		{"root-memory-stat-excludes-other-sandboxes", func() error {
			return atMostHeld("root memory.stat anon", s.rootAnon, held)
		}},
		{"meminfo-anon-excludes-other-sandboxes", func() error {
			return atMostHeld("AnonPages", s.meminfoAnon, held)
		}},
	}
	if limitMiB > 0 {
		checks = append(checks, check{"memory-max-ignores-other-sandboxes", func() error {
			if !s.hogAlive {
				return fmt.Errorf("the OOM killer ended the child: it holds %d MiB under a %d MiB limit", holdMiB, limitMiB)
			}
			if s.oomKills != 0 {
				return fmt.Errorf("memory.events oom_kill = %d, want 0", s.oomKills)
			}
			return nil
		}})
	}
	return checks
}

func atMostHeld(name string, got, held uint64) error {
	if got > held+memcgSlack {
		return fmt.Errorf("%s = %d bytes, want at most %d: the memory of another sandbox counts", name, got, held+memcgSlack)
	}
	return nil
}

func (s *memcgState) start() error {
	// The root cgroup enables no controller for its children. Docker and runc
	// enable them in the same way.
	if err := os.WriteFile(memcgRoot+"/cgroup.subtree_control", []byte("+memory"), 0o644); err != nil {
		return err
	}
	if err := os.Mkdir(memcgPath, 0o755); err != nil {
		return err
	}
	if s.limitMiB > 0 {
		if err := os.WriteFile(memcgPath+"/memory.max", []byte(strconv.Itoa(s.limitMiB<<20)), 0o644); err != nil {
			return err
		}
	}
	cmd := exec.Command("/proc/self/exe", "memcg-hog", strconv.Itoa(s.holdMiB))
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	hog := &memcgHog{cmd: cmd, in: in, done: make(chan struct{})}
	s.hog = hog
	allocated := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(out).ReadString('\n')
		if err == nil && line != "ALLOCATED\n" {
			err = fmt.Errorf("the child printed %q", line)
		}
		allocated <- err
		_, _ = io.Copy(io.Discard, out)
		_ = cmd.Wait()
		close(hog.done)
	}()
	if err := os.WriteFile(memcgPath+"/cgroup.procs", []byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil {
		return err
	}
	if _, err := io.WriteString(in, "go\n"); err != nil {
		return err
	}
	select {
	case err := <-allocated:
		if err != nil {
			return err
		}
	case <-time.After(time.Minute):
		return errors.New("the child did not commit its memory")
	}
	// A node agent reads memory.current of its cgroups all the time. The read
	// makes the Sentry scan the memory file, so the sandbox counts the memory
	// of the child before the probe prints HOLDING. A host that updates the
	// block count of a file late does not show it to the periodic scans.
	if _, err := readUint(memcgPath + "/memory.current"); err != nil {
		return err
	}
	fmt.Println("HOLDING")
	return nil
}

func (s *memcgState) read() error {
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		return err
	}
	select {
	case <-s.hog.done:
	default:
		s.hogAlive = true
	}
	defer func() {
		_ = s.hog.in.Close()
		<-s.hog.done
		_ = os.Remove(memcgPath)
	}()
	var err error
	if s.current, err = readUint(memcgPath + "/memory.current"); err != nil {
		return err
	}
	if s.cgroupAnon, err = statValue(memcgPath+"/memory.stat", "anon"); err != nil {
		return err
	}
	if s.rootAnon, err = statValue(memcgRoot+"/memory.stat", "anon"); err != nil {
		return err
	}
	if s.meminfoAnon, err = meminfoValue("AnonPages"); err != nil {
		return err
	}
	if s.limitMiB > 0 {
		if s.oomKills, err = statValue(memcgPath+"/memory.events", "oom_kill"); err != nil {
			return err
		}
	}
	return nil
}

func readUint(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

// statValue returns the value of key in a flat-keyed control file.
func statValue(path, key string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if k, v, ok := strings.Cut(line, " "); ok && k == key {
			return strconv.ParseUint(v, 10, 64)
		}
	}
	return 0, fmt.Errorf("%s has no key %s", path, key)
}

// meminfoValue returns the field of /proc/meminfo in bytes.
func meminfoValue(field string) (uint64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		rest, ok := strings.CutPrefix(line, field+":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) != 2 || fields[1] != "kB" {
			return 0, fmt.Errorf("%s line %q has an unexpected form", field, line)
		}
		kb, err := strconv.ParseUint(fields[0], 10, 64)
		return kb << 10, err
	}
	return 0, fmt.Errorf("/proc/meminfo has no %s line", field)
}

// memcgHogMain is the child side of memcgChecks. It waits for the parent to move
// it into the cgroup, commits mib MiB, prints ALLOCATED, and holds the memory
// until its input ends.
func memcgHogMain(mib int) {
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		os.Exit(2)
	}
	mem, err := unix.Mmap(-1, 0, mib<<20, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANONYMOUS|unix.MAP_PRIVATE)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mmap:", err)
		os.Exit(3)
	}
	for i := 0; i < len(mem); i += os.Getpagesize() {
		mem[i] = 1
	}
	fmt.Println("ALLOCATED")
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}
