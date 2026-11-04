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
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// meminfoTotal returns MemTotal of /proc/meminfo in bytes.
func meminfoTotal() (uint64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "MemTotal:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) != 2 || fields[1] != "kB" {
			return 0, fmt.Errorf("MemTotal line %q has an unexpected form", sc.Text())
		}
		kb, err := strconv.ParseUint(fields[0], 10, 64)
		return kb << 10, err
	}
	return 0, fmt.Errorf("/proc/meminfo has no MemTotal line")
}

// cpuRange returns the text of a CPU list of cpus CPUs.
func cpuRange(cpus int) string {
	if cpus == 1 {
		return "0"
	}
	return fmt.Sprintf("0-%d", cpus-1)
}

// capacityChecks checks that the memory and the CPUs that the guest sees follow
// the limits of the sandbox. A difference of one page is fine for the memory.
func capacityChecks(mem uint64, cpus int) []check {
	within := func(got, want uint64) bool {
		page := uint64(os.Getpagesize())
		return got+page >= want && got <= want+page
	}
	return []check{
		{"meminfo-total-follows-the-memory-limit", func() error {
			got, err := meminfoTotal()
			if err != nil {
				return err
			}
			if !within(got, mem) {
				return fmt.Errorf("MemTotal = %d bytes, want %d within one page", got, mem)
			}
			return nil
		}},
		{"sysinfo-total-follows-the-memory-limit", func() error {
			var si unix.Sysinfo_t
			if err := unix.Sysinfo(&si); err != nil {
				return err
			}
			if got := uint64(si.Totalram) * uint64(si.Unit); !within(got, mem) {
				return fmt.Errorf("sysinfo totalram = %d bytes, want %d within one page", got, mem)
			}
			return nil
		}},
		{"sched-getaffinity-counts-the-cpus", func() error {
			var set unix.CPUSet
			if err := unix.SchedGetaffinity(0, &set); err != nil {
				return err
			}
			if got := set.Count(); got != cpus {
				return fmt.Errorf("sched_getaffinity returns %d CPUs, want %d", got, cpus)
			}
			if got := runtime.NumCPU(); got != cpus {
				return fmt.Errorf("runtime.NumCPU = %d, want %d", got, cpus)
			}
			return nil
		}},
		{"cpu-online-lists-the-cpus", func() error {
			for _, name := range []string{"online", "possible", "present"} {
				if err := expectValue("/sys/devices/system/cpu/"+name, cpuRange(cpus)); err != nil {
					return err
				}
			}
			return nil
		}},
		{"cpuinfo-lists-the-cpus", func() error {
			data, err := os.ReadFile("/proc/cpuinfo")
			if err != nil {
				return err
			}
			var got int
			for line := range strings.SplitSeq(string(data), "\n") {
				if strings.HasPrefix(line, "processor") {
					got++
				}
			}
			if got != cpus {
				return fmt.Errorf("/proc/cpuinfo lists %d processors, want %d", got, cpus)
			}
			return nil
		}},
	}
}

// memTotalChecks writes writeMiB MiB to a file, prints MemTotal, waits for the
// end of the standard input, and checks that the value stays. Then it prints the
// sectors that /proc/diskstats shows as written. The test closes the input of
// every sandbox only after all of them printed their value, so the runs overlap,
// and each sandbox must count only its own writes.
func memTotalChecks(writeMiB int) []check {
	var first uint64
	return []check{
		{"memtotal-first-read", func() error {
			if writeMiB > 0 {
				if err := os.WriteFile("/tmp/diskfile", make([]byte, writeMiB<<20), 0o644); err != nil {
					return err
				}
			}
			var err error
			first, err = meminfoTotal()
			fmt.Printf("MEMTOTAL %d\n", first)
			return err
		}},
		{"memtotal-stays-while-other-sandboxes-run", func() error {
			if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
				return err
			}
			got, err := meminfoTotal()
			if err != nil {
				return err
			}
			if got != first {
				return fmt.Errorf("MemTotal changed from %d to %d", first, got)
			}
			var si unix.Sysinfo_t
			if err := unix.Sysinfo(&si); err != nil {
				return err
			}
			if total := uint64(si.Totalram) * uint64(si.Unit); total+uint64(os.Getpagesize()) < first || total > first+uint64(os.Getpagesize()) {
				return fmt.Errorf("sysinfo totalram = %d, MemTotal = %d", total, first)
			}
			return nil
		}},
		{"diskstats-count-only-this-sandbox", func() error {
			_, written, err := diskSectors()
			fmt.Printf("SECTORS %d\n", written)
			return err
		}},
	}
}
