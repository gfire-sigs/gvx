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

//go:build ignore

// Command init is process 1 of the initramfs that scripts/linux16k/run.sh
// boots in QEMU on a Linux kernel with 16 KB pages. It runs androidprobe
// report, generates the synthetic ELF guests in /tmp/elfguests, runs rungv
// with the synthetic ELF probes and hostfs voltree, runs the systrap, hostfs,
// ext4lite, and offline e2e test suites, prints "PASS name" or "FAIL name" for
// each, prints "VMSMOKE-OK" when all pass, and powers off the machine.
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// step is one rungv invocation and the substrings that its output must contain.
// The offline e2e suite runs the remaining acceptprog guest probes.
type step struct {
	label string
	args  []string
	wants []string
}

var steps = []step{
	{"guest-pie", []string{"-bin=/tmp/elfguests/guest-pie"}, []string{"guest-pie ok"}},
	{"guest-fixed-0x10000", []string{"-bin=/tmp/elfguests/guest-fixed-0x10000"}, []string{"guest-fixed-0x10000 ok"}},
	{"guest-fixed-0x400000", []string{"-bin=/tmp/elfguests/guest-fixed-0x400000"}, []string{"guest-fixed-0x400000 ok"}},
	{"guest-shared-page", []string{"-bin=/tmp/elfguests/guest-shared-page"}, []string{"shared-page-ok"}},
	{"voltree-write-hostfs", []string{"-workspace=/tmp/vws", "-bin=/guests/voltree", "write", "/workspace"}, []string{"write ok"}},
	{"voltree-verify-hostfs", []string{"-workspace=/tmp/vws", "-bin=/guests/voltree", "verify", "/workspace"}, []string{"verify ok"}},
}

func main() {
	defer powerOff()
	for _, m := range []struct{ src, dst, fs, opts string }{
		{"proc", "/proc", "proc", ""},
		{"sysfs", "/sys", "sysfs", ""},
		{"devtmpfs", "/dev", "devtmpfs", ""},
		{"tmpfs", "/dev/shm", "tmpfs", "mode=1777"},
		{"tmpfs", "/tmp", "tmpfs", "size=2g,mode=1777"},
	} {
		if err := os.MkdirAll(m.dst, 0o755); err != nil {
			fmt.Println("mkdir", m.dst, err)
		}
		if err := syscall.Mount(m.src, m.dst, m.fs, 0, m.opts); err != nil {
			fmt.Println("mount", m.dst, err)
		}
	}
	bringUpLoopback()
	var uts syscall.Utsname
	_ = syscall.Uname(&uts)
	fmt.Printf("page size %d, kernel %s\n", os.Getpagesize(), charsToString(uts.Release[:]))
	os.Setenv("HOME", "/tmp")
	os.Setenv("TMPDIR", "/tmp")
	os.Setenv("XDG_CACHE_HOME", "/tmp/cache")
	os.Setenv("GVX_E2E_OFFLINE", "1")
	os.Setenv("GVX_PREBUILT_DIR", "/guests")
	// QEMU emulates the CPU with TCG, so checks of the throttle ratio against
	// the wall clock see host TCG jitter; keep the deterministic cgroup checks.
	os.Setenv("GVX_E2E_CPUMAX_CHECKS", "memory-stat-exists-at-root,cpu-stat-usage-of-parent-includes-children,cpu-stat-usage-of-parent-keeps-removed-children")
	for _, d := range []string{"/tmp/cache", "/tmp/vws"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			fmt.Println("mkdir", d, err)
		}
	}

	reportOK := runProbeReport()
	elvesOK := buildELFGuests()
	ok := reportOK && elvesOK
	for _, s := range steps {
		if !runStep(s) {
			ok = false
		}
	}
	for _, suite := range []struct {
		label   string
		bin     string
		timeout time.Duration
	}{
		{"systrap.test", "/systrap.test", 5 * time.Minute},
		{"hostfs.test", "/hostfs.test", 5 * time.Minute},
		{"ext4lite.test", "/ext4lite.test", 6 * time.Minute},
		{"e2e.test", "/e2e.test", 25 * time.Minute},
	} {
		if !runTestBinary(suite.label, suite.bin, suite.timeout) {
			ok = false
		}
		_ = os.Remove(suite.bin)
	}
	if ok {
		fmt.Println("VMSMOKE-OK")
	} else {
		fmt.Println("VMSMOKE-FAIL")
	}
}

func bringUpLoopback() {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		fmt.Println("loopback socket:", err)
		return
	}
	defer syscall.Close(fd)
	var ifr [40]byte
	copy(ifr[:16], "lo")
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		fmt.Println("loopback SIOCGIFFLAGS:", errno)
		return
	}
	flags := *(*uint16)(unsafe.Pointer(&ifr[16])) | syscall.IFF_UP | syscall.IFF_RUNNING
	*(*uint16)(unsafe.Pointer(&ifr[16])) = flags
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		fmt.Println("loopback SIOCSIFFLAGS:", errno)
	}
}

func runTestBinary(label, bin string, timeout time.Duration) bool {
	fmt.Println("== " + label)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-test.v", "-test.count=1", "-test.timeout="+timeout.String())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println("FAIL", label, err)
		return false
	}
	fmt.Println("PASS", label)
	return true
}

func runProbeReport() bool {
	out, err := exec.Command("/androidprobe", "report").CombinedOutput()
	fmt.Print(string(out))
	if err != nil || strings.Contains(string(out), " FAIL ") {
		fmt.Println("FAIL androidprobe-report", err)
		return false
	}
	fmt.Println("PASS androidprobe-report")
	return true
}

func buildELFGuests() bool {
	out, err := exec.Command("/androidprobe", "guests", "/tmp/elfguests").CombinedOutput()
	if err != nil {
		fmt.Println("FAIL androidprobe-guests", err, string(out))
		return false
	}
	return true
}

func runStep(s step) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var out bytes.Buffer
	args := append([]string{"run", "-platform=systrap", "-net=none"}, s.args...)
	cmd := exec.CommandContext(ctx, "/rungv", args...)
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	text := out.String()
	passed := err == nil && !strings.HasPrefix(text, "FAIL ") && !strings.Contains(text, "\nFAIL ")
	for _, w := range s.wants {
		if !strings.Contains(text, w) {
			passed = false
		}
	}
	if passed {
		fmt.Println("PASS", s.label)
		return true
	}
	fmt.Println("FAIL", s.label, err)
	// A Go panic names its cause in the first lines.
	fmt.Println(head(text, 40))
	return false
}

func charsToString(cs []int8) string {
	b := make([]byte, 0, len(cs))
	for _, c := range cs {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func head(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

func powerOff() {
	syscall.Sync()
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
}
