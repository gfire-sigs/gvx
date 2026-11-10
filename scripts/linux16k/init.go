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
// boots in QEMU on a Linux kernel with 16 KB pages. It runs rungv with each
// guest probe in /guests, prints "PASS name" or "FAIL name" for each, prints
// "VMSMOKE-OK" when all pass, and powers off the machine.
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
)

// step is one rungv invocation and the substrings that its output must contain.
type step struct {
	label string
	args  []string
	wants []string
}

var steps = []step{
	{"guest-pie", []string{"-bin=/tmp/elfguests/guest-pie"}, []string{"guest-pie ok"}},
	{"guest-fixed-0x10000", []string{"-bin=/tmp/elfguests/guest-fixed-0x10000"}, []string{"guest-fixed-0x10000 ok"}},
	{"guest-fixed-0x400000", []string{"-bin=/tmp/elfguests/guest-fixed-0x400000"}, []string{"guest-fixed-0x400000 ok"}},
	{"guest-shared-page", []string{"-bin=/tmp/elfguests/guest-shared-page"}, []string{"guest-shared-page ok"}},
	{"gostatic", []string{"-bin=/guests/gostatic"}, []string{"recover boom"}},
	{"regprobe", []string{"-bin=/guests/regprobe"}, []string{"REGPROBE-OK"}},
	{"sigframeprobe", []string{"-bin=/guests/sigframeprobe"}, []string{"SIGFRAMEPROBE-OK"}},
	{"forkprobe", []string{"-bin=/guests/forkprobe"}, []string{"FORKPROBE-OK"}},
	{"cowprobe", []string{"-bin=/guests/cowprobe"}, []string{"COWPROBE-OK"}},
	{"spareprobe", []string{"-bin=/guests/spareprobe"}, []string{"SPAREPROBE-OK"}},
	{"brkgrow", []string{"-bin=/guests/brkgrow"}, []string{"brk grew 1024 MiB"}},
	{"membarrierprobe", []string{"-bin=/guests/membarrierprobe", "checks"}, []string{"DONE"}},
	{"eintrprobe", []string{"-bin=/guests/eintrprobe", "checks", "10"}, []string{"DONE"}},
	{
		"codewrite",
		[]string{
			"-workspace=/tmp/cws",
			"--mount=type=volume,src=/tmp/cvol.ext4,dst=/mnt,driver=ext4lite",
			"-bin=/guests/codewrite",
			"dir=/workspace",
			"dir=/mnt",
		},
		[]string{
			"PASS shared-file-writes:/workspace",
			"PASS shared-file-writes:/mnt",
			"CODEWRITE-OK",
		},
	},
	{"fsfeatures-hostfs", []string{"-workspace=/tmp/fsws", "-bin=/guests/fsfeatures", "hostfs", "/workspace"}, []string{"hostfs ok"}},
	{"fsfeatures-ext4lite", []string{"--mount=type=volume,src=/tmp/fsvol.ext4,dst=/mnt,driver=ext4lite", "-bin=/guests/fsfeatures", "ext4lite", "/mnt"}, []string{"ext4lite ok"}},
	{"voltree-write-hostfs", []string{"-workspace=/tmp/vws", "-bin=/guests/voltree", "write", "/workspace"}, []string{"write ok"}},
	{"voltree-verify-hostfs", []string{"-workspace=/tmp/vws", "-bin=/guests/voltree", "verify", "/workspace"}, []string{"verify ok"}},
	{"voltree-write-ext4lite", []string{"--mount=type=volume,src=/tmp/vvol.ext4,dst=/mnt,driver=ext4lite", "-bin=/guests/voltree", "write", "/mnt"}, []string{"write ok"}},
	{"voltree-verify-ext4lite", []string{"--mount=type=volume,src=/tmp/vvol.ext4,dst=/mnt,driver=ext4lite", "-bin=/guests/voltree", "verify", "/mnt"}, []string{"verify ok"}},
}

func main() {
	defer powerOff()
	for _, m := range []struct{ src, dst, fs string }{
		{"proc", "/proc", "proc"},
		{"sysfs", "/sys", "sysfs"},
		{"devtmpfs", "/dev", "devtmpfs"},
		{"tmpfs", "/tmp", "tmpfs"},
	} {
		if err := os.MkdirAll(m.dst, 0o755); err != nil {
			fmt.Println("mkdir", m.dst, err)
		}
		if err := syscall.Mount(m.src, m.dst, m.fs, 0, ""); err != nil {
			fmt.Println("mount", m.dst, err)
		}
	}
	var uts syscall.Utsname
	_ = syscall.Uname(&uts)
	fmt.Printf("page size %d, kernel %s\n", os.Getpagesize(), charsToString(uts.Release[:]))
	os.Setenv("HOME", "/tmp")
	os.Setenv("TMPDIR", "/tmp")
	os.Setenv("XDG_CACHE_HOME", "/tmp/cache")
	for _, d := range []string{"/tmp/cache", "/tmp/cws", "/tmp/fsws", "/tmp/vws"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			fmt.Println("mkdir", d, err)
		}
	}

	ok := runProbeReport() && buildELFGuests()
	for _, s := range steps {
		if !runStep(s) {
			ok = false
		}
	}
	if ok {
		fmt.Println("VMSMOKE-OK")
	} else {
		fmt.Println("VMSMOKE-FAIL")
	}
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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
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
