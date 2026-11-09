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

// guests maps each guest probe to the line that it prints when all its checks
// pass.
var guests = []struct{ name, want string }{
	{"gostatic", "recover boom"},
	{"regprobe", "REGPROBE-OK"},
	{"sigframeprobe", "SIGFRAMEPROBE-OK"},
	{"forkprobe", "FORKPROBE-OK"},
	{"cowprobe", "COWPROBE-OK"},
	{"codewrite", "CODEWRITE-OK"},
	{"spareprobe", "SPAREPROBE-OK"},
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
	os.Setenv("XDG_CACHE_HOME", "/tmp/cache")

	ok := true
	for _, g := range guests {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		var out bytes.Buffer
		cmd := exec.CommandContext(ctx, "/rungv", "run", "-platform=systrap", "-net=none", "-bin=/guests/"+g.name)
		cmd.Stdout = &out
		cmd.Stderr = &out
		err := cmd.Run()
		cancel()
		if strings.Contains(out.String(), g.want) {
			fmt.Println("PASS", g.name)
			continue
		}
		ok = false
		fmt.Println("FAIL", g.name, err)
		// A Go panic names its cause in the first lines.
		fmt.Println(head(out.String(), 30))
	}
	if ok {
		fmt.Println("VMSMOKE-OK")
	} else {
		fmt.Println("VMSMOKE-FAIL")
	}
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
