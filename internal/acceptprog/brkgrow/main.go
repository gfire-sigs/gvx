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

// Command brkgrow moves the program break up by 1 GiB in steps of 16 MiB and
// prints how far it moved. An allocator that uses only brk needs this growth.
// The Go runtime itself never calls brk, so nothing else uses the range.
package main

import (
	"fmt"
	"os"
	"syscall"
)

const (
	step   = 16 << 20
	target = 1 << 30
)

func brk(addr uintptr) uintptr {
	r, _, _ := syscall.RawSyscall(syscall.SYS_BRK, addr, 0, 0)
	return r
}

func main() {
	start := brk(0)
	cur := start
	for cur-start < target {
		next := brk(cur + step)
		if next != cur+step {
			break
		}
		cur = next
	}
	fmt.Printf("brk grew %d MiB\n", (cur-start)>>20)
	if cur-start < target {
		os.Exit(1)
	}
}
