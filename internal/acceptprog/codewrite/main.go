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

// Command codewrite checks that a guest can change the code that it runs. Each
// check writes machine code in one of the ways that a program or the kernel can
// write memory, and then runs that code. The checks cover:
//
//   - a store from a page into the same page, which changes the next instruction
//     and a data word beside the code,
//   - a store through a second view of the executing frame,
//   - read(2) into a mapped region,
//   - write(2) to a file that another mapping executes,
//   - process_vm_writev(2) into another process.
//
// Each check prints "PASS name" or "FAIL name: reason", and the program prints
// "CODEWRITE-OK" when all pass. The program runs as the only guest process.
//
// Usage:
//
//	codewrite            run every check
//	codewrite pvw-child  serve the process_vm_writev check, started by the parent
package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	pageSize = 4096
	protRWX  = syscall.PROT_READ | syscall.PROT_WRITE | syscall.PROT_EXEC
	protRX   = syscall.PROT_READ | syscall.PROT_EXEC
	protRW   = syscall.PROT_READ | syscall.PROT_WRITE
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "pvw-child" {
		if err := pvwChild(); err != nil {
			fmt.Fprintln(os.Stderr, "pvw-child:", err)
			os.Exit(1)
		}
		return
	}
	checks := []struct {
		name string
		fn   func() error
	}{
		{"self-patch", checkSelfPatch},
		{"data-in-code-page", checkDataInCodePage},
		{"alias-store-into-executing-frame", checkAliasStore},
		{"alias-rewrite-between-runs", checkAliasRewrite},
		{"read-into-code", checkReadIntoCode},
		{"write-to-executed-file", checkWriteToExecutedFile},
		{"process-vm-writev", checkProcessVMWritev},
	}
	failed := false
	for _, c := range checks {
		if err := c.fn(); err != nil {
			fmt.Printf("FAIL %s: %v\n", c.name, err)
			failed = true
			continue
		}
		fmt.Println("PASS", c.name)
	}
	if failed {
		os.Exit(1)
	}
	fmt.Println("CODEWRITE-OK")
}

func addr(b []byte) uintptr { return uintptr(unsafe.Pointer(&b[0])) }

// run runs the code at mem[0:] after it syncs the instruction cache.
func run(mem []byte, arg uintptr) uint32 {
	syncICache(addr(mem), len(mem))
	return callCode(addr(mem), arg)
}

func want(what string, got, want uint32) error {
	if got != want {
		return fmt.Errorf("%s returned %d, want %d", what, got, want)
	}
	return nil
}

func anonRWX() ([]byte, error) {
	mem, err := syscall.Mmap(-1, 0, pageSize, protRWX, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		return nil, fmt.Errorf("mmap rwx: %w", err)
	}
	return mem, nil
}

// checkSelfPatch runs code that changes the next instruction of its own page.
func checkSelfPatch() error {
	mem, err := anonRWX()
	if err != nil {
		return err
	}
	defer syscall.Munmap(mem)
	copy(mem, codeSelfPatch())
	for i := range 2 {
		if err := want(fmt.Sprintf("run %d of the self-patching code", i+1), run(mem, 0), 42); err != nil {
			return err
		}
	}
	return nil
}

// checkDataInCodePage runs code that stores a counter in the page that holds
// the code, and reads the counter from the guest side too.
func checkDataInCodePage() error {
	mem, err := anonRWX()
	if err != nil {
		return err
	}
	defer syscall.Munmap(mem)
	copy(mem, codeCounter())
	if err := want("the counter code", run(mem, 0), 1); err != nil {
		return err
	}
	if got := binary.LittleEndian.Uint32(mem[slotOff:]); got != 1 {
		return fmt.Errorf("the data word in the code page holds %d, want 1", got)
	}
	return nil
}

// sharedViews maps one memfd page twice and returns the writable view, the
// executable view, and the descriptor.
func sharedViews() (rw, rx []byte, fd int, err error) {
	fd, err = memfdCreate("codewrite")
	if err != nil {
		return nil, nil, -1, fmt.Errorf("memfd_create: %w", err)
	}
	if err := syscall.Ftruncate(fd, pageSize); err != nil {
		syscall.Close(fd)
		return nil, nil, -1, fmt.Errorf("ftruncate: %w", err)
	}
	if rw, err = syscall.Mmap(fd, 0, pageSize, protRW, syscall.MAP_SHARED); err != nil {
		syscall.Close(fd)
		return nil, nil, -1, fmt.Errorf("mmap rw view: %w", err)
	}
	if rx, err = syscall.Mmap(fd, 0, pageSize, protRX, syscall.MAP_SHARED); err != nil {
		syscall.Munmap(rw)
		syscall.Close(fd)
		return nil, nil, -1, fmt.Errorf("mmap rx view: %w", err)
	}
	return rw, rx, fd, nil
}

func unmapViews(rw, rx []byte, fd int) {
	syscall.Munmap(rx)
	syscall.Munmap(rw)
	syscall.Close(fd)
}

// checkAliasStore runs code through one view of a frame while that code stores
// into the frame through another view and then runs the stored bytes.
func checkAliasStore() error {
	rw, rx, fd, err := sharedViews()
	if err != nil {
		return err
	}
	defer unmapViews(rw, rx, fd)
	copy(rw, codeAliasPatch())
	syncICache(addr(rx), len(rx))
	return want("the alias-patching code", callCode(addr(rx), addr(rw)), 42)
}

// checkAliasRewrite runs a function through the executable view, rewrites it
// through the writable view, and runs it again.
func checkAliasRewrite() error {
	rw, rx, fd, err := sharedViews()
	if err != nil {
		return err
	}
	defer unmapViews(rw, rx, fd)
	for _, n := range []uint32{7, 9, 11} {
		copy(rw, codeReturn(n))
		syncICache(addr(rx), len(rx))
		if err := want("the function after a rewrite", callCode(addr(rx), 0), n); err != nil {
			return err
		}
	}
	return nil
}

// checkReadIntoCode runs code, replaces it with read(2) from a pipe, and runs
// it again.
func checkReadIntoCode() error {
	mem, err := anonRWX()
	if err != nil {
		return err
	}
	defer syscall.Munmap(mem)
	var fds [2]int
	if err := syscall.Pipe(fds[:]); err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])
	copy(mem, codeReturn(7))
	if err := want("the first function", run(mem, 0), 7); err != nil {
		return err
	}
	for _, n := range []uint32{9, 11} {
		code := codeReturn(n)
		if _, err := syscall.Write(fds[1], code); err != nil {
			return fmt.Errorf("write to the pipe: %w", err)
		}
		got, err := syscall.Read(fds[0], mem[:len(code)])
		if err != nil || got != len(code) {
			return fmt.Errorf("read into the code page = (%d, %v), want %d bytes", got, err, len(code))
		}
		if err := want("the function after read(2)", run(mem, 0), n); err != nil {
			return err
		}
	}
	return nil
}

// checkWriteToExecutedFile runs code through a shared file mapping, replaces
// the code with write(2) to the file, and runs it again.
func checkWriteToExecutedFile() error {
	rw, rx, fd, err := sharedViews()
	if err != nil {
		return err
	}
	defer unmapViews(rw, rx, fd)
	if _, err := syscall.Pwrite(fd, codeReturn(7), 0); err != nil {
		return fmt.Errorf("pwrite: %w", err)
	}
	if err := want("the first function", run(rx, 0), 7); err != nil {
		return err
	}
	for _, n := range []uint32{9, 11} {
		code := codeReturn(n)
		if _, err := syscall.Seek(fd, 0, 0); err != nil {
			return fmt.Errorf("seek: %w", err)
		}
		if _, err := syscall.Write(fd, code); err != nil {
			return fmt.Errorf("write to the file: %w", err)
		}
		if err := want("the function after write(2)", run(rx, 0), n); err != nil {
			return err
		}
	}
	return nil
}

func memfdCreate(name string) (int, error) {
	b := append([]byte(name), 0)
	fd, _, errno := syscall.Syscall(sysMemfdCreate, uintptr(unsafe.Pointer(&b[0])), 0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

type iovec struct {
	base uintptr
	len  uint64
}

// processVMWritev writes data at remote in the process pid.
func processVMWritev(pid int, remote uintptr, data []byte) error {
	local := iovec{addr(data), uint64(len(data))}
	dst := iovec{remote, uint64(len(data))}
	n, _, errno := syscall.Syscall6(sysProcessVMWritev, uintptr(pid), uintptr(unsafe.Pointer(&local)), 1, uintptr(unsafe.Pointer(&dst)), 1, 0)
	if errno != 0 {
		return errno
	}
	if int(n) != len(data) {
		return fmt.Errorf("process_vm_writev wrote %d of %d bytes", n, len(data))
	}
	return nil
}

// checkProcessVMWritev starts a child that runs a function, rewrites the
// function of the child with process_vm_writev(2), and lets the child run it
// again.
func checkProcessVMWritev() error {
	cmd := exec.Command("/proc/self/exe", "pvw-child")
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start the child: %w", err)
	}
	defer func() {
		in.Close()
		cmd.Wait()
	}()
	rd := bufio.NewReader(out)
	first, err := rd.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read the first report of the child: %w", err)
	}
	var result uint32
	var page uintptr
	if _, err := fmt.Sscanf(first, "R1 %d ADDR %d", &result, &page); err != nil {
		return fmt.Errorf("parse the first report %q: %w", strings.TrimSpace(first), err)
	}
	if err := want("the function of the child", result, 7); err != nil {
		return err
	}
	if err := processVMWritev(cmd.Process.Pid, page, codeReturn(9)); err != nil {
		return fmt.Errorf("process_vm_writev: %w", err)
	}
	if _, err := fmt.Fprintln(in, "go"); err != nil {
		return fmt.Errorf("signal the child: %w", err)
	}
	second, err := rd.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read the second report of the child: %w", err)
	}
	var again uint32
	if _, err := fmt.Sscanf(second, "R2 %d", &again); err != nil {
		return fmt.Errorf("parse the second report %q: %w", strings.TrimSpace(second), err)
	}
	return want("the function of the child after process_vm_writev", again, 9)
}

// pvwChild runs the function, reports it and the address of its page, waits for
// the parent to rewrite the function, and runs it again.
func pvwChild() error {
	mem, err := anonRWX()
	if err != nil {
		return err
	}
	copy(mem, codeReturn(7))
	fmt.Printf("R1 %d ADDR %d\n", run(mem, 0), addr(mem))
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, os.ErrClosed) {
		return fmt.Errorf("wait for the parent: %w", err)
	}
	if strings.TrimSpace(line) != "go" {
		return fmt.Errorf("the parent sent %q, want go", strings.TrimSpace(line))
	}
	fmt.Printf("R2 %s\n", strconv.FormatUint(uint64(run(mem, 0)), 10))
	return nil
}
