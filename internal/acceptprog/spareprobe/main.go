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

// Command spareprobe checks that the guest and the guest kernel see the same
// bytes in 4 KB pages that share a 16 KB block with pages of another mapping.
// On a host with 16 KB pages, the Linux systrap engine can map such a block
// directly and hold the pages of the block without a guest page as spare
// pages. A change of the block must then end the use of the spare pages. Each
// check maps single pages at fixed addresses in one 16 KB block:
//
//   - remap-reads-zero: a page that the guest wrote, unmapped, and mapped
//     again reads as zeros,
//   - new-neighbor: a new page next to a written page reads as zeros, and the
//     kernel reads the guest stores into it and the guest reads the kernel
//     stores into it,
//   - guard-gains-access: a page without access next to a written page reads
//     as zeros after mprotect gives it access, and the kernel and the guest
//     agree on its bytes,
//   - dontneed-reads-zero: a page reads as zeros after MADV_DONTNEED, and the
//     other page of the block keeps its bytes,
//   - fork-isolation: the stores of a forked child do not reach the parent.
//
// Each check prints "PASS name" or "FAIL name: reason", and the program prints
// "SPAREPROBE-OK" when all pass.
package main

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	pageSize  = 4096
	blockSize = 16384
)

func main() {
	checks := []struct {
		name string
		run  func(block uintptr) error
	}{
		{"remap-reads-zero", remapReadsZero},
		{"new-neighbor", newNeighbor},
		{"guard-gains-access", guardGainsAccess},
		{"dontneed-reads-zero", dontneedReadsZero},
		{"fork-isolation", forkIsolation},
	}
	ok := true
	for _, c := range checks {
		block, err := reserveBlock()
		if err == nil {
			err = c.run(block)
		}
		if err != nil {
			ok = false
			fmt.Printf("FAIL %s: %v\n", c.name, err)
			continue
		}
		fmt.Printf("PASS %s\n", c.name)
	}
	if !ok {
		os.Exit(1)
	}
	fmt.Println("SPAREPROBE-OK")
}

// reserveBlock returns the address of a 16 KB block that no mapping uses. It
// maps 32 KB, and unmaps all of it, so that the block is free.
func reserveBlock() (uintptr, error) {
	addr, err := mmap(0, 2*blockSize, syscall.PROT_NONE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return 0, err
	}
	block := (addr + blockSize - 1) &^ (blockSize - 1)
	if err := munmap(addr, 2*blockSize); err != nil {
		return 0, err
	}
	return block, nil
}

func mmap(addr, length uintptr, prot, flags int) (uintptr, error) {
	r, _, errno := syscall.Syscall6(syscall.SYS_MMAP, addr, length, uintptr(prot), uintptr(flags), ^uintptr(0), 0)
	if errno != 0 {
		return 0, fmt.Errorf("mmap(%#x, %#x): %w", addr, length, errno)
	}
	return r, nil
}

// mapPage maps one anonymous page at addr.
func mapPage(addr uintptr, prot int) error {
	got, err := mmap(addr, pageSize, prot, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS|syscall.MAP_FIXED)
	if err == nil && got != addr {
		err = fmt.Errorf("mmap returned %#x, want %#x", got, addr)
	}
	return err
}

func munmap(addr, length uintptr) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_MUNMAP, addr, length, 0); errno != 0 {
		return fmt.Errorf("munmap(%#x, %#x): %w", addr, length, errno)
	}
	return nil
}

func mprotect(addr uintptr, prot int) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_MPROTECT, addr, pageSize, uintptr(prot)); errno != 0 {
		return fmt.Errorf("mprotect(%#x): %w", addr, errno)
	}
	return nil
}

func page(addr uintptr) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(addr)), pageSize)
}

// settle makes system calls, so that the engine prepares the address space
// for the next run of the guest several times. The engine coalesces a block
// at such a point.
func settle() {
	for range 4 {
		syscall.Getppid()
	}
}

// fill writes a pattern that depends on seed into p.
func fill(p []byte, seed byte) {
	for i := range p {
		p[i] = seed + byte(i*7)
	}
}

func checkZero(p []byte, what string) error {
	if i := bytes.IndexFunc(p, func(r rune) bool { return r != 0 }); i >= 0 {
		return fmt.Errorf("%s: byte %d is %#x, want 0", what, i, p[i])
	}
	return nil
}

// kernelAgrees checks that the kernel reads the guest bytes of p, and that the
// guest reads the bytes that the kernel writes into p.
func kernelAgrees(p []byte, seed byte) error {
	var fds [2]int
	if err := syscall.Pipe(fds[:]); err != nil {
		return err
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])
	fill(p, seed)
	if n, err := syscall.Write(fds[1], p); err != nil || n != len(p) {
		return fmt.Errorf("write from the page: %d, %v", n, err)
	}
	got := make([]byte, len(p))
	if n, err := syscall.Read(fds[0], got); err != nil || n != len(p) {
		return fmt.Errorf("read: %d, %v", n, err)
	}
	if !bytes.Equal(got, p) {
		return fmt.Errorf("the kernel read other bytes than the guest wrote")
	}
	want := make([]byte, len(p))
	fill(want, seed+1)
	if n, err := syscall.Write(fds[1], want); err != nil || n != len(want) {
		return fmt.Errorf("write: %d, %v", n, err)
	}
	if n, err := syscall.Read(fds[0], p); err != nil || n != len(p) {
		return fmt.Errorf("read into the page: %d, %v", n, err)
	}
	if !bytes.Equal(p, want) {
		return fmt.Errorf("the guest read other bytes than the kernel wrote")
	}
	return nil
}

func remapReadsZero(block uintptr) error {
	p0, p1 := block, block+pageSize
	if err := mapPage(p0, syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
		return err
	}
	if err := mapPage(p1, syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
		return err
	}
	fill(page(p0), 1)
	fill(page(p1), 2)
	settle()
	fill(page(p1), 3)
	if err := munmap(p1, pageSize); err != nil {
		return err
	}
	settle()
	if err := mapPage(p1, syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
		return err
	}
	if err := checkZero(page(p1), "the page mapped again"); err != nil {
		return err
	}
	want := make([]byte, pageSize)
	fill(want, 1)
	if !bytes.Equal(page(p0), want) {
		return fmt.Errorf("the other page of the block lost its bytes")
	}
	return munmap(block, blockSize)
}

func newNeighbor(block uintptr) error {
	p0, p2 := block, block+2*pageSize
	if err := mapPage(p0, syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
		return err
	}
	fill(page(p0), 4)
	settle()
	fill(page(p0), 5)
	if err := mapPage(p2, syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
		return err
	}
	if err := checkZero(page(p2), "the new page"); err != nil {
		return err
	}
	if err := kernelAgrees(page(p2), 6); err != nil {
		return err
	}
	settle()
	if err := kernelAgrees(page(p2), 8); err != nil {
		return fmt.Errorf("after a switch: %w", err)
	}
	return munmap(block, blockSize)
}

func guardGainsAccess(block uintptr) error {
	p0, p1 := block, block+pageSize
	if err := mapPage(p0, syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
		return err
	}
	if err := mapPage(p1, syscall.PROT_NONE); err != nil {
		return err
	}
	fill(page(p0), 10)
	settle()
	fill(page(p0), 11)
	if err := mprotect(p1, syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
		return err
	}
	if err := checkZero(page(p1), "the guard page after mprotect"); err != nil {
		return err
	}
	if err := kernelAgrees(page(p1), 12); err != nil {
		return err
	}
	return munmap(block, blockSize)
}

func dontneedReadsZero(block uintptr) error {
	p0, p1 := block, block+pageSize
	if err := mapPage(p0, syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
		return err
	}
	if err := mapPage(p1, syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
		return err
	}
	fill(page(p0), 14)
	fill(page(p1), 15)
	settle()
	fill(page(p1), 16)
	if err := syscall.Madvise(page(p1), syscall.MADV_DONTNEED); err != nil {
		return fmt.Errorf("madvise: %w", err)
	}
	if err := checkZero(page(p1), "the page after MADV_DONTNEED"); err != nil {
		return err
	}
	want := make([]byte, pageSize)
	fill(want, 14)
	if !bytes.Equal(page(p0), want) {
		return fmt.Errorf("the other page of the block lost its bytes")
	}
	if err := kernelAgrees(page(p1), 17); err != nil {
		return err
	}
	return munmap(block, blockSize)
}

func forkIsolation(block uintptr) error {
	p0 := block
	if err := mapPage(p0, syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
		return err
	}
	fill(page(p0), 20)
	settle()
	fill(page(p0), 21)
	// The child must not run Go code that can allocate, so it uses only
	// raw system calls and stores.
	pid, _, errno := syscall.RawSyscall6(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD), 0, 0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("fork: %w", errno)
	}
	if pid == 0 {
		p := page(p0)
		for i := range p {
			p[i] = 0x5a
		}
		status := uintptr(0)
		for i := range p {
			if p[i] != 0x5a {
				status = 1
			}
		}
		syscall.RawSyscall(syscall.SYS_EXIT_GROUP, status, 0, 0)
	}
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(int(pid), &ws, 0, nil); err != nil {
		return fmt.Errorf("wait4: %w", err)
	}
	if !ws.Exited() || ws.ExitStatus() != 0 {
		return fmt.Errorf("the child did not read its own stores: %v", ws)
	}
	want := make([]byte, pageSize)
	fill(want, 21)
	if !bytes.Equal(page(p0), want) {
		return fmt.Errorf("the stores of the child reached the parent")
	}
	return munmap(block, blockSize)
}
