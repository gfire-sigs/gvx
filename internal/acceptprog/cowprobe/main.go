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

// Command cowprobe makes the first access to a private file mapping a write
// to a page that follows a 64 KiB chunk boundary of the file and a 2 MiB
// boundary of the address space. The file systems of a bind mount and of a
// volume cache a file in 64 KiB chunks and translate each chunk on its own,
// so the Sentry gets a translation that ends before the faulting page and has
// to break copy-on-write for the next one only.
//
// For each directory that a dir= argument names, the program makes one file
// and maps it with and without PROT_EXEC at many chunk boundaries. A write
// must change the mapping, must keep the other bytes, and must leave the file
// as it was. The program prints "PASS cow-prefix:DIR" for each directory.
//
// Usage:
//
//	cowprobe dir=DIR...
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	pageSize  = 4096
	chunkSize = 64 << 10
	hugeSize  = 2 << 20
	// chunks is the count of chunk boundaries that the probe maps. The
	// memory file may place two chunks side by side, which makes one
	// translation. Many boundaries make a case that it does not.
	chunks = 32
)

func main() {
	failed := false
	for _, arg := range os.Args[1:] {
		dir, ok := strings.CutPrefix(arg, "dir=")
		if !ok {
			continue // The runtime passes the program path as an argument.
		}
		if err := probeDir(dir); err != nil {
			fmt.Printf("FAIL cow-prefix:%s: %v\n", dir, err)
			failed = true
			continue
		}
		fmt.Printf("PASS cow-prefix:%s\n", dir)
	}
	if failed {
		os.Exit(1)
	}
	fmt.Println("COWPROBE-OK")
}

// probeDir runs every mapping case on a file in dir.
func probeDir(dir string) error {
	path := filepath.Join(dir, "cowprobe.dat")
	content := make([]byte, (chunks+1)*chunkSize)
	for i := range content {
		content[i] = byte(i/pageSize*7 + i/251)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return fmt.Errorf("write the file: %w", err)
	}
	defer os.Remove(path)
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	// The region is a reserved range of the address space. Each mapping
	// replaces a part of it, so the range stays inside the guest layout.
	region, err := syscall.Mmap(-1, 0, 4*hugeSize, syscall.PROT_NONE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		return fmt.Errorf("reserve the region: %w", err)
	}
	defer syscall.Munmap(region)
	start := unsafe.Pointer(&region[0])
	boundary := unsafe.Add(start, (hugeSize-uintptr(start)%hugeSize)%hugeSize)

	for _, prot := range []int{syscall.PROT_READ | syscall.PROT_WRITE, syscall.PROT_READ | syscall.PROT_WRITE | syscall.PROT_EXEC} {
		for i := 1; i <= chunks; i++ {
			if err := probeBoundary(f, content, boundary, prot, i); err != nil {
				return fmt.Errorf("prot %#x, chunk boundary %d: %w", prot, i, err)
			}
		}
	}
	return nil
}

// probeBoundary maps four pages that surround the chunk boundary i of the file
// at four pages that surround the address boundary, and writes to the page at
// the boundary as the first access.
func probeBoundary(f *os.File, content []byte, boundary unsafe.Pointer, prot, i int) error {
	const length = 4 * pageSize
	fileOff := int64(i*chunkSize - 2*pageSize)
	mappedAt := unsafe.Add(boundary, -2*pageSize)
	_, _, errno := syscall.Syscall6(syscall.SYS_MMAP, uintptr(mappedAt), length, uintptr(prot),
		syscall.MAP_PRIVATE|syscall.MAP_FIXED, f.Fd(), uintptr(fileOff))
	if errno != 0 {
		return fmt.Errorf("mmap: %w", errno)
	}
	defer syscall.Syscall(syscall.SYS_MUNMAP, uintptr(mappedAt), length, 0)
	// The mapping, as a slice of the address range that it names.
	mapped := unsafe.Slice((*byte)(mappedAt), length)

	// The first access is a plain store, so no read fault installs the pages.
	mapped[2*pageSize] = 0xA5

	want := bytes.Clone(content[fileOff : fileOff+length])
	want[2*pageSize] = 0xA5
	if !bytes.Equal(mapped, want) {
		return fmt.Errorf("the mapping differs from the file with one stored byte")
	}
	onDisk := make([]byte, length)
	if _, err := f.ReadAt(onDisk, fileOff); err != nil {
		return fmt.Errorf("read the file: %w", err)
	}
	if !bytes.Equal(onDisk, content[fileOff:fileOff+length]) {
		return fmt.Errorf("the write through a private mapping reached the file")
	}
	return nil
}
