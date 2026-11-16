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
		if err := probeRelrSplit(dir); err != nil {
			fmt.Printf("FAIL relr-split:%s: %v\n", dir, err)
			failed = true
			continue
		}
		fmt.Printf("PASS relr-split:%s\n", dir)
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

//go:noinline
func applyRelr3(p *[3]uint64, base uint64) {
	p[0] += base
	p[1] += base
	p[2] += base
}

//go:noinline
func readVolatileByte(p *byte) byte {
	return *p
}

// probeRelrSplit maps a file with PROT_READ|PROT_EXEC and MAP_PRIVATE, then
// maps +0x3ef000 with PROT_READ|PROT_WRITE and MAP_FIXED from offset 0x3df000.
// It zeroes the BSS tail and applies in-place RELR relocations at +0x3ef3e0.
func probeRelrSplit(dir string) error {
	const (
		fileSize     = 0x452b98
		totalMapLen  = 0x466000
		rwVirtOff    = 0x3ef000
		rwMapLen     = 0x77000
		rwFileOff    = 0x3df000
		anonVirtOff  = 0x463000
		anonMapLen   = 0x3000
		bssZeroStart = 0x462408
		bssZeroLen   = 0xbf8
		relrFileOff  = 0x3df3e0
		relrVirtOff  = 0x3ef3e0
		word0        = uint64(0x50c0c)
		word1        = uint64(0x50880)
		word2        = uint64(0x50bac)
	)

	path := filepath.Join(dir, "relrsplit.so")
	content := make([]byte, fileSize)
	for i := range content {
		content[i] = byte((i/pageSize)*13 + (i % 251) + 1)
	}
	putU64 := func(off int, v uint64) {
		for b := 0; b < 8; b++ {
			content[off+b] = byte(v >> (8 * b))
		}
	}
	putU64(relrFileOff+0, word0)
	putU64(relrFileOff+8, word1)
	putU64(relrFileOff+16, word2)

	if err := os.WriteFile(path, content, 0o755); err != nil {
		return fmt.Errorf("write relrsplit file: %w", err)
	}
	defer os.Remove(path)

	runOne := func(label string, fixedPtr unsafe.Pointer, touchLoad0 bool) error {
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("%s: open: %w", label, err)
		}
		defer f.Close()

		var basePtr unsafe.Pointer
		if fixedPtr == nil {
			mapped, err := syscall.Mmap(int(f.Fd()), 0, totalMapLen, syscall.PROT_READ|syscall.PROT_EXEC, syscall.MAP_PRIVATE)
			if err != nil {
				return fmt.Errorf("%s: mmap LOAD0: %w", label, err)
			}
			defer syscall.Munmap(mapped)
			basePtr = unsafe.Pointer(&mapped[0])
		} else {
			if _, _, errno := syscall.Syscall6(
				syscall.SYS_MMAP,
				uintptr(fixedPtr),
				totalMapLen,
				syscall.PROT_READ|syscall.PROT_EXEC,
				syscall.MAP_PRIVATE|syscall.MAP_FIXED,
				f.Fd(),
				0,
			); errno != 0 {
				return fmt.Errorf("%s: mmap LOAD0: %w", label, errno)
			}
			basePtr = fixedPtr
		}
		base := uintptr(basePtr)

		if touchLoad0 {
			_ = readVolatileByte((*byte)(basePtr))
			_ = readVolatileByte((*byte)(unsafe.Add(basePtr, 0x3ec000)))
		}

		if _, _, errno := syscall.Syscall6(
			syscall.SYS_MMAP,
			uintptr(unsafe.Add(basePtr, rwVirtOff)),
			rwMapLen,
			syscall.PROT_READ|syscall.PROT_WRITE,
			syscall.MAP_PRIVATE|syscall.MAP_FIXED,
			f.Fd(),
			rwFileOff,
		); errno != 0 {
			return fmt.Errorf("%s: mmap LOAD1: %w", label, errno)
		}

		if _, _, errno := syscall.Syscall6(
			syscall.SYS_MMAP,
			uintptr(unsafe.Add(basePtr, anonVirtOff)),
			anonMapLen,
			syscall.PROT_READ|syscall.PROT_WRITE,
			syscall.MAP_PRIVATE|syscall.MAP_FIXED|syscall.MAP_ANON,
			^uintptr(0),
			0,
		); errno != 0 {
			return fmt.Errorf("%s: mmap BSS: %w", label, errno)
		}

		bssTail := unsafe.Slice((*byte)(unsafe.Add(basePtr, bssZeroStart)), bssZeroLen)
		clear(bssTail)

		relrPtr := (*[3]uint64)(unsafe.Add(basePtr, relrVirtOff))
		applyRelr3(relrPtr, uint64(base))

		got := *relrPtr
		want := [3]uint64{uint64(base) + word0, uint64(base) + word1, uint64(base) + word2}
		if got != want {
			return fmt.Errorf(
				"%s (base=%#x, base%%0x4000=%#x, base%%0x200000=%#x): relr words = [%#x, %#x, %#x] (deltas [%#x, %#x, %#x]), want [%#x, %#x, %#x]",
				label, base, base%0x4000, base%0x200000,
				got[0], got[1], got[2],
				got[0]-uint64(base), got[1]-uint64(base), got[2]-uint64(base),
				want[0], want[1], want[2],
			)
		}
		return nil
	}

	// Test OS-assigned bases across 16 cold and 16 pre-touched rounds.
	for round := 0; round < 16; round++ {
		if err := runOne(fmt.Sprintf("aslr-%d-cold", round), nil, false); err != nil {
			return err
		}
		if err := runOne(fmt.Sprintf("aslr-%d-touch0", round), nil, true); err != nil {
			return err
		}
	}

	// Test all four 16 KB sub-block alignments across three 2 MiB offsets.
	reserve, err := syscall.Mmap(-1, 0, 8*hugeSize, syscall.PROT_NONE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		return fmt.Errorf("reserve arena: %w", err)
	}
	defer syscall.Munmap(reserve)
	arenaStart := unsafe.Pointer(&reserve[0])
	alignedHuge := unsafe.Add(arenaStart, (hugeSize-uintptr(arenaStart)%hugeSize)%hugeSize)

	for _, hugeOff := range []uintptr{0, 0x1a0000, 0x1a4000} {
		for sub := uintptr(0); sub < 0x4000; sub += pageSize {
			fixed := unsafe.Add(alignedHuge, hugeOff+sub)
			if err := runOne(fmt.Sprintf("fixed-h%#x-s%#x-cold", hugeOff, sub), fixed, false); err != nil {
				return err
			}
			if err := runOne(fmt.Sprintf("fixed-h%#x-s%#x-touch0", hugeOff, sub), fixed, true); err != nil {
				return err
			}
		}
	}
	return nil
}
