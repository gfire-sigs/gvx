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

//go:build linux && amd64

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"

	"z.gfire.dev/gvx/internal/acceptprog/compatprobe/report"
)

const (
	archSetGS      = 0x1001
	archSetFS      = 0x1002
	archGetFS      = 0x1003
	archGetGS      = 0x1004
	sysGetrandom   = 318
	sysMemfdCreate = 319
)

func asmCPUID(leaf, sub uint32) (eax, ebx, ecx, edx uint32)
func asmProbeGSAMD64(faultPage, writeVal uint64) (selfBefore, pebBefore, selfAfterSVC, tls1AfterFault uint64)
func asmReadGS30AMD64() uint64
func asmBenchTEBAMD64(iters int) uint64
func asmProbeSIMDAMD64(in, out *[16][2]uint64, faultPage uint64)
func asmCallEntryAMD64(fn uintptr, arg uint64) uint64

func archPrctlGet(code uintptr) (uint64, error) {
	var val uint64
	_, _, errno := syscall.RawSyscall(syscall.SYS_ARCH_PRCTL, code, uintptr(unsafe.Pointer(&val)), 0)
	if errno != 0 {
		return 0, errno
	}
	return val, nil
}

func archPrctlSet(code uintptr, addr uint64) error {
	_, _, errno := syscall.RawSyscall(syscall.SYS_ARCH_PRCTL, code, uintptr(addr), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func collectCPUFingerprint() report.CPUFingerprint {
	maxLeaf, ebx0, ecx0, edx0 := asmCPUID(0, 0)
	var vendor [12]byte
	binary.LittleEndian.PutUint32(vendor[0:4], ebx0)
	binary.LittleEndian.PutUint32(vendor[4:8], edx0)
	binary.LittleEndian.PutUint32(vendor[8:12], ecx0)

	_, _, ecx1, edx1 := asmCPUID(1, 0)
	_, ebx7, ecx7, _ := asmCPUID(7, 0)

	maxExt, _, _, _ := asmCPUID(0x80000000, 0)
	var brand [48]byte
	if maxExt >= 0x80000004 {
		for i := uint32(0); i < 3; i++ {
			a, b, c, d := asmCPUID(0x80000002+i, 0)
			off := i * 16
			binary.LittleEndian.PutUint32(brand[off+0:], a)
			binary.LittleEndian.PutUint32(brand[off+4:], b)
			binary.LittleEndian.PutUint32(brand[off+8:], c)
			binary.LittleEndian.PutUint32(brand[off+12:], d)
		}
	}
	fsBase, _ := archPrctlGet(archGetFS)
	gsBase, _ := archPrctlGet(archGetGS)
	return report.CPUFingerprint{
		Vendor:   strings.TrimRight(string(vendor[:]), "\x00 "),
		Brand:    strings.TrimSpace(strings.TrimRight(string(brand[:]), "\x00")),
		MaxLeaf:  maxLeaf,
		Leaf1ECX: fmt.Sprintf("%#08x", ecx1),
		Leaf1EDX: fmt.Sprintf("%#08x", edx1),
		Leaf7EBX: fmt.Sprintf("%#08x", ebx7),
		Leaf7ECX: fmt.Sprintf("%#08x", ecx7),
		FSBase:   fmt.Sprintf("%#x", fsBase),
		GSBase:   fmt.Sprintf("%#x", gsBase),
	}
}

func probeDualTLSWine64TEB() (string, string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pageSize := syscall.Getpagesize()
	tebMem, err := syscall.Mmap(-1, 0, 3*pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return "", "", fmt.Errorf("mmap TEB/PEB: %w", err)
	}
	defer syscall.Munmap(tebMem)

	faultMem, err := syscall.Mmap(-1, 0, pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return "", "", fmt.Errorf("mmap fault page: %w", err)
	}
	defer syscall.Munmap(faultMem)

	tebAddr := uint64(uintptr(unsafe.Pointer(&tebMem[0])))
	pebAddr := tebAddr + uint64(2*pageSize)
	faultAddr := uint64(uintptr(unsafe.Pointer(&faultMem[0])))

	// Populate Windows x64 TEB layout.
	binary.LittleEndian.PutUint64(tebMem[0x08:], tebAddr+uint64(2*pageSize)) // StackBase
	binary.LittleEndian.PutUint64(tebMem[0x10:], tebAddr)                    // StackLimit
	binary.LittleEndian.PutUint64(tebMem[0x30:], tebAddr)                    // NtTib.Self
	binary.LittleEndian.PutUint64(tebMem[0x40:], uint64(os.Getpid()))
	binary.LittleEndian.PutUint64(tebMem[0x60:], pebAddr) // ProcessEnvironmentBlock
	binary.LittleEndian.PutUint64(tebMem[0x1488:], 0x1000)

	fsBefore, err := archPrctlGet(archGetFS)
	if err != nil || fsBefore == 0 {
		return "", "", fmt.Errorf("ARCH_GET_FS = (%#x, %v)", fsBefore, err)
	}
	if err := archPrctlSet(archSetGS, tebAddr); err != nil {
		return "", "", fmt.Errorf("ARCH_SET_GS(%#x): %w", tebAddr, err)
	}
	gsGot, err := archPrctlGet(archGetGS)
	if err != nil || gsGot != tebAddr {
		return "", "", fmt.Errorf("ARCH_GET_GS = (%#x, %v), want %#x", gsGot, err, tebAddr)
	}

	const wantTLS0 = 0xcafe1234dead5678
	selfBefore, pebBefore, selfAfterSVC, tls1AfterFault := asmProbeGSAMD64(faultAddr, wantTLS0)
	gotTLS0 := binary.LittleEndian.Uint64(tebMem[0x1480:])
	fsAfter, _ := archPrctlGet(archGetFS)

	if selfBefore != tebAddr || pebBefore != pebAddr || selfAfterSVC != tebAddr {
		return "", "", fmt.Errorf("TEB mismatch: selfBefore=%#x pebBefore=%#x selfAfterSVC=%#x want teb=%#x peb=%#x",
			selfBefore, pebBefore, selfAfterSVC, tebAddr, pebAddr)
	}
	if gotTLS0 != wantTLS0 || tls1AfterFault != 0x102a {
		return "", "", fmt.Errorf("TLS slots mismatch: tls0=%#x tls1=%#x", gotTLS0, tls1AfterFault)
	}
	if fsAfter != fsBefore {
		return "", "", fmt.Errorf("FS_BASE changed from %#x to %#x", fsBefore, fsAfter)
	}

	// Verify GS preservation across signal delivery.
	var sigSeen atomic.Uint64
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	defer signal.Stop(ch)
	_ = syscall.Kill(os.Getpid(), syscall.SIGUSR1)
	<-ch
	if gsAfterSig := asmReadGS30AMD64(); gsAfterSig == tebAddr {
		sigSeen.Store(1)
	}
	if sigSeen.Load() != 1 {
		return "", "", fmt.Errorf("GS:0x30 corrupted after signal delivery")
	}

	digest := fmt.Sprintf("teb:self=ok:peb=ok:tls0=%#x:tls1=%#x:svc=ok:fault=ok:sig=ok", gotTLS0, tls1AfterFault)
	detail := fmt.Sprintf("ARCH_SET_GS=%#x ARCH_GET_FS=%#x verified across syscall, page fault, and SIGUSR1", tebAddr, fsAfter)
	return digest, detail, nil
}

func probeSIMDFP() (string, string, error) {
	faultMem, err := syscall.Mmap(-1, 0, 0x1000, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return "", "", fmt.Errorf("mmap fault page: %w", err)
	}
	defer syscall.Munmap(faultMem)

	var in, out [16][2]uint64
	for i := range in {
		in[i][0] = 0xa5a5a5a500000000 | uint64(i*2+1)
		in[i][1] = 0x5a5a5a5a00000000 | uint64(i*2+2)
	}
	asmProbeSIMDAMD64(&in, &out, uint64(uintptr(unsafe.Pointer(&faultMem[0]))))
	if out != in {
		return "", "", fmt.Errorf("XMM0..XMM15 mismatch: got %v want %v", out, in)
	}
	xor := (out[0][0] & 0xffffffff00000000) | ((out[15][1] >> 32) & 0xffffffff)
	digest := fmt.Sprintf("simd:128bit:lanes=ok:svc=ok:fault=ok:xor=%#016x", xor)
	return digest, "XMM0..XMM15 128-bit registers preserved across SYSCALL and page fault", nil
}

func peMachineCode() (uint16, []byte) {
	// Windows x64 PE32+ entry point machine code at RVA 0x4000:
	//   mov rax, gs:[0x30]             ; 65 48 8b 04 25 30 00 00 00 (TEB)
	//   mov rdx, [rax+0x60]            ; 48 8b 50 60                (PEB)
	//   mov r8,  [rdx+0x10]            ; 4c 8b 42 10                (PEB->ImageBaseAddress = 0x140000000)
	//   mov r9,  0x77696e6536346f6b    ; 49 b9 6b 6f 34 36 65 6e 69 77
	//   mov gs:[0x1490], r9            ; 65 4c 89 0c 25 90 14 00 00 (TEB->TlsSlots[2])
	//   mov dword ptr [rip+0x7fd2], 0x57494e45 ; c7 05 d2 7f 00 00 45 4e 49 57 (writes to .data at RVA 0xc000)
	//   lea rax, [r8+rcx]              ; 49 8d 04 08                (ImageBase + arg)
	//   ret                            ; c3
	code := []byte{
		0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,
		0x48, 0x8b, 0x50, 0x60,
		0x4c, 0x8b, 0x42, 0x10,
		0x49, 0xb9, 0x6b, 0x6f, 0x34, 0x36, 0x65, 0x6e, 0x69, 0x77,
		0x65, 0x4c, 0x89, 0x0c, 0x25, 0x90, 0x14, 0x00, 0x00,
		0xc7, 0x05, 0xd2, 0x7f, 0x00, 0x00, 0x45, 0x4e, 0x49, 0x57,
		0x49, 0x8d, 0x04, 0x08,
		0xc3,
	}
	return 0x8664, code
}

func runPEEntry(entryVA uintptr, tebAddr uint64, arg uint64) (uint64, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := archPrctlSet(archSetGS, tebAddr); err != nil {
		return 0, err
	}
	return asmCallEntryAMD64(entryVA, arg), nil
}

func probeJITWX() (string, string, error) {
	mem, err := syscall.Mmap(-1, 0, 0x1000, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return "", "", fmt.Errorf("mmap jit: %w", err)
	}
	defer syscall.Munmap(mem)

	// mov eax, imm32 (b8 <imm32>); lea rax, [rdi + rax*2] (48 8d 04 47); ret (c3)
	copy(mem, []byte{0xb8, 50, 0, 0, 0, 0x48, 0x8d, 0x04, 0x47, 0xc3})
	if err := syscall.Mprotect(mem, syscall.PROT_READ|syscall.PROT_EXEC); err != nil {
		return "", "", fmt.Errorf("mprotect RX v1: %w", err)
	}
	fn := uintptr(unsafe.Pointer(&mem[0]))
	v1 := asmCallEntryAMD64(fn, 21) // 21 + 50*2 = 121

	if err := syscall.Mprotect(mem, syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
		return "", "", fmt.Errorf("mprotect RW: %w", err)
	}
	binary.LittleEndian.PutUint32(mem[1:5], 128)
	if err := syscall.Mprotect(mem, syscall.PROT_READ|syscall.PROT_EXEC); err != nil {
		return "", "", fmt.Errorf("mprotect RX v2: %w", err)
	}
	v2 := asmCallEntryAMD64(fn, 21) // 21 + 128*2 = 277
	if v1 != 121 || v2 != 277 {
		return "", "", fmt.Errorf("jit results = (%d, %d), want (121, 277)", v1, v2)
	}
	return fmt.Sprintf("jit:v1=%d:v2=%d:wx_transition=ok", v1, v2), "RW->RX->RW->RX dynamic code patch verified", nil
}

func benchTEBAccess(iters int) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tebMem, err := syscall.Mmap(-1, 0, 0x2000, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return
	}
	defer syscall.Munmap(tebMem)
	tebAddr := uint64(uintptr(unsafe.Pointer(&tebMem[0])))
	binary.LittleEndian.PutUint64(tebMem[0x30:], tebAddr)
	_ = archPrctlSet(archSetGS, tebAddr)
	_ = asmBenchTEBAMD64(iters)
}
