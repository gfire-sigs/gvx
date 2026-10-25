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

//go:build linux && arm64

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"z.gfire.dev/gvx/internal/acceptprog/compatprobe/report"
)

const (
	sysGetrandom   = 278
	sysMemfdCreate = 279
)

func asmReadSysRegsARM64() (midr, pfr0, isar0, mmfr0, ctr, dczid, cntvct, tpidr uint64)
func asmProbeX18ARM64(teb, faultPage, writeVal uint64) (selfBefore, pebBefore, selfAfterSVC, tls1AfterFault uint64)
func asmSetTPIDRARM64(val uint64)
func asmSetX18ARM64(val uint64)
func asmReadX18ARM64() uint64
func asmBenchTEBARM64(teb uint64, iters int) uint64
func asmProbeSIMDARM64(in, out *[32][2]uint64, faultPage uint64)
func asmCallEntryARM64(fn uintptr, arg, teb uint64) uint64
func asmFlushICacheARM64(addr uintptr)

var tpidrAnchor uint64 = 0x54504944525f4f4b

func collectCPUFingerprint() report.CPUFingerprint {
	midr, pfr0, isar0, mmfr0, ctr, dczid, cntvct, tpidr := asmReadSysRegsARM64()
	if tpidr == 0 {
		asmSetTPIDRARM64(uint64(uintptr(unsafe.Pointer(&tpidrAnchor))))
		_, _, _, _, _, _, _, tpidr = asmReadSysRegsARM64()
	}
	x18 := asmReadX18ARM64()
	return report.CPUFingerprint{
		MIDREL1:       fmt.Sprintf("%#08x", midr),
		IDAA64PFR0EL1: fmt.Sprintf("%#016x", pfr0),
		IDAA64ISAR0:   fmt.Sprintf("%#016x", isar0),
		IDAA64MMFR0:   fmt.Sprintf("%#016x", mmfr0),
		CTREL0:        fmt.Sprintf("%#08x", ctr),
		DCZIDEL0:      fmt.Sprintf("%#04x", dczid),
		CNTVCTEL0:     fmt.Sprintf("%#x", cntvct),
		TPIDREL0:      fmt.Sprintf("%#x", tpidr),
		X18:           fmt.Sprintf("%#x", x18),
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

	// Populate Windows ARM64 TEB layout.
	binary.LittleEndian.PutUint64(tebMem[0x08:], tebAddr+uint64(2*pageSize)) // StackBase
	binary.LittleEndian.PutUint64(tebMem[0x10:], tebAddr)                    // StackLimit
	binary.LittleEndian.PutUint64(tebMem[0x30:], tebAddr)                    // NtTib.Self
	binary.LittleEndian.PutUint64(tebMem[0x40:], uint64(os.Getpid()))
	binary.LittleEndian.PutUint64(tebMem[0x60:], pebAddr) // ProcessEnvironmentBlock
	binary.LittleEndian.PutUint64(tebMem[0x1488:], 0x1000)

	wantTPIDR := tebAddr + uint64(pageSize)
	asmSetTPIDRARM64(wantTPIDR)
	_, _, _, _, _, _, _, tpidrBefore := asmReadSysRegsARM64()
	const wantTLS0 = 0xcafe1234dead5678
	selfBefore, pebBefore, selfAfterSVC, tls1AfterFault := asmProbeX18ARM64(tebAddr, faultAddr, wantTLS0)
	gotTLS0 := binary.LittleEndian.Uint64(tebMem[0x1480:])
	_, _, _, _, _, _, _, tpidrAfter := asmReadSysRegsARM64()

	if selfBefore != tebAddr || pebBefore != pebAddr || selfAfterSVC != tebAddr {
		return "", "", fmt.Errorf("X18 TEB mismatch: selfBefore=%#x pebBefore=%#x selfAfterSVC=%#x want teb=%#x peb=%#x",
			selfBefore, pebBefore, selfAfterSVC, tebAddr, pebAddr)
	}
	if gotTLS0 != wantTLS0 || tls1AfterFault != 0x102a {
		return "", "", fmt.Errorf("TLS slots mismatch: tls0=%#x tls1=%#x", gotTLS0, tls1AfterFault)
	}
	if tpidrBefore != wantTPIDR || tpidrAfter != wantTPIDR {
		return "", "", fmt.Errorf("TPIDR_EL0 = (%#x, %#x), want %#x", tpidrBefore, tpidrAfter, wantTPIDR)
	}

	// Verify X18 preservation across signal delivery.
	var sigSeen atomic.Uint64
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	defer signal.Stop(ch)
	asmSetX18ARM64(tebAddr)
	_ = syscall.Kill(os.Getpid(), syscall.SIGUSR1)
	<-ch
	if x18AfterSig := asmReadX18ARM64(); x18AfterSig == tebAddr {
		sigSeen.Store(1)
	}
	if sigSeen.Load() != 1 {
		return "", "", fmt.Errorf("X18 corrupted after signal delivery")
	}

	digest := fmt.Sprintf("teb:self=ok:peb=ok:tls0=%#x:tls1=%#x:svc=ok:fault=ok:sig=ok", gotTLS0, tls1AfterFault)
	detail := fmt.Sprintf("X18=%#x TPIDR_EL0=%#x verified across SVC, page fault, and SIGUSR1", tebAddr, tpidrAfter)
	return digest, detail, nil
}

func probeSIMDFP() (string, string, error) {
	pageSize := syscall.Getpagesize()
	faultMem, err := syscall.Mmap(-1, 0, pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return "", "", fmt.Errorf("mmap fault page: %w", err)
	}
	defer syscall.Munmap(faultMem)

	var in, out [32][2]uint64
	for i := range in {
		in[i][0] = 0xa5a5a5a500000000 | uint64(i*2+1)
		in[i][1] = 0x5a5a5a5a00000000 | uint64(i*2+2)
	}
	asmProbeSIMDARM64(&in, &out, uint64(uintptr(unsafe.Pointer(&faultMem[0]))))
	if out != in {
		return "", "", fmt.Errorf("V0..V31 mismatch: got %v want %v", out, in)
	}
	xor := (out[0][0] & 0xffffffff00000000) | ((out[15][1] >> 32) & 0xffffffff)
	digest := fmt.Sprintf("simd:128bit:lanes=ok:svc=ok:fault=ok:xor=%#016x", xor)
	return digest, "V0..V31 128-bit NEON registers preserved across SVC and page fault", nil
}

func peMachineCode() (uint16, []byte) {
	// Windows ARM64 PE32+ entry point machine code at RVA 0x4000:
	//   ldr x1, [x18, #0x30]             ; f9401a41 (TEB->Self)
	//   ldr x2, [x1, #0x60]              ; f9403022 (PEB)
	//   ldr x3, [x2, #0x10]              ; f9400843 (PEB->ImageBaseAddress = 0x140000000)
	//   movz x4, #0x6f6b                 ; d28ded64
	//   movk x4, #0x3634, lsl #16        ; f2a6c684
	//   movk x4, #0x6e65, lsl #32        ; f2cdcca4
	//   movk x4, #0x7769, lsl #48        ; f2eeed24
	//   str x4, [x18, #0x1490]           ; f90a4a44 (TEB->TlsSlots[2])
	//   adrp x5, +0x8000                 ; 90000045 (.data at RVA 0xc000)
	//   movz w6, #0x4e45                 ; 5289c8a6
	//   movk w6, #0x5749, lsl #16        ; 72aae926
	//   str w6, [x5]                     ; b90000a6
	//   add x0, x3, x0                   ; 8b000060 (ImageBase + arg)
	//   ret                              ; d65f03c0
	words := []uint32{
		0xf9401a41,
		0xf9403022,
		0xf9400843,
		0xd28ded64,
		0xf2a6c684,
		0xf2cdcca4,
		0xf2eeed24,
		0xf90a4a44,
		0x90000045,
		0x5289c8a6,
		0x72aae926,
		0xb90000a6,
		0x8b000060,
		0xd65f03c0,
	}
	code := make([]byte, len(words)*4)
	for i, w := range words {
		binary.LittleEndian.PutUint32(code[i*4:], w)
	}
	return 0xaa64, code
}

func runPEEntry(entryVA uintptr, tebAddr uint64, arg uint64) (uint64, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return asmCallEntryARM64(entryVA, arg, tebAddr), nil
}

func probeJITWX() (string, string, error) {
	pageSize := syscall.Getpagesize()
	mem, err := syscall.Mmap(-1, 0, pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return "", "", fmt.Errorf("mmap jit: %w", err)
	}
	defer syscall.Munmap(mem)

	// movz x1, #50; add x0, x0, x1, lsl #1; ret
	binary.LittleEndian.PutUint32(mem[0:4], 0xd2800001|(50<<5))
	binary.LittleEndian.PutUint32(mem[4:8], 0x8b010400)
	binary.LittleEndian.PutUint32(mem[8:12], 0xd65f03c0)
	fn := uintptr(unsafe.Pointer(&mem[0]))
	asmFlushICacheARM64(fn)
	if err := syscall.Mprotect(mem, syscall.PROT_READ|syscall.PROT_EXEC); err != nil {
		return "", "", fmt.Errorf("mprotect RX v1: %w", err)
	}
	v1 := asmCallEntryARM64(fn, 21, 0) // 21 + 50*2 = 121

	if err := syscall.Mprotect(mem, syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
		return "", "", fmt.Errorf("mprotect RW: %w", err)
	}
	binary.LittleEndian.PutUint32(mem[0:4], 0xd2800001|(128<<5))
	asmFlushICacheARM64(fn)
	if err := syscall.Mprotect(mem, syscall.PROT_READ|syscall.PROT_EXEC); err != nil {
		return "", "", fmt.Errorf("mprotect RX v2: %w", err)
	}
	v2 := asmCallEntryARM64(fn, 21, 0) // 21 + 128*2 = 277
	if v1 != 121 || v2 != 277 {
		return "", "", fmt.Errorf("jit results = (%d, %d), want (121, 277)", v1, v2)
	}
	return fmt.Sprintf("jit:v1=%d:v2=%d:wx_transition=ok", v1, v2), "RW->RX->RW->RX dynamic code patch and icache sync verified", nil
}

func benchTEBAccess(iters int) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pageSize := syscall.Getpagesize()
	tebMem, err := syscall.Mmap(-1, 0, max(2*pageSize, 0x2000), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return
	}
	defer syscall.Munmap(tebMem)
	tebAddr := uint64(uintptr(unsafe.Pointer(&tebMem[0])))
	binary.LittleEndian.PutUint64(tebMem[0x30:], tebAddr)
	_ = asmBenchTEBARM64(tebAddr, iters)
}
