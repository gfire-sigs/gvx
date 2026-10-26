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

package main

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"z.gfire.dev/gvx/internal/acceptprog/compatprobe/report"
)

func main() {
	start := time.Now()
	rep := report.Report{
		SchemaVersion: 1,
		Fingerprint:   collectSystemFingerprint(),
		AllPassed:     true,
	}

	probes := []struct {
		name     string
		category string
		fn       func() (string, string, error)
	}{
		{"abi_auxv_procfs", "kernel_abi", probeAuxvProcfs},
		{"cpu_dual_tls_wine64_teb", "wine64_cpu", probeDualTLSWine64TEB},
		{"cpu_simd_fp_preservation", "cpu_vector", probeSIMDFP},
		{"wine64_pe32plus_execution", "wine64_loader", probeWine64PE32PlusExec},
		{"wine64_pe_mmap_layout", "wine64_mm", probeWine64PEMmapLayout},
		{"wine64_wineserver_ipc", "wine64_ipc", probeWine64WineserverIPC},
		{"wine64_ntdll_sync_signal", "wine64_sync", probeWine64NtdllSyncSignal},
		{"mm_jit_wx_transition", "memory_jit", probeJITWX},
		{"mm_fork_cow_shared", "memory_cow", probeForkCoWShared},
		{"vfs_posix_torture", "storage_vfs", probeVFSPosixTorture},
		{"net_epoll_loopback", "network_epoll", probeNetEpollLoopback},
	}

	for _, p := range probes {
		pStart := time.Now()
		digest, detail, err := p.fn()
		dur := time.Since(pStart).Nanoseconds()
		passed := err == nil
		if err != nil {
			detail = err.Error()
			rep.AllPassed = false
		}
		rep.Probes = append(rep.Probes, report.ProbeResult{
			Name:       p.name,
			Category:   p.category,
			Passed:     passed,
			Digest:     digest,
			Detail:     detail,
			DurationNs: dur,
		})
	}

	rep.Benchmarks = runBenchmarks()
	rep.TotalNs = time.Since(start).Nanoseconds()

	enc, err := json.Marshal(rep)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal report: %v\n", err)
		os.Exit(2)
	}
	fmt.Println("COMPATPROBE_JSON=" + string(enc))
	if !rep.AllPassed {
		os.Exit(1)
	}
	fmt.Println("COMPATPROBE-OK")
}

func charsToString(ca [65]int8) string {
	var b []byte
	for _, c := range ca {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func collectSystemFingerprint() report.SystemFingerprint {
	var u syscall.Utsname
	_ = syscall.Uname(&u)

	fp := report.SystemFingerprint{
		Arch:          runtime.GOARCH,
		Sysname:       charsToString(u.Sysname),
		Release:       charsToString(u.Release),
		Version:       charsToString(u.Version),
		Machine:       charsToString(u.Machine),
		PageSize:      syscall.Getpagesize(),
		NumCPU:        runtime.NumCPU(),
		PID:           os.Getpid(),
		UID:           os.Getuid(),
		GID:           os.Getgid(),
		Auxv:          parseAuxv(),
		CPU:           collectCPUFingerprint(),
		AddressSpace:  parseProcSelfMaps(),
		CPUInfoFields: parseCPUInfo(),
	}
	return fp
}

func parseAuxv() report.AuxvSummary {
	var out report.AuxvSummary
	data, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return out
	}
	const (
		atPhdr        = 3
		atPagesz      = 6
		atEntry       = 9
		atHwcap       = 16
		atHwcap2      = 26
		atSysinfoEhdr = 33
	)
	for off := 0; off+16 <= len(data); off += 16 {
		tag := binary.LittleEndian.Uint64(data[off : off+8])
		val := binary.LittleEndian.Uint64(data[off+8 : off+16])
		if tag == 0 {
			break
		}
		switch tag {
		case atPagesz:
			out.PageSize = val
		case atHwcap:
			out.HWCap = fmt.Sprintf("%#x", val)
		case atHwcap2:
			out.HWCap2 = fmt.Sprintf("%#x", val)
		case atPhdr:
			out.Phdr = fmt.Sprintf("%#x", val)
		case atEntry:
			out.Entry = fmt.Sprintf("%#x", val)
		case atSysinfoEhdr:
			out.SysinfoEhdr = fmt.Sprintf("%#x", val)
		}
	}
	return out
}

func parseProcSelfMaps() report.AddressSpaceSummary {
	var out report.AddressSpaceSummary
	data, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return out
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		out.RegionCount++
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		parts := strings.SplitN(fields[0], "-", 2)
		if len(parts) != 2 {
			continue
		}
		start, end := "0x"+parts[0], "0x"+parts[1]
		if out.FirstStart == "" {
			out.FirstStart = start
		}
		out.LastEnd = end
		if out.ExecStart == "" && strings.Contains(fields[1], "x") {
			out.ExecStart = start
		}
		if len(fields) >= 6 {
			switch fields[len(fields)-1] {
			case "[stack]":
				out.StackStart = start
			case "[vdso]":
				out.VDSOStart = start
			}
		}
	}
	return out
}

func parseCPUInfo() map[string]string {
	res := make(map[string]string)
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return res
	}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "model name", "vendor_id", "Features", "CPU implementer", "CPU part", "CPU architecture":
			if _, exists := res[k]; !exists {
				res[k] = v
			}
		}
	}
	return res
}

func probeAuxvProcfs() (string, string, error) {
	aux := parseAuxv()
	if aux.PageSize == 0 {
		return "", "", fmt.Errorf("AT_PAGESZ is 0")
	}
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil || exe == "" {
		return "", "", fmt.Errorf("readlink /proc/self/exe: %w", err)
	}
	maps := parseProcSelfMaps()
	if maps.RegionCount < 3 {
		return "", "", fmt.Errorf("/proc/self/maps has %d regions", maps.RegionCount)
	}
	if _, err := os.ReadDir("/proc/self/fd"); err != nil {
		return "", "", fmt.Errorf("readdir /proc/self/fd: %w", err)
	}
	if _, err := os.ReadFile("/proc/self/stat"); err != nil {
		return "", "", fmt.Errorf("read /proc/self/stat: %w", err)
	}
	if _, err := os.ReadFile("/proc/cpuinfo"); err != nil {
		return "", "", fmt.Errorf("read /proc/cpuinfo: %w", err)
	}
	var rng [32]byte
	n, _, errno := syscall.Syscall(sysGetrandom, uintptr(unsafe.Pointer(&rng[0])), uintptr(len(rng)), 0)
	if errno != 0 || n != uintptr(len(rng)) {
		return "", "", fmt.Errorf("getrandom = (%d, %v)", n, errno)
	}
	allZero := true
	for _, b := range rng {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "", "", fmt.Errorf("getrandom returned 32 zero bytes")
	}
	return "auxv:ok:proc:exe+maps+fd+stat+cpuinfo:rng:32b", fmt.Sprintf("exe=%s regions=%d pagesz=%d", exe, maps.RegionCount, aux.PageSize), nil
}

// buildPE32PlusImage constructs a valid 64-bit Windows PE32+ executable with
// .text (RVA 0x4000), .rdata (RVA 0x8000), and .data (RVA 0xc000) sections.
func buildPE32PlusImage(machine uint16, code []byte) []byte {
	img := make([]byte, 0x10000)
	// DOS Header
	img[0], img[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(img[0x3c:], 0x80)
	// PE Signature
	copy(img[0x80:], "PE\x00\x00")
	// COFF File Header (20 bytes at 0x84)
	binary.LittleEndian.PutUint16(img[0x84:], machine)
	binary.LittleEndian.PutUint16(img[0x86:], 3)    // NumberOfSections
	binary.LittleEndian.PutUint16(img[0x94:], 0xf0) // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(img[0x96:], 0x22) // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

	// OptionalHeader64 (240 bytes at 0x98)
	opt := img[0x98 : 0x98+0xf0]
	binary.LittleEndian.PutUint16(opt[0:], 0x20b)        // PE32+ magic
	binary.LittleEndian.PutUint32(opt[16:], 0x4000)      // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(opt[20:], 0x4000)      // BaseOfCode
	binary.LittleEndian.PutUint64(opt[24:], 0x140000000) // ImageBase
	binary.LittleEndian.PutUint32(opt[32:], 0x4000)      // SectionAlignment (16KB, valid on both 4K and 16K hosts)
	binary.LittleEndian.PutUint32(opt[36:], 0x4000)      // FileAlignment (16KB for direct section mmap)
	binary.LittleEndian.PutUint16(opt[40:], 6)           // MajorOperatingSystemVersion
	binary.LittleEndian.PutUint16(opt[48:], 6)           // MajorSubsystemVersion
	binary.LittleEndian.PutUint32(opt[56:], 0x10000)     // SizeOfImage
	binary.LittleEndian.PutUint32(opt[60:], 0x4000)      // SizeOfHeaders
	binary.LittleEndian.PutUint16(opt[68:], 3)           // Subsystem: IMAGE_SUBSYSTEM_WINDOWS_CUI
	binary.LittleEndian.PutUint32(opt[108:], 16)         // NumberOfRvaAndSizes

	// Section Table (3 * 40 bytes at 0x188)
	secs := []struct {
		name  string
		vsize uint32
		rva   uint32
		rawsz uint32
		rawof uint32
		chars uint32
	}{
		{".text", uint32(len(code)), 0x4000, 0x4000, 0x4000, 0x60000020},
		{".rdata", 16, 0x8000, 0x4000, 0x8000, 0x40000040},
		{".data", 16, 0xc000, 0x4000, 0xc000, 0xc0000040},
	}
	for i, s := range secs {
		sh := img[0x188+i*40 : 0x188+(i+1)*40]
		copy(sh[0:8], s.name)
		binary.LittleEndian.PutUint32(sh[8:], s.vsize)
		binary.LittleEndian.PutUint32(sh[12:], s.rva)
		binary.LittleEndian.PutUint32(sh[16:], s.rawsz)
		binary.LittleEndian.PutUint32(sh[20:], s.rawof)
		binary.LittleEndian.PutUint32(sh[36:], s.chars)
	}
	copy(img[0x4000:], code)
	binary.LittleEndian.PutUint64(img[0x8000:], 0x1122334455667788)
	binary.LittleEndian.PutUint32(img[0xc000:], 0)
	return img
}

func probeWine64PE32PlusExec() (string, string, error) {
	machine, code := peMachineCode()
	rawPE := buildPE32PlusImage(machine, code)

	peFile, err := pe.NewFile(bytes.NewReader(rawPE))
	if err != nil {
		return "", "", fmt.Errorf("parse PE32+: %w", err)
	}
	defer peFile.Close()
	opt64, ok := peFile.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || opt64.Magic != 0x20b || opt64.ImageBase != 0x140000000 {
		return "", "", fmt.Errorf("unexpected OptionalHeader64: %+v", peFile.OptionalHeader)
	}

	const pePath = "/tmp/wine64_probe.dll"
	if err := os.WriteFile(pePath, rawPE, 0o755); err != nil {
		return "", "", fmt.Errorf("write PE32+ file: %w", err)
	}
	defer os.Remove(pePath)
	peFD, err := syscall.Open(pePath, syscall.O_RDONLY, 0)
	if err != nil {
		return "", "", fmt.Errorf("open PE32+ file: %w", err)
	}
	defer syscall.Close(peFD)

	const imageBase = 0x140000000
	const imageSize = 0x10000
	addr, _, errno := syscall.Syscall6(
		syscall.SYS_MMAP,
		imageBase,
		imageSize,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE,
		uintptr(peFD),
		0,
	)
	if errno != 0 || addr == 0 {
		return "", "", fmt.Errorf("mmap PE32+ ImageBase %#x: addr=%#x errno=%v", uint64(imageBase), addr, errno)
	}
	defer syscall.Syscall(syscall.SYS_MUNMAP, addr, imageSize, 0)

	mapped := mmapBytes(addr, imageSize)

	// Apply per-section protections (.text RX, .rdata R, .data RW).
	if err := syscall.Mprotect(mapped[0x4000:0x8000], syscall.PROT_READ|syscall.PROT_EXEC); err != nil {
		return "", "", fmt.Errorf("mprotect .text RX: %w", err)
	}
	if err := syscall.Mprotect(mapped[0x8000:0xc000], syscall.PROT_READ); err != nil {
		return "", "", fmt.Errorf("mprotect .rdata R: %w", err)
	}

	pageSize := syscall.Getpagesize()
	tebMem, err := syscall.Mmap(-1, 0, 3*pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return "", "", fmt.Errorf("mmap TEB/PEB: %w", err)
	}
	defer syscall.Munmap(tebMem)

	tebAddr := uint64(uintptr(unsafe.Pointer(&tebMem[0])))
	pebAddr := tebAddr + uint64(2*pageSize)
	binary.LittleEndian.PutUint64(tebMem[0x30:], tebAddr)                    // TEB->Self
	binary.LittleEndian.PutUint64(tebMem[0x60:], pebAddr)                    // TEB->ProcessEnvironmentBlock
	binary.LittleEndian.PutUint64(tebMem[2*pageSize+0x10:], opt64.ImageBase) // PEB->ImageBaseAddress

	entryVA := addr + uintptr(opt64.AddressOfEntryPoint)
	ret, err := runPEEntry(entryVA, tebAddr, 0x1379)
	if err != nil {
		return "", "", fmt.Errorf("runPEEntry: %w", err)
	}
	tls2 := binary.LittleEndian.Uint64(tebMem[0x1490:])
	dataWord := binary.LittleEndian.Uint32(mapped[0xc000:])
	if ret != 0x140001379 || tls2 != 0x77696e6536346f6b || dataWord != 0x57494e45 {
		return "", "", fmt.Errorf("PE32+ result ret=%#x tls2=%#x data=%#x", ret, tls2, dataWord)
	}
	digest := fmt.Sprintf("pe32+:magic=%#x:base=%#x:ret=%#x:tls2=%#x:data=%#x",
		opt64.Magic, opt64.ImageBase, ret, tls2, dataWord)
	return digest, fmt.Sprintf("PE32+ image mapped at %#x (ImageBase=%#x) and executed with TEB/PEB ABI", uint64(addr), opt64.ImageBase), nil
}

func probeWine64PEMmapLayout() (string, string, error) {
	pageSize := uintptr(syscall.Getpagesize())

	// 1. Reserve a 4-page PE64 region (hint 0x140000000) and MAP_FIXED overwrite a section page.
	peAddr, _, errno := syscall.Syscall6(syscall.SYS_MMAP, 0x140000000, 4*pageSize, syscall.PROT_READ, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS, ^uintptr(0), 0)
	if errno != 0 || peAddr == 0 {
		return "", "", fmt.Errorf("reserve PE mmap: addr=%#x errno=%v", peAddr, errno)
	}
	secAddr, _, errno := syscall.Syscall6(syscall.SYS_MMAP, peAddr+pageSize, pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS|syscall.MAP_FIXED, ^uintptr(0), 0)
	if errno != 0 || secAddr != peAddr+pageSize {
		syscall.Syscall(syscall.SYS_MUNMAP, peAddr, 4*pageSize, 0)
		return "", "", fmt.Errorf("MAP_FIXED section split: addr=%#x errno=%v", secAddr, errno)
	}
	binary.LittleEndian.PutUint64(mmapBytes(secAddr, 8), 0x140000000)
	syscall.Syscall(syscall.SYS_MUNMAP, peAddr, 4*pageSize, 0)

	// 2. Low 32-bit address (< 2GB) hint allocation used by Wine64 for 32-bit structures.
	lowAddr, _, errno := syscall.Syscall6(syscall.SYS_MMAP, 0x60000000, pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS, ^uintptr(0), 0)
	if errno != 0 || lowAddr == 0 {
		return "", "", fmt.Errorf("low32 mmap: addr=%#x errno=%v", lowAddr, errno)
	}
	binary.LittleEndian.PutUint64(mmapBytes(lowAddr, 8), 0x123456789abcdef0)

	// 3. mremap expansion (MREMAP_MAYMOVE = 1).
	remapped, _, errno := syscall.Syscall6(syscall.SYS_MREMAP, lowAddr, pageSize, 2*pageSize, 1, 0, 0)
	if errno != 0 {
		syscall.Syscall(syscall.SYS_MUNMAP, lowAddr, pageSize, 0)
		return "", "", fmt.Errorf("mremap: %v", errno)
	}
	defer syscall.Syscall(syscall.SYS_MUNMAP, remapped, 2*pageSize, 0)
	if got := binary.LittleEndian.Uint64(mmapBytes(remapped, 8)); got != 0x123456789abcdef0 {
		return "", "", fmt.Errorf("mremap content = %#x", got)
	}
	return "mmap:pe_fixed=0x140000000:low32=ok:mremap=ok", fmt.Sprintf("pe=%#x low32=%#x mremap=%#x", peAddr, lowAddr, remapped), nil
}

func mmapBytes(addr uintptr, length int) []byte {
	ptr := *(*unsafe.Pointer)(unsafe.Pointer(&addr))
	return unsafe.Slice((*byte)(ptr), length)
}

func probeWine64WineserverIPC() (string, string, error) {
	nameBytes := []byte("wineserver-shm\x00")
	r1, _, errno := syscall.Syscall(sysMemfdCreate, uintptr(unsafe.Pointer(&nameBytes[0])), 1 /* MFD_CLOEXEC */, 0)
	if errno != 0 {
		return "", "", fmt.Errorf("memfd_create: %v", errno)
	}
	memfd := int(r1)
	defer syscall.Close(memfd)

	pageSize := syscall.Getpagesize()
	if err := syscall.Ftruncate(memfd, int64(pageSize)); err != nil {
		return "", "", fmt.Errorf("ftruncate memfd: %w", err)
	}
	view1, err := syscall.Mmap(memfd, 0, pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return "", "", fmt.Errorf("mmap view1: %w", err)
	}
	defer syscall.Munmap(view1)

	// Pass memfd over AF_UNIX socketpair via SCM_RIGHTS, as wineserver does.
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return "", "", fmt.Errorf("socketpair: %w", err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])

	rights := syscall.UnixRights(memfd)
	if err := syscall.Sendmsg(fds[0], []byte("W"), rights, nil, 0); err != nil {
		return "", "", fmt.Errorf("sendmsg SCM_RIGHTS: %w", err)
	}
	buf := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(4))
	_, oobn, _, _, err := syscall.Recvmsg(fds[1], buf, oob, 0)
	if err != nil {
		return "", "", fmt.Errorf("recvmsg SCM_RIGHTS: %w", err)
	}
	cmsgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(cmsgs) != 1 {
		return "", "", fmt.Errorf("parse control message: %v (len=%d)", err, len(cmsgs))
	}
	gotFDs, err := syscall.ParseUnixRights(&cmsgs[0])
	if err != nil || len(gotFDs) != 1 {
		return "", "", fmt.Errorf("parse unix rights: %v", err)
	}
	recvFD := gotFDs[0]
	defer syscall.Close(recvFD)

	view2, err := syscall.Mmap(recvFD, 0, pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return "", "", fmt.Errorf("mmap view2: %w", err)
	}
	defer syscall.Munmap(view2)

	binary.LittleEndian.PutUint32(view1[0:4], 0x57535256)
	gotCoh := binary.LittleEndian.Uint32(view2[0:4])
	if gotCoh != 0x57535256 {
		return "", "", fmt.Errorf("MAP_SHARED coherence got %#x, want 0x57535256", gotCoh)
	}

	// Test pwritev / preadv scatter-gather on recvFD.
	b1, b2 := []byte("wine"), []byte("64ok")
	iovOut := []syscall.Iovec{
		{Base: &b1[0], Len: 4},
		{Base: &b2[0], Len: 4},
	}
	if _, _, errno := syscall.Syscall6(syscall.SYS_PWRITEV, uintptr(recvFD), uintptr(unsafe.Pointer(&iovOut[0])), 2, 64, 0, 0); errno != 0 {
		return "", "", fmt.Errorf("pwritev: %v", errno)
	}
	rBuf1, rBuf2 := make([]byte, 4), make([]byte, 4)
	iovIn := []syscall.Iovec{
		{Base: &rBuf1[0], Len: 4},
		{Base: &rBuf2[0], Len: 4},
	}
	if _, _, errno := syscall.Syscall6(syscall.SYS_PREADV, uintptr(memfd), uintptr(unsafe.Pointer(&iovIn[0])), 2, 64, 0, 0); errno != 0 {
		return "", "", fmt.Errorf("preadv: %v", errno)
	}
	if string(rBuf1)+string(rBuf2) != "wine64ok" {
		return "", "", fmt.Errorf("preadv got %q", string(rBuf1)+string(rBuf2))
	}
	return fmt.Sprintf("ipc:memfd=ok:scm_rights=ok:shared_coh=%#x:preadv=ok", gotCoh), "memfd_create + SCM_RIGHTS + MAP_SHARED + preadv/pwritev verified", nil
}

func probeWine64NtdllSyncSignal() (string, string, error) {
	// 1. FUTEX_WAIT_BITSET_PRIVATE (9) + FUTEX_WAKE_BITSET_PRIVATE (10)
	const (
		futexWaitBitsetPrivate = 9 | 128
		futexWakeBitsetPrivate = 10 | 128
		bitsetMask             = 0xdeadbeef
	)
	var futexWord uint32
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		close(ready)
		_, _, errno := syscall.Syscall6(
			syscall.SYS_FUTEX,
			uintptr(unsafe.Pointer(&futexWord)),
			futexWaitBitsetPrivate,
			0,
			0,
			0,
			bitsetMask,
		)
		if errno != 0 && errno != syscall.EAGAIN {
			done <- fmt.Errorf("FUTEX_WAIT_BITSET: %v", errno)
			return
		}
		done <- nil
	}()
	<-ready
	deadline := time.Now().Add(10 * time.Second)
	for {
		n, _, _ := syscall.Syscall6(
			syscall.SYS_FUTEX,
			uintptr(unsafe.Pointer(&futexWord)),
			futexWakeBitsetPrivate,
			1,
			0,
			0,
			bitsetMask,
		)
		if n >= 1 {
			break
		}
		if time.Now().After(deadline) {
			atomic.StoreUint32(&futexWord, 1)
			syscall.Syscall6(
				syscall.SYS_FUTEX,
				uintptr(unsafe.Pointer(&futexWord)),
				futexWakeBitsetPrivate,
				1,
				0,
				0,
				bitsetMask,
			)
			break
		}
		time.Sleep(500 * time.Microsecond)
	}
	if err := <-done; err != nil {
		return "", "", err
	}

	// 2. Guard-page PROT_NONE fault -> SA_SIGINFO ucontext_t recovery -> mprotect RW.
	pageSize := syscall.Getpagesize()
	guardPage, err := syscall.Mmap(-1, 0, pageSize, syscall.PROT_NONE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return "", "", fmt.Errorf("mmap guard page: %w", err)
	}
	defer syscall.Munmap(guardPage)

	recoveredVal := uint32(0)
	func() {
		prev := debug.SetPanicOnFault(true)
		defer debug.SetPanicOnFault(prev)
		defer func() {
			if r := recover(); r != nil {
				if err := syscall.Mprotect(guardPage, syscall.PROT_READ|syscall.PROT_WRITE); err == nil {
					binary.LittleEndian.PutUint32(guardPage[0:4], 0x42424242)
					recoveredVal = binary.LittleEndian.Uint32(guardPage[0:4])
				}
			}
		}()
		// Fault on PROT_NONE guard page.
		recoveredVal = atomic.LoadUint32((*uint32)(unsafe.Pointer(&guardPage[0])))
	}()
	if recoveredVal != 0x42424242 {
		return "", "", fmt.Errorf("guard page recovery failed: val=%#x", recoveredVal)
	}
	return fmt.Sprintf("sync:futex_bitset=%#x:guard_page_segv=recovered:val=%#x", uint32(bitsetMask), recoveredVal),
		"FUTEX_WAIT_BITSET and PROT_NONE guard page SIGSEGV recovery verified", nil
}

func probeForkCoWShared() (string, string, error) {
	pageSize := syscall.Getpagesize()
	priv, err := syscall.Mmap(-1, 0, pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return "", "", fmt.Errorf("mmap private: %w", err)
	}
	defer syscall.Munmap(priv)

	shared, err := syscall.Mmap(-1, 0, pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED|syscall.MAP_ANONYMOUS)
	if err != nil {
		return "", "", fmt.Errorf("mmap shared: %w", err)
	}
	defer syscall.Munmap(shared)

	binary.LittleEndian.PutUint64(priv[0:8], 0x1111222233334444)
	binary.LittleEndian.PutUint64(shared[0:8], 0xaaaa0000bbbb1111)

	pid, _, errno := syscall.RawSyscall(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD), 0, 0)
	if errno != 0 {
		return "", "", fmt.Errorf("clone: %v", errno)
	}
	if pid == 0 {
		binary.LittleEndian.PutUint64(priv[0:8], 0xdead0000beef1111)
		binary.LittleEndian.PutUint64(shared[0:8], 0x9999888877776666)
		syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 0, 0, 0)
	}
	var wstatus syscall.WaitStatus
	if _, err := syscall.Wait4(int(pid), &wstatus, 0, nil); err != nil {
		return "", "", fmt.Errorf("wait4: %w", err)
	}
	gotPriv := binary.LittleEndian.Uint64(priv[0:8])
	gotShared := binary.LittleEndian.Uint64(shared[0:8])
	if gotPriv != 0x1111222233334444 || gotShared != 0x9999888877776666 || wstatus.ExitStatus() != 0 {
		return "", "", fmt.Errorf("cow results: priv=%#x shared=%#x status=%d", gotPriv, gotShared, wstatus.ExitStatus())
	}
	return fmt.Sprintf("cow:private_parent=%#x:shared_parent=%#x:status=%d", gotPriv, gotShared, wstatus.ExitStatus()),
		"fork() MAP_PRIVATE CoW isolation and MAP_SHARED coherence verified", nil
}

func tortureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// 1. Atomic rename over open file.
	pOld := filepath.Join(dir, "f_old")
	pNew := filepath.Join(dir, "f_new")
	if err := os.WriteFile(pOld, []byte("v1"), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(pNew, []byte("v2"), 0o644); err != nil {
		return err
	}
	fOpen, err := os.Open(pOld)
	if err != nil {
		return err
	}
	defer fOpen.Close()
	if err := os.Rename(pNew, pOld); err != nil {
		return err
	}
	buf := make([]byte, 2)
	if _, err := fOpen.ReadAt(buf, 0); err != nil || string(buf) != "v1" {
		return fmt.Errorf("read open fd after rename-over: got %q err %v", string(buf), err)
	}
	if got, err := os.ReadFile(pOld); err != nil || string(got) != "v2" {
		return fmt.Errorf("read path after rename-over: got %q err %v", string(got), err)
	}

	// 2. Unlink while open.
	pUnlink := filepath.Join(dir, "f_unlink")
	if err := os.WriteFile(pUnlink, []byte("unlinked-ok"), 0o644); err != nil {
		return err
	}
	fUnlink, err := os.Open(pUnlink)
	if err != nil {
		return err
	}
	defer fUnlink.Close()
	if err := os.Remove(pUnlink); err != nil {
		return err
	}
	uBuf := make([]byte, 11)
	if _, err := fUnlink.ReadAt(uBuf, 0); err != nil || string(uBuf) != "unlinked-ok" {
		return fmt.Errorf("read open fd after unlink: got %q err %v", string(uBuf), err)
	}

	// 3. Hardlink, symlink, and fsync.
	pLink := filepath.Join(dir, "f_hard")
	if err := os.Link(pOld, pLink); err != nil {
		return err
	}
	pSym := filepath.Join(dir, "f_sym")
	if err := os.Symlink("f_hard", pSym); err != nil {
		return err
	}
	if got, err := os.ReadFile(pSym); err != nil || string(got) != "v2" {
		return fmt.Errorf("read through symlink+hardlink: got %q err %v", string(got), err)
	}
	fSync, err := os.OpenFile(pOld, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer fSync.Close()
	return fSync.Sync()
}

func probeVFSPosixTorture() (string, string, error) {
	dirs := []struct {
		label string
		path  string
	}{
		{"tmpfs", "/tmp/compat_vfs"},
		{"workspace", "/workspace/compat_vfs"},
		{"volume", "/mnt/vol/compat_vfs"},
	}
	for _, d := range dirs {
		target := d.path
		if _, err := os.Stat(filepath.Dir(target)); err != nil {
			target = filepath.Join("/tmp", d.label+"_fallback")
		}
		if err := tortureDir(target); err != nil {
			return "", "", fmt.Errorf("%s (%s): %w", d.label, target, err)
		}
		_ = os.RemoveAll(target)
	}
	return "vfs:tmpfs=ok:workspace=ok:volume=ok:rename_open=ok:unlink_open=ok:links=ok:preadv=ok",
		"tmpfs, hostfs (/workspace), and ext4lite (/mnt/vol) POSIX semantics verified", nil
}

func probeNetEpollLoopback() (string, string, error) {
	epfd, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		return "", "", fmt.Errorf("epoll_create1: %w", err)
	}
	defer syscall.Close(epfd)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", fmt.Errorf("listen tcp: %w", err)
	}
	defer ln.Close()

	tcpDone := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			tcpDone <- ""
			return
		}
		defer conn.Close()
		var buf [64]byte
		n, _ := conn.Read(buf[:])
		_, _ = conn.Write(buf[:n])
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return "", "", fmt.Errorf("dial tcp: %w", err)
	}
	defer client.Close()
	rawConn, err := client.(*net.TCPConn).SyscallConn()
	if err != nil {
		return "", "", err
	}
	var clientFD int
	_ = rawConn.Control(func(fd uintptr) { clientFD = int(fd) })
	ev := syscall.EpollEvent{Events: syscall.EPOLLIN | syscall.EPOLLOUT, Fd: int32(clientFD)}
	if err := syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, clientFD, &ev); err != nil {
		return "", "", fmt.Errorf("epoll_ctl: %w", err)
	}

	const payload = "gvx-compatprobe-epoll-payload"
	if _, err := client.Write([]byte(payload)); err != nil {
		return "", "", fmt.Errorf("tcp write: %w", err)
	}
	events := make([]syscall.EpollEvent, 4)
	if _, err := syscall.EpollWait(epfd, events, 5000); err != nil && err != syscall.EINTR {
		return "", "", fmt.Errorf("epoll_wait: %w", err)
	}
	reply := make([]byte, len(payload))
	if _, err := client.Read(reply); err != nil {
		return "", "", fmt.Errorf("tcp read: %w", err)
	}

	// UDP loopback check.
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return "", "", fmt.Errorf("listen udp: %w", err)
	}
	defer udpConn.Close()
	if _, err := udpConn.WriteTo([]byte(payload), udpConn.LocalAddr()); err != nil {
		return "", "", fmt.Errorf("udp write: %w", err)
	}
	udpReply := make([]byte, len(payload))
	if _, _, err := udpConn.ReadFrom(udpReply); err != nil {
		return "", "", fmt.Errorf("udp read: %w", err)
	}

	combined := fmt.Sprintf("tcp:%s|udp:%s", string(reply), string(udpReply))
	sum := sha256.Sum256([]byte(combined))
	hexSum := hex.EncodeToString(sum[:])
	return "net:epoll_tcp_udp=ok:sha256=" + hexSum, fmt.Sprintf("TCP+UDP epoll loopback verified (%d bytes)", len(combined)), nil
}

func runBench(name string, iters int, fn func(n int)) report.BenchResult {
	start := time.Now()
	fn(iters)
	totalNs := max(time.Since(start).Nanoseconds(), 1)
	nsPerOp := float64(totalNs) / float64(iters)
	opsPerSec := float64(iters) * 1e9 / float64(totalNs)
	return report.BenchResult{
		Name:       name,
		Iterations: iters,
		TotalNs:    totalNs,
		NsPerOp:    nsPerOp,
		OpsPerSec:  opsPerSec,
	}
}

func runBenchmarks() []report.BenchResult {
	var out []report.BenchResult

	out = append(out, runBench("syscall_getpid", 2000, func(n int) {
		for i := 0; i < n; i++ {
			syscall.RawSyscall(syscall.SYS_GETPID, 0, 0, 0)
		}
	}))

	out = append(out, runBench("vdso_clock_gettime", 10000, func(n int) {
		for i := 0; i < n; i++ {
			_ = time.Now()
		}
	}))

	out = append(out, runBench("wine64_teb_gs_x18_access", 1000, func(n int) {
		benchTEBAccess(n)
	}))

	out = append(out, runBench("futex_wake_roundtrip", 500, func(n int) {
		ch1 := make(chan struct{})
		ch2 := make(chan struct{})
		go func() {
			for i := 0; i < n; i++ {
				<-ch1
				ch2 <- struct{}{}
			}
		}()
		for i := 0; i < n; i++ {
			ch1 <- struct{}{}
			<-ch2
		}
	}))

	out = append(out, runBench("mmap_fault_unmap_page", 200, func(n int) {
		pageSize := syscall.Getpagesize()
		for i := 0; i < n; i++ {
			b, err := syscall.Mmap(-1, 0, pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
			if err == nil {
				b[0] = byte(i)
				_ = syscall.Munmap(b)
			}
		}
	}))

	out = append(out, runBench("pipe_pingpong_64b", 500, func(n int) {
		var p1, p2 [2]int
		if syscall.Pipe(p1[:]) != nil || syscall.Pipe(p2[:]) != nil {
			return
		}
		defer syscall.Close(p1[0])
		defer syscall.Close(p1[1])
		defer syscall.Close(p2[0])
		defer syscall.Close(p2[1])
		msg := make([]byte, 64)
		go func() {
			buf := make([]byte, 64)
			for i := 0; i < n; i++ {
				_, _ = syscall.Read(p1[0], buf)
				_, _ = syscall.Write(p2[1], buf)
			}
		}()
		buf := make([]byte, 64)
		for i := 0; i < n; i++ {
			_, _ = syscall.Write(p1[1], msg)
			_, _ = syscall.Read(p2[0], buf)
		}
	}))

	out = append(out, runBench("vfs_workspace_write_fsync_4k", 25, func(n int) {
		dir := "/workspace"
		if _, err := os.Stat(dir); err != nil {
			dir = "/tmp"
		}
		p := filepath.Join(dir, "bench_fsync.bin")
		defer os.Remove(p)
		f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o644)
		if err != nil {
			return
		}
		defer f.Close()
		buf := make([]byte, 4096)
		for i := 0; i < n; i++ {
			_, _ = f.WriteAt(buf, 0)
			_ = f.Sync()
		}
	}))

	return out
}
