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

// Package testelf synthesizes tiny Linux ELF64 guest executables for tests.
// The programs use raw system calls, so they need no libc or dynamic loader.
package testelf

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
)

const pageSize4K = 4096

// BuildGuestELF64 synthesizes a valid static Linux ELF64 executable for
// targetArch ("arm64" or "amd64") that writes stdoutText to fd 1 via SYS_WRITE
// and terminates with exitCode via SYS_EXIT_GROUP.
func BuildGuestELF64(targetArch string, exitCode int, stdoutText string) ([]byte, error) {
	return BuildGuestELF64At(targetArch, 0x400000, exitCode, stdoutText)
}

// BuildGuestELF64At is like BuildGuestELF64 but links the ET_EXEC image at
// baseVA. The code is position independent, so any page-aligned baseVA that
// the execution backend allows as a guest address works. The systrap backend
// on macOS needs a baseVA above the host reservations of the process.
func BuildGuestELF64At(targetArch string, baseVA uint64, exitCode int, stdoutText string) ([]byte, error) {
	return buildELF64Binary(targetArch, baseVA, exitCode, stdoutText, false)
}

// BuildDynamicGuestELF64 synthesizes a valid PIE (ET_DYN) Linux ELF64
// executable for targetArch ("arm64" or "amd64") that exercises 4KB anonymous
// mmap, writes stdoutText to fd 1, and exits with exitCode.
func BuildDynamicGuestELF64(targetArch string, exitCode int, stdoutText string) ([]byte, error) {
	return buildELF64Binary(targetArch, 0, exitCode, stdoutText, true)
}

func buildELF64Binary(targetArch string, staticBaseVA uint64, exitCode int, stdoutText string, isDynamic bool) ([]byte, error) {
	const (
		codeOffset = 0x100
		msgOffset  = 0x200
	)

	baseVA := staticBaseVA
	elfType := uint16(elf.ET_EXEC)
	if isDynamic {
		baseVA = 0
		elfType = uint16(elf.ET_DYN)
	}

	var code []byte
	var machine uint16

	switch targetArch {
	case "arm64", "aarch64":
		machine = uint16(elf.EM_AARCH64)
		var words []uint32
		if isDynamic {
			// Exercise anonymous 4KB mmap: SYS_mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
			words = append(words,
				0xd2800000, // MOVZ X0, #0
				0xd2820001, // MOVZ X1, #4096
				0xd2800062, // MOVZ X2, #3 (PROT_READ|PROT_WRITE)
				0xd2800443, // MOVZ X3, #0x22 (MAP_PRIVATE|MAP_ANONYMOUS)
				0x92800004, // MOVN X4, #0 (-1)
				0xd2800005, // MOVZ X5, #0
				0xd2801bc8, // MOVZ X8, #222 (SYS_mmap)
				0xd4000001, // SVC #0
			)
		}
		if len(stdoutText) > 0 {
			// MOVZ X0, #1 (fd = stdout)
			words = append(words, 0xd2800020)
			// PC-relative ADR X1, #delta to msgOffset so PIE works at any load bias
			curOff := codeOffset + len(words)*4
			delta := uint32(msgOffset - curOff)
			words = append(words, 0x10000001|((delta>>2)<<5))
			// MOVZ X2, #len(stdoutText)
			words = append(words, 0xd2800002|(uint32(len(stdoutText)&0xffff)<<5))
			// MOVZ X8, #64 (SYS_write on arm64)
			words = append(words, 0xd2800808)
			// SVC #0
			words = append(words, 0xd4000001)
		}
		// MOVZ X0, #exitCode
		words = append(words, 0xd2800000|(uint32(exitCode&0xffff)<<5))
		// MOVZ X8, #94 (SYS_exit_group on arm64)
		words = append(words, 0xd2800bc8)
		// SVC #0
		words = append(words, 0xd4000001)

		code = encodeARM64Words(words)

	case "amd64", "x86_64":
		machine = uint16(elf.EM_X86_64)
		if isDynamic {
			// SYS_mmap(0, 4096, 3, 0x22, -1, 0)
			code = append(code,
				0x48, 0x31, 0xff, // XOR RDI, RDI
				0x48, 0xc7, 0xc6, 0x00, 0x10, 0x00, 0x00, // MOV RSI, 4096
				0x48, 0xc7, 0xc2, 0x03, 0x00, 0x00, 0x00, // MOV RDX, 3
				0x49, 0xc7, 0xc2, 0x22, 0x00, 0x00, 0x00, // MOV R10, 0x22
				0x49, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, // MOV R8, -1
				0x4d, 0x31, 0xc9, // XOR R9, R9
				0x48, 0xc7, 0xc0, 0x09, 0x00, 0x00, 0x00, // MOV RAX, 9 (SYS_mmap)
				0x0f, 0x05, // SYSCALL
			)
		}
		if len(stdoutText) > 0 {
			// MOV RDI, 1 (48 c7 c7 01 00 00 00)
			code = append(code, 0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00)
			// PC-relative LEA RSI, [RIP + disp32] (48 8d 35 <disp32>)
			nextRIP := codeOffset + len(code) + 7
			disp32 := uint32(int32(msgOffset - nextRIP))
			var lea [7]byte
			lea[0] = 0x48
			lea[1] = 0x8d
			lea[2] = 0x35
			binary.LittleEndian.PutUint32(lea[3:7], disp32)
			code = append(code, lea[:]...)
			// MOV RDX, len (48 c7 c2 <imm32>)
			var rdx [7]byte
			rdx[0] = 0x48
			rdx[1] = 0xc7
			rdx[2] = 0xc2
			binary.LittleEndian.PutUint32(rdx[3:7], uint32(len(stdoutText)))
			code = append(code, rdx[:]...)
			// MOV RAX, 1 (SYS_write on amd64)
			code = append(code, 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00)
			// SYSCALL (0f 05)
			code = append(code, 0x0f, 0x05)
		}
		// MOV RDI, exitCode (48 c7 c7 <imm32>)
		var rdi [7]byte
		rdi[0] = 0x48
		rdi[1] = 0xc7
		rdi[2] = 0xc7
		binary.LittleEndian.PutUint32(rdi[3:7], uint32(exitCode))
		code = append(code, rdi[:]...)
		// MOV RAX, 231 (SYS_exit_group on amd64)
		code = append(code, 0x48, 0xc7, 0xc0, 0xe7, 0x00, 0x00, 0x00)
		// SYSCALL (0f 05)
		code = append(code, 0x0f, 0x05)

	default:
		return nil, fmt.Errorf("gvx: unsupported ELF64 target architecture %q", targetArch)
	}

	img := makeSingleSegmentELF64(elfType, machine, baseVA, uint32(elf.PF_R|elf.PF_X))
	copy(img[codeOffset:], code)
	copy(img[msgOffset:], stdoutText)
	return img, nil
}

// BuildGuestCatELF64 synthesizes a position-independent (ET_DYN) Linux ELF64 executable for targetArch
// ("arm64" or "amd64") that iterates over argv[1..], opens each file via
// SYS_openat, copies its contents to stdout via SYS_read and SYS_write, and
// exits with status 0 (or 1 if any file cannot be opened).
func BuildGuestCatELF64(targetArch string) ([]byte, error) {
	const codeOffset = 0x100
	var code []byte
	var machine uint16

	switch targetArch {
	case "arm64", "aarch64":
		machine = uint16(elf.EM_AARCH64)
		relLoop := int32(-23)
		bLoop := uint32(relLoop) & 0x03ffffff
		words := []uint32{
			0x910043f3,             // 0: ADD X19, SP, #16 (&argv[1])
			0xd11003ff,             // 1: SUB SP, SP, #1024
			0xf9400261,             // 2 (loop): LDR X1, [X19]
			0x91002273,             // 3: ADD X19, X19, #8
			0xb4000001 | (22 << 5), // 4: CBZ X1, done_ok (26)
			0x92800c60,             // 5: MOVN X0, #99 (AT_FDCWD = -100)
			0xd2800002,             // 6: MOVZ X2, #0 (O_RDONLY)
			0xd2800003,             // 7: MOVZ X3, #0
			0xd2800708,             // 8: MOVZ X8, #56 (SYS_openat)
			0xd4000001,             // 9: SVC #0
			0xb7f80000 | (19 << 5), // 10: TBNZ X0, #63, done_err (29)
			0xaa0003f4,             // 11: MOV X20, X0 (fd)
			0x910003e1,             // 12: MOV X1, SP
			0xd2808002,             // 13: MOVZ X2, #1024
			0xd28007e8,             // 14: MOVZ X8, #63 (SYS_read)
			0xd4000001,             // 15: SVC #0
			0xb7f80000 | (13 << 5), // 16: TBNZ X0, #63, done_err (29)
			0xaa0003e2,             // 17: MOV X2, X0
			0xd2800020,             // 18: MOVZ X0, #1 (stdout)
			0x910003e1,             // 19: MOV X1, SP
			0xd2800808,             // 20: MOVZ X8, #64 (SYS_write)
			0xd4000001,             // 21: SVC #0
			0xaa1403e0,             // 22: MOV X0, X20 (fd)
			0xd2800728,             // 23: MOVZ X8, #57 (SYS_close)
			0xd4000001,             // 24: SVC #0
			0x14000000 | bLoop,     // 25: B loop (2)
			0xd2800000,             // 26 (done_ok): MOVZ X0, #0
			0xd2800bc8,             // 27: MOVZ X8, #94 (SYS_exit_group)
			0xd4000001,             // 28: SVC #0
			0xd2800020,             // 29 (done_err): MOVZ X0, #1
			0xd2800bc8,             // 30: MOVZ X8, #94 (SYS_exit_group)
			0xd4000001,             // 31: SVC #0
		}
		code = encodeARM64Words(words)

	case "amd64", "x86_64":
		machine = uint16(elf.EM_X86_64)
		// Assemble loop with exact branch displacements.
		code = append(code,
			0x48, 0x8d, 0x5c, 0x24, 0x10, // LEA RBX, [RSP+16]
			0x48, 0x81, 0xec, 0x00, 0x04, 0x00, 0x00, // SUB RSP, 1024
		)
		loopPos := len(code)
		code = append(code,
			0x48, 0x8b, 0x33, // MOV RSI, [RBX]
			0x48, 0x83, 0xc3, 0x08, // ADD RBX, 8
			0x48, 0x85, 0xf6, // TEST RSI, RSI
		)
		jzDoneOkPos := len(code)
		code = append(code, 0x0f, 0x84, 0, 0, 0, 0) // JZ done_ok
		code = append(code,
			0x48, 0xc7, 0xc7, 0x9c, 0xff, 0xff, 0xff, // MOV RDI, -100 (AT_FDCWD)
			0x48, 0x31, 0xd2, // XOR RDX, RDX (O_RDONLY)
			0x4d, 0x31, 0xd2, // XOR R10, R10
			0x48, 0xc7, 0xc0, 0x01, 0x01, 0x00, 0x00, // MOV RAX, 257 (SYS_openat)
			0x0f, 0x05, // SYSCALL
			0x48, 0x85, 0xc0, // TEST RAX, RAX
		)
		jsErr1Pos := len(code)
		code = append(code, 0x0f, 0x88, 0, 0, 0, 0) // JS done_err
		code = append(code,
			0x49, 0x89, 0xc4, // MOV R12, RAX
			0x4c, 0x89, 0xe7, // MOV RDI, R12
			0x48, 0x89, 0xe6, // MOV RSI, RSP
			0x48, 0xc7, 0xc2, 0x00, 0x04, 0x00, 0x00, // MOV RDX, 1024
			0x48, 0x31, 0xc0, // XOR RAX, RAX (SYS_read)
			0x0f, 0x05, // SYSCALL
			0x48, 0x85, 0xc0, // TEST RAX, RAX
		)
		jsErr2Pos := len(code)
		code = append(code, 0x0f, 0x88, 0, 0, 0, 0) // JS done_err
		code = append(code,
			0x48, 0x89, 0xc2, // MOV RDX, RAX
			0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, // MOV RDI, 1
			0x48, 0x89, 0xe6, // MOV RSI, RSP
			0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // MOV RAX, 1 (SYS_write)
			0x0f, 0x05, // SYSCALL
			0x4c, 0x89, 0xe7, // MOV RDI, R12
			0x48, 0xc7, 0xc0, 0x03, 0x00, 0x00, 0x00, // MOV RAX, 3 (SYS_close)
			0x0f, 0x05, // SYSCALL
		)
		jmpLoopPos := len(code)
		code = append(code, 0xe9, 0, 0, 0, 0) // JMP loop
		binary.LittleEndian.PutUint32(code[jmpLoopPos+1:jmpLoopPos+5], uint32(int32(loopPos-(jmpLoopPos+5))))

		doneOkPos := len(code)
		binary.LittleEndian.PutUint32(code[jzDoneOkPos+2:jzDoneOkPos+6], uint32(int32(doneOkPos-(jzDoneOkPos+6))))
		code = append(code,
			0x48, 0x31, 0xff, // XOR RDI, RDI
			0x48, 0xc7, 0xc0, 0xe7, 0x00, 0x00, 0x00, // MOV RAX, 231 (SYS_exit_group)
			0x0f, 0x05, // SYSCALL
		)

		doneErrPos := len(code)
		binary.LittleEndian.PutUint32(code[jsErr1Pos+2:jsErr1Pos+6], uint32(int32(doneErrPos-(jsErr1Pos+6))))
		binary.LittleEndian.PutUint32(code[jsErr2Pos+2:jsErr2Pos+6], uint32(int32(doneErrPos-(jsErr2Pos+6))))
		code = append(code,
			0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, // MOV RDI, 1
			0x48, 0xc7, 0xc0, 0xe7, 0x00, 0x00, 0x00, // MOV RAX, 231 (SYS_exit_group)
			0x0f, 0x05, // SYSCALL
		)

	default:
		return nil, fmt.Errorf("gvx: unsupported ELF64 target architecture %q", targetArch)
	}

	img := makeSingleSegmentELF64(uint16(elf.ET_DYN), machine, 0, uint32(elf.PF_R|elf.PF_X))
	copy(img[codeOffset:], code)
	return img, nil
}

// BuildGuestWriteFileELF64 synthesizes a position-independent (ET_DYN) Linux ELF64 executable for
// targetArch ("arm64" or "amd64") that creates guestPath with SYS_openat
// (O_WRONLY|O_CREAT|O_TRUNC, mode 0644), writes content with SYS_write, closes
// the file, and exits with status 0. It exits with status 1 when openat fails
// and with status 2 when write returns a short count or an error.
func BuildGuestWriteFileELF64(targetArch, guestPath, content string) ([]byte, error) {
	const (
		codeOffset = 0x100
		pathOff    = 0x500
		contentOff = 0x580
		maxPathLen = contentOff - pathOff - 1
		maxContent = pageSize4K - contentOff - 1
	)
	if len(guestPath) == 0 || len(guestPath) > maxPathLen {
		return nil, fmt.Errorf("gvx: guest path length %d outside 1..%d", len(guestPath), maxPathLen)
	}
	if len(content) > maxContent {
		return nil, fmt.Errorf("gvx: content length %d exceeds %d", len(content), maxContent)
	}

	var code []byte
	var machine uint16
	switch targetArch {
	case "arm64", "aarch64":
		machine = uint16(elf.EM_AARCH64)
		var words []uint32
		// adr emits ADR Xreg, <image offset>, which keeps the image position independent.
		adr := func(reg uint32, imageOff int) {
			delta := uint32(imageOff - (codeOffset + len(words)*4))
			words = append(words, 0x10000000|reg|(((delta>>2)&0x7ffff)<<5)|((delta&3)<<29))
		}
		words = append(words, 0x92800c60) // MOVN X0, #99 (AT_FDCWD = -100)
		adr(1, pathOff)
		words = append(words,
			0xd2804822, // MOVZ X2, #0x241 (O_WRONLY|O_CREAT|O_TRUNC)
			0xd2803483, // MOVZ X3, #0x1a4 (0644)
			0xd2800708, // MOVZ X8, #56 (SYS_openat)
			0xd4000001, // SVC #0
		)
		tbnzPos := len(words)
		words = append(words, 0xb7f80000, // TBNZ X0, #63, err_open (patched)
			0xaa0003f3, // MOV X19, X0 (fd)
		)
		adr(1, contentOff)
		words = append(words,
			0xd2800002|(uint32(len(content))<<5), // MOVZ X2, #len
			0xd2800808,                           // MOVZ X8, #64 (SYS_write)
			0xd4000001,                           // SVC #0
			0xf100001f|(uint32(len(content))<<10), // CMP X0, #len
		)
		bnePos := len(words)
		words = append(words, 0x54000001, // B.NE err_write (patched)
			0xaa1303e0, // MOV X0, X19
			0xd2800728, // MOVZ X8, #57 (SYS_close)
			0xd4000001, // SVC #0
			0xd2800000, // MOVZ X0, #0
			0xd2800bc8, // MOVZ X8, #94 (SYS_exit_group)
			0xd4000001, // SVC #0
		)
		errOpenPos := len(words)
		words = append(words,
			0xd2800020, // MOVZ X0, #1
			0xd2800bc8, // MOVZ X8, #94
			0xd4000001, // SVC #0
		)
		errWritePos := len(words)
		words = append(words,
			0xd2800040, // MOVZ X0, #2
			0xd2800bc8, // MOVZ X8, #94
			0xd4000001, // SVC #0
		)
		words[tbnzPos] |= uint32(errOpenPos-tbnzPos) << 5
		words[bnePos] |= uint32(errWritePos-bnePos) << 5
		code = encodeARM64Words(words)

	case "amd64", "x86_64":
		machine = uint16(elf.EM_X86_64)
		movImm32 := func(prefix1, prefix2 byte, val uint32) {
			var b [7]byte
			b[0] = prefix1
			b[1] = 0xc7
			b[2] = prefix2
			binary.LittleEndian.PutUint32(b[3:7], val)
			code = append(code, b[:]...)
		}
		// leaRSI emits LEA RSI, [RIP + disp32] for an image offset.
		leaRSI := func(imageOff int) {
			var b [7]byte
			b[0], b[1], b[2] = 0x48, 0x8d, 0x35
			binary.LittleEndian.PutUint32(b[3:7], uint32(int32(imageOff-(codeOffset+len(code)+7))))
			code = append(code, b[:]...)
		}
		movImm32(0x48, 0xc7, ^uint32(99)) // MOV RDI, -100 (AT_FDCWD)
		leaRSI(pathOff)
		movImm32(0x48, 0xc2, 0x241)           // MOV RDX, O_WRONLY|O_CREAT|O_TRUNC
		movImm32(0x49, 0xc2, 0o644)           // MOV R10, 0644
		movImm32(0x48, 0xc0, 257)             // MOV RAX, 257 (SYS_openat)
		code = append(code, 0x0f, 0x05)       // SYSCALL
		code = append(code, 0x48, 0x85, 0xc0) // TEST RAX, RAX
		jsPos := len(code)
		code = append(code, 0x0f, 0x88, 0, 0, 0, 0) // JS err_open
		code = append(code, 0x49, 0x89, 0xc4)       // MOV R12, RAX (fd)
		code = append(code, 0x4c, 0x89, 0xe7)       // MOV RDI, R12
		leaRSI(contentOff)
		movImm32(0x48, 0xc2, uint32(len(content)))
		movImm32(0x48, 0xc0, 1)                                                          // MOV RAX, 1 (SYS_write)
		code = append(code, 0x0f, 0x05)                                                  // SYSCALL
		code = append(code, 0x48, 0x3d, byte(len(content)), byte(len(content)>>8), 0, 0) // CMP RAX, len
		jnePos := len(code)
		code = append(code, 0x0f, 0x85, 0, 0, 0, 0) // JNE err_write
		code = append(code, 0x4c, 0x89, 0xe7)       // MOV RDI, R12
		movImm32(0x48, 0xc0, 3)                     // MOV RAX, 3 (SYS_close)
		code = append(code, 0x0f, 0x05)             // SYSCALL
		code = append(code, 0x48, 0x31, 0xff)       // XOR RDI, RDI
		movImm32(0x48, 0xc0, 231)                   // MOV RAX, 231 (SYS_exit_group)
		code = append(code, 0x0f, 0x05)             // SYSCALL
		errOpenPos := len(code)
		movImm32(0x48, 0xc7, 1) // MOV RDI, 1
		movImm32(0x48, 0xc0, 231)
		code = append(code, 0x0f, 0x05)
		errWritePos := len(code)
		movImm32(0x48, 0xc7, 2) // MOV RDI, 2
		movImm32(0x48, 0xc0, 231)
		code = append(code, 0x0f, 0x05)
		binary.LittleEndian.PutUint32(code[jsPos+2:jsPos+6], uint32(int32(errOpenPos-(jsPos+6))))
		binary.LittleEndian.PutUint32(code[jnePos+2:jnePos+6], uint32(int32(errWritePos-(jnePos+6))))

	default:
		return nil, fmt.Errorf("gvx: unsupported ELF64 target architecture %q", targetArch)
	}

	img := makeSingleSegmentELF64(uint16(elf.ET_DYN), machine, 0, uint32(elf.PF_R|elf.PF_W|elf.PF_X))
	copy(img[codeOffset:], code)
	copy(img[pathOff:], guestPath)
	copy(img[contentOff:], content)
	return img, nil
}

// BuildGuestHTTPServerELF64 synthesizes a static Linux ELF64 executable for
// targetArch ("arm64" or "amd64") that optionally writes workspaceOutContent to
// workspaceOutPath via SYS_openat/SYS_write, reads serveFilePath from the guest
// rootfs via SYS_openat/SYS_read, binds a TCP listener on port via
// SYS_socket/SYS_bind/SYS_listen, accepts one HTTP request via SYS_accept,
// replies with an HTTP 200 response containing the file body, and exits 0.
func BuildGuestHTTPServerELF64(targetArch string, port uint16, serveFilePath string, workspaceOutPath string, workspaceOutContent string) ([]byte, error) {
	return BuildGuestHTTPServerELF64At(targetArch, 0x400000, port, serveFilePath, workspaceOutPath, workspaceOutContent)
}

// BuildGuestHTTPServerELF64At is like BuildGuestHTTPServerELF64 but links the
// image at baseVA. Both codes reach any 48-bit baseVA.
func BuildGuestHTTPServerELF64At(targetArch string, baseVA uint64, port uint16, serveFilePath string, workspaceOutPath string, workspaceOutContent string) ([]byte, error) {
	if baseVA >= 1<<48 {
		return nil, fmt.Errorf("testelf: baseVA %#x is above the 48-bit address space", baseVA)
	}
	const (
		codeOffset     = 0x100
		wsPathOff      = 0x500
		wsContentOff   = 0x580
		servePathOff   = 0x600
		sockaddrOff    = 0x680
		httpRespOff    = 0x700
		httpHeaderText = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"
		httpHeaderLen  = uint64(len(httpHeaderText)) // 38
		httpBodyOff    = uint64(httpRespOff) + httpHeaderLen
		reqScratchOff  = 0xb00
	)

	var code []byte
	var machine uint16

	switch targetArch {
	case "arm64", "aarch64":
		machine = uint16(elf.EM_AARCH64)
		var words []uint32
		loadAddr := func(reg uint32, addr uint64) {
			words = append(words,
				0xd2800000|reg|(uint32(addr&0xffff)<<5),
				0xf2a00000|reg|(uint32((addr>>16)&0xffff)<<5),
			)
			if addr>>32 != 0 {
				words = append(words, 0xf2c00000|reg|(uint32((addr>>32)&0xffff)<<5)) // MOVK lsl 32
			}
		}

		if workspaceOutPath != "" {
			// SYS_openat(AT_FDCWD=-100, wsPathVA, O_WRONLY|O_CREAT|O_TRUNC=0x241, 0644=0x1a4)
			words = append(words, 0x92800c60) // MOVN X0, #99 (-100)
			loadAddr(1, baseVA+wsPathOff)
			words = append(words,
				0xd2804822, // MOVZ X2, #0x241
				0xd2803483, // MOVZ X3, #0x1a4
				0xd2800708, // MOVZ X8, #56 (SYS_openat)
				0xd4000001, // SVC #0
				0xaa0003f3, // MOV X19, X0 (fd)
			)
			loadAddr(1, baseVA+wsContentOff)
			words = append(words,
				0xd2800002|(uint32(len(workspaceOutContent)&0xffff)<<5), // MOVZ X2, #len
				0xd2800808, // MOVZ X8, #64 (SYS_write)
				0xd4000001, // SVC #0
				0xaa1303e0, // MOV X0, X19
				0xd2800728, // MOVZ X8, #57 (SYS_close)
				0xd4000001, // SVC #0
			)
		}

		// Read serveFilePath into baseVA + httpBodyOff.
		words = append(words, 0x92800c60) // MOVN X0, #99 (-100)
		loadAddr(1, baseVA+servePathOff)
		words = append(words,
			0xd2800002, // MOVZ X2, #0 (O_RDONLY)
			0xd2800003, // MOVZ X3, #0
			0xd2800708, // MOVZ X8, #56 (SYS_openat)
			0xd4000001, // SVC #0
			0xaa0003f3, // MOV X19, X0 (fd)
		)
		loadAddr(1, baseVA+httpBodyOff)
		words = append(words,
			0xd2804002, // MOVZ X2, #512
			0xd28007e8, // MOVZ X8, #63 (SYS_read)
			0xd4000001, // SVC #0
			0xaa0003f5, // MOV X21, X0 (bodyLen)
			0xaa1303e0, // MOV X0, X19
			0xd2800728, // MOVZ X8, #57 (SYS_close)
			0xd4000001, // SVC #0
		)

		// SYS_socket(AF_INET=2, SOCK_STREAM=1, 0)
		words = append(words,
			0xd2800040, // MOVZ X0, #2
			0xd2800021, // MOVZ X1, #1
			0xd2800002, // MOVZ X2, #0
			0xd28018c8, // MOVZ X8, #198 (SYS_socket)
			0xd4000001, // SVC #0
			0xaa0003f3, // MOV X19, X0 (listenFD)
		)
		// SYS_bind(listenFD, sockaddrVA, 16)
		loadAddr(1, baseVA+sockaddrOff)
		words = append(words,
			0xd2800202, // MOVZ X2, #16
			0xd2801908, // MOVZ X8, #200 (SYS_bind)
			0xd4000001, // SVC #0
			// SYS_listen(listenFD, 8)
			0xaa1303e0, // MOV X0, X19
			0xd2800101, // MOVZ X1, #8
			0xd2801928, // MOVZ X8, #201 (SYS_listen)
			0xd4000001, // SVC #0
			// SYS_accept(listenFD, 0, 0)
			0xaa1303e0, // MOV X0, X19
			0xd2800001, // MOVZ X1, #0
			0xd2800002, // MOVZ X2, #0
			0xd2801948, // MOVZ X8, #202 (SYS_accept)
			0xd4000001, // SVC #0
			0xaa0003f4, // MOV X20, X0 (connFD)
		)
		// SYS_read(connFD, reqScratchVA, 512)
		loadAddr(1, baseVA+reqScratchOff)
		words = append(words,
			0xd2804002, // MOVZ X2, #512
			0xd28007e8, // MOVZ X8, #63 (SYS_read)
			0xd4000001, // SVC #0
			// SYS_write(connFD, httpRespVA, httpHeaderLen + bodyLen)
			0xaa1403e0, // MOV X0, X20
		)
		loadAddr(1, baseVA+httpRespOff)
		words = append(words,
			0x91009aa2, // ADD X2, X21, #38 (httpHeaderLen)
			0xd2800808, // MOVZ X8, #64 (SYS_write)
			0xd4000001, // SVC #0
			// SYS_close(connFD) & SYS_close(listenFD) & SYS_exit_group(0)
			0xaa1403e0, // MOV X0, X20
			0xd2800728, // MOVZ X8, #57 (SYS_close)
			0xd4000001, // SVC #0
			0xaa1303e0, // MOV X0, X19
			0xd2800728, // MOVZ X8, #57 (SYS_close)
			0xd4000001, // SVC #0
			0xd2800000, // MOVZ X0, #0
			0xd2800bc8, // MOVZ X8, #94 (SYS_exit_group)
			0xd4000001, // SVC #0
		)
		code = encodeARM64Words(words)

	case "amd64", "x86_64":
		machine = uint16(elf.EM_X86_64)
		movImm32 := func(prefix1, prefix2 byte, val uint32) {
			var b [7]byte
			b[0] = prefix1
			b[1] = 0xc7
			b[2] = prefix2
			binary.LittleEndian.PutUint32(b[3:7], val)
			code = append(code, b[:]...)
		}
		// movAddr loads a 64-bit address into RSI with MOVABS.
		movAddr := func(val uint64) {
			code = append(code, 0x48, 0xbe)
			code = binary.LittleEndian.AppendUint64(code, val)
		}

		if workspaceOutPath != "" {
			movImm32(0x48, 0xc7, ^uint32(99))     // MOV RDI, -100
			movAddr(baseVA + wsPathOff)           // MOV RSI, wsPathVA
			movImm32(0x48, 0xc2, 0x241)           // MOV RDX, O_WRONLY|O_CREAT|O_TRUNC
			movImm32(0x49, 0xc2, 0o644)           // MOV R10, 0644
			movImm32(0x48, 0xc0, 257)             // MOV RAX, 257 (SYS_openat)
			code = append(code, 0x0f, 0x05)       // SYSCALL
			code = append(code, 0x49, 0x89, 0xc4) // MOV R12, RAX
			code = append(code, 0x4c, 0x89, 0xe7) // MOV RDI, R12
			movAddr(baseVA + wsContentOff)
			movImm32(0x48, 0xc2, uint32(len(workspaceOutContent)))
			movImm32(0x48, 0xc0, 1)               // MOV RAX, 1 (SYS_write)
			code = append(code, 0x0f, 0x05)       // SYSCALL
			code = append(code, 0x4c, 0x89, 0xe7) // MOV RDI, R12
			movImm32(0x48, 0xc0, 3)               // MOV RAX, 3 (SYS_close)
			code = append(code, 0x0f, 0x05)       // SYSCALL
		}

		// Read serveFilePath into baseVA + httpBodyOff.
		movImm32(0x48, 0xc7, ^uint32(99))
		movAddr(baseVA + servePathOff)
		code = append(code, 0x48, 0x31, 0xd2, 0x4d, 0x31, 0xd2) // XOR RDX, RDX; XOR R10, R10
		movImm32(0x48, 0xc0, 257)                               // SYS_openat
		code = append(code, 0x0f, 0x05)
		code = append(code, 0x49, 0x89, 0xc4) // MOV R12, RAX (fd)
		code = append(code, 0x4c, 0x89, 0xe7) // MOV RDI, R12
		movAddr(baseVA + httpBodyOff)
		movImm32(0x48, 0xc2, 512)
		code = append(code, 0x48, 0x31, 0xc0, 0x0f, 0x05) // SYS_read
		code = append(code, 0x49, 0x89, 0xc5)             // MOV R13, RAX (bodyLen)
		code = append(code, 0x4c, 0x89, 0xe7)             // MOV RDI, R12
		movImm32(0x48, 0xc0, 3)                           // SYS_close
		code = append(code, 0x0f, 0x05)

		// SYS_socket(2, 1, 0)
		movImm32(0x48, 0xc7, 2)
		movImm32(0x48, 0xc6, 1)
		code = append(code, 0x48, 0x31, 0xd2)
		movImm32(0x48, 0xc0, 41) // SYS_socket
		code = append(code, 0x0f, 0x05)
		code = append(code, 0x49, 0x89, 0xc4) // MOV R12, RAX (listenFD)

		// SYS_bind(listenFD, sockaddrVA, 16)
		code = append(code, 0x4c, 0x89, 0xe7)
		movAddr(baseVA + sockaddrOff)
		movImm32(0x48, 0xc2, 16)
		movImm32(0x48, 0xc0, 49) // SYS_bind
		code = append(code, 0x0f, 0x05)

		// SYS_listen(listenFD, 8)
		code = append(code, 0x4c, 0x89, 0xe7)
		movImm32(0x48, 0xc6, 8)
		movImm32(0x48, 0xc0, 50) // SYS_listen
		code = append(code, 0x0f, 0x05)

		// SYS_accept(listenFD, 0, 0)
		code = append(code, 0x4c, 0x89, 0xe7, 0x48, 0x31, 0xf6, 0x48, 0x31, 0xd2)
		movImm32(0x48, 0xc0, 43) // SYS_accept
		code = append(code, 0x0f, 0x05)
		code = append(code, 0x49, 0x89, 0xc6) // MOV R14, RAX (connFD)

		// SYS_read(connFD, reqScratchVA, 512)
		code = append(code, 0x4c, 0x89, 0xf7) // MOV RDI, R14
		movAddr(baseVA + reqScratchOff)
		movImm32(0x48, 0xc2, 512)
		code = append(code, 0x48, 0x31, 0xc0, 0x0f, 0x05)

		// SYS_write(connFD, httpRespVA, 38 + R13)
		code = append(code, 0x4c, 0x89, 0xf7) // MOV RDI, R14
		movAddr(baseVA + httpRespOff)
		code = append(code, 0x4c, 0x89, 0xea)     // MOV RDX, R13
		code = append(code, 0x48, 0x83, 0xc2, 38) // ADD RDX, 38
		movImm32(0x48, 0xc0, 1)                   // SYS_write
		code = append(code, 0x0f, 0x05)

		// Close connFD, listenFD, and exit(0).
		code = append(code, 0x4c, 0x89, 0xf7)
		movImm32(0x48, 0xc0, 3)
		code = append(code, 0x0f, 0x05)
		code = append(code, 0x4c, 0x89, 0xe7)
		movImm32(0x48, 0xc0, 3)
		code = append(code, 0x0f, 0x05)
		code = append(code, 0x48, 0x31, 0xff)
		movImm32(0x48, 0xc0, 231)
		code = append(code, 0x0f, 0x05)

	default:
		return nil, fmt.Errorf("gvx: unsupported ELF64 target architecture %q", targetArch)
	}

	img := makeSingleSegmentELF64(uint16(elf.ET_EXEC), machine, baseVA, uint32(elf.PF_R|elf.PF_W|elf.PF_X))
	copy(img[codeOffset:], code)
	if workspaceOutPath != "" {
		copy(img[wsPathOff:], workspaceOutPath)
		copy(img[wsContentOff:], workspaceOutContent)
	}
	copy(img[servePathOff:], serveFilePath)
	// Populate sockaddr_in (AF_INET = 2, port in network byte order, INADDR_ANY = 0).
	binary.LittleEndian.PutUint16(img[sockaddrOff+0:sockaddrOff+2], 2)
	binary.BigEndian.PutUint16(img[sockaddrOff+2:sockaddrOff+4], port)
	copy(img[httpRespOff:], httpHeaderText)
	return img, nil
}

func encodeARM64Words(words []uint32) []byte {
	out := make([]byte, len(words)*4)
	for i, w := range words {
		binary.LittleEndian.PutUint32(out[i*4:], w)
	}
	return out
}

func makeSingleSegmentELF64(elfType, machine uint16, baseVA uint64, progFlags uint32) []byte {
	const (
		elfHeaderSize = 64
		phdrSize      = 56
		codeOffset    = 0x100
	)
	img := make([]byte, pageSize4K)
	copy(img[0:4], []byte{0x7f, 'E', 'L', 'F'})
	img[4] = byte(elf.ELFCLASS64)
	img[5] = byte(elf.ELFDATA2LSB)
	img[6] = byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(img[16:18], elfType)
	binary.LittleEndian.PutUint16(img[18:20], machine)
	binary.LittleEndian.PutUint32(img[20:24], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint64(img[24:32], baseVA+codeOffset) // e_entry
	binary.LittleEndian.PutUint64(img[32:40], elfHeaderSize)     // e_phoff
	binary.LittleEndian.PutUint16(img[52:54], elfHeaderSize)     // e_ehsize
	binary.LittleEndian.PutUint16(img[54:56], phdrSize)          // e_phentsize
	binary.LittleEndian.PutUint16(img[56:58], 1)                 // e_phnum

	ph := img[elfHeaderSize : elfHeaderSize+phdrSize]
	binary.LittleEndian.PutUint32(ph[0:4], uint32(elf.PT_LOAD))
	binary.LittleEndian.PutUint32(ph[4:8], progFlags)
	binary.LittleEndian.PutUint64(ph[8:16], 0)
	binary.LittleEndian.PutUint64(ph[16:24], baseVA)
	binary.LittleEndian.PutUint64(ph[24:32], baseVA)
	binary.LittleEndian.PutUint64(ph[32:40], pageSize4K)
	binary.LittleEndian.PutUint64(ph[40:48], pageSize4K)
	binary.LittleEndian.PutUint64(ph[48:56], pageSize4K)
	return img
}
