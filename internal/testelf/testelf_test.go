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

package testelf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"
)

func TestBuildGuestHTTPServerELF64AtDrainSequence(t *testing.T) {
	arches := []struct {
		arch    string
		machine elf.Machine
	}{
		{"arm64", elf.EM_AARCH64},
		{"amd64", elf.EM_X86_64},
	}
	bases := []uint64{0x400000, 0x5000_0000_0000}

	for _, tc := range arches {
		for _, base := range bases {
			img, err := BuildGuestHTTPServerELF64At(tc.arch, base, 18080, "/etc/ready.txt", "/workspace/out.txt", "ok\n")
			if err != nil {
				t.Fatalf("BuildGuestHTTPServerELF64At(%s, %#x): %v", tc.arch, base, err)
			}
			f, err := elf.NewFile(bytes.NewReader(img))
			if err != nil {
				t.Fatalf("parse ELF(%s, %#x): %v", tc.arch, base, err)
			}
			if f.Machine != tc.machine || f.Entry != base+0x100 {
				t.Fatalf("ELF(%s, %#x) machine=%v entry=%#x, want %v %#x", tc.arch, base, f.Machine, f.Entry, tc.machine, base+0x100)
			}
			code := img[0x100:0x500]
			switch tc.arch {
			case "arm64":
				// Verify SYS_shutdown(SHUT_WR=1) followed by CMP X0, #0 and backward B.GT.
				shutdownSeq := encodeARM64Words([]uint32{0xaa1403e0, 0xd2800021, 0xd2801a48, 0xd4000001})
				idx := bytes.Index(code, shutdownSeq)
				if idx < 0 {
					t.Fatalf("arm64(%#x) missing SYS_shutdown sequence", base)
				}
				cmpBytes := encodeARM64Words([]uint32{0xf100001f})
				cmpIdx := bytes.Index(code[idx+len(shutdownSeq):], cmpBytes)
				if cmpIdx < 0 {
					t.Fatalf("arm64(%#x) missing CMP X0, #0 in drain loop", base)
				}
				bgtOff := idx + len(shutdownSeq) + cmpIdx + 4
				bgtWord := binary.LittleEndian.Uint32(code[bgtOff : bgtOff+4])
				if bgtWord&0xff00001f != 0x5400000c {
					t.Fatalf("arm64(%#x) word after CMP = %#08x, want B.GT", base, bgtWord)
				}
				imm19 := int32((bgtWord>>5)&0x7ffff) << 13 >> 13
				targetOff := bgtOff + int(imm19)*4
				wantLoopStart := idx + len(shutdownSeq)
				if targetOff != wantLoopStart {
					t.Fatalf("arm64(%#x) B.GT target = %#x, want %#x (imm19=%d)", base, targetOff, wantLoopStart, imm19)
				}
			case "amd64":
				// Verify SYS_shutdown(SHUT_WR=1) followed by TEST RAX, RAX and backward JG rel32.
				shutdownSeq := []byte{
					0x4c, 0x89, 0xf7,
					0x48, 0xc7, 0xc6, 1, 0, 0, 0,
					0x48, 0xc7, 0xc0, 48, 0, 0, 0,
					0x0f, 0x05,
				}
				idx := bytes.Index(code, shutdownSeq)
				if idx < 0 {
					t.Fatalf("amd64(%#x) missing SYS_shutdown sequence", base)
				}
				testJG := []byte{0x48, 0x85, 0xc0, 0x0f, 0x8f}
				jgIdx := bytes.Index(code[idx+len(shutdownSeq):], testJG)
				if jgIdx < 0 {
					t.Fatalf("amd64(%#x) missing TEST RAX, RAX; JG in drain loop", base)
				}
				relOff := idx + len(shutdownSeq) + jgIdx + len(testJG)
				rel32 := int32(binary.LittleEndian.Uint32(code[relOff : relOff+4]))
				targetOff := relOff + 4 + int(rel32)
				wantLoopStart := idx + len(shutdownSeq)
				if targetOff != wantLoopStart {
					t.Fatalf("amd64(%#x) JG target = %#x, want %#x (rel32=%d)", base, targetOff, wantLoopStart, rel32)
				}
			}
		}
	}
}
