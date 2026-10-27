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

//go:build darwin && arm64

package systrap

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// buildCodeELF returns a minimal arm64 ELF64 executable with one load segment
// at va. A section named .text marks the first textSize bytes as code. The
// rest of the segment has no section that holds instructions.
func buildCodeELF(va, textSize uint64) []byte {
	const (
		phdrAt   = 64
		shdrAt   = 0x200
		strtabAt = 0x1c0
	)
	names := "\x00.text\x00.shstrtab\x00"
	img := make([]byte, shdrAt+3*64)
	le := binary.LittleEndian
	copy(img, "\x7fELF\x02\x01\x01")
	le.PutUint16(img[16:], uint16(elf.ET_EXEC))
	le.PutUint16(img[18:], uint16(elf.EM_AARCH64))
	le.PutUint32(img[20:], 1)
	le.PutUint64(img[24:], va)
	le.PutUint64(img[32:], phdrAt)
	le.PutUint64(img[40:], shdrAt)
	le.PutUint16(img[52:], 64)
	le.PutUint16(img[54:], 56)
	le.PutUint16(img[56:], 1)
	le.PutUint16(img[58:], 64)
	le.PutUint16(img[60:], 3)
	le.PutUint16(img[62:], 2)
	ph := img[phdrAt:]
	le.PutUint32(ph[0:], uint32(elf.PT_LOAD))
	le.PutUint32(ph[4:], uint32(elf.PF_R|elf.PF_X))
	le.PutUint64(ph[16:], va)
	le.PutUint64(ph[32:], blockSize)
	le.PutUint64(ph[40:], blockSize)
	copy(img[strtabAt:], names)
	text := img[shdrAt+64:]
	le.PutUint32(text[0:], 1)
	le.PutUint32(text[4:], uint32(elf.SHT_PROGBITS))
	le.PutUint64(text[8:], uint64(elf.SHF_ALLOC|elf.SHF_EXECINSTR))
	le.PutUint64(text[16:], va)
	le.PutUint64(text[32:], textSize)
	strtab := img[shdrAt+128:]
	le.PutUint32(strtab[0:], 7)
	le.PutUint32(strtab[4:], uint32(elf.SHT_STRTAB))
	le.PutUint64(strtab[24:], strtabAt)
	le.PutUint64(strtab[32:], uint64(len(names)))
	return img
}

// imageMM reports the file that backs one page, like the memory manager of the
// Sentry does for a mapped executable.
type imageMM struct {
	*testMM
	va    uint64
	image []byte
}

func (m imageMM) ExecImageAt(_ context.Context, addr hostarch.Addr) platform.ExecImage {
	if uint64(addr) < m.va || uint64(addr) >= m.va+blockSize {
		return platform.ExecImage{Kind: platform.MappingAnonymous}
	}
	return platform.ExecImage{
		Kind: platform.MappingFile, Device: 1, Inode: 1, Offset: uint64(addr) - m.va,
		File: bytes.NewReader(m.image), Release: func() {},
	}
}

func TestZoneScanLeavesDataWordsOutsideTheExecutableSections(t *testing.T) {
	// A string that starts the read-only data shares the block with the end of
	// the code. The word 0x70736575 spells "uesp" and decodes as an adr whose
	// target lies in the zone. The patcher must not turn it into a branch.
	const dataAt, stringWord = 0x80, 0x70736575
	r := newZoneRig(t)
	prog := make([]uint32, dataAt/4+1)
	copy(prog, append(loadAddr(0, zoneCode+dataAt),
		0xb9400001, // ldr w1, [x0]
		movz(8, 9), insnSVC0))
	prog[dataAt/4] = stringWord
	r.zoneProgram(zoneCode, prog...)
	mm := imageMM{testMM: r.mm, va: zoneCode, image: buildCodeELF(zoneCode, 0x40)}
	si, _, err := r.ctx.Switch(r.rctx, mm, r.ac, -1)
	mustSyscall(t, si, err, 9, r.ac)
	if got := r.regs().Regs[1]; got != stringWord {
		t.Errorf("the guest read %#x from the data word, want %#x: the patcher changed a word outside the code", got, stringWord)
	}
}
