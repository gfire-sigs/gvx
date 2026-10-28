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

//go:build darwin || windows

package systrap

import "encoding/binary"

// The stub image is the executable that Windows maps into a stub process. The
// loader of Windows finishes in the stub, and the engine parks the initial
// thread before the entry point runs. The image therefore needs no code that
// runs. It needs a header that the loader accepts, and a small header keeps the
// creation of a stub fast.
//
// The loader of Windows 10 and later fails an image without a load
// configuration directory with STATUS_INVALID_IMAGE_FORMAT (0xC000007B). With a
// null security cookie, the directory must also set GuardFlags to
// IMAGE_GUARD_SECURITY_COOKIE_UNUSED. The other fields stay zero.

const (
	peMachineAMD64 = 0x8664
	peMachineARM64 = 0xAA64

	// stubImageSize is the size of the file in bytes.
	stubImageSize = 0x400

	peFileAlign    = 0x200
	peSectionAlign = 0x1000
	peImageBase    = 0x140000000

	// Offsets inside the one section. Its relative virtual address is
	// peSectionAlign and its file offset is peFileAlign.
	stubImageRelocOff = 0x20
	stubImageLoadOff  = 0x40
	stubImageLoadSize = 0x140

	// GuardFlags of IMAGE_LOAD_CONFIG_DIRECTORY64 sits at offset 0x90.
	loadConfigGuardFlagsOff   = 0x90
	guardSecurityCookieUnused = 0x800
)

// buildStubImage returns the bytes of a console executable for machine. The
// image has one section with the entry code, an empty base relocation block, and
// the load configuration. The entry code returns zero.
func buildStubImage(machine uint16) []byte {
	le := binary.LittleEndian
	img := make([]byte, stubImageSize)
	copy(img, "MZ")
	le.PutUint32(img[0x3C:], 0x40)

	nt := img[0x40:]
	copy(nt, "PE\x00\x00")
	le.PutUint16(nt[4:], machine)
	le.PutUint16(nt[6:], 1)     // sections
	le.PutUint16(nt[20:], 0xF0) // size of the optional header
	le.PutUint16(nt[22:], 0x22) // executable, large address aware

	opt := nt[24:]
	le.PutUint16(opt[0:], 0x20B) // PE32+
	le.PutUint32(opt[4:], peFileAlign)
	le.PutUint32(opt[16:], peSectionAlign) // entry point
	le.PutUint32(opt[20:], peSectionAlign) // base of code
	le.PutUint64(opt[24:], peImageBase)
	le.PutUint32(opt[32:], peSectionAlign)
	le.PutUint32(opt[36:], peFileAlign)
	le.PutUint16(opt[40:], 10) // operating system version
	le.PutUint16(opt[48:], 10) // subsystem version
	le.PutUint32(opt[56:], 2*peSectionAlign)
	le.PutUint32(opt[60:], peFileAlign)
	le.PutUint16(opt[68:], 3) // console subsystem
	// High entropy, dynamic base, no execute, and terminal server aware. Without
	// high entropy, the loader places a 64-bit image below 4 GB, where it can
	// take a part of the low guest window.
	le.PutUint16(opt[70:], 0x8160)
	le.PutUint64(opt[72:], 0x100000)
	le.PutUint64(opt[80:], 0x1000)
	le.PutUint64(opt[88:], 0x100000)
	le.PutUint64(opt[96:], 0x1000)
	le.PutUint32(opt[108:], 16)
	// Directory 5 is the base relocation table, and directory 10 is the load
	// configuration.
	le.PutUint32(opt[112+5*8:], peSectionAlign+stubImageRelocOff)
	le.PutUint32(opt[112+5*8+4:], 8)
	le.PutUint32(opt[112+10*8:], peSectionAlign+stubImageLoadOff)
	le.PutUint32(opt[112+10*8+4:], stubImageLoadSize)

	sec := nt[24+0xF0:]
	copy(sec, ".text")
	le.PutUint32(sec[8:], peFileAlign)
	le.PutUint32(sec[12:], peSectionAlign)
	le.PutUint32(sec[16:], peFileAlign)
	le.PutUint32(sec[20:], peFileAlign)
	le.PutUint32(sec[36:], 0x60000020) // code, execute, read

	text := img[peFileAlign:]
	switch machine {
	case peMachineARM64:
		le.PutUint32(text[0:], 0x52800000) // mov w0, #0
		le.PutUint32(text[4:], 0xD65F03C0) // ret
	default:
		copy(text, []byte{0x31, 0xC0, 0xC3}) // xor eax, eax; ret
	}
	le.PutUint32(text[stubImageRelocOff:], peSectionAlign) // page of the empty block
	le.PutUint32(text[stubImageRelocOff+4:], 8)            // size of the block
	le.PutUint32(text[stubImageLoadOff:], stubImageLoadSize)
	le.PutUint32(text[stubImageLoadOff+loadConfigGuardFlagsOff:], guardSecurityCookieUnused)
	return img
}
