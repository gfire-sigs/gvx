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

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"testing"
)

// TestStubImageIsAWellFormedExecutable checks the facts that the Windows loader
// enforces. The loader of Windows 11 rejects an image without a valid load
// configuration with 0xC000007B, and no Linux or macOS host can run the image.
func TestStubImageIsAWellFormedExecutable(t *testing.T) {
	for _, machine := range []uint16{peMachineAMD64, peMachineARM64} {
		img := buildStubImage(machine)
		f, err := pe.NewFile(bytes.NewReader(img))
		if err != nil {
			t.Fatalf("machine %#x: debug/pe rejects the image: %v", machine, err)
		}
		if f.Machine != machine {
			t.Errorf("machine %#x: Machine = %#x", machine, f.Machine)
		}
		oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
		if !ok {
			t.Fatalf("machine %#x: the optional header is not PE32+", machine)
		}
		if len(f.Sections) != 1 {
			t.Fatalf("machine %#x: %d sections, want 1", machine, len(f.Sections))
		}
		s := f.Sections[0]
		if int(s.Offset)+int(s.Size) > len(img) {
			t.Errorf("machine %#x: the section data [%#x, %#x) leaves the %#x-byte file", machine, s.Offset, s.Offset+s.Size, len(img))
		}
		if oh.AddressOfEntryPoint < s.VirtualAddress || oh.AddressOfEntryPoint >= s.VirtualAddress+s.VirtualSize {
			t.Errorf("machine %#x: the entry point %#x is outside the section", machine, oh.AddressOfEntryPoint)
		}
		if oh.SizeOfImage < s.VirtualAddress+s.VirtualSize || oh.SizeOfImage%oh.SectionAlignment != 0 {
			t.Errorf("machine %#x: SizeOfImage %#x does not cover the section or the alignment", machine, oh.SizeOfImage)
		}
		if oh.DllCharacteristics&0x20 != 0 {
			t.Errorf("machine %#x: the image asks for high entropy, so the loader may place it in the guest window", machine)
		}

		lc := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]
		if lc.Size != stubImageLoadSize || lc.VirtualAddress < s.VirtualAddress || lc.VirtualAddress+lc.Size > s.VirtualAddress+s.VirtualSize {
			t.Fatalf("machine %#x: load configuration directory = %+v, want %#x bytes inside the section", machine, lc, stubImageLoadSize)
		}
		cfg := img[s.Offset+lc.VirtualAddress-s.VirtualAddress:][:lc.Size]
		if got := binary.LittleEndian.Uint32(cfg); got != lc.Size {
			t.Errorf("machine %#x: load configuration Size = %#x, want the directory size %#x", machine, got, lc.Size)
		}
		if got := binary.LittleEndian.Uint32(cfg[loadConfigGuardFlagsOff:]); got&guardSecurityCookieUnused == 0 {
			t.Errorf("machine %#x: GuardFlags = %#x without IMAGE_GUARD_SECURITY_COOKIE_UNUSED", machine, got)
		}
		if cookie := binary.LittleEndian.Uint64(cfg[0x58:]); cookie != 0 {
			t.Errorf("machine %#x: SecurityCookie = %#x, but the flag says that the image has none", machine, cookie)
		}
	}
}
