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

package systrap

import (
	"encoding/binary"
	"errors"
	"os"
	"runtime"
)

// writeStubImage creates a PE executable with no imports, runtime, or caller data.
// The debugger parks its initial thread before its entry point runs.
func writeStubImage() (path string, err error) {
	image := make([]byte, 1024)
	put16 := func(offset int, value uint16) { binary.LittleEndian.PutUint16(image[offset:], value) }
	put32 := func(offset int, value uint32) { binary.LittleEndian.PutUint32(image[offset:], value) }
	put64 := func(offset int, value uint64) { binary.LittleEndian.PutUint64(image[offset:], value) }
	copy(image, "MZ")
	put32(0x3c, 0x80)
	copy(image[0x80:], "PE\x00\x00")
	machine := uint16(0xaa64)
	if runtime.GOARCH == "amd64" {
		machine = 0x8664
	}
	put16(0x84, machine)
	put16(0x86, 1)
	put16(0x94, 0xf0)
	put16(0x96, 0x22)
	const optional = 0x98
	put16(optional, 0x20b)
	put32(optional+4, 512)
	put32(optional+16, 0x1000)
	put32(optional+20, 0x1000)
	put64(optional+24, 0x140000000)
	put32(optional+32, 0x1000)
	put32(optional+36, 512)
	put16(optional+40, 6)
	put16(optional+42, 2)
	put16(optional+48, 6)
	put16(optional+50, 2)
	put32(optional+56, 0x2000)
	put32(optional+60, 512)
	put16(optional+68, 3)
	put16(optional+70, 0x160)
	put64(optional+72, 1<<20)
	put64(optional+80, 4096)
	put64(optional+88, 1<<20)
	put64(optional+96, 4096)
	put32(optional+108, 16)
	const section = optional + 0xf0
	copy(image[section:], ".text")
	put32(section+8, 8)
	put32(section+12, 0x1000)
	put32(section+16, 512)
	put32(section+20, 512)
	put32(section+36, 0x60000020)
	if runtime.GOARCH == "arm64" {
		put32(512, 0xd43e0000)
		put32(516, 0x14000000)
	} else {
		copy(image[512:], []byte{0xcc, 0xeb, 0xfe})
	}
	file, err := os.CreateTemp("", "gvx-systrap-image-*.exe")
	if err != nil {
		return "", err
	}
	path = file.Name()
	_, writeErr := file.Write(image)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}
