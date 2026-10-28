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

import "encoding/binary"

// elfBase is the load address of the executable that trueELF returns.
const elfBase = 0x400000

// trueELF returns a static executable that exits with status 0 and does
// nothing else. It has one load segment, so the cost of running it is the cost of
// the backend, not of a runtime.
func trueELF() []byte {
	const hdr = 64 + 56
	code := trueCode()
	size := hdr + len(code)
	b := make([]byte, size)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	le := binary.LittleEndian
	le.PutUint16(b[16:], 2) // ET_EXEC
	le.PutUint16(b[18:], elfMachine)
	le.PutUint32(b[20:], 1)
	le.PutUint64(b[24:], elfBase+hdr) // entry
	le.PutUint64(b[32:], 64)          // program headers
	le.PutUint16(b[52:], 64)
	le.PutUint16(b[54:], 56)
	le.PutUint16(b[56:], 1)
	ph := b[64:]
	le.PutUint32(ph[0:], 1) // PT_LOAD
	le.PutUint32(ph[4:], 5) // R+X
	le.PutUint64(ph[16:], elfBase)
	le.PutUint64(ph[24:], elfBase)
	le.PutUint64(ph[32:], uint64(size))
	le.PutUint64(ph[40:], uint64(size))
	le.PutUint64(ph[48:], 0x1000)
	copy(b[hdr:], code)
	return b
}
