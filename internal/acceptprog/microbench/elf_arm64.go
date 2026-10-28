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

import "encoding/binary"

const elfMachine = 183 // EM_AARCH64

// trueCode is `mov x0, #0; mov x8, #94; svc #0`: exit_group(0).
func trueCode() []byte {
	b := make([]byte, 12)
	for i, w := range []uint32{0xd2800000, 0xd2800bc8, 0xd4000001} {
		binary.LittleEndian.PutUint32(b[4*i:], w)
	}
	return b
}
