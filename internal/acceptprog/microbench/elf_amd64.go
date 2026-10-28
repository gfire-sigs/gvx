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

//go:build linux && amd64

package main

const elfMachine = 62 // EM_X86_64

// trueCode is `xor edi, edi; mov eax, 231; syscall`: exit_group(0).
func trueCode() []byte {
	return []byte{0x31, 0xFF, 0xB8, 0xE7, 0x00, 0x00, 0x00, 0x0F, 0x05}
}
