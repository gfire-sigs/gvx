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

//go:build darwin && amd64

package systrap

import "unsafe"

// newHostContext allocates a 16-byte-aligned Windows AMD64 CONTEXT buffer for
// cross-platform unit tests running under darwin/amd64.
func newHostContext() *hostContext {
	raw := make([]byte, hostContextSize+16)
	start := (16 - int(uintptr(unsafe.Pointer(&raw[0]))&15)) & 15
	return &hostContext{buf: raw[start : start+hostContextSize]}
}

func (c *hostContext) guestFlags() uint32   { return ctxFlagGuestAll }
func (c *hostContext) fpFlags() uint32      { return ctxFlagFloat }
func (c *hostContext) loadXState(_ []byte)  {}
func (c *hostContext) storeXState(_ []byte) {}
