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

//go:build linux

package systrap

// flushICache makes the instructions in [addr, addr+length) visible to
// instruction fetch through every mapping of the same memory. The sub-block
// layer calls it after it copies code into a composite page, because the
// guest cannot know about that copy (icache_xplat_arm64.s).
//
//go:noescape
func flushICache(addr, length uintptr)
