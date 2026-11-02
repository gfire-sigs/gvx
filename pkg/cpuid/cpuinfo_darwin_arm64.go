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

package cpuid

// hvfMIDR is the MIDR_EL1 value that an hvf vCPU returns. Hypervisor.framework
// hides the host core: the part number and revision read as 0, and the
// implementer is Apple (0x61). The value matches an Apple M1 host. A test in
// the hvf package compares it with the register of a real vCPU.
const hvfMIDR = 0x610f0000

// HVFMIDR returns the MIDR_EL1 value that an hvf guest reads.
func HVFMIDR() uint64 { return hvfMIDR }

// platformMIDR returns the MIDR_EL1 value of the guest on this host.
func platformMIDR() uint64 { return hvfMIDR }
