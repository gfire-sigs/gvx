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

package hvf

import "z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"

// EL1 system register values that every vCPU receives at creation.
const (
	cntvCtlMasked  uint64 = 2
	pstateModeMask uint64 = 0x1f
	pstateUserMask uint64 = 0xf0000000
)

// sctlrEL1 enables the MMU and the caches, and lets EL0 run the instructions
// that glibc and the Go runtime use without a trap to EL1.
const sctlrEL1 uint64 = hvcommon.SCTLREL1Set |
	1<<3 | // SA: SP alignment check at EL1.
	1<<4 | // SA0: SP alignment check at EL0, as Linux does.
	1<<16 | // nTWI: WFI runs at EL0.
	1<<18 | // nTWE: WFE runs at EL0.
	sctlrRes1

// sctlrRes1 holds the bits that are RES1 on cores without the matching
// features, with the values Linux writes.
const sctlrRes1 uint64 = 1<<11 | 1<<20 | 1<<22 | 1<<23 | 1<<28 | 1<<29
