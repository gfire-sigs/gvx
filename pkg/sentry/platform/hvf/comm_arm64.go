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

// CommPage is the 4KB page that the EL1 stub and the Sentry share. The stub
// writes it on every guest exit and reads it on every guest entry.
type CommPage struct {
	hvcommon.CommHeader
	Flags uint64        // 304: host-to-guest flush flags.
	_     uint64        // 312.
	VRegs [32][2]uint64 // 320: V0..V31 (Q0..Q31).
	FPSR  uint64        // 832.
	FPCR  uint64        // 840.
	_     [3248]byte    // 848: pads the page to 4096 bytes.
}

const maxUserAddress = hvcommon.MaxUserAddrA64
