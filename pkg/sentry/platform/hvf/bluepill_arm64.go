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

import (
	"fmt"
	"unsafe"

	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

const (
	vectorSlotCount    = hvcommon.VectorSlots
	vectorSlotSize     = hvcommon.VectorSlotSize
	vectorCommonOffset = hvcommon.VectorCommonOffset
	vectorReloadOffset = 0x8b8

	vecCurrentELSPxSync = hvcommon.SlotCurrentSPxSync
	vecLowerELSync      = hvcommon.SlotLowerSync
	vecLowerELIRQ       = hvcommon.SlotLowerIRQ
	vecLowerELSError    = hvcommon.SlotLowerSError
)

const (
	commOffFlags = unsafe.Offsetof(CommPage{}.Flags)
	commOffVRegs = unsafe.Offsetof(CommPage{}.VRegs)
	commOffFPSR  = unsafe.Offsetof(CommPage{}.FPSR)
	commOffFPCR  = unsafe.Offsetof(CommPage{}.FPCR)
)

const (
	flagFlushTLB    = 1 << 0
	flagFlushICache = 1 << 1
)

func buildVectorPage() []byte {
	page, _, reloadOff, _ := hvcommon.BuildA64VectorPage(hvcommon.A64StubOptions{
		SpillFP:  true,
		OffFlags: int(commOffFlags),
		OffVRegs: int(commOffVRegs),
		OffFPSR:  int(commOffFPSR),
		OffFPCR:  int(commOffFPCR),
	})
	if reloadOff != vectorReloadOffset {
		panic(fmt.Sprintf("hvf: vector spill routine ends at %#x, want %#x", reloadOff, vectorReloadOffset))
	}
	return page
}
