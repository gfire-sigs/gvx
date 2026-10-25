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

package whpx

import "z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"

// Vector table slot numbers in architectural order.
const (
	a64SlotCurSP0Sync = 0
	a64SlotCurSPxSync = hvcommon.SlotCurrentSPxSync
	a64SlotLowA64Sync = hvcommon.SlotLowerSync
	a64SlotLowA64IRQ  = hvcommon.SlotLowerIRQ
	a64SlotLowA64FIQ  = 10
	a64SlotLowA64SErr = hvcommon.SlotLowerSError
	a64SlotLowA32Sync = 12
	a64VectorSlots    = hvcommon.VectorSlots
	a64VectorSlotSize = hvcommon.VectorSlotSize
	a64CodeOffVectors = 0x000
	a64CodeOffCommon  = hvcommon.VectorCommonOffset
	a64PstateKernel   = hvcommon.PstateEL1h
	a64PstateModeMask = 0xF
	a64PstateUserMask = 0x3CF
)

// MAIR_EL1 attribute bytes. Index 0 must be Normal write-back because
// hostarch.MemoryTypeWriteBack is zero and PTE attribute index 0 selects it.
const (
	a64MairNormal   = hvcommon.MAIRNormalWB
	a64MairNormalNC = 0x44
	a64MairDevice   = 0x00

	// a64Mair mirrors the MAIR_EL1 value of the KVM platform.
	a64Mair = a64MairNormal | a64MairNormalNC<<8 | a64MairDevice<<16

	a64SctlrM      = 1 << 0
	a64SctlrC      = 1 << 2
	a64SctlrI      = 1 << 12
	a64SctlrDZE    = 1 << 14
	a64SctlrUCT    = 1 << 15
	a64SctlrUCI    = 1 << 26
	a64SctlrSet    = hvcommon.SCTLREL1Set
	a64CpacrNoTrap = hvcommon.CPACRNoTrap
	a64CntkctlEL0  = hvcommon.CNTKCTLEL0
)

// a64TCR configures 48-bit translation for both halves with 4KB granules,
// inner-shareable write-back write-allocate walks, a 36-bit physical address
// size (IPS 1), and top-byte-ignore for TTBR0.
var a64TCR = hvcommon.TCR(1)

// a64Stubs is the generated arm64 guest code.
type a64Stubs struct {
	Code      []byte
	Vectors   int
	Common    int
	Hvc       int
	Reload    int
	ReloadEnd int
}

// buildA64Stubs generates the stub code page using hvcommon.BuildA64VectorPage.
func buildA64Stubs() (*a64Stubs, error) {
	page, hvcOff, reloadOff, reloadEnd := hvcommon.BuildA64VectorPage(hvcommon.A64StubOptions{
		WriteExitReason: true,
		OffExitReason:   int(commOffExitReason),
		ExitException:   uint16(ExitException),
		ReloadTTBR0:     true,
		OffRoot:         int(commOffRoot),
		OffFlags:        int(commOffFlags),
	})
	return &a64Stubs{
		Code:      page,
		Vectors:   a64CodeOffVectors,
		Common:    a64CodeOffCommon,
		Hvc:       hvcOff,
		Reload:    reloadOff,
		ReloadEnd: reloadEnd,
	}, nil
}
