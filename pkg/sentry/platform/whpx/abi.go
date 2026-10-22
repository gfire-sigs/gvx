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

// This file mirrors the numeric values of winhvplatformdefs.h. The values are
// the Windows Hypervisor Platform ABI, so they never change. Every constant is
// compiled on every host to let tests validate the tables on any OS.

// WHV_REGISTER_NAME values for x64 partitions.
const (
	x64RegRax uint32 = 0x00000000
	x64RegRcx uint32 = 0x00000001
	x64RegRdx uint32 = 0x00000002
	x64RegRbx uint32 = 0x00000003
	x64RegRsp uint32 = 0x00000004
	x64RegRbp uint32 = 0x00000005
	x64RegRsi uint32 = 0x00000006
	x64RegRdi uint32 = 0x00000007
	x64RegR8  uint32 = 0x00000008
	x64RegR9  uint32 = 0x00000009
	x64RegR10 uint32 = 0x0000000A
	x64RegR11 uint32 = 0x0000000B
	x64RegR12 uint32 = 0x0000000C
	x64RegR13 uint32 = 0x0000000D
	x64RegR14 uint32 = 0x0000000E
	x64RegR15 uint32 = 0x0000000F

	x64RegRip    uint32 = 0x00000010
	x64RegRflags uint32 = 0x00000011
	x64RegEs     uint32 = 0x00000012
	x64RegCs     uint32 = 0x00000013
	x64RegSs     uint32 = 0x00000014
	x64RegDs     uint32 = 0x00000015
	x64RegFs     uint32 = 0x00000016
	x64RegGs     uint32 = 0x00000017
	x64RegLdtr   uint32 = 0x00000018
	x64RegTr     uint32 = 0x00000019
	x64RegIdtr   uint32 = 0x0000001A
	x64RegGdtr   uint32 = 0x0000001B
	x64RegCr0    uint32 = 0x0000001C
	x64RegCr2    uint32 = 0x0000001D
	x64RegCr3    uint32 = 0x0000001E
	x64RegCr4    uint32 = 0x0000001F
	x64RegXcr0   uint32 = 0x00000027

	x64RegXmm0              uint32 = 0x00001000
	x64RegFpMmx0            uint32 = 0x00001010
	x64RegFpControlStatus   uint32 = 0x00001018
	x64RegXmmControlStatus  uint32 = 0x00001019
	x64RegEfer              uint32 = 0x00002001
	x64RegKernelGsBase      uint32 = 0x00002002
	x64RegStar              uint32 = 0x00002008
	x64RegLstar             uint32 = 0x00002009
	x64RegCstar             uint32 = 0x0000200A
	x64RegSfmask            uint32 = 0x0000200B
	x64RegInternalActivity  uint32 = 0x80000005
	x64RegPendingInterrupt  uint32 = 0x80000000
	x64RegPendingEvent      uint32 = 0x80000002
	x64RegInterruptState    uint32 = 0x80000001
	x64RegSysenterCs        uint32 = 0x00002005
	x64RegSysenterEip       uint32 = 0x00002006
	x64RegSysenterEsp       uint32 = 0x00002007
	x64RegPat               uint32 = 0x00002004
	x64RegDeliverabilityNot uint32 = 0x80000004
)

// WHV_REGISTER_NAME values for arm64 partitions.
const (
	a64RegX0       uint32 = 0x00020000 // X0..X28 follow in steps of one.
	a64RegFp       uint32 = 0x0002001D // X29.
	a64RegLr       uint32 = 0x0002001E // X30.
	a64RegSp       uint32 = 0x0002001F
	a64RegSpEl0    uint32 = 0x00020020
	a64RegSpEl1    uint32 = 0x00020021
	a64RegPc       uint32 = 0x00020022
	a64RegPstate   uint32 = 0x00020023
	a64RegQ0       uint32 = 0x00030000 // Q0..Q31 follow in steps of one.
	a64RegSctlr    uint32 = 0x00040002
	a64RegCpacr    uint32 = 0x00040004
	a64RegTtbr0    uint32 = 0x00040005
	a64RegTtbr1    uint32 = 0x00040006
	a64RegTcr      uint32 = 0x00040007
	a64RegEsr      uint32 = 0x00040008
	a64RegFar      uint32 = 0x00040009
	a64RegMair     uint32 = 0x0004000B
	a64RegVbar     uint32 = 0x0004000C
	a64RegTpidrEl1 uint32 = 0x0004000E
	a64RegTpidrro  uint32 = 0x00040010
	a64RegTpidrEl0 uint32 = 0x00040011
	a64RegFpcr     uint32 = 0x00040012
	a64RegFpsr     uint32 = 0x00040013
	a64RegSpsrEl1  uint32 = 0x00040014
	a64RegElrEl1   uint32 = 0x00040015
	a64RegCntkctl  uint32 = 0x00058008
	a64RegGicrBase uint32 = 0x00063000
	a64RegActivity uint32 = 0x00000004
)

// WHV_RUN_VP_EXIT_REASON values for x64 partitions.
const (
	x64ExitNone               uint32 = 0x00000000
	x64ExitMemoryAccess       uint32 = 0x00000001
	x64ExitIoPortAccess       uint32 = 0x00000002
	x64ExitUnrecoverable      uint32 = 0x00000004
	x64ExitInvalidVpRegister  uint32 = 0x00000005
	x64ExitUnsupportedFeature uint32 = 0x00000006
	x64ExitInterruptWindow    uint32 = 0x00000007
	x64ExitHalt               uint32 = 0x00000008
	x64ExitApicEoi            uint32 = 0x00000009
	x64ExitMsrAccess          uint32 = 0x00001000
	x64ExitCpuid              uint32 = 0x00001001
	x64ExitException          uint32 = 0x00001002
	x64ExitRdtsc              uint32 = 0x00001003
	x64ExitHypercall          uint32 = 0x00001005
	x64ExitCanceled           uint32 = 0x00002001
)

// WHV_RUN_VP_EXIT_REASON values for arm64 partitions.
const (
	a64ExitNone               uint32 = 0x00000000
	a64ExitUnmappedGpa        uint32 = 0x80000000
	a64ExitGpaIntercept       uint32 = 0x80000001
	a64ExitInvalidVpRegister  uint32 = 0x80000020
	a64ExitUnrecoverable      uint32 = 0x80000021
	a64ExitUnsupportedFeature uint32 = 0x80000022
	a64ExitHypercall          uint32 = 0x80000050
	a64ExitSynicSint          uint32 = 0x80000062
	a64ExitReset              uint32 = 0x8001000C
	a64ExitCanceled           uint32 = 0xFFFFFFFF
)

// WHV_CAPABILITY_CODE and WHV_PARTITION_PROPERTY_CODE values.
const (
	capCodeHypervisorPresent uint32 = 0x00000000
	capCodeFeatures          uint32 = 0x00000001
	capCodeXsaveFeatures     uint32 = 0x00001003
	capCodeGicLpiIntIdBits   uint32 = 0x00002011

	propCodeExtendedVmExits    uint32 = 0x00000001
	propCodeXsaveFeatures      uint32 = 0x00001006
	propCodeProcessorCount     uint32 = 0x00001FFF
	propCodeLocalApicEmulation uint32 = 0x00001005
	propCodeArm64IcParameters  uint32 = 0x00001012
)

// a64ICParameters matches WHV_ARM64_IC_PARAMETERS, including its reserved fields.
type a64ICParameters struct {
	EmulationMode  uint32
	_              uint32
	Distributor    uint64
	ITSTranslater  uint64
	_              uint32
	LPIBits        uint32
	TimerPPI       uint32
	PerformancePPI uint32
	_              [6]uint32
}

// Bits of WHV_CAPABILITY_FEATURES and related unions.
const (
	// featArm64Support is the Arm64Support bit of WHV_CAPABILITY_FEATURES.
	// The bit follows PartialUnmap, two reserved bits, DirtyPageTracking,
	// SpeculationControl, one reserved bit, IdleSuspend, VirtualPciDeviceSupport,
	// IommuSupport, VpHotAddRemove and DeviceAccessTracking.
	featArm64Support uint64 = 1 << 11

	// xsaveFeatXsaveSupport is the XsaveSupport bit of
	// WHV_PROCESSOR_XSAVE_FEATURES.
	xsaveFeatXsaveSupport uint64 = 1 << 0

	// extExitHypercall is the HypercallExit bit of WHV_EXTENDED_VM_EXITS.
	// Five reserved or x64-only bits precede it on both architectures.
	extExitHypercall uint64 = 1 << 5
)

// WHV_MAP_GPA_RANGE_FLAGS values.
const (
	mapFlagRead    uint32 = 1 << 0
	mapFlagWrite   uint32 = 1 << 1
	mapFlagExecute uint32 = 1 << 2
)

// Layout constants of WHV_REGISTER_VALUE and its members.
const (
	regValueSize = 16

	// Offsets inside a WHV_X64_SEGMENT_REGISTER value.
	segOffBase     = 0
	segOffLimit    = 8
	segOffSelector = 12
	segOffAttr     = 14

	// Offsets inside a WHV_X64_TABLE_REGISTER value.
	tblOffLimit = 6
	tblOffBase  = 8
)

// hresultFailed reports whether an HRESULT is a failure code.
func hresultFailed(hr uintptr) bool {
	return int32(hr) < 0
}
