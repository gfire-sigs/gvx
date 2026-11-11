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

// Exported types, constants, and helpers for black-box tests in package whpx_test.
type (
	A64StubsForTest = a64Stubs
	X64StubsForTest = x64Stubs
)

const (
	PageSizeForTest          = pageSize
	KernelBaseX64ForTest     = kernelBaseX64
	KernelBaseA64ForTest     = kernelBaseA64
	KernelCodeOffForTest     = kernelCodeOff
	KernelSysOffForTest      = kernelSysOff
	KernelCommOffForTest     = kernelCommOff
	CommOffRegsForTest       = commOffRegs
	CommOffSPForTest         = commOffSP
	CommOffPCForTest         = commOffPC
	CommOffPstateForTest     = commOffPstate
	CommOffTLSForTest        = commOffTLS
	CommOffFaultAddrForTest  = commOffFaultAddr
	CommOffFaultCodeForTest  = commOffFaultCode
	CommOffVectorForTest     = commOffVector
	CommOffCSForTest         = commOffCS
	CommOffSSForTest         = commOffSS
	CommOffRootForTest       = commOffRoot
	CommOffExitReasonForTest = commOffExitReason
	CommOffFlagsForTest      = commOffFlags
	CommTSSOffForTest        = commTSSOff
	CommTSSSizeForTest       = commTSSSize
	CommStackTopForTest      = commStackTop
	FlagReloadRootForTest    = flagReloadRoot
	FlagFullRestoreForTest   = flagFullRestore
	FlagICacheSyncForTest    = flagICacheSync

	A64VectorSlotsForTest    = a64VectorSlots
	A64VectorSlotSizeForTest = a64VectorSlotSize
	A64MairNormalForTest     = a64MairNormal
	A64MairNormalNCForTest   = a64MairNormalNC
	A64MairDeviceForTest     = a64MairDevice
	A64MairForTest           = a64Mair
	A64PstateKernelForTest   = a64PstateKernel
	A64PstateModeMaskForTest = a64PstateModeMask
	A64PstateUserMaskForTest = a64PstateUserMask
	A64SctlrSetForTest       = a64SctlrSet
	A64SctlrMForTest         = a64SctlrM
	A64SctlrCForTest         = a64SctlrC
	A64SctlrIForTest         = a64SctlrI

	X64ExcStubSizeForTest    = x64ExcStubSize
	X64IDTVectorsForTest     = x64IDTVectors
	X64IDTLimitForTest       = x64IDTLimit
	X64GDTLimitForTest       = x64GDTLimit
	X64SysOffGDTForTest      = x64SysOffGDT
	X64SysOffIDTForTest      = x64SysOffIDT
	X64SelKernelCSForTest    = x64SelKernelCS
	X64SelKernelSSForTest    = x64SelKernelSS
	X64SelUserCS32ForTest    = x64SelUserCS32
	X64SelUserSSForTest      = x64SelUserSS
	X64SelUserCSForTest      = x64SelUserCS
	X64StarUserBaseForTest   = x64StarUserBase
	X64AttrKernelCS64ForTest = x64AttrKernelCS64
	X64AttrKernelSSForTest   = x64AttrKernelSS
	X64AttrUserCS32ForTest   = x64AttrUserCS32
	X64AttrUserDataForTest   = x64AttrUserData
	X64AttrUserCS64ForTest   = x64AttrUserCS64
)

var (
	A64TCRForTest          = a64TCR
	BuildA64StubsForTest   = buildA64Stubs
	BuildX64StubsForTest   = buildX64Stubs
	OverlayCommPageForTest = overlayCommPage
	X64InitTSSForTest      = x64InitTSS
)
