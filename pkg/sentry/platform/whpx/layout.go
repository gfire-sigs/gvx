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

import (
	"unsafe"

	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

const (
	pageSize  = hvcommon.PageSize4K
	pageShift = 12
	pageMask  = hvcommon.PageMask4K

	// minUserAddr is the lowest address the Sentry maps for applications.
	minUserAddr = hvcommon.MinUserAddr

	// maxUserAddrX64 and maxUserAddrA64 bound the lower canonical halves of
	// 4-level paging and of a 48-bit TTBR0 region.
	maxUserAddrX64 = hvcommon.MaxUserAddrX64
	maxUserAddrA64 = hvcommon.MaxUserAddrA64

	// gpaWindowBase leaves the first GiB of guest physical space unbacked by
	// RAM for interrupt controllers and the EL1 notification page.
	// minGPABits and maxGPABits bound the partition GPA width between 64 GiB
	// and 1 TiB according to the host physical address width.
	gpaWindowBase   = 1 << 30
	minGPABits      = 36
	maxGPABits      = 40
	minGPAWindowEnd = 1 << minGPABits
	maxGPAWindowEnd = 1 << maxGPABits

	// gpaTableEnd ends the 4 GiB zone for the kernel region and page-table
	// slabs. Guest file and memory-file regions occupy [gpaTableEnd, gpaEnd).
	gpaTableEnd = gpaWindowBase + 4<<30

	// maxVPs caps the virtual processors of one partition.
	maxVPs = 64

	// GIC registers occupy GPA ranges below RAM. Each redistributor uses
	// two 64KiB frames, one for control and one for SGIs and PPIs.
	a64GicDistributor = 0x08000000
	a64GicTranslator  = 0x08080000
	a64GicRedistBase  = 0x080A0000
	a64GicRedistSize  = 0x20000
)

// Kernel region layout. The region lives in the upper canonical half. All
// address spaces share its page tables, and applications cannot reach it
// because every entry is supervisor-only.
const (
	// kernelBaseX64 starts the last PML4 slot of 4-level paging.
	kernelBaseX64 uint64 = 0xFFFFFF8000000000

	// kernelBaseA64 starts the TTBR1 region of a 48-bit virtual address space.
	kernelBaseA64 uint64 = 0xFFFF000000000000

	// kernelCodeOff is the offset of the stub code page. The page stays
	// executable and read-only.
	kernelCodeOff = 0x1000

	// kernelSysOff is the offset of the amd64 GDT and IDT page. The page
	// stays read-only.
	kernelSysOff = 0x2000

	// kernelCommOff is the offset of the first per-VP CommPage. Slot i
	// starts at kernelCommOff + i*pageSize.
	kernelCommOff = 0x10000
)

// ExitReason identifies why the in-partition stub stopped a virtual processor.
type ExitReason uint32

// Values of CommPage.ExitReason. The stub writes them before it halts.
const (
	// ExitNone means the stub has not stopped since the last resume.
	ExitNone ExitReason = 0

	// ExitSyscall means a SYSCALL instruction entered the amd64 stub.
	ExitSyscall ExitReason = 1

	// ExitException means a CPU exception from user mode reached the stub. On
	// arm64 every exception from EL0 uses this value, including SVC.
	ExitException ExitReason = 2

	// ExitKernelFault means an exception happened inside the stub itself.
	ExitKernelFault ExitReason = 3
)

// Bits of CommPage.Flags. The Sentry sets them before it resumes the stub.
const (
	// flagReloadRoot asks the stub to write the page-table root and flush
	// the TLB before it returns to user mode.
	flagReloadRoot uint32 = 1 << 0

	// flagFullRestore asks the amd64 stub to return with IRETQ so RCX and R11
	// keep their values.
	flagFullRestore uint32 = 1 << 1

	// flagICacheSync asks the arm64 stub to invalidate the instruction cache.
	flagICacheSync uint32 = 1 << 2
)

// CommPage is the 4KB page that the in-partition stub and the Sentry share.
type CommPage struct {
	hvcommon.CommHeader
	CS         uint64
	SS         uint64
	Root       uint64
	ExitReason uint32
	Flags      uint32
	_          [commTSSOff - commEnd]byte
	TSS        [commTSSSize]byte
	_          [pageSize - commTSSOff - commTSSSize]byte
}

// Byte offsets inside CommPage. The stubs encode them, so TestCommPageOffsets
// pins them to the struct.
const (
	commOffRegs       = hvcommon.CommOffRegs
	commOffSP         = hvcommon.CommOffSP
	commOffPC         = hvcommon.CommOffPC
	commOffPstate     = hvcommon.CommOffPstate
	commOffTLS        = hvcommon.CommOffTLS
	commOffFaultAddr  = hvcommon.CommOffFaultAddr
	commOffFaultCode  = hvcommon.CommOffESR
	commOffVector     = hvcommon.CommOffVector
	commOffCS         = 0x130
	commOffSS         = 0x138
	commOffRoot       = 0x140
	commOffExitReason = 0x148
	commOffFlags      = 0x14C
	commEnd           = 0x150

	// commTSSOff holds the per-VP amd64 task state segment.
	commTSSOff  = 0x800
	commTSSSize = 104

	// commStackTop is the amd64 kernel stack top. The stack grows down inside
	// the page from this offset, above the TSS.
	commStackTop = pageSize
)

// commPageSize is the size of CommPage in bytes.
const commPageSize = unsafe.Sizeof(CommPage{})

// overlayCommPage casts a page-sized host buffer to a CommPage.
func overlayCommPage(page []byte) *CommPage {
	if len(page) < pageSize {
		panic("whpx: CommPage buffer is shorter than one page")
	}
	return (*CommPage)(unsafe.Pointer(&page[0]))
}

// kernelLayout holds the guest virtual addresses of the shared kernel region.
type kernelLayout struct {
	base uint64
}

func newKernelLayout(arm64 bool) kernelLayout {
	if arm64 {
		return kernelLayout{base: kernelBaseA64}
	}
	return kernelLayout{base: kernelBaseX64}
}

// code returns the address of the stub code page.
func (k kernelLayout) code() uint64 { return k.base + kernelCodeOff }

// sys returns the address of the amd64 GDT and IDT page.
func (k kernelLayout) sys() uint64 { return k.base + kernelSysOff }

// comm returns the address of the CommPage of virtual processor slot.
func (k kernelLayout) comm(slot int) uint64 {
	return k.base + kernelCommOff + uint64(slot)*pageSize
}

// selectGPABits chooses the partition guest physical address width in
// [minGPABits, maxGPABits] from the hypervisor capability and CPU limit.
func selectGPABits(arm64 bool, capBits, cpuBits uint32) uint32 {
	bits := capBits
	if bits == 0 {
		bits = minGPABits
	}
	if cpuBits != 0 && cpuBits < bits {
		bits = cpuBits
	}
	bits = min(max(bits, minGPABits), maxGPABits)
	if arm64 && bits < 40 {
		return minGPABits
	}
	return bits
}
