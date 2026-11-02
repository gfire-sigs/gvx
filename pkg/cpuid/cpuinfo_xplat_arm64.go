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

//go:build arm64 && !linux

package cpuid

// readCNTFRQ returns CNTFRQ_EL0, the frequency of the system counter in Hz.
func readCNTFRQ() uint64

// midrFields splits MIDR_EL1 into the fields that /proc/cpuinfo lists.
type midrFields struct {
	implementer uint64
	variant     uint64
	part        uint64
	revision    uint64
}

// decodeMIDR splits a MIDR_EL1 value. Bits 31:24 hold the implementer, 23:20
// the variant, 15:4 the part number, and 3:0 the revision. Bits 19:16 hold the
// architecture field, which is 0xf for every Armv8 core. The Linux kernel
// prints "8" for that field, so decodeMIDR does not return it.
func decodeMIDR(midr uint64) midrFields {
	return midrFields{
		implementer: midr >> 24 & 0xff,
		variant:     midr >> 20 & 0xf,
		part:        midr >> 4 & 0xfff,
		revision:    midr & 0xf,
	}
}

// bogoMIPS returns the BogoMIPS value that the Linux arm64 kernel prints for a
// system counter of cntfrq Hz. The kernel derives it from the timer, so it is
// twice the frequency in MHz. A 24 MHz counter gives 48.00.
func bogoMIPS(cntfrq uint64) float64 {
	return 2 * float64(cntfrq) / 1e6
}

// cpuArchitectureArmv8 is the "CPU architecture" value that Linux prints for
// every core that has the Armv8 architecture field.
const cpuArchitectureArmv8 = 8

// setCPUInfo fills the /proc/cpuinfo fields of fs from a MIDR_EL1 value and a
// system counter frequency.
func setCPUInfo(fs *FeatureSet, midr, cntfrq uint64) {
	f := decodeMIDR(midr)
	fs.cpuFreqMHz = bogoMIPS(cntfrq)
	fs.cpuImplHex = f.implementer
	fs.cpuArchDec = cpuArchitectureArmv8
	fs.cpuVarHex = f.variant
	fs.cpuPartHex = f.part
	fs.cpuRevDec = f.revision
}

// init fills the /proc/cpuinfo fields of the host feature set.
//
// WHY: initCPUInfo reads the host /proc/cpuinfo and returns early on a host
// that has none. Without this function the fields stay 0, and tools such as
// containerd report the platform "linux/arm64/unknown". The guest reads
// MIDR_EL1 through the hypervisor backend, so the fields use the value that the
// backend serves. This function runs at package initialization, before any
// host lockdown.
func init() {
	setCPUInfo(&hostFeatureSet, platformMIDR(), readCNTFRQ())
}
