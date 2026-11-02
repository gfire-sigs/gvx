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

package hvf

import (
	"runtime"
	"testing"

	"z.gfire.dev/gvx/pkg/cpuid"
)

// TestVCPUMIDRMatchesCPUInfo verifies that /proc/cpuinfo lists the MIDR_EL1
// value that a guest reads. The cpuid package cannot create a vCPU, so it
// holds the expected value as a constant.
func TestVCPUMIDRMatchesCPUInfo(t *testing.T) {
	requireHypervisor(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := hvVMCreate(); err != nil {
		t.Fatalf("hv_vm_create: %v", err)
	}
	defer func() {
		if err := hvVMDestroy(); err != nil {
			t.Errorf("hv_vm_destroy: %v", err)
		}
	}()
	id, _, err := hvVCPUCreate()
	if err != nil {
		t.Fatalf("hv_vcpu_create: %v", err)
	}
	defer func() {
		if err := hvVCPUDestroy(id); err != nil {
			t.Errorf("hv_vcpu_destroy: %v", err)
		}
	}()
	midr, err := hvGetSysReg(id, hvSysRegMIDR)
	if err != nil {
		t.Fatalf("read MIDR_EL1: %v", err)
	}
	if midr != cpuid.HVFMIDR() {
		t.Fatalf("vCPU MIDR_EL1 = %#x, cpuid.HVFMIDR() = %#x", midr, cpuid.HVFMIDR())
	}
	fs := cpuid.HostFeatureSet()
	if got, want := fs.CPUImplementer(), uint8(midr>>24); got != want {
		t.Errorf("CPUImplementer() = %#x, want %#x", got, want)
	}
	if got, want := fs.CPUPartnum(), uint16(midr>>4&0xfff); got != want {
		t.Errorf("CPUPartnum() = %#x, want %#x", got, want)
	}
}
