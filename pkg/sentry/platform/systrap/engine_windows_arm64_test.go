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

//go:build windows && arm64

package systrap

import (
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
)

// TestDataCacheMaintenanceRuns runs the data cache operations that JIT
// engines and the compiler runtime use. Windows raises an illegal
// instruction exception for each of them at EL0. The engine replaces them with
// NOP, so the guest reaches its system call with the stored value intact.
func TestDataCacheMaintenanceRuns(t *testing.T) {
	r := newRig(t, newPlatform(t))
	code := gConst(1, dataVA)
	code = append(code, wordBytes(
		0xd50b7e21, // dc civac, x1
		0xd50b7b21, // dc cvau, x1
		0xd50b7a21, // dc cvac, x1
		0xd50b7c21, // dc cvap, x1
	)...)
	r.program(gStoreTo(dataVA, 0x0102030405060708), code, gInvalidateICache(), gSyscall(93))
	data := r.mapPage(dataVA, hostarch.ReadWrite)
	si, _, err := r.run()
	mustSyscall(t, si, err, 93, r.ac)
	if got := load64(data); got != 0x0102030405060708 {
		t.Errorf("data = %#x, want 0x0102030405060708", got)
	}
}

// TestCacheTypeRegisterNeedsNoMaintenance reads CTR_EL0 in the guest. The
// engine flushes the instruction cache when it maps a patched copy, so the
// register reports that a guest needs neither `dc cvau` nor `ic ivau`.
func TestCacheTypeRegisterNeedsNoMaintenance(t *testing.T) {
	r := newRig(t, newPlatform(t))
	r.program(gReadCacheType(), gSyscall(93))
	si, _, err := r.run()
	mustSyscall(t, si, err, 93, r.ac)
	got := regRet(r.ac)
	const dic, idc = 1 << 29, 1 << 28
	if got&dic == 0 || got&idc == 0 {
		t.Errorf("CTR_EL0 = %#x, want DIC and IDC set", got)
	}
	if line := 4 << (got & 0xf); line != 64 {
		t.Errorf("CTR_EL0 = %#x reports an instruction line of %d bytes, want 64", got, line)
	}
}
