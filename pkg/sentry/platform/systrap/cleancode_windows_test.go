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

//go:build windows

package systrap

import (
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

// A scan that finds no system call in a read-only page records the page as
// clean. The memory file reuses frames, and the guest can write a frame through
// another mapping, so the record must hold for the scanned bytes and not for the
// address. A page with new bytes must get a new scan, or its system call would
// run as an NT service in the stub.
func TestCleanPageRecordHoldsOnlyForTheScannedBytes(t *testing.T) {
	r := newRig(t, newPlatform(t))
	fr, mem := r.allocFrames(1, gLoadFrom(dataVA))
	r.mapRange(codeVA, memmap.FileRange{Start: fr.Start, End: fr.Start + blockSize}, execAccess)
	r.mapPage(stackVA, hostarch.ReadWrite)
	r.ac.SetIP(codeVA)
	r.ac.SetStack(stackVA + blockSize - 0x100)

	si, _, err := r.run()
	wantSignal(t, si, err, linux.SIGSEGV)
	if got := r.as.PatchedBlocks(); got != 1 {
		t.Fatalf("patched blocks = %d after the first run, want 1", got)
	}

	// The frame gets new code, and the same frame maps at the same address.
	r.as.Unmap(hostarch.Addr(codeVA), blockSize)
	for i := range mem {
		mem[i] = 0
	}
	copy(mem, gSyscall(77))
	r.mapRange(codeVA, memmap.FileRange{Start: fr.Start, End: fr.Start + blockSize}, execAccess)
	r.ac.SetIP(codeVA)
	si, _, err = r.run()
	mustSyscall(t, si, err, 77, r.ac)
}
