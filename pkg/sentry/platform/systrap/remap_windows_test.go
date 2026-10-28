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

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

// The memory manager maps a whole mapping at each fault, so it maps a page
// again that the guest already runs. The page must keep its patch. A reset
// leaves a thread that already trapped at a patched SYSCALL without its site.
// The guest then receives a SIGTRAP that it did not raise.
func TestMapAgainKeepsAPatchedBlock(t *testing.T) {
	r := newRig(t, newPlatform(t))
	fr, _ := r.allocFrames(2, gSyscall(93, 42, 7), gSyscall(94, 1, 2, 3, 4, 5, 6))
	r.mapRange(codeVA, memmap.FileRange{Start: fr.Start, End: fr.Start + blockSize}, execAccess)
	r.mapPage(stackVA, hostarch.ReadWrite)
	r.ac.SetIP(codeVA)
	r.ac.SetStack(stackVA + blockSize - 0x100)

	si, _, err := r.run()
	mustSyscall(t, si, err, 93, r.ac)
	if got := r.as.PatchedBlocks(); got != 1 {
		t.Fatalf("patched blocks = %d after the first system call, want 1", got)
	}

	// A fault in the second page maps both pages again.
	r.mapRange(codeVA, fr, execAccess)

	setRet(r.ac, 1000)
	si, _, err = r.run()
	mustSyscall(t, si, err, 94, r.ac)
	if got := r.as.PatchedBlocks(); got != 1 {
		t.Errorf("patched blocks = %d after the mapping of both pages, want 1: the second mapping reset the patched page", got)
	}
}

// A page that the memory manager maps from another frame is new code, and the
// engine must patch it again.
func TestMapAnotherFrameReplacesAPatchedBlock(t *testing.T) {
	r := newRig(t, newPlatform(t))
	first, _ := r.allocFrames(1, gSyscall(93, 1))
	second, _ := r.allocFrames(1, gSyscall(77, 2))
	r.mapRange(codeVA, first, execAccess)
	r.mapPage(stackVA, hostarch.ReadWrite)
	r.ac.SetIP(codeVA)
	r.ac.SetStack(stackVA + blockSize - 0x100)

	si, _, err := r.run()
	mustSyscall(t, si, err, 93, r.ac)

	r.mapRange(codeVA, second, execAccess)
	r.ac.SetIP(codeVA)
	si, _, err = r.run()
	mustSyscall(t, si, err, 77, r.ac)
	if got := r.as.PatchedBlocks(); got != 2 {
		t.Errorf("patched blocks = %d, want 2: the new frame needs its own patch", got)
	}
}
