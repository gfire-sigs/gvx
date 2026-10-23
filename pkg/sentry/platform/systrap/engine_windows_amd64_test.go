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

//go:build windows && amd64

package systrap

import (
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/hostarch"
)

// TestFSBaseIsRepairedAfterPreemption runs a loop that reads through %fs for
// long enough that Windows switches the thread out. The switch resets the FS
// base, the next read faults at a low address, and the engine loads the base
// again. The sum proves that no read returned a wrong value.
func TestFSBaseIsRepairedAfterPreemption(t *testing.T) {
	r := newRig(t, newPlatform(t))
	const iterations = 1_500_000_000
	loop := imm64([]byte{0x48, 0xB9}, iterations)                 // mov rcx, iterations
	loop = append(loop, 0x31, 0xDB)                               // xor ebx, ebx
	loop = append(loop, 0x64, 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0) // loop: mov rax, fs:[0]
	loop = append(loop, 0x48, 0x01, 0xC3)                         // add rbx, rax
	loop = append(loop, 0x48, 0xFF, 0xC9)                         // dec rcx
	loop = append(loop, 0x75, 0xEF)                               // jnz loop (back 17 bytes)
	r.program(loop, gSyscall(93))
	page := r.mapPage(dataVA, hostarch.ReadWrite)
	store64(page, 7)
	setTLSBase(r.ac, dataVA)
	si, _, err := r.run()
	mustSyscall(t, si, err, 93, r.ac)
	if got, want := regAcc(r.ac), uint64(7*iterations); got != want {
		t.Errorf("sum = %d, want %d", got, want)
	}
	t.Logf("the engine repaired the FS base %d times", r.as.sp.fsRepairs.Load())
}

// TestInstructionCrossesBlockBoundary runs an instruction whose first bytes
// end one block and whose last bytes start the next block. The first block is
// executable when the fetch of the next block faults, so pc stays in a block
// that needs no patch. The engine must patch the block that the fault names.
// A guest that runs a pipeline of a shell hit this fault in a call
// instruction.
func TestInstructionCrossesBlockBoundary(t *testing.T) {
	r := newRig(t, newPlatform(t))
	movabs := imm64([]byte{0x48, 0xB8}, 93) // mov rax, 93: ten bytes.
	const inFirst = 4
	first := make([]byte, blockSize)
	for i := range first {
		first[i] = 0x90 // nop
	}
	copy(first[blockSize-inFirst:], movabs[:inFirst])
	second := append(append([]byte(nil), movabs[inFirst:]...), 0x0F, 0x05)
	r.mapPage(codeVA, execAccess, first)
	r.mapPage(codeVA+blockSize, execAccess, second)
	r.mapPage(stackVA, hostarch.ReadWrite)
	r.ac.SetIP(codeVA)
	r.ac.SetStack(stackVA + blockSize - 0x100)

	// A livelock of faults would block Switch for good, so a timer stops it.
	stop := time.AfterFunc(30*time.Second, r.ctx.Interrupt)
	defer stop.Stop()
	si, _, err := r.run()
	mustSyscall(t, si, err, 93, r.ac)
}

// TestNearZeroBase checks which faults look like an access through a lost FS
// base. A positive offset from a zero base lies below the lowest guest
// address. A real guest address never counts, so a static executable at
// 0x400000 can use its own TLS block when the low window exists.
func TestNearZeroBase(t *testing.T) {
	for _, tc := range []struct {
		name     string
		guestMin uint64
		addr     uint64
		want     bool
	}{
		{"high window only, zero base", winBase, 0, true},
		{"high window only, small offset", winBase, 0x28, true},
		{"high window only, offset of a large TLS block", winBase, 0x100000, true},
		{"high window only, a guest address", winBase, winBase, false},
		{"low window, small offset", lowBase, 0x28, true},
		{"low window, last address below the guest range", lowBase, lowBase - 1, true},
		{"low window, lowest guest address", lowBase, lowBase, false},
		{"low window, address in a static executable", lowBase, 0x400000, false},
		{"low window, small negative offset", lowBase, ^uint64(0) - 7, true},
		{"high window only, small negative offset", winBase, ^uint64(0) - 0xfff, true},
		{"low window, a high guest address", lowBase, 0x7e4a080dfb28, false},
	} {
		if got := nearZeroBase(tc.addr, tc.guestMin); got != tc.want {
			t.Errorf("%s: nearZeroBase(%#x, %#x) = %v, want %v", tc.name, tc.addr, tc.guestMin, got, tc.want)
		}
	}
}
