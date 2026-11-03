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
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
)

// writeFrame writes code at the start of the frame the way a Sentry file
// system does: it asks the memory file for a write mapping and copies into it.
func writeFrame(t *testing.T, r *rig, fr memmap.FileRange, off int, code []byte) {
	t.Helper()
	bs, err := r.mf.MapInternal(fr, hostarch.Write)
	if err != nil {
		t.Fatalf("MapInternal(write): %v", err)
	}
	copy(bs.Head().ToSlice()[off:], code)
}

// TestSentryWriteReplacesExecutedCode runs a function, lets the Sentry rewrite
// its frame through a write mapping of the memory file, and runs it again. The
// second run must execute the new bytes, because the write drops the patched
// copy. This is the write(2) of a file that the guest maps shared.
func TestSentryWriteReplacesExecutedCode(t *testing.T) {
	r := newRig(t, newPlatform(t))
	fr, _ := r.allocFrames(1, gSyscall(41))
	r.mapRange(rxVA, fr, execAccess)
	r.program(gJump(rxVA))
	r.wantCall(41)

	writeFrame(t, r, fr, 0, gSyscall(42))
	r.ac.SetIP(codeVA)
	r.wantCall(42)
	if got := r.p.HostWriteDrops(); got != 1 {
		t.Errorf("frames that lost a copy to a write of the Sentry = %d, want 1", got)
	}
}

// TestSentryWriteThroughACachedMappingIsReported covers the copy-out of a
// system call. The memory manager keeps its internal mapping of a page and
// writes through it without asking the memory file again, then reports the
// write.
func TestSentryWriteThroughACachedMappingIsReported(t *testing.T) {
	r := newRig(t, newPlatform(t))
	fr, mem := r.allocFrames(1, gSyscall(41))
	r.mapRange(rxVA, fr, execAccess)
	r.program(gJump(rxVA))
	r.wantCall(41)

	copy(mem, gSyscall(42))
	r.mf.NoteHostWrite(fr)
	r.ac.SetIP(codeVA)
	r.wantCall(42)
}

// TestSentryWriteDropsCopiesInEveryAddressSpace maps one frame as code in two
// address spaces and rewrites it from the Sentry. Both must run the new bytes.
func TestSentryWriteDropsCopiesInEveryAddressSpace(t *testing.T) {
	first := newRig(t, newPlatform(t))
	second := newRigOn(t, first.p, first.mf)
	fr, _ := first.allocFrames(1, gSyscall(41))
	first.mapRange(rxVA, fr, execAccess)
	second.mapRange(rxVA, fr, execAccess)
	first.program(gJump(rxVA))
	second.program(gJump(rxVA))
	first.wantCall(41)
	second.wantCall(41)

	writeFrame(t, first, fr, 0, gSyscall(42))
	for _, r := range []*rig{first, second} {
		r.ac.SetIP(codeVA)
		r.wantCall(42)
	}
}

// TestSentryWriteLeavesOtherFramesAlone checks that a write to one frame keeps
// the patched copy of its neighbor, so that data writes next to code cost no
// patch.
func TestSentryWriteLeavesOtherFramesAlone(t *testing.T) {
	r := newRig(t, newPlatform(t))
	fr, _ := r.allocFrames(2, gSyscall(41))
	code := memmap.FileRange{Start: fr.Start, End: fr.Start + blockSize}
	data := memmap.FileRange{Start: fr.Start + blockSize, End: fr.End}
	r.mapRange(rxVA, code, execAccess)
	r.program(gJump(rxVA))
	r.wantCall(41)
	before := r.as.PatchedBlocks()

	writeFrame(t, r, data, 0, []byte{1, 2, 3})
	r.ac.SetIP(codeVA)
	r.wantCall(41)
	if got := r.as.PatchedBlocks(); got != before {
		t.Errorf("patched blocks = %d after a write to another frame, want %d", got, before)
	}
	if got := r.p.HostWriteDrops(); got != 0 {
		t.Errorf("frames that lost a copy = %d, want 0", got)
	}
}

// wrappedFile hides the type of a memory file behind a wrapper, as the chunk
// memory of hostfs and ext4lite does.
type wrappedFile struct{ *pgalloc.MemoryFile }

// TestWrapperOfAMemoryFileGetsOneObserver maps one memory file through the
// file and through a wrapper of it. The platform must watch the file once,
// and a Sentry write must still drop the copy.
func TestWrapperOfAMemoryFileGetsOneObserver(t *testing.T) {
	r := newRig(t, newPlatform(t))
	fr, _ := r.allocFrames(2, gSyscall(41))
	code := memmap.FileRange{Start: fr.Start, End: fr.Start + blockSize}
	other := memmap.FileRange{Start: fr.Start + blockSize, End: fr.End}
	if err := r.as.MapFile(rxVA, wrappedFile{r.mf}, code, execAccess, false); err != nil {
		t.Fatalf("MapFile through the wrapper: %v", err)
	}
	r.mapRange(rxVA+blockSize, other, hostarch.Read)
	r.program(gJump(rxVA))
	r.wantCall(41)
	if got := len(r.p.hostWrites.stops); got != 1 {
		t.Errorf("the platform watches the file with %d observers, want 1", got)
	}
	writeFrame(t, r, code, 0, gSyscall(42))
	r.ac.SetIP(codeVA)
	r.wantCall(42)
}

// TestSentryWriteDuringAStoreWindowDropsTheCopy writes a frame from the Sentry
// while a store step holds the copy of that frame open, and then closes the
// window although the store changed no byte. The copy must not survive.
func TestSentryWriteDuringAStoreWindowDropsTheCopy(t *testing.T) {
	r := newRig(t, newPlatform(t))
	fr, mem := r.allocFrames(1, gSyscall(41))
	r.mapRange(codeVA, fr, rwxAccess)
	r.mapStack()
	r.wantCall(41)

	w, res, err := r.as.openStoreWindow(codeVA+0x400, codeVA)
	if err != nil || res != windowOpen {
		t.Fatalf("openStoreWindow = (%v, %v), want an open window", res, err)
	}
	copy(mem, gSyscall(42))
	r.mf.NoteHostWrite(fr)
	if err := r.as.closeStoreStep(&storeStep{windows: []storeWindow{w}}); err != nil {
		t.Fatalf("closeStoreStep: %v", err)
	}
	r.ac.SetIP(codeVA)
	r.wantCall(42)
}
