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

package whpx

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

const guestMemoryFileDataAddr = 0x10000000

// guestReadWriteDataCode reads [guestMemoryFileDataAddr] into R8, writes R9
// into [guestMemoryFileDataAddr], and stops with SYSCALL.
var guestReadWriteDataCode = bytes.Join([][]byte{
	{0x48, 0xB8, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00}, // movabs rax, 0x10000000
	{0x4C, 0x8B, 0x00}, // mov r8, [rax]
	{0x4C, 0x89, 0x08}, // mov [rax], r9
	{0x0F, 0x05},       // syscall
}, nil)

// TestRealWHPXMemoryFileDecommitAndReuse verifies that a private VirtualAlloc
// pgalloc.MemoryFile (MEM_RESERVE chunks with on-demand MEM_COMMIT and
// VirtualFree(MEM_DECOMMIT) on release) works end-to-end under WHvMapGpaRange
// across both Decommit (MADV_DONTNEED) and DecRef + re-allocation.
func TestRealWHPXMemoryFileDecommitAndReuse(t *testing.T) {
	p := newRealPlatform(t)
	mf, err := pgalloc.NewDefaultMemoryFile(pgalloc.MemoryFileOpts{DisableMemoryAccounting: true})
	if err != nil {
		t.Fatalf("NewDefaultMemoryFile: %v", err)
	}
	t.Cleanup(mf.Destroy)

	c, mm, ac := realGuest(t, p, guestReadWriteDataCode)

	const span = uint64(2 << 20)
	fr, err := mf.Allocate(span, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if err := mm.as.MapFile(guestMemoryFileDataAddr, mf, fr, hostarch.ReadWrite, false); err != nil {
		mf.DecRef(fr)
		t.Fatalf("MapFile: %v", err)
	}

	// Pass 1: guest reads initial zero, writes 0x1122334455667788.
	ac.StateData().Regs.R9 = 0x1122334455667788
	if sig, _, err := c.Switch(nil, mm, ac, -1); err != nil || sig != nil {
		mf.DecRef(fr)
		t.Fatalf("Switch pass 1: sig=%v err=%v", sig, err)
	}
	if got := ac.StateData().Regs.R8; got != 0 {
		mf.DecRef(fr)
		t.Fatalf("pass 1 initial guest read = %#x, want 0", got)
	}
	bs, err := mf.MapInternal(fr, hostarch.Read)
	if err != nil {
		mf.DecRef(fr)
		t.Fatalf("MapInternal pass 1: %v", err)
	}
	if got := binary.LittleEndian.Uint64(bs.Head().ToSlice()[:8]); got != 0x1122334455667788 {
		mf.DecRef(fr)
		t.Fatalf("host view after pass 1 = %#x, want 0x1122334455667788", got)
	}

	// Pass 2: Decommit (MADV_DONTNEED) while mapped in WHPX; guest must read 0.
	mf.Decommit(fr)
	setGuestEntry(ac, guestCodeAddr)
	ac.StateData().Regs.R9 = 0xCAFEBABEDEADBEEF
	if sig, _, err := c.Switch(nil, mm, ac, -1); err != nil || sig != nil {
		mf.DecRef(fr)
		t.Fatalf("Switch pass 2: sig=%v err=%v", sig, err)
	}
	if got := ac.StateData().Regs.R8; got != 0 {
		mf.DecRef(fr)
		t.Fatalf("pass 2 read after Decommit = %#x, want 0", got)
	}
	if got := binary.LittleEndian.Uint64(bs.Head().ToSlice()[:8]); got != 0xCAFEBABEDEADBEEF {
		mf.DecRef(fr)
		t.Fatalf("host view after pass 2 = %#x, want 0xCAFEBABEDEADBEEF", got)
	}

	// Pass 3: Unmap + DecRef (triggers VirtualFree(MEM_DECOMMIT) in releaser),
	// wait deterministically for the backing VA to transition to MEM_RESERVE,
	// then re-allocate and remap through the same persistent WHvMapGpaRange chunk.
	baseVA := uintptr(unsafe.Pointer(&bs.Head().ToSlice()[0]))
	var info windows.MemoryBasicInformation
	if err := windows.VirtualQuery(baseVA, &info, unsafe.Sizeof(info)); err != nil {
		mf.DecRef(fr)
		t.Fatalf("VirtualQuery before DecRef: %v", err)
	}
	if info.State != windows.MEM_COMMIT {
		mf.DecRef(fr)
		t.Fatalf("VA %#x state before DecRef = %#x, want MEM_COMMIT (%#x)", baseVA, info.State, windows.MEM_COMMIT)
	}

	mm.as.Unmap(guestMemoryFileDataAddr, span)
	mf.DecRef(fr)

	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := windows.VirtualQuery(baseVA, &info, unsafe.Sizeof(info)); err != nil {
			t.Fatalf("VirtualQuery after DecRef: %v", err)
		}
		if info.State == windows.MEM_RESERVE {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("VA %#x stayed in state %#x after DecRef, want MEM_RESERVE (%#x)", baseVA, info.State, windows.MEM_RESERVE)
		}
		time.Sleep(time.Millisecond)
	}

	fr2, err := mf.Allocate(span, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate pass 3: %v", err)
	}
	defer mf.DecRef(fr2)
	if fr2 != fr {
		t.Fatalf("re-allocated FileRange = %v, want %v (reuse of decommitted range)", fr2, fr)
	}
	if err := windows.VirtualQuery(baseVA, &info, unsafe.Sizeof(info)); err != nil {
		t.Fatalf("VirtualQuery after re-Allocate: %v", err)
	}
	if info.State != windows.MEM_COMMIT {
		t.Fatalf("VA %#x state after re-Allocate = %#x, want MEM_COMMIT (%#x)", baseVA, info.State, windows.MEM_COMMIT)
	}
	if err := mm.as.MapFile(guestMemoryFileDataAddr, mf, fr2, hostarch.ReadWrite, false); err != nil {
		t.Fatalf("MapFile pass 3: %v", err)
	}
	setGuestEntry(ac, guestCodeAddr)
	ac.StateData().Regs.R9 = 0xA5A55A5A01234567
	if sig, _, err := c.Switch(nil, mm, ac, -1); err != nil || sig != nil {
		t.Fatalf("Switch pass 3: sig=%v err=%v", sig, err)
	}
	if got := ac.StateData().Regs.R8; got != 0 {
		t.Fatalf("pass 3 read after DecRef + re-Allocate = %#x, want 0", got)
	}
	bs2, err := mf.MapInternal(fr2, hostarch.Read)
	if err != nil {
		t.Fatalf("MapInternal pass 3: %v", err)
	}
	if got := binary.LittleEndian.Uint64(bs2.Head().ToSlice()[:8]); got != 0xA5A55A5A01234567 {
		t.Fatalf("host view after pass 3 = %#x, want 0xA5A55A5A01234567", got)
	}
}
