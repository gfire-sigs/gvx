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

//go:build linux && amd64

package usertrap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/usermem"
)

type pinnedSiteMM struct {
	usermem.IO
	blocks []safemem.Block
	pinErr error
	pins   int
	addr   hostarch.Addr
	length int
}

func (*pinnedSiteMM) MMap(context.Context, memmap.MMapOpts) (hostarch.Addr, error) {
	return 0, nil
}

func (*pinnedSiteMM) FindVMAByName(hostarch.AddrRange, string) (hostarch.Addr, uint64, error) {
	return 0, 0, nil
}

func (m *pinnedSiteMM) WithPinnedMappings(_ context.Context, addr hostarch.Addr, length int, f func(safemem.BlockSeq) error) error {
	m.pins++
	m.addr = addr
	m.length = length
	if m.pinErr != nil {
		return m.pinErr
	}
	return f(safemem.BlockSeqFromSlice(m.blocks))
}

func jumpTargetCode(trapAddr uint32) [jmpInstLen]uint8 {
	var code [jmpInstLen]uint8
	copy(code[:jmpInstOpcodeLen], jmpInst[:jmpInstOpcodeLen])
	binary.LittleEndian.PutUint32(code[jmpInstOpcodeLen:], trapAddr)
	return code
}

func TestPatchSyscallSiteWritesJumpAcrossSplitBlocksInOnePin(t *testing.T) {
	const (
		sysno     = 39 // getpid
		siteAddr  = uintptr(0x401ffd)
		trapEntry = uint32(0x60050)
	)
	orig := origSyscallCode(sysno)
	frameA := bytes.Clone(orig[:3])
	frameB := bytes.Clone(orig[3:])
	mm := &pinnedSiteMM{
		blocks: []safemem.Block{
			safemem.BlockFromSafeSlice(frameA),
			safemem.BlockFromSafeSlice(frameB),
		},
	}
	want := jumpTargetCode(trapEntry)

	applied, err := patchSyscallSite(context.Background(), mm, siteAddr, sysno, want)
	if err != nil {
		t.Fatalf("patchSyscallSite: %v", err)
	}
	if !applied {
		t.Fatal("patchSyscallSite = false, want true")
	}
	if mm.pins != 1 || mm.addr != hostarch.Addr(siteAddr) || mm.length != jmpInstLen {
		t.Fatalf("pin call = (count=%d, addr=%#x, len=%d), want (1, %#x, %d)", mm.pins, mm.addr, mm.length, siteAddr, jmpInstLen)
	}
	got := append(bytes.Clone(frameA), frameB...)
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("patched bytes = % x, want % x", got, want)
	}
	if !isPatchedWith(got, hostarch.Addr(trapEntry)) {
		t.Fatalf("isPatchedWith(% x, %#x) = false, want true", got, trapEntry)
	}
}

func TestPatchSyscallSiteSkipsModifiedSiteWithoutWriting(t *testing.T) {
	const (
		expectedSysno = 39
		otherSysno    = 60
		siteAddr      = uintptr(0x402000)
	)
	modified := origSyscallCode(otherSysno)
	backing := bytes.Clone(modified[:])
	mm := &pinnedSiteMM{
		blocks: []safemem.Block{safemem.BlockFromSafeSlice(backing)},
	}

	applied, err := patchSyscallSite(context.Background(), mm, siteAddr, expectedSysno, jumpTargetCode(0x60050))
	if err != nil {
		t.Fatalf("patchSyscallSite: %v", err)
	}
	if applied {
		t.Fatal("patchSyscallSite = true on mismatched syscall site, want false")
	}
	if !bytes.Equal(backing, modified[:]) {
		t.Fatalf("backing bytes changed to % x, want untouched % x", backing, modified)
	}
}

func TestUnpatchSyscallSiteRestoresOriginalCodeAndPropagatesPinError(t *testing.T) {
	const (
		sysno    = 1
		siteAddr = hostarch.Addr(0x403ffc)
	)
	patched := jumpTargetCode(0x600a0)
	frameA := bytes.Clone(patched[:4])
	frameB := bytes.Clone(patched[4:])
	mm := &pinnedSiteMM{
		blocks: []safemem.Block{
			safemem.BlockFromSafeSlice(frameA),
			safemem.BlockFromSafeSlice(frameB),
		},
	}
	want := origSyscallCode(sysno)

	if err := unpatchSyscallSite(context.Background(), mm, siteAddr, sysno, want); err != nil {
		t.Fatalf("unpatchSyscallSite: %v", err)
	}
	if mm.pins != 1 {
		t.Fatalf("WithPinnedMappings count = %d, want 1", mm.pins)
	}
	got := append(bytes.Clone(frameA), frameB...)
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("unpatched bytes = % x, want % x", got, want)
	}

	errPin := errors.New("unmapped page")
	failMM := &pinnedSiteMM{pinErr: errPin}
	if err := unpatchSyscallSite(context.Background(), failMM, siteAddr, sysno, want); !errors.Is(err, errPin) {
		t.Fatalf("unpatchSyscallSite error = %v, want %v", err, errPin)
	}
}
