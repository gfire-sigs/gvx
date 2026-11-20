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

//go:build linux

package systrap

import (
	"bytes"
	"runtime"
	"strings"
	"sync"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

type fakeCompBlockHost struct{}

func (fakeCompBlockHost) mapRange(addr, length uintptr, prot int, populate bool, fd int, off uint64) error {
	return nil
}

func (fakeCompBlockHost) unmapRange(addr, length uintptr) error { return nil }

func (fakeCompBlockHost) allocComp() (compPage, error) {
	return compPage{buf: make([]byte, subBlockSize)}, nil
}

func (fakeCompBlockHost) freeComp(c compPage) {}

func (fakeCompBlockHost) compFD() int { return 0 }

type noopSubBlockPopulator struct {
	platform.MemoryManager
}

func (noopSubBlockPopulator) PopulateSubBlock(context.Context, hostarch.Addr) bool {
	return false
}

type funcSubBlockPopulator struct {
	platform.MemoryManager
	fn func(context.Context, hostarch.Addr) bool
}

func (p funcSubBlockPopulator) PopulateSubBlock(ctx context.Context, addr hostarch.Addr) bool {
	return p.fn(ctx, addr)
}

// TestConcurrentBeforeSwitchWaitsForPopulatePartial verifies that a second
// thread in beforeSwitch waits for populatePartial to finish. It must not map
// a deferred block with zero-filled sub-pages while PopulateSubBlock runs.
func TestConcurrentBeforeSwitchWaitsForPopulatePartial(t *testing.T) {
	mf, err := createMemoryFile()
	if err != nil {
		t.Fatalf("createMemoryFile: %v", err)
	}
	defer mf.Destroy()

	// Allocate 5 guest pages and map starting at page 1 so the 4 sub-pages of
	// the block are backed by non-block-aligned file offsets and use a
	// composite page.
	page := uint64(hostarch.PageSize)
	fr, err := mf.Allocate(5*page, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer mf.DecRef(fr)

	bs, err := mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	raw := bs.Head().ToSlice()
	for i := range raw {
		raw[i] = 0x5a
	}

	layer := newSubBlockLayer(fakeCompBlockHost{})
	defer layer.reset()

	const blockAddr = hostarch.Addr(0x248000)
	baseOff := fr.Start + page
	sub23FR := memmap.FileRange{Start: baseOff + 2*page, End: baseOff + 4*page}
	if err := layer.mapFile(blockAddr+2*hostarch.Addr(page), mf, sub23FR, hostarch.Read, false); err != nil {
		t.Fatalf("mapFile sub-pages 2..3: %v", err)
	}

	var enteredOnce sync.Once
	enteredPopulate := make(chan struct{})
	bStarted := make(chan struct{})

	pop := funcSubBlockPopulator{
		fn: func(_ context.Context, addr hostarch.Addr) bool {
			enteredOnce.Do(func() {
				close(enteredPopulate)
				<-bStarted
				buf := make([]byte, 1<<18)
				for {
					n := runtime.Stack(buf, true)
					if strings.Count(string(buf[:n]), "subBlockLayer).beforeSwitch(") >= 2 {
						break
					}
					runtime.Gosched()
				}
				sub01FR := memmap.FileRange{Start: baseOff, End: baseOff + 2*page}
				if err := layer.mapFile(blockAddr, mf, sub01FR, hostarch.Read, false); err != nil {
					t.Errorf("mapFile sub-pages 0..1: %v", err)
				}
			})
			return true
		},
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		layer.beforeSwitch(nil, pop)
	}()

	var bSub0FirstByte byte
	var bMapped uint8
	go func() {
		defer wg.Done()
		<-enteredPopulate
		close(bStarted)
		layer.beforeSwitch(nil, pop)
		layer.mu.Lock()
		if hb := layer.blocks[uintptr(blockAddr)]; hb != nil {
			bMapped = hb.mapped
			if hb.hasComp && len(hb.comp.buf) > 0 {
				bSub0FirstByte = hb.comp.buf[0]
			}
		}
		layer.mu.Unlock()
	}()
	wg.Wait()

	if bMapped != allSubPages {
		t.Fatalf("second beforeSwitch returned with hb.mapped = %#b, want %#b", bMapped, uint8(allSubPages))
	}
	if bSub0FirstByte != 0x5a {
		t.Fatalf("second beforeSwitch returned with composite sub-page 0 byte = %#x, want 0x5a", bSub0FirstByte)
	}
}

// TestPopulatePartialRepopulatesAfterConcurrentRelease verifies that a
// ReleaseHostBlocks call during PopulateSubBlock causes populatePartial to
// re-populate the affected block before beforeSwitch maps deferred blocks.
func TestPopulatePartialRepopulatesAfterConcurrentRelease(t *testing.T) {
	mf, err := createMemoryFile()
	if err != nil {
		t.Fatalf("createMemoryFile: %v", err)
	}
	defer mf.Destroy()

	page := uint64(hostarch.PageSize)
	fr, err := mf.Allocate(5*page, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer mf.DecRef(fr)

	bs, err := mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	for i, b := range bs.Head().ToSlice() {
		_ = b
		bs.Head().ToSlice()[i] = 0xa5
	}

	layer := newSubBlockLayer(fakeCompBlockHost{})
	defer layer.reset()

	const blockAddr = hostarch.Addr(0x300000)
	baseOff := fr.Start + page
	sub23FR := memmap.FileRange{Start: baseOff + 2*page, End: baseOff + 4*page}
	if err := layer.mapFile(blockAddr+2*hostarch.Addr(page), mf, sub23FR, hostarch.Read, false); err != nil {
		t.Fatalf("mapFile sub-pages 2..3: %v", err)
	}

	calls := 0
	pop := funcSubBlockPopulator{
		fn: func(_ context.Context, addr hostarch.Addr) bool {
			if addr != blockAddr {
				return false
			}
			calls++
			if calls == 1 {
				// Simulate a concurrent MMap/MProtect that calls release on the
				// block before the new VMA is populated on the retry pass.
				layer.release(hostarch.AddrRange{Start: blockAddr, End: blockAddr + subBlockSize})
				return false
			}
			sub01FR := memmap.FileRange{Start: baseOff, End: baseOff + 2*page}
			if err := layer.mapFile(blockAddr, mf, sub01FR, hostarch.Read, false); err != nil {
				t.Errorf("mapFile sub-pages 0..1: %v", err)
			}
			return true
		},
	}

	layer.beforeSwitch(nil, pop)
	if calls < 2 {
		t.Fatalf("PopulateSubBlock call count = %d, want >= 2 after concurrent release", calls)
	}
	layer.mu.Lock()
	hb := layer.blocks[uintptr(blockAddr)]
	var got []byte
	if hb != nil && hb.hasComp {
		got = bytes.Clone(hb.comp.buf[:4])
	}
	layer.mu.Unlock()
	if !bytes.Equal(got, []byte{0xa5, 0xa5, 0xa5, 0xa5}) {
		t.Fatalf("composite sub-page 0 prefix = %x, want a5a5a5a5", got)
	}
}

// TestPopulatePartialRepopulatesAfterSiblingUnmap verifies that an unmap during
// PopulateSubBlock (such as breaking COW on a merged PMA) causes populatePartial
// to re-populate cleared sub-pages instead of zero-filling them.
func TestPopulatePartialRepopulatesAfterSiblingUnmap(t *testing.T) {
	mf, err := createMemoryFile()
	if err != nil {
		t.Fatalf("createMemoryFile: %v", err)
	}
	defer mf.Destroy()

	page := uint64(hostarch.PageSize)
	pageAddr := hostarch.Addr(page)
	fr, err := mf.Allocate(9*page, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer mf.DecRef(fr)

	bs, err := mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	raw := bs.Head().ToSlice()
	for i := range raw {
		raw[i] = 0xc5
	}

	layer := newSubBlockLayer(fakeCompBlockHost{})
	defer layer.reset()

	const (
		headBlock = hostarch.Addr(0x400000)
		tailBlock = hostarch.Addr(0x410000)
	)
	baseOff := fr.Start + page
	pageAt := func(idx uint64) memmap.FileRange {
		off := baseOff + idx*page
		return memmap.FileRange{Start: off, End: off + page}
	}

	// Map headBlock sub-page 3 and tailBlock sub-pages 0..2 to match one 64 KiB COW PMA.
	if err := layer.mapFile(headBlock+3*pageAddr, mf, pageAt(3), hostarch.Read, false); err != nil {
		t.Fatalf("mapFile head sub-page 3: %v", err)
	}
	tailInitFR := memmap.FileRange{Start: baseOff + 4*page, End: baseOff + 7*page}
	if err := layer.mapFile(tailBlock, mf, tailInitFR, hostarch.Read, false); err != nil {
		t.Fatalf("mapFile tail sub-pages 0..2: %v", err)
	}

	cowBroken := false
	pop := funcSubBlockPopulator{
		fn: func(_ context.Context, addr hostarch.Addr) bool {
			switch addr {
			case headBlock, headBlock + pageAddr, headBlock + 2*pageAddr:
				idx := uint64(addr-headBlock) / page
				if err := layer.mapFile(addr, mf, pageAt(idx), hostarch.Read, false); err != nil {
					t.Errorf("mapFile(%#x): %v", addr, err)
				}
				return true
			case headBlock + 3*pageAddr:
				if err := layer.mapFile(addr, mf, pageAt(3), hostarch.ReadWrite, false); err != nil {
					t.Errorf("mapFile(%#x): %v", addr, err)
				}
				return true
			case tailBlock, tailBlock + pageAddr, tailBlock + 2*pageAddr:
				idx := 4 + uint64(addr-tailBlock)/page
				if err := layer.mapFile(addr, mf, pageAt(idx), hostarch.ReadWrite, false); err != nil {
					t.Errorf("mapFile(%#x): %v", addr, err)
				}
				return true
			case tailBlock + 3*pageAddr:
				if !cowBroken {
					cowBroken = true
					// Breaking COW on the merged PMA unmaps [headBlock+3*PageSize, tailBlock+3*PageSize)
					// while PopulateSubBlock maps only the faulting page at tailBlock+3*PageSize.
					layer.unmap(headBlock+3*pageAddr, uint64(tailBlock-headBlock))
				}
				if err := layer.mapFile(addr, mf, pageAt(7), hostarch.ReadWrite, false); err != nil {
					t.Errorf("mapFile(%#x): %v", addr, err)
				}
				return true
			default:
				return false
			}
		},
	}

	layer.beforeSwitch(nil, pop)

	layer.mu.Lock()
	headHB := layer.blocks[uintptr(headBlock)]
	tailHB := layer.blocks[uintptr(tailBlock)]
	var headSub3, tailSub0 []byte
	var headMapped, tailMapped uint8
	if headHB != nil {
		headMapped = headHB.mapped
		if headHB.hasComp {
			off := 3 * int(page)
			headSub3 = bytes.Clone(headHB.comp.buf[off : off+4])
		}
	}
	if tailHB != nil {
		tailMapped = tailHB.mapped
		if tailHB.hasComp {
			tailSub0 = bytes.Clone(tailHB.comp.buf[:4])
		}
	}
	layer.mu.Unlock()

	if headMapped != allSubPages || !bytes.Equal(headSub3, []byte{0xc5, 0xc5, 0xc5, 0xc5}) {
		t.Fatalf("headBlock mapped=%#b sub-page 3 prefix=%x, want %#b and c5c5c5c5", headMapped, headSub3, uint8(allSubPages))
	}
	if tailMapped != allSubPages || !bytes.Equal(tailSub0, []byte{0xc5, 0xc5, 0xc5, 0xc5}) {
		t.Fatalf("tailBlock mapped=%#b sub-page 0 prefix=%x, want %#b and c5c5c5c5", tailMapped, tailSub0, uint8(allSubPages))
	}
}

func TestAlignToPageSpan(t *testing.T) {
	for _, tc := range []struct {
		name           string
		addr, size, ps uintptr
		wantAddr       uintptr
		wantSize       uintptr
	}{
		{"4 KB aligned stack on 4 KB host", 0x601000, 0x1000, 0x1000, 0x601000, 0x1000},
		{"4 KB sub-page stack on 16 KB host", 0x601000, 0x1000, 0x4000, 0x600000, 0x4000},
		{"cross-boundary span on 16 KB host", 0x603000, 0x2000, 0x4000, 0x600000, 0x8000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotAddr, gotSize := alignToPageSpan(tc.addr, tc.size, tc.ps)
			if gotAddr != tc.wantAddr || gotSize != tc.wantSize {
				t.Fatalf("alignToPageSpan(%#x, %#x, %#x) = (%#x, %#x), want (%#x, %#x)",
					tc.addr, tc.size, tc.ps, gotAddr, gotSize, tc.wantAddr, tc.wantSize)
			}
		})
	}
}

func TestSubprocessSubBlockSwitchAndUnmapHooks(t *testing.T) {
	var nilSubproc subprocess
	var ctx platformContext
	ctx.subBlockSeq = 7
	ctx.subBlockChanges = 9
	nilSubproc.beforeSubBlockSwitch(nil, &ctx, noopSubBlockPopulator{})
	if ctx.subBlockSeq != 7 || ctx.subBlockChanges != 9 {
		t.Fatalf("nil subBlocks modified counters to (%d, %d), want (7, 9)", ctx.subBlockSeq, ctx.subBlockChanges)
	}
	if nilSubproc.unmapSubBlocks(0x200000, subBlockSize) {
		t.Fatal("nil subBlocks unmapSubBlocks = true, want false")
	}

	mf, err := createMemoryFile()
	if err != nil {
		t.Fatalf("createMemoryFile: %v", err)
	}
	defer mf.Destroy()

	page := uint64(hostarch.PageSize)
	fr, err := mf.Allocate(2*page, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer mf.DecRef(fr)

	layer := newSubBlockLayer(fakeCompBlockHost{})
	defer layer.reset()
	layer.storeSeq.Store(41)

	const blockAddr = hostarch.Addr(0x200000)
	pageFR := memmap.FileRange{Start: fr.Start + page, End: fr.End}
	if err := layer.mapFile(blockAddr, mf, pageFR, hostarch.Read, false); err != nil {
		t.Fatalf("mapFile: %v", err)
	}

	subproc := subprocess{subBlocks: layer}
	subproc.beforeSubBlockSwitch(nil, &ctx, noopSubBlockPopulator{})
	if ctx.subBlockSeq != 41 {
		t.Fatalf("subBlockSeq = %d, want 41", ctx.subBlockSeq)
	}
	if ctx.subBlockChanges == 0 {
		t.Fatal("subBlockChanges = 0 after mapping deferred composite block, want > 0")
	}
	if !subproc.unmapSubBlocks(blockAddr, subBlockSize) {
		t.Fatal("active subBlocks unmapSubBlocks = false, want true")
	}
	layer.mu.Lock()
	_, exists := layer.blocks[uintptr(blockAddr)]
	layer.mu.Unlock()
	if exists {
		t.Fatalf("block %#x remained present after unmapSubBlocks", blockAddr)
	}
}

func TestResolveSubBlockFault(t *testing.T) {
	ac := arch.New(arch.Host)
	ac.SetIP(0x500000)

	var nilSubproc subprocess
	var ctx platformContext
	ctx.subBlockRetries = 3
	si := linux.SignalInfo{Signo: int32(linux.SIGSEGV), Code: segvAccerr}
	at := hostarch.Write
	if nilSubproc.resolveSubBlockFault(&ctx, ac, &si, &at) {
		t.Fatal("nil subBlocks resolveSubBlockFault = true, want false")
	}
	if ctx.subBlockRetries != 3 || at != hostarch.Write {
		t.Fatalf("nil subBlocks mutated state: retries=%d at=%v", ctx.subBlockRetries, at)
	}

	mf, err := createMemoryFile()
	if err != nil {
		t.Fatalf("createMemoryFile: %v", err)
	}
	defer mf.Destroy()

	page := uint64(hostarch.PageSize)
	fr, err := mf.Allocate(2*page, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer mf.DecRef(fr)

	layer := newSubBlockLayer(fakeCompBlockHost{})
	defer layer.reset()

	const blockAddr = hostarch.Addr(0x400000)
	pageFR := memmap.FileRange{Start: fr.Start + page, End: fr.End}
	if err := layer.mapFile(blockAddr, mf, pageFR, hostarch.ReadWrite, false); err != nil {
		t.Fatalf("mapFile: %v", err)
	}
	subproc := subprocess{subBlocks: layer}
	subproc.beforeSubBlockSwitch(nil, &ctx, noopSubBlockPopulator{})

	// A write fault on a writable composite sub-page with an unreadable PC is
	// refused: access clears to NoAccess and retries reset to zero.
	ctx.signalInfo = linux.SignalInfo{Signo: int32(linux.SIGSEGV), Code: segvAccerr}
	ctx.signalInfo.SetAddr(uint64(blockAddr))
	si = ctx.signalInfo
	at = hostarch.Write
	ctx.subBlockRetries = 5
	if subproc.resolveSubBlockFault(&ctx, ac, &si, &at) {
		t.Fatal("refused store returned restart = true, want false")
	}
	if at != hostarch.NoAccess || ctx.subBlockRetries != 0 {
		t.Fatalf("after refused store: at=%v retries=%d, want NoAccess and 0", at, ctx.subBlockRetries)
	}

	// A SEGV_ACCERR on an unmapped sub-page of a mapped block becomes SEGV_MAPERR.
	missingAddr := uint64(blockAddr) + page
	ctx.signalInfo = linux.SignalInfo{Signo: int32(linux.SIGSEGV), Code: segvAccerr}
	ctx.signalInfo.SetAddr(missingAddr)
	si = ctx.signalInfo
	at = hostarch.Read
	if subproc.resolveSubBlockFault(&ctx, ac, &si, &at) {
		t.Fatal("missing-page SEGV returned restart = true, want false")
	}
	if si.Code != segvMaperr {
		t.Fatalf("missing-page si.Code = %d, want segvMaperr (%d)", si.Code, segvMaperr)
	}

	// SIGILL while changes advanced restarts at most maxSubBlockFaultRetries times.
	layer.changes.Add(1)
	si = linux.SignalInfo{Signo: int32(linux.SIGILL)}
	at = hostarch.Execute
	for i := 1; i <= maxSubBlockFaultRetries; i++ {
		if !subproc.resolveSubBlockFault(&ctx, ac, &si, &at) {
			t.Fatalf("retry %d: resolveSubBlockFault = false, want true", i)
		}
		if ctx.subBlockRetries != i {
			t.Fatalf("retry %d: subBlockRetries = %d, want %d", i, ctx.subBlockRetries, i)
		}
	}
	if subproc.resolveSubBlockFault(&ctx, ac, &si, &at) {
		t.Fatal("17th consecutive SIGILL returned restart = true, want false")
	}
	if ctx.subBlockRetries != 0 {
		t.Fatalf("subBlockRetries after cap = %d, want 0", ctx.subBlockRetries)
	}
}

type recordingCompBlockHost struct {
	mf        *pgalloc.MemoryFile
	mapCalls  int
	lastProt  int
	compRange memmap.FileRange
}

func (h *recordingCompBlockHost) mapRange(addr, length uintptr, prot int, populate bool, fd int, off uint64) error {
	h.mapCalls++
	h.lastProt = prot
	return nil
}

func (h *recordingCompBlockHost) unmapRange(addr, length uintptr) error { return nil }

func (h *recordingCompBlockHost) allocComp() (compPage, error) {
	fr, err := h.mf.AllocateAligned(subBlockSize, subBlockSize, pgalloc.AllocOpts{Kind: usage.System})
	if err != nil {
		return compPage{}, err
	}
	bs, err := h.mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		h.mf.DecRef(fr)
		return compPage{}, err
	}
	h.compRange = fr
	return compPage{fr: fr, buf: bs.Head().ToSlice()}, nil
}

func (h *recordingCompBlockHost) freeComp(c compPage) {
	h.mf.DecRef(c.fr)
}

func (h *recordingCompBlockHost) compFD() int {
	return h.mf.FD()
}

// TestCompositeWXSiblingExecCleansStubICache verifies that mprotect cleans and
// remaps a composite block after a guest store into a writable sub-page. A
// sibling sub-page holds execute access throughout the test.
func TestCompositeWXSiblingExecCleansStubICache(t *testing.T) {
	mf, err := createMemoryFile()
	if err != nil {
		t.Fatalf("createMemoryFile: %v", err)
	}
	defer mf.Destroy()

	page := uint64(hostarch.PageSize)
	fr, err := mf.Allocate(5*page, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer mf.DecRef(fr)

	host := &recordingCompBlockHost{mf: mf}
	layer := newSubBlockLayer(host)
	defer layer.reset()

	const blockAddr = hostarch.Addr(0x600000)
	baseOff := fr.Start + page
	pageAt := func(idx uint64) memmap.FileRange {
		off := baseOff + idx*page
		return memmap.FileRange{Start: off, End: off + page}
	}
	rxPerms := hostarch.AccessType{Read: true, Execute: true}
	rwxPerms := hostarch.AccessType{Read: true, Write: true, Execute: true}

	for i := uint64(0); i < 3; i++ {
		if err := layer.mapFile(blockAddr+hostarch.Addr(i*page), mf, pageAt(i), hostarch.ReadWrite, false); err != nil {
			t.Fatalf("mapFile sub-page %d: %v", i, err)
		}
	}
	if err := layer.mapFile(blockAddr+3*hostarch.Addr(page), mf, pageAt(3), rxPerms, false); err != nil {
		t.Fatalf("mapFile sub-page 3 RX: %v", err)
	}
	layer.beforeSwitch(nil, noopSubBlockPopulator{})
	initMaps := host.mapCalls
	if initMaps == 0 {
		t.Fatal("initial composite mapping recorded zero mapRange calls")
	}

	// Emulated stores to a non-executable data sub-page must not remap the stub.
	layer.mu.Lock()
	layer.writeLocked(uint64(blockAddr), []byte{1, 2, 3, 4})
	layer.mu.Unlock()
	layer.beforeSwitch(nil, noopSubBlockPopulator{})
	if host.mapCalls != initMaps {
		t.Fatalf("data-only store remapped composite block (%d vs %d)", host.mapCalls, initMaps)
	}

	// Cycle 1: store machine code to RW sub-page 1, then mprotect sub-page 1 to RX.
	p1Addr := blockAddr + hostarch.Addr(page)
	codeV1 := []byte{0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6}
	layer.mu.Lock()
	layer.writeLocked(uint64(p1Addr), codeV1)
	layer.mu.Unlock()
	beforeWX1 := host.mapCalls
	if err := layer.mapFile(p1Addr, mf, pageAt(1), rxPerms, false); err != nil {
		t.Fatalf("mprotect sub-page 1 RX (cycle 1): %v", err)
	}
	if host.mapCalls <= beforeWX1 {
		t.Fatalf("cycle 1 RW to RX transition did not remap stub (%d vs %d)", host.mapCalls, beforeWX1)
	}

	// Cycle 2: flip sub-page 1 back to RW, overwrite machine code, and flip to RX again.
	if err := layer.mapFile(p1Addr, mf, pageAt(1), hostarch.ReadWrite, false); err != nil {
		t.Fatalf("mprotect sub-page 1 RW (cycle 2): %v", err)
	}
	codeV2 := []byte{0x60, 0x0c, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6}
	layer.mu.Lock()
	layer.writeLocked(uint64(p1Addr), codeV2)
	layer.mu.Unlock()
	beforeWX2 := host.mapCalls
	if err := layer.mapFile(p1Addr, mf, pageAt(1), rxPerms, false); err != nil {
		t.Fatalf("mprotect sub-page 1 RX (cycle 2): %v", err)
	}
	if host.mapCalls <= beforeWX2 {
		t.Fatalf("cycle 2 RW to RX transition did not remap stub (%d vs %d)", host.mapCalls, beforeWX2)
	}

	// Self-modifying store on an RWX composite sub-page must remap on beforeSwitch.
	if err := layer.mapFile(p1Addr, mf, pageAt(1), rwxPerms, false); err != nil {
		t.Fatalf("mprotect sub-page 1 RWX: %v", err)
	}
	beforeRWX := host.mapCalls
	layer.mu.Lock()
	layer.writeLocked(uint64(p1Addr), codeV1)
	layer.mu.Unlock()
	layer.beforeSwitch(nil, noopSubBlockPopulator{})
	if host.mapCalls <= beforeRWX {
		t.Fatalf("RWX store did not remap stub on beforeSwitch (%d vs %d)", host.mapCalls, beforeRWX)
	}
}
