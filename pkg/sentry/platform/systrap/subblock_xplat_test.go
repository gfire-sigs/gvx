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
	"sync"
	"testing"
	"time"

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
	fr, err := mf.Allocate(5*hostarch.PageSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
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
	baseOff := fr.Start + hostarch.PageSize
	sub23FR := memmap.FileRange{Start: baseOff + 2*hostarch.PageSize, End: baseOff + 4*hostarch.PageSize}
	if err := layer.mapFile(blockAddr+2*hostarch.PageSize, mf, sub23FR, hostarch.Read, false); err != nil {
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
				time.Sleep(15 * time.Millisecond)
				sub01FR := memmap.FileRange{Start: baseOff, End: baseOff + 2*hostarch.PageSize}
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

	fr, err := mf.Allocate(5*hostarch.PageSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
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
	baseOff := fr.Start + hostarch.PageSize
	sub23FR := memmap.FileRange{Start: baseOff + 2*hostarch.PageSize, End: baseOff + 4*hostarch.PageSize}
	if err := layer.mapFile(blockAddr+2*hostarch.PageSize, mf, sub23FR, hostarch.Read, false); err != nil {
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
			sub01FR := memmap.FileRange{Start: baseOff, End: baseOff + 2*hostarch.PageSize}
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

	fr, err := mf.Allocate(2*hostarch.PageSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer mf.DecRef(fr)

	layer := newSubBlockLayer(fakeCompBlockHost{})
	defer layer.reset()
	layer.storeSeq.Store(41)

	const blockAddr = hostarch.Addr(0x200000)
	pageFR := memmap.FileRange{Start: fr.Start + hostarch.PageSize, End: fr.End}
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

	fr, err := mf.Allocate(2*hostarch.PageSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer mf.DecRef(fr)

	layer := newSubBlockLayer(fakeCompBlockHost{})
	defer layer.reset()

	const blockAddr = hostarch.Addr(0x400000)
	pageFR := memmap.FileRange{Start: fr.Start + hostarch.PageSize, End: fr.End}
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
	missingAddr := uint64(blockAddr + hostarch.PageSize)
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
