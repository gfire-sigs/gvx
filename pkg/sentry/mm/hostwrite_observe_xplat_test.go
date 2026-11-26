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

//go:build windows || linux

package mm

import (
	"bytes"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/pkg/usermem"
)

// chunkLike wraps a memory file as the chunk memory of hostfs and ext4lite does.
type chunkLike struct{ *pgalloc.MemoryFile }

// wrappedFileMappable translates a fixed range into a chunkLike memory file.
type wrappedFileMappable struct {
	memmap.MappableNoHugepages
	file  chunkLike
	start uint64
}

func (m *wrappedFileMappable) AddMapping(context.Context, memmap.MappingSpace, hostarch.AddrRange, uint64, bool) error {
	return nil
}

func (m *wrappedFileMappable) RemoveMapping(context.Context, memmap.MappingSpace, hostarch.AddrRange, uint64, bool) {
}

func (m *wrappedFileMappable) CopyMapping(context.Context, memmap.MappingSpace, hostarch.AddrRange, hostarch.AddrRange, uint64, bool) error {
	return nil
}

func (m *wrappedFileMappable) Translate(_ context.Context, required, _ memmap.MappableRange, _ hostarch.AccessType) ([]memmap.Translation, error) {
	return []memmap.Translation{{
		Source: required,
		File:   m.file,
		Offset: m.start + required.Start,
		Perms:  hostarch.ReadWrite,
	}}, nil
}

func (m *wrappedFileMappable) InvalidateUnsavable(context.Context) error { return nil }

func newWatchedMapping(t *testing.T) (context.Context, *MemoryManager, hostarch.Addr, memmap.FileRange, *[]memmap.FileRange, *pgalloc.MemoryFile) {
	t.Helper()
	mf, err := newCOWTestMemoryFile()
	if err != nil {
		t.Fatalf("newCOWTestMemoryFile: %v", err)
	}
	t.Cleanup(mf.Destroy)
	page := uint64(hostarch.PageSize)
	fr, err := mf.Allocate(2*page, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	ls := linuxLimits(t)
	ctx := context.WithValues(context.Background(), map[any]any{
		pgalloc.CtxMemoryFile: mf,
		limits.CtxLimits:      ls,
	})
	manager, err := NewMemoryManager(faultPlatform{}, mf)
	if err != nil {
		t.Fatalf("NewMemoryManager: %v", err)
	}
	if _, err := manager.SetMmapLayout(arch.New(arch.Host), ls); err != nil {
		t.Fatalf("SetMmapLayout: %v", err)
	}
	addr, err := manager.MMap(ctx, memmap.MMapOpts{
		Length:   2 * page,
		Mappable: &wrappedFileMappable{file: chunkLike{mf}, start: fr.Start},
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.ReadWrite,
	})
	if err != nil {
		t.Fatalf("MMap: %v", err)
	}
	got := new([]memmap.FileRange)
	stop := mf.ObserveHostWrites(func(r memmap.FileRange) { *got = append(*got, r) })
	t.Cleanup(stop)
	return ctx, manager, addr, fr, got, mf
}

// TestNoteHostWriteThroughInternalMappings verifies that CopyOut reports writes
// on both slow (unfaulted) and fast (cached PMA) paths, while CopyIn does not.
func TestNoteHostWriteThroughInternalMappings(t *testing.T) {
	ctx, manager, addr, fr, got, _ := newWatchedMapping(t)
	page := uint64(hostarch.PageSize)
	secondAddr := addr + hostarch.Addr(page)
	payload := bytes.Repeat([]byte{0x5A}, int(page))

	// First write takes the slow path (faults PMA in) and reports the written range.
	if _, err := manager.CopyOut(ctx, secondAddr, payload, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut slow path: %v", err)
	}
	want := memmap.FileRange{Start: fr.Start + page, End: fr.End}
	if len(*got) != 1 || (*got)[0] != want {
		t.Fatalf("slow-path writes = %v, want [%v]", *got, want)
	}

	// Second write hits the cached-PMA fast path and still reports the write.
	*got = nil
	if _, err := manager.CopyOut(ctx, secondAddr, payload, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut fast path: %v", err)
	}
	if len(*got) != 1 || (*got)[0] != want {
		t.Fatalf("fast-path writes = %v, want [%v]", *got, want)
	}

	// CopyIn must not report a write.
	*got = nil
	buf := make([]byte, page)
	if _, err := manager.CopyIn(ctx, secondAddr, buf, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyIn: %v", err)
	}
	if len(*got) != 0 {
		t.Fatalf("CopyIn reported writes = %v, want none", *got)
	}
}

// TestNoteHostWriteVecThroughInternalMappings verifies that CopyOutFrom reports
// every range in a multi-range vector write on both slow and fast paths.
func TestNoteHostWriteVecThroughInternalMappings(t *testing.T) {
	ctx, manager, addr, fr, got, _ := newWatchedMapping(t)
	page := uint64(hostarch.PageSize)
	first := hostarch.AddrRange{Start: addr, End: addr + hostarch.Addr(page)}
	second := hostarch.AddrRange{Start: addr + hostarch.Addr(page), End: addr + 2*hostarch.Addr(page)}
	ars := hostarch.AddrRangeSeqFromSlice([]hostarch.AddrRange{second, first})
	want := []memmap.FileRange{
		{Start: fr.Start + page, End: fr.End},
		{Start: fr.Start, End: fr.Start + page},
	}

	// Slow path (PMAs not yet populated).
	src := bytes.Repeat([]byte{0x3C}, int(2*page))
	if _, err := manager.CopyOutFrom(ctx, ars, safemem.FromIOReader{Reader: bytes.NewReader(src)}, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOutFrom slow path: %v", err)
	}
	if len(*got) != 2 || (*got)[0] != want[0] || (*got)[1] != want[1] {
		t.Fatalf("slow-path vec writes = %v, want %v", *got, want)
	}

	// Fast path (PMAs already cached).
	*got = nil
	if _, err := manager.CopyOutFrom(ctx, ars, safemem.FromIOReader{Reader: bytes.NewReader(src)}, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOutFrom fast path: %v", err)
	}
	if len(*got) != 2 || (*got)[0] != want[0] || (*got)[1] != want[1] {
		t.Fatalf("fast-path vec writes = %v, want %v", *got, want)
	}

	// Partial vector write (unmapped trailing range) still reports the written
	// prefix through pars.TakeFirst64(int64(imlen)).
	*got = nil
	unmapped := hostarch.AddrRange{Start: addr + 4*hostarch.Addr(page), End: addr + 5*hostarch.Addr(page)}
	partialARS := hostarch.AddrRangeSeqFromSlice([]hostarch.AddrRange{second, unmapped})
	if n, err := manager.CopyOutFrom(ctx, partialARS, safemem.FromIOReader{Reader: bytes.NewReader(src)}, usermem.IOOpts{}); err == nil || n != int64(page) {
		t.Fatalf("CopyOutFrom partial = (%d, %v), want (%d, non-nil error)", n, err, page)
	}
	if len(*got) != 1 || (*got)[0] != want[0] {
		t.Fatalf("partial vec writes = %v, want [%v]", *got, want[0])
	}
}

// TestMappingAPMAReportsNoWrite verifies that mapping a PMA with ReadWrite
// access via mapInternalOf does not emit a write notification, while direct
// MapInternal(Write) does.
func TestMappingAPMAReportsNoWrite(t *testing.T) {
	_, _, _, fr, got, mf := newWatchedMapping(t)
	if _, err := mapInternalOf(chunkLike{mf}, fr, hostarch.ReadWrite); err != nil {
		t.Fatalf("mapInternalOf: %v", err)
	}
	if len(*got) != 0 {
		t.Errorf("mapping a pma reported %v", *got)
	}
	if _, err := mf.MapInternal(fr, hostarch.Write); err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	if len(*got) != 1 {
		t.Errorf("a direct request for write access reported %v, want one range", *got)
	}
}

// TestObservedCopyOutNoescapeAcrossStackGrowth verifies that CopyOut stays
// non-escaping across stack growth and GC while an observer is active and
// still reports the written file range.
func TestObservedCopyOutNoescapeAcrossStackGrowth(t *testing.T) {
	mf, err := newCOWTestMemoryFile()
	if err != nil {
		t.Fatalf("newCOWTestMemoryFile: %v", err)
	}
	t.Cleanup(mf.Destroy)
	page := uint64(hostarch.PageSize)
	fr, err := mf.Allocate(page, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	ls := linuxLimits(t)
	ctx := context.WithValues(context.Background(), map[any]any{
		pgalloc.CtxMemoryFile: mf,
		limits.CtxLimits:      ls,
	})
	manager, err := NewMemoryManager(faultPlatform{}, mf)
	if err != nil {
		t.Fatalf("NewMemoryManager: %v", err)
	}
	if _, err := manager.SetMmapLayout(arch.New(arch.Host), ls); err != nil {
		t.Fatalf("SetMmapLayout: %v", err)
	}
	addr, err := manager.MMap(ctx, memmap.MMapOpts{
		Length:   page,
		Mappable: &stackGrowMappable{mf: mf, start: fr.Start},
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.ReadWrite,
	})
	if err != nil {
		t.Fatalf("MMap: %v", err)
	}
	var got []memmap.FileRange
	stop := mf.ObserveHostWrites(func(r memmap.FileRange) { got = append(got, r) })
	t.Cleanup(stop)

	cc := &mmCopyContext{ctx: ctx, mm: manager}
	want := linux.SignalStack{
		Addr:  0xdeadbeefcafebabe,
		Flags: linux.SS_DISABLE,
		Size:  0x4000,
	}
	errCh := make(chan error, 1)
	go func() {
		src := want
		_, err := src.CopyOut(cc, addr)
		errCh <- err
	}()
	if err := <-errCh; err != nil {
		t.Fatalf("SignalStack.CopyOut: %v", err)
	}
	wantRange := memmap.FileRange{Start: fr.Start, End: fr.Start + uint64(want.SizeBytes())}
	if len(got) != 1 || got[0] != wantRange {
		t.Fatalf("reported writes = %v, want [%v]", got, wantRange)
	}
	var readBack linux.SignalStack
	if _, err := readBack.CopyIn(cc, addr); err != nil {
		t.Fatalf("SignalStack.CopyIn: %v", err)
	}
	if readBack != want {
		t.Fatalf("CopyOut produced %+v, want %+v", readBack, want)
	}
}
