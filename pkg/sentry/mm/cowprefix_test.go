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

package mm

import (
	"bytes"
	"testing"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/cpuid"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/pkg/usermem"
)

func init() {
	// arch.New builds the floating-point state of the host, which needs the
	// CPUID feature set on amd64.
	cpuid.Initialize()
}

// faultPlatform is a platform that accepts every mapping and runs no guest code.
type faultPlatform struct{ platform.Platform }

func (faultPlatform) SupportsAddressSpaceIO() bool  { return false }
func (faultPlatform) MinUserAddress() hostarch.Addr { return hostarch.PageSize }
func (faultPlatform) MaxUserAddress() hostarch.Addr { return 0x0000_7fff_ffff_f000 }
func (faultPlatform) MapUnit() uint64               { return 0 }
func (faultPlatform) NewAddressSpace(platform.AddressSpaceOptions) (platform.AddressSpace, error) {
	return faultAddressSpace{}, nil
}

type faultAddressSpace struct{ platform.AddressSpace }

func (faultAddressSpace) Release()                    {}
func (faultAddressSpace) Unmap(hostarch.Addr, uint64) {}
func (faultAddressSpace) MapFile(hostarch.Addr, memmap.File, memmap.FileRange, hostarch.AccessType, bool) error {
	return nil
}

// splitMappable is a file mapping whose Translate returns one translation for
// each part of its optional range, as the file cache of hostfs and ext4lite
// does for each 64 KiB chunk. The parts do not lie next to each other in the
// memory file, so the memory manager keeps them as separate pmas. The first
// part of a request to the second half of the range lies before the required
// range.
type splitMappable struct {
	memmap.MappableNoHugepages

	mf *pgalloc.MemoryFile
	// prefixStart and tailStart are the offsets in mf of the copies of the file
	// that the part before the required range and the other part use.
	prefixStart, tailStart uint64
}

func (m *splitMappable) AddMapping(context.Context, memmap.MappingSpace, hostarch.AddrRange, uint64, bool) error {
	return nil
}
func (m *splitMappable) RemoveMapping(context.Context, memmap.MappingSpace, hostarch.AddrRange, uint64, bool) {
}
func (m *splitMappable) CopyMapping(context.Context, memmap.MappingSpace, hostarch.AddrRange, hostarch.AddrRange, uint64, bool) error {
	return nil
}

func (m *splitMappable) Translate(_ context.Context, required, optional memmap.MappableRange, _ hostarch.AccessType) ([]memmap.Translation, error) {
	var ts []memmap.Translation
	add := func(src memmap.MappableRange, start uint64) {
		if src.Length() == 0 {
			return
		}
		ts = append(ts, memmap.Translation{
			Source: src,
			File:   m.mf,
			Offset: start + src.Start,
			Perms:  hostarch.ReadExecute,
		})
	}
	add(memmap.MappableRange{Start: optional.Start, End: required.Start}, m.prefixStart)
	add(memmap.MappableRange{Start: required.Start, End: optional.End}, m.tailStart)
	return ts, nil
}

func (m *splitMappable) InvalidateUnsavable(context.Context) error { return nil }

// TestWriteFaultAfterPrefixTranslationBreaksCopyOnWrite checks the write fault
// on a private file mapping whose translations start before the faulting page.
// The fault must copy the faulting page, and must not ask the memory file for
// an empty range.
func TestWriteFaultAfterPrefixTranslationBreaksCopyOnWrite(t *testing.T) {
	for _, tc := range []struct {
		name  string
		perms hostarch.AccessType
	}{
		{"executable", hostarch.AnyAccess},
		{"not executable", hostarch.ReadWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const (
				pages        = 4
				hugeBoundary = 0x40_0000
				fileBytes    = pages * hostarch.PageSize
			)
			mf, err := newCOWTestMemoryFile()
			if err != nil {
				t.Fatalf("newCOWTestMemoryFile: %v", err)
			}
			t.Cleanup(mf.Destroy)
			ls := linuxLimits(t)
			ctx := context.WithValues(context.Background(), map[any]any{
				pgalloc.CtxMemoryFile: mf,
				limits.CtxLimits:      ls,
			})

			// The file has two copies of the same content. The part before the
			// required range reads the second copy.
			fr, err := mf.Allocate(2*fileBytes, pgalloc.AllocOpts{Kind: usage.Anonymous})
			if err != nil {
				t.Fatalf("Allocate: %v", err)
			}
			content := make([]byte, fileBytes)
			for i := range content {
				content[i] = byte(i/hostarch.PageSize + 1)
			}
			dst, err := mf.MapInternal(fr, hostarch.Write)
			if err != nil {
				t.Fatalf("MapInternal: %v", err)
			}
			twice := append(bytes.Clone(content), content...)
			if _, err := safemem.CopySeq(dst, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(twice))); err != nil {
				t.Fatalf("fill the file range: %v", err)
			}

			manager, err := NewMemoryManager(faultPlatform{}, mf)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.SetMmapLayout(arch.New(arch.Host), ls); err != nil {
				t.Fatalf("SetMmapLayout: %v", err)
			}
			// The mapping crosses a hugepage boundary at the faulting page, so the
			// copy range of the part before it is empty for any perms.
			want := hostarch.Addr(hugeBoundary) - 2*hostarch.PageSize
			addr, err := manager.MMap(ctx, memmap.MMapOpts{
				Addr:     want,
				Fixed:    true,
				Length:   fileBytes,
				Mappable: &splitMappable{mf: mf, tailStart: fr.Start, prefixStart: fr.Start + fileBytes},
				Private:  true,
				Perms:    tc.perms,
				MaxPerms: hostarch.AnyAccess,
			})
			if err != nil {
				t.Fatalf("MMap: %v", err)
			}

			if addr != want {
				t.Fatalf("MMap placed the mapping at %#x, want %#x", uint64(addr), uint64(want))
			}
			fault := addr + 2*hostarch.PageSize
			if err := manager.HandleUserFault(ctx, fault, hostarch.Write, 0); err != nil {
				t.Fatalf("HandleUserFault(write at %#x) = %v", uint64(fault), err)
			}
			if _, err := manager.CopyOut(ctx, fault, []byte{0xA5}, usermem.IOOpts{}); err != nil {
				t.Fatalf("CopyOut after the fault: %v", err)
			}
			got := make([]byte, fileBytes)
			if _, err := manager.CopyIn(ctx, addr, got, usermem.IOOpts{}); err != nil {
				t.Fatalf("CopyIn: %v", err)
			}
			expect := bytes.Clone(content)
			expect[2*hostarch.PageSize] = 0xA5
			if !bytes.Equal(got, expect) {
				t.Errorf("the mapping differs from the file with one written byte")
			}
			shared, err := mf.MapInternal(fr, hostarch.Read)
			if err != nil {
				t.Fatalf("MapInternal: %v", err)
			}
			inFile := make([]byte, 2*fileBytes)
			if _, err := safemem.CopySeq(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(inFile)), shared); err != nil {
				t.Fatalf("read the file range: %v", err)
			}
			if !bytes.Equal(inFile, twice) {
				t.Errorf("the write reached the file range")
			}
		})
	}
}

func linuxLimits(t *testing.T) *limits.LimitSet {
	t.Helper()
	ls, err := limits.NewLinuxLimitSet()
	if err != nil {
		t.Fatal(err)
	}
	ls.SetUnchecked(limits.AS, limits.Limit{Cur: limits.Infinity, Max: limits.Infinity})
	return ls
}
