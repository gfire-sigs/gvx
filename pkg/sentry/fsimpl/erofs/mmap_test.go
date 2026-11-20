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

//go:build !windows

package erofs_test

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"testing"

	"z.gfire.dev/gvx/pkg/cpuid"
	erofsimg "z.gfire.dev/gvx/pkg/erofs"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/mm"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

func init() {
	// arch.New builds the floating-point state of the host. On amd64 that
	// reads the CPUID feature set, which must exist before the first test.
	cpuid.Initialize()
}

// stubPlatform backs a MemoryManager that never runs guest code. The test
// only reads and writes through internal mappings.
type stubPlatform struct{ platform.Platform }

func (stubPlatform) SupportsAddressSpaceIO() bool  { return false }
func (stubPlatform) MinUserAddress() hostarch.Addr { return hostarch.Addr(hostarch.PageSize) }
func (stubPlatform) MaxUserAddress() hostarch.Addr { return 0x0000_7fff_ffff_f000 }
func (stubPlatform) MapUnit() uint64               { return 0 }
func (stubPlatform) NewAddressSpace(platform.AddressSpaceOptions) (platform.AddressSpace, error) {
	return stubAddressSpace{}, nil
}

type stubAddressSpace struct{ platform.AddressSpace }

func (stubAddressSpace) Release() {}

// Unmap is a no-op because the stub address space maps nothing.
func (stubAddressSpace) Unmap(hostarch.Addr, uint64) {}

// fileLayout names a way that the compiler can store a regular file.
type fileLayout string

const (
	layoutPlain   fileLayout = "plain"
	layoutChunked fileLayout = "chunked"
	layoutSparse  fileLayout = "sparse"
)

// minHoleBlocks mirrors the shortest hole that the compiler stores as a
// sparse range: 64 KiB, and at least one block.
func minHoleBlocks(bs int) int { return max(1, 65536/bs) }

func blocksOf(size, bs int) int { return (size + bs - 1) / bs }

// layoutFor returns the data layout that the compiler must choose for a file
// of the given kind and size, or false if the size cannot show the kind.
func layoutFor(kind fileLayout, size, bs int) (uint16, bool) {
	n, hole := blocksOf(size, bs), minHoleBlocks(bs)
	switch kind {
	case layoutChunked:
		// One data block, a hole of n-2 blocks, then a data block.
		if n-2 < hole {
			return 0, false
		}
		return erofsimg.InodeDataLayoutChunkBased, true
	case layoutSparse:
		if n >= hole {
			return erofsimg.InodeDataLayoutChunkBased, true
		}
		return erofsimg.InodeDataLayoutFlatPlain, true
	}
	return erofsimg.InodeDataLayoutFlatPlain, true
}

func layoutContent(kind fileLayout, size, bs int) []byte {
	data := patternBytes(size, uint64(size)*7+uint64(len(kind)))
	switch kind {
	case layoutChunked:
		clear(data[bs : (blocksOf(size, bs)-1)*bs])
	case layoutSparse:
		clear(data)
	}
	return data
}

func TestErofsFilesReadAndMapInEveryLayout(t *testing.T) {
	forEachBlockSize(t, runErofsFilesReadAndMap)
}

func runErofsFilesReadAndMap(t *testing.T, bs int) {
	sizes := []int{1, 4095, 4096, 4097, 65536 + 1, 1<<20 + 13, bs - 1, bs, bs + 1, 3*bs + 5}
	slices.Sort(sizes)
	sizes = slices.Compact(sizes)
	type fileCase struct {
		name string
		kind fileLayout
		size int
	}
	var cases []fileCase
	wantLayouts := make(map[string]uint16)
	var entries []tarEntry
	for _, kind := range []fileLayout{layoutPlain, layoutChunked, layoutSparse} {
		for _, size := range sizes {
			layout, ok := layoutFor(kind, size, bs)
			if !ok {
				continue
			}
			c := fileCase{name: fmt.Sprintf("%s-%d", kind, size), kind: kind, size: size}
			cases = append(cases, c)
			wantLayouts[c.name] = layout
			entries = append(entries, fileEntry(c.name, string(layoutContent(kind, size, bs))))
		}
	}
	layer, _ := compileTar(t, bs, buildTar(t, entries...))

	// The layer must use the layouts that the cases name. Regular files never
	// tail-pack, because the sentry maps them by image offset.
	assertLayouts(t, layer, wantLayouts)

	s := newSentry(t)
	root := s.mountErofs(layer)
	defer root.DecRef(s.ctx)
	s.root = root

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want := layoutContent(c.kind, c.size, bs)
			s.t = t
			verifyPread(t, s, "/"+c.name, want, bs)
			verifyTranslate(t, s, "/"+c.name, want)
			verifyPrivateMapping(t, s, "/"+c.name, want, bs)
		})
	}
}

func assertLayouts(t *testing.T, path string, want map[string]uint16) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	img, err := erofsimg.OpenImage(f)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	root, err := img.Inode(img.RootNid())
	if err != nil {
		t.Fatal(err)
	}
	for name, w := range want {
		nid, err := root.Lookup(name)
		if err != nil {
			t.Fatalf("lookup %s: %v", name, err)
		}
		ino, err := img.Inode(nid)
		if err != nil {
			t.Fatal(err)
		}
		if got := ino.DataLayout(); got != w {
			t.Errorf("%s has data layout %d, want %d", name, got, w)
		}
	}
}

func openFile(t *testing.T, s *sentry, p string) *vfs.FileDescription {
	t.Helper()
	fd, err := s.vfs.OpenAt(s.ctx, s.creds, s.pop(p), &vfs.OpenOptions{Flags: 0 /* O_RDONLY */})
	if err != nil {
		t.Fatalf("open %s: %v", p, err)
	}
	t.Cleanup(func() { fd.DecRef(s.ctx) })
	return fd
}

// verifyPread reads the whole file, and ranges around block and EOF
// boundaries, with positional reads.
func verifyPread(t *testing.T, s *sentry, p string, want []byte, bs int) {
	t.Helper()
	fd := openFile(t, s, p)
	size := len(want)
	for _, r := range [][2]int{
		{0, size}, {0, 1}, {size - 1, 1}, {max(size-4097, 0), min(size, 4097)},
		{bs - 1, 2}, {size / 2, size - size/2},
	} {
		off, n := r[0], r[1]
		if off < 0 || off+n > size || n <= 0 {
			continue
		}
		buf := make([]byte, n)
		got, err := fd.PRead(s.ctx, usermem.BytesIOSequence(buf), int64(off), vfs.ReadOptions{})
		if err != nil || int(got) != n {
			t.Fatalf("PRead(%d, %d) = %d, %v", off, n, got, err)
		}
		if !bytes.Equal(buf, want[off:off+n]) {
			t.Fatalf("PRead(%d, %d) returned wrong bytes", off, n)
		}
	}
	// A read that starts at EOF returns no bytes.
	if got, _ := fd.PRead(s.ctx, usermem.BytesIOSequence(make([]byte, 8)), int64(size), vfs.ReadOptions{}); got != 0 {
		t.Errorf("PRead at EOF returned %d bytes", got)
	}
}

func mappableOf(t *testing.T, s *sentry, p string, length uint64) (memmap.MMapOpts, *vfs.FileDescription) {
	t.Helper()
	fd := openFile(t, s, p)
	opts := memmap.MMapOpts{
		Length:   length,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	}
	if err := fd.ConfigureMMap(s.ctx, &opts); err != nil {
		t.Fatalf("ConfigureMMap(%s): %v", p, err)
	}
	return opts, fd
}

// verifyTranslate translates every page of the file, as a page fault does,
// and compares the bytes behind each translation. The last page extends past
// EOF and must read as zeroes there.
func verifyTranslate(t *testing.T, s *sentry, p string, want []byte) {
	t.Helper()
	pgend, _ := hostarch.PageRoundUp(uint64(len(want)))
	opts, _ := mappableOf(t, s, p, pgend)

	page := uint64(hostarch.PageSize)
	for pg := uint64(0); pg < pgend; pg += page {
		required := memmap.MappableRange{Start: pg, End: pg + page}
		ts, err := opts.Mappable.Translate(s.ctx, required, required, hostarch.Read)
		if err != nil {
			t.Fatalf("Translate(page at %d): %v", pg, err)
		}
		var covered uint64
		for _, tr := range ts {
			if tr.Source.Start < required.Start {
				t.Fatalf("translation %v starts before the requested page %v", tr.Source, required)
			}
			covered += min(tr.Source.End, required.End) - tr.Source.Start
			if tr.Perms.Write || !tr.Perms.Read {
				t.Errorf("translation perms = %v, want read-only", tr.Perms)
			}
			seq, err := tr.File.MapInternal(memmap.FileRange{Start: tr.Offset, End: tr.Offset + (min(tr.Source.End, required.End) - tr.Source.Start)}, hostarch.Read)
			if err != nil {
				t.Fatalf("MapInternal for page at %d: %v", pg, err)
			}
			got := make([]byte, seq.NumBytes())
			if _, err := safemem.CopySeq(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(got)), seq); err != nil {
				t.Fatal(err)
			}
			expect := make([]byte, len(got))
			if tr.Source.Start < uint64(len(want)) {
				copy(expect, want[tr.Source.Start:])
			}
			if !bytes.Equal(got, expect) {
				t.Fatalf("page at %d (translation %v) holds wrong bytes", pg, tr.Source)
			}
		}
		if covered != page {
			t.Fatalf("translations of page %d cover %d bytes, want a full page", pg, covered)
		}
	}
	// A page wholly beyond the last file page is a bus error, not data.
	beyond := memmap.MappableRange{Start: pgend, End: pgend + page}
	if _, err := opts.Mappable.Translate(s.ctx, beyond, beyond, hostarch.Read); err == nil {
		t.Errorf("Translate beyond EOF succeeded")
	}
}

// verifyPrivateMapping maps the file privately, zeroes the tail of its last
// page as the ELF loader does for a PT_LOAD segment, and checks that the copy
// on write kept the file bytes and cleared only the tail.
func verifyPrivateMapping(t *testing.T, s *sentry, p string, want []byte, bs int) {
	t.Helper()
	mf := pgalloc.MemoryFileFromContext(s.ctx)
	manager, err := mm.NewMemoryManager(stubPlatform{}, mf)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.DecUsers(s.ctx)
	if _, err := manager.SetMmapLayout(arch.New(arch.Host), limits.FromContext(s.ctx)); err != nil {
		t.Fatalf("SetMmapLayout: %v", err)
	}

	pgend, _ := hostarch.PageRoundUp(uint64(len(want)))
	opts, _ := mappableOf(t, s, p, pgend)
	addr, err := manager.MMap(s.ctx, opts)
	if err != nil {
		t.Fatalf("MMap: %v", err)
	}
	ioOpts := usermem.IOOpts{}

	size := int64(len(want))
	if tail := int64(pgend) - size; tail > 0 {
		// The tail already reads as zero in the image. Dirty it first so that
		// ZeroOut has to clear bytes in a copied page.
		if _, err := manager.CopyOut(s.ctx, addr+hostarch.Addr(size), bytes.Repeat([]byte{0xEE}, int(tail)), ioOpts); err != nil {
			t.Fatalf("CopyOut into the tail page (copy on write): %v", err)
		}
		if n, err := manager.ZeroOut(s.ctx, addr+hostarch.Addr(size), tail, ioOpts); err != nil || n != tail {
			t.Fatalf("ZeroOut(%d bytes at the file tail) = %d, %v", tail, n, err)
		}
	}

	got := make([]byte, pgend)
	if n, err := manager.CopyIn(s.ctx, addr, got, ioOpts); err != nil || uint64(n) != pgend {
		t.Fatalf("CopyIn of the mapping = %d, %v", n, err)
	}
	expect := make([]byte, pgend)
	copy(expect, want)
	if !bytes.Equal(got, expect) {
		first, count := -1, 0
		for i := range got {
			if got[i] != expect[i] {
				if first < 0 {
					first = i
				}
				count++
			}
		}
		t.Fatalf("the private mapping differs from the file after the tail was zeroed: %d bytes differ, first at %d (got %#x want %#x)", count, first, got[first], expect[first])
	}

	// A write to the middle of the mapping copies the page and leaves the
	// file untouched.
	if _, err := manager.CopyOut(s.ctx, addr, []byte{0xAB}, ioOpts); err != nil {
		t.Fatalf("CopyOut into a private mapping: %v", err)
	}
	verifyPread(t, s, p, want, bs)
}
