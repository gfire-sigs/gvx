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

package loader

import (
	"debug/elf"
	"slices"
	"testing"

	"z.gfire.dev/gvx/pkg/abi"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/cpuid"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/mm"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

func init() {
	cpuid.Initialize()
}

type testPlatform struct{ platform.Platform }

func (testPlatform) SupportsAddressSpaceIO() bool  { return false }
func (testPlatform) MinUserAddress() hostarch.Addr { return hostarch.PageSize }
func (testPlatform) MaxUserAddress() hostarch.Addr { return 0x0000_7fff_ffff_f000 }
func (testPlatform) MapUnit() uint64               { return 0 }
func (testPlatform) NewAddressSpace(platform.AddressSpaceOptions) (platform.AddressSpace, error) {
	return testAddressSpace{}, nil
}

type testAddressSpace struct{ platform.AddressSpace }

func (testAddressSpace) Release()                    {}
func (testAddressSpace) Unmap(hostarch.Addr, uint64) {}
func (testAddressSpace) MapFile(hostarch.Addr, memmap.File, memmap.FileRange, hostarch.AccessType, bool) error {
	return nil
}

type testMappable struct {
	memmap.MappableNoHugepages
}

func (testMappable) AddMapping(context.Context, memmap.MappingSpace, hostarch.AddrRange, uint64, bool) error {
	return nil
}
func (testMappable) RemoveMapping(context.Context, memmap.MappingSpace, hostarch.AddrRange, uint64, bool) {
}
func (testMappable) CopyMapping(context.Context, memmap.MappingSpace, hostarch.AddrRange, hostarch.AddrRange, uint64, bool) error {
	return nil
}
func (testMappable) Translate(context.Context, memmap.MappableRange, memmap.MappableRange, hostarch.AccessType) ([]memmap.Translation, error) {
	return nil, linuxerr.EFAULT
}
func (testMappable) InvalidateUnsavable(context.Context) error {
	return nil
}

type testELFFileFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD
}

func (*testELFFileFD) Release(context.Context) {}

func (fd *testELFFileFD) ConfigureMMap(_ context.Context, opts *memmap.MMapOpts) error {
	return vfs.GenericConfigureMMap(&fd.vfsfd, testMappable{}, opts)
}

type mappedRegion struct {
	start hostarch.Addr
	end   hostarch.Addr
	perms hostarch.AccessType
}

func newTestLoaderMM(t *testing.T) (context.Context, *mm.MemoryManager) {
	t.Helper()
	ls, err := limits.NewLinuxLimitSet()
	if err != nil {
		t.Fatalf("NewLinuxLimitSet: %v", err)
	}
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	ctx := context.WithValues(context.Background(), map[any]any{
		limits.CtxLimits:    ls,
		auth.CtxCredentials: creds,
	})
	m, err := mm.NewMemoryManager(testPlatform{}, nil)
	if err != nil {
		t.Fatalf("NewMemoryManager: %v", err)
	}
	t.Cleanup(func() {
		m.DecUsers(ctx)
	})
	if _, err := m.SetMmapLayout(arch.New(arch.Host), ls); err != nil {
		t.Fatalf("SetMmapLayout: %v", err)
	}
	return ctx, m
}

func newTestELFFileFD(t *testing.T, ctx context.Context) *vfs.FileDescription {
	t.Helper()
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VirtualFilesystem.Init: %v", err)
	}
	t.Cleanup(func() {
		vfsObj.Release(ctx)
	})
	vd := vfsObj.NewAnonVirtualDentry("elf-test")
	t.Cleanup(func() {
		vd.DecRef(ctx)
	})
	fd := &testELFFileFD{}
	if err := fd.vfsfd.Init(fd, uint32(linux.O_RDONLY), auth.CredentialsFromContext(ctx), vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		SpecialFile:       true,
	}); err != nil {
		t.Fatalf("FileDescription.Init: %v", err)
	}
	t.Cleanup(func() {
		fd.vfsfd.DecRef(ctx)
	})
	return &fd.vfsfd
}

func mapPrivatePages(t *testing.T, ctx context.Context, m *mm.MemoryManager, addr hostarch.Addr, length uint64, perms hostarch.AccessType) {
	t.Helper()
	if _, err := m.MMap(ctx, memmap.MMapOpts{
		Addr:     addr,
		Length:   length,
		Mappable: testMappable{},
		Fixed:    true,
		Unmap:    true,
		Private:  true,
		Perms:    perms,
		MaxPerms: hostarch.AnyAccess,
	}); err != nil {
		t.Fatalf("MMap(%#x, %#x, %s): %v", uint64(addr), length, perms, err)
	}
}

func readMappedRegions(ctx context.Context, m *mm.MemoryManager) []mappedRegion {
	var out []mappedRegion
	m.ReadMapsDataInto(ctx, func(start, end hostarch.Addr, perms hostarch.AccessType, _ string, _ uint64, _, _ uint32, _ uint64, path string) {
		if path == "[vsyscall]" {
			return
		}
		out = append(out, mappedRegion{start: start, end: end, perms: perms})
	})
	return out
}

func TestLoadParsedELFMergesSharedBoundaryPagePerms(t *testing.T) {
	const (
		page = uint64(hostarch.PageSize)
		half = page / 2
	)
	for _, tc := range []struct {
		name             string
		sharedObject     bool
		vbase            uint64
		sharedLoadOffset hostarch.Addr
	}{
		{
			name:         "fixed executable",
			sharedObject: false,
			vbase:        0x40 * page,
		},
		{
			name:             "relocated shared object",
			sharedObject:     true,
			vbase:            0,
			sharedLoadOffset: hostarch.Addr(0x80 * page),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, m := newTestLoaderMM(t)
			fd := newTestELFFileFD(t, ctx)

			phdrs := []elf.ProgHeader{
				{
					Type:   elf.PT_LOAD,
					Flags:  elf.PF_R | elf.PF_X,
					Off:    0,
					Vaddr:  tc.vbase,
					Filesz: page + half,
					Memsz:  page + half,
				},
				{
					Type:   elf.PT_LOAD,
					Flags:  elf.PF_R | elf.PF_W,
					Off:    page + half,
					Vaddr:  tc.vbase + page + half,
					Filesz: page,
					Memsz:  page,
				},
			}
			info := elfInfo{
				os:           abi.Linux,
				arch:         arch.Host,
				entry:        hostarch.Addr(tc.vbase),
				phdrs:        phdrs,
				phdrSize:     prog64Size,
				sharedObject: tc.sharedObject,
			}

			loaded, err := loadParsedELF(ctx, m, fd, info, tc.sharedLoadOffset)
			if err != nil {
				t.Fatalf("loadParsedELF: %v", err)
			}

			base := loaded.start
			want := []mappedRegion{
				{start: base, end: base + hostarch.Addr(page), perms: hostarch.ReadExecute},
				{start: base + hostarch.Addr(page), end: base + hostarch.Addr(2*page), perms: hostarch.AnyAccess},
				{start: base + hostarch.Addr(2*page), end: base + hostarch.Addr(3*page), perms: hostarch.ReadWrite},
			}
			if got := readMappedRegions(ctx, m); !slices.Equal(got, want) {
				t.Fatalf("mapped regions = %+v, want %+v", got, want)
			}
		})
	}
}

func TestMergeSharedPagePermsUnionSemantics(t *testing.T) {
	const (
		page    = uint64(hostarch.PageSize)
		half    = page / 2
		quarter = page / 4
		base    = hostarch.Addr(0x20 * page)
	)
	for _, tc := range []struct {
		name        string
		offset      hostarch.Addr
		initialPerm hostarch.AccessType
		phdrs       []elf.ProgHeader
		wantPerm    hostarch.AccessType
	}{
		{
			name:        "read and execute union",
			initialPerm: hostarch.Execute,
			phdrs: []elf.ProgHeader{
				{Type: elf.PT_LOAD, Flags: elf.PF_R, Vaddr: uint64(base), Memsz: half},
				{Type: elf.PT_LOAD, Flags: elf.PF_X, Vaddr: uint64(base) + half, Memsz: half},
			},
			wantPerm: hostarch.ReadExecute,
		},
		{
			name:        "read and write union",
			initialPerm: hostarch.Write,
			phdrs: []elf.ProgHeader{
				{Type: elf.PT_LOAD, Flags: elf.PF_R, Vaddr: uint64(base), Memsz: half},
				{Type: elf.PT_LOAD, Flags: elf.PF_W, Vaddr: uint64(base) + half, Memsz: half},
			},
			wantPerm: hostarch.ReadWrite,
		},
		{
			name:        "write and execute union without read",
			initialPerm: hostarch.Execute,
			phdrs: []elf.ProgHeader{
				{Type: elf.PT_LOAD, Flags: elf.PF_W, Vaddr: uint64(base), Memsz: half},
				{Type: elf.PT_LOAD, Flags: elf.PF_X, Vaddr: uint64(base) + half, Memsz: half},
			},
			wantPerm: hostarch.AccessType{Write: true, Execute: true},
		},
		{
			name:        "three sub-page segments with load offset",
			offset:      base,
			initialPerm: hostarch.Read,
			phdrs: []elf.ProgHeader{
				{Type: elf.PT_LOAD, Flags: elf.PF_R, Vaddr: 0, Memsz: quarter},
				{Type: elf.PT_LOAD, Flags: elf.PF_W, Vaddr: quarter, Memsz: quarter},
				{Type: elf.PT_LOAD, Flags: elf.PF_X, Vaddr: 2 * quarter, Memsz: quarter},
			},
			wantPerm: hostarch.AnyAccess,
		},
		{
			name:        "overlapping segments in one page",
			initialPerm: hostarch.ReadWrite,
			phdrs: []elf.ProgHeader{
				{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Vaddr: uint64(base), Memsz: half},
				{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_W, Vaddr: uint64(base), Memsz: half},
			},
			wantPerm: hostarch.AnyAccess,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, m := newTestLoaderMM(t)
			mapPrivatePages(t, ctx, m, base, page, tc.initialPerm)

			if err := mergeSharedPagePerms(ctx, m, tc.phdrs, tc.offset); err != nil {
				t.Fatalf("mergeSharedPagePerms: %v", err)
			}

			want := []mappedRegion{{start: base, end: base + hostarch.Addr(page), perms: tc.wantPerm}}
			if got := readMappedRegions(ctx, m); !slices.Equal(got, want) {
				t.Fatalf("mapped regions = %+v, want %+v", got, want)
			}
		})
	}
}

func TestMergeSharedPagePermsPreservesDisjointAndNonLoadSegments(t *testing.T) {
	const (
		page = uint64(hostarch.PageSize)
		base = hostarch.Addr(0x20 * page)
	)
	ctx, m := newTestLoaderMM(t)
	mapPrivatePages(t, ctx, m, base, 2*page, hostarch.ReadExecute)
	mapPrivatePages(t, ctx, m, base+hostarch.Addr(2*page), 2*page, hostarch.ReadWrite)
	mapPrivatePages(t, ctx, m, base+hostarch.Addr(5*page), page, hostarch.Read)

	phdrs := []elf.ProgHeader{
		{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Vaddr: uint64(base), Memsz: 2 * page},
		{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_W, Vaddr: uint64(base) + 2*page, Memsz: 2 * page},
		{Type: elf.PT_LOAD, Flags: elf.PF_R, Vaddr: uint64(base) + 5*page, Memsz: page},
		{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_W | elf.PF_X, Vaddr: uint64(base), Memsz: 0},
		{Type: elf.PT_GNU_STACK, Flags: elf.PF_R | elf.PF_W | elf.PF_X, Vaddr: uint64(base), Memsz: page},
	}

	if err := mergeSharedPagePerms(ctx, m, phdrs, 0); err != nil {
		t.Fatalf("mergeSharedPagePerms: %v", err)
	}

	want := []mappedRegion{
		{start: base, end: base + hostarch.Addr(2*page), perms: hostarch.ReadExecute},
		{start: base + hostarch.Addr(2*page), end: base + hostarch.Addr(4*page), perms: hostarch.ReadWrite},
		{start: base + hostarch.Addr(5*page), end: base + hostarch.Addr(6*page), perms: hostarch.Read},
	}
	if got := readMappedRegions(ctx, m); !slices.Equal(got, want) {
		t.Fatalf("mapped regions = %+v, want %+v", got, want)
	}
}

func TestMergeSharedPagePermsRejectsAddressOverflow(t *testing.T) {
	const maxAddr = ^uint64(0)
	ctx, m := newTestLoaderMM(t)

	for _, tc := range []struct {
		name   string
		offset hostarch.Addr
		phdr   elf.ProgHeader
	}{
		{
			name:   "offset plus vaddr overflows",
			offset: hostarch.Addr(hostarch.PageSize),
			phdr:   elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R, Vaddr: maxAddr, Memsz: 16},
		},
		{
			name: "start plus memsz overflows",
			phdr: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R, Vaddr: maxAddr - 7, Memsz: 16},
		},
		{
			name: "end roundup overflows",
			phdr: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R, Vaddr: maxAddr - 16, Memsz: 8},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := mergeSharedPagePerms(ctx, m, []elf.ProgHeader{tc.phdr}, tc.offset)
			if !linuxerr.Equals(linuxerr.ENOEXEC, err) {
				t.Fatalf("mergeSharedPagePerms = %v, want ENOEXEC", err)
			}
		})
	}
}
