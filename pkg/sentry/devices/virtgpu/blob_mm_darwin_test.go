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

package virtgpu

import (
	"os"
	"testing"

	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/mm"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/usermem"
)

// countingIdentity stands in for the DRM file MappingIdentity in mm tests.
type countingIdentity struct {
	refs atomicbitops.Int64
}

var _ memmap.MappingIdentity = (*countingIdentity)(nil)

func newCountingIdentity() *countingIdentity {
	c := &countingIdentity{}
	c.refs.Store(1)
	return c
}

func (c *countingIdentity) IncRef()                           { c.refs.Add(1) }
func (c *countingIdentity) DecRef(context.Context)            { c.refs.Add(-1) }
func (c *countingIdentity) MappedName(context.Context) string { return "countingIdentity" }
func (c *countingIdentity) DeviceID() uint64                  { return 0 }
func (c *countingIdentity) InodeID() uint64                   { return 0 }
func (c *countingIdentity) Msync(context.Context, memmap.MappableRange) error {
	return nil
}

type stubPlatform struct{ platform.Platform }

func (stubPlatform) SupportsAddressSpaceIO() bool  { return false }
func (stubPlatform) MinUserAddress() hostarch.Addr { return hostarch.Addr(hostarch.PageSize) }
func (stubPlatform) MaxUserAddress() hostarch.Addr { return 0x0000_7fff_ffff_f000 }
func (stubPlatform) MapUnit() uint64               { return 0 }
func (stubPlatform) NewAddressSpace(platform.AddressSpaceOptions) (platform.AddressSpace, error) {
	return stubAddressSpace{}, nil
}

type stubAddressSpace struct{ platform.AddressSpace }

func (stubAddressSpace) Release()                    {}
func (stubAddressSpace) Unmap(hostarch.Addr, uint64) {}
func (stubAddressSpace) PreFork()                    {}
func (stubAddressSpace) PostFork()                   {}
func (stubAddressSpace) MapFile(hostarch.Addr, memmap.File, memmap.FileRange, hostarch.AccessType, bool) error {
	return nil
}

func newBlobTestMM(t *testing.T) (context.Context, *mm.MemoryManager) {
	t.Helper()
	memFD, err := memutil.CreateMemFD("virtgpu-mm-test", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	mf, err := pgalloc.NewMemoryFile(os.NewFile(uintptr(memFD), "virtgpu-mm-test"), pgalloc.MemoryFileOpts{})
	if err != nil {
		t.Fatalf("NewMemoryFile: %v", err)
	}
	t.Cleanup(mf.Destroy)

	ls, err := limits.NewLinuxLimitSet()
	if err != nil {
		t.Fatalf("NewLinuxLimitSet: %v", err)
	}
	ls.Set(limits.AS, limits.Limit{Cur: limits.Infinity, Max: limits.Infinity}, true)

	ctx := context.WithValues(context.Background(), map[any]any{
		pgalloc.CtxMemoryFile: mf,
		limits.CtxLimits:      ls,
	})
	m, err := mm.NewMemoryManager(stubPlatform{}, mf)
	if err != nil {
		t.Fatalf("NewMemoryManager: %v", err)
	}
	if _, err := m.SetMmapLayout(arch.New(arch.Host), ls); err != nil {
		m.DecUsers(ctx)
		t.Fatalf("SetMmapLayout: %v", err)
	}
	t.Cleanup(func() { m.DecUsers(ctx) })
	return ctx, m
}

func mapBlobInMM(t *testing.T, ctx context.Context, m *mm.MemoryManager, b *blob, file memmap.MappingIdentity, addr hostarch.Addr, length, offset uint64) hostarch.Addr {
	t.Helper()
	id := newBlobMapping(b, file)
	defer id.DecRef(ctx)
	mapped, err := m.MMap(ctx, memmap.MMapOpts{
		Addr:            addr,
		Fixed:           true,
		Unmap:           true,
		Length:          length,
		Offset:          offset,
		Mappable:        b,
		MappingIdentity: id,
		Perms:           hostarch.ReadWrite,
		MaxPerms:        hostarch.ReadWrite,
	})
	if err != nil {
		t.Fatalf("MMap(%#x, %#x): %v", addr, length, err)
	}
	return mapped
}

func TestBlobOwnedByMappingAcrossPartialUnmap(t *testing.T) {
	ctx, m := newBlobTestMM(t)
	d := newBlobTestDevice(t)
	shm := newTestShm(t, 0x4000)
	b := mustNewBlob(t, d, shm.handle, 0x4000)
	fileID := newCountingIdentity()

	const baseAddr = hostarch.Addr(0x100000)
	mapBlobInMM(t, ctx, m, b, fileID, baseAddr, 0x4000, 0)
	// Drop creator owner (GEM_CLOSE).
	b.decOwner()

	// Two splits via partial unmaps of pages 0 and 2.
	if err := m.MUnmap(ctx, baseAddr, 0x1000); err != nil {
		t.Fatalf("MUnmap page 0: %v", err)
	}
	if err := m.MUnmap(ctx, baseAddr+0x2000, 0x1000); err != nil {
		t.Fatalf("MUnmap page 2: %v", err)
	}
	if got := d.BlobBytes(); got != 0x4000 {
		t.Fatalf("BlobBytes after partial unmaps = %#x, want 0x4000", got)
	}

	// Page 3 is still mapped and writable through mm.
	if _, err := m.CopyOut(ctx, baseAddr+0x3008, []byte{0x5a}, usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut to page 3: %v", err)
	}
	if got := shm.second[0x3008]; got != 0x5a {
		t.Errorf("shm.second[0x3008] = %#x, want 0x5a", got)
	}

	if err := m.MUnmap(ctx, baseAddr, 0x4000); err != nil {
		t.Fatalf("MUnmap rest: %v", err)
	}
	if got := d.BlobBytes(); got != 0 {
		t.Errorf("BlobBytes after full unmap = %#x, want 0", got)
	}
	if got := fileID.refs.Load(); got != 1 {
		t.Errorf("file identity refs = %d, want 1", got)
	}
}

func TestBlobOwnedByMappingAcrossMerge(t *testing.T) {
	ctx, m := newBlobTestMM(t)
	d := newBlobTestDevice(t)
	shm := newTestShm(t, 0x8000)
	b := mustNewBlob(t, d, shm.handle, 0x8000)
	fileID := newCountingIdentity()

	const baseAddr = hostarch.Addr(0x200000)
	mapBlobInMM(t, ctx, m, b, fileID, baseAddr, 0x4000, 0)

	// Grow in place from 0x4000 to 0x8000 so mm merges the extension into one VMA.
	if _, err := m.MRemap(ctx, baseAddr, 0x4000, 0x8000, mm.MRemapOpts{Move: mm.MRemapNoMove}); err != nil {
		t.Fatalf("MRemap grow in place: %v", err)
	}
	b.decOwner()

	if err := m.MUnmap(ctx, baseAddr, 0x8000); err != nil {
		t.Fatalf("MUnmap all: %v", err)
	}
	if got := d.BlobBytes(); got != 0 {
		t.Errorf("BlobBytes after merged unmap = %#x, want 0", got)
	}
	if got := fileID.refs.Load(); got != 1 {
		t.Errorf("file identity refs = %d, want 1", got)
	}
}

func TestBlobOwnedByMappingAcrossFixedOverwrite(t *testing.T) {
	ctx, m := newBlobTestMM(t)
	d := newBlobTestDevice(t)
	shm := newTestShm(t, 0x4000)
	b := mustNewBlob(t, d, shm.handle, 0x4000)
	fileID := newCountingIdentity()

	const baseAddr = hostarch.Addr(0x300000)
	mapBlobInMM(t, ctx, m, b, fileID, baseAddr, 0x4000, 0)
	b.decOwner()

	// Overwrite page 1 with an anonymous MAP_FIXED mapping.
	if _, err := m.MMap(ctx, memmap.MMapOpts{
		Addr:     baseAddr + 0x1000,
		Fixed:    true,
		Unmap:    true,
		Private:  true,
		Length:   0x1000,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.ReadWrite,
	}); err != nil {
		t.Fatalf("anonymous MAP_FIXED overwrite: %v", err)
	}

	for _, pageOff := range []uint64{0x0000, 0x2000, 0x3000} {
		want := byte(0xa0 + pageOff>>12)
		if _, err := m.CopyOut(ctx, baseAddr+hostarch.Addr(pageOff)+4, []byte{want}, usermem.IOOpts{}); err != nil {
			t.Fatalf("CopyOut at page offset %#x: %v", pageOff, err)
		}
		if got := shm.second[pageOff+4]; got != want {
			t.Errorf("shm.second[%#x] = %#x, want %#x", pageOff+4, got, want)
		}
	}

	if err := m.MUnmap(ctx, baseAddr, 0x4000); err != nil {
		t.Fatalf("MUnmap all: %v", err)
	}
	if got := d.BlobBytes(); got != 0 {
		t.Errorf("BlobBytes after unmap = %#x, want 0", got)
	}
	if got := fileID.refs.Load(); got != 1 {
		t.Errorf("file identity refs = %d, want 1", got)
	}
}

func TestBlobOwnedByMappingAcrossFork(t *testing.T) {
	ctx, m := newBlobTestMM(t)
	d := newBlobTestDevice(t)
	shm := newTestShm(t, 0x4000)
	b := mustNewBlob(t, d, shm.handle, 0x4000)
	fileID := newCountingIdentity()

	const baseAddr = hostarch.Addr(0x400000)
	mapBlobInMM(t, ctx, m, b, fileID, baseAddr, 0x4000, 0)

	child, err := m.Fork(ctx)
	if err != nil {
		t.Fatalf("Fork: %v", err)
	}
	b.decOwner()
	if err := m.MUnmap(ctx, baseAddr, 0x4000); err != nil {
		child.DecUsers(ctx)
		t.Fatalf("parent MUnmap: %v", err)
	}
	if got := d.BlobBytes(); got != 0x4000 {
		child.DecUsers(ctx)
		t.Fatalf("BlobBytes while child holds mapping = %#x, want 0x4000", got)
	}

	if _, err := child.CopyOut(ctx, baseAddr+0x100, []byte{0x77}, usermem.IOOpts{}); err != nil {
		child.DecUsers(ctx)
		t.Fatalf("child CopyOut: %v", err)
	}
	if got := shm.second[0x100]; got != 0x77 {
		t.Errorf("shm.second[0x100] = %#x, want 0x77", got)
	}

	child.DecUsers(ctx)
	if got := d.BlobBytes(); got != 0 {
		t.Errorf("BlobBytes after child DecUsers = %#x, want 0", got)
	}
	if got := fileID.refs.Load(); got != 1 {
		t.Errorf("file identity refs = %d, want 1", got)
	}
}

func TestBlobGrowBeyondGuestSizeFaultsWithoutPanic(t *testing.T) {
	ctx, m := newBlobTestMM(t)
	d := newBlobTestDevice(t)
	shm := newTestShm(t, 0x4000)
	b := mustNewBlob(t, d, shm.handle, 0x4000)
	defer b.decOwner()
	fileID := newCountingIdentity()

	const baseAddr = hostarch.Addr(0x500000)
	mapBlobInMM(t, ctx, m, b, fileID, baseAddr, 0x4000, 0)

	// Grow VMA past guestSize in place.
	if _, err := m.MRemap(ctx, baseAddr, 0x4000, 0x8000, mm.MRemapOpts{Move: mm.MRemapNoMove}); err != nil {
		t.Fatalf("MRemap past guest size: %v", err)
	}
	if _, err := m.CopyOut(ctx, baseAddr+0x5000, []byte{0x11}, usermem.IOOpts{}); !linuxerr.Equals(linuxerr.EFAULT, err) {
		t.Errorf("CopyOut at offset 0x5000: got %v, want EFAULT", err)
	}
	if _, err := m.CopyOut(ctx, baseAddr+0x1000, []byte{0x22}, usermem.IOOpts{}); err != nil {
		t.Errorf("CopyOut at offset 0x1000: got %v, want nil", err)
	}
	if got := shm.second[0x1000]; got != 0x22 {
		t.Errorf("shm.second[0x1000] = %#x, want 0x22", got)
	}
}
