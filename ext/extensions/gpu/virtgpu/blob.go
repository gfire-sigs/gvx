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
	"errors"
	"fmt"
	"maps"
	"slices"

	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fd"
	"z.gfire.dev/gvx/pkg/gvx/shm"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/fsutil"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sync"
)

// maxBlobBytes is the largest host size of one blob (D9).
const maxBlobBytes = 1 << 30

// errBlobSize reports a renderer shm object whose size the device refuses.
var errBlobSize = errors.New("virtgpu: blob size refused")

// blob is the memory of one mappable virtio-gpu resource. It wraps a
// pkg/gvx/shm.ImportedRegion over a host shared-memory descriptor allocated by
// the renderer and implements both memmap.Mappable and memmap.File for guest
// mappings.
//
// Lifetime (invariant I-5.1): the view stays mapped while owners or
// MmapFileRefs page references remain above zero. A guest mapping owns the
// blob through its blobMapping identity, whose reference count matches its
// VMA segments. mm drops page references only after AddressSpace.Unmap
// returns, so munmap always follows hv_vm_unmap.
type blob struct {
	memmap.NoBufferedIOFallback
	memmap.DefaultMemoryType
	memmap.MappableNoTrackMappings
	memmap.MappableNoHugepages
	fsutil.MmapFileRefs

	dev *Device

	// guestSize is the number of bytes that the guest can map, a multiple of
	// hostarch.PageSize. guestSize <= hostSize.
	guestSize uint64

	// hostSize is the fstat size of the shm object and the length of the view.
	hostSize uint64

	// accounted is the byte share this blob holds in dev.budget.
	accounted uint64

	// owners counts GEM handles and blobMapping identities whose reference
	// count is above zero. MmapFileRefs.MappableRelease runs when it drops to
	// zero. A guest VMA never counts directly: its identity does.
	owners atomicbitops.Int64

	viewMu sync.Mutex
	// region is the imported host shared-memory view. It is nil after unmapView.
	// +checklocks:viewMu
	region *shm.ImportedRegion
}

func (d *Device) ensureImporter() *shm.Importer {
	d.blobsMu.Lock()
	defer d.blobsMu.Unlock()
	if d.importer == nil {
		quota := d.limits.BlobBytes
		if quota == 0 {
			quota = defaultBlobBytes
		}
		d.importer = shm.NewImporter(shm.Options{
			HostMappingAlign: blobAlignment,
			QuotaBytes:       quota,
		})
	}
	return d.importer
}

// newBlob maps the shm object of handle once via pkg/gvx/shm.Importer and
// takes ownership of handle: it closes the descriptor before returning, also
// on error. guestSize is the guest-visible size rounded up to hostarch.PageSize.
// On success, newBlob takes over the caller's budget reservation of reserved
// bytes and settles it to hostSize. The new blob has one owner, the GEM handle
// of the caller.
func newBlob(d *Device, handle *fd.HostHandle, guestSize, reserved uint64) (*blob, error) {
	defer func() {
		if err := handle.Close(); err != nil {
			log.Warningf("virtgpu: close blob descriptor: %v", err)
		}
	}()
	if guestSize == 0 || guestSize%uint64(hostarch.PageSize) != 0 {
		return nil, fmt.Errorf("%w: guest size %d", errBlobSize, guestSize)
	}
	raw, err := handle.RawHandle()
	if err != nil {
		return nil, err
	}
	imp := d.ensureImporter()
	reg, err := imp.ImportWholeFD(int(raw), guestSize, maxBlobBytes, true)
	if err != nil {
		if errors.Is(err, shm.ErrInvalidRange) || errors.Is(err, shm.ErrMisaligned) || errors.Is(err, shm.ErrUnsupportedBackend) {
			return nil, fmt.Errorf("%w: %w", errBlobSize, err)
		}
		return nil, err
	}
	hostSize := reg.HostSize()
	accounted := max(reserved, hostSize)
	if hostSize > reserved {
		d.budget.grow(hostSize - reserved)
	}
	b := &blob{
		dev:       d,
		guestSize: guestSize,
		hostSize:  hostSize,
		accounted: accounted,
		region:    reg,
	}
	b.owners.Store(1)
	b.MmapFileRefs.Closer = b
	d.blobsMu.Lock()
	d.blobs[b] = struct{}{}
	d.blobsMu.Unlock()
	return b, nil
}

// incOwner adds an owner. The caller holds an owner, or holds the lock that
// keeps a handle in its table (renderFD.gemMu).
func (b *blob) incOwner() {
	b.owners.Add(1)
}

// decOwner drops an owner. The last owner hands the view to MmapFileRefs,
// which unmaps it when no page reference is left.
func (b *blob) decOwner() {
	n := b.owners.Add(-1)
	if n < 0 {
		panic(fmt.Sprintf("virtgpu: blob owner count %d", n))
	}
	if n == 0 {
		b.MmapFileRefs.MappableRelease()
	}
}

// Close implements io.Closer for MmapFileRefs. It runs once, after the last
// owner and the last page reference are gone.
func (b *blob) Close() error {
	b.dev.blobsMu.Lock()
	delete(b.dev.blobs, b)
	b.dev.blobsMu.Unlock()
	return b.unmapView()
}

// unmapView releases the imported shared-memory view if it is still mapped.
func (b *blob) unmapView() error {
	b.viewMu.Lock()
	reg := b.region
	b.region = nil
	b.viewMu.Unlock()
	if reg == nil {
		return nil
	}
	reg.Release()
	b.dev.budget.release(b.accounted)
	return nil
}

// MapInternal implements memmap.File.MapInternal. It delegates to the imported
// shared-memory region and refuses execute access.
func (b *blob) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	if fr.Start >= fr.End || fr.End > b.guestSize {
		return safemem.BlockSeq{}, linuxerr.EINVAL
	}
	b.viewMu.Lock()
	reg := b.region
	b.viewMu.Unlock()
	if reg == nil {
		return safemem.BlockSeq{}, linuxerr.EIO
	}
	return reg.MapInternal(fr, at)
}

// ConfigureMMap enforces the non-executable invariant of imported shared memory.
func (b *blob) ConfigureMMap(opts *memmap.MMapOpts) error {
	b.viewMu.Lock()
	reg := b.region
	b.viewMu.Unlock()
	if reg == nil {
		return linuxerr.EIO
	}
	return reg.ConfigureMMap(opts)
}

// Translate implements memmap.Mappable.Translate. Imported GPU blobs never
// allow guest code execution.
func (b *blob) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	if at.Execute {
		return nil, linuxerr.EACCES
	}
	if required.Start >= b.guestSize {
		return nil, &memmap.BusError{Err: linuxerr.EFAULT}
	}
	src := optional.Intersect(memmap.MappableRange{Start: 0, End: b.guestSize})
	ts := []memmap.Translation{{Source: src, File: b, Offset: src.Start, Perms: hostarch.ReadWrite}}
	if required.End > b.guestSize {
		return ts, &memmap.BusError{Err: linuxerr.EFAULT}
	}
	return ts, nil
}

// DataFD implements memmap.File.DataFD. newBlob closes the descriptor after it
// maps the view, and hvf maps the view through MapInternal.
func (b *blob) DataFD(memmap.FileRange) (int, error) {
	return -1, linuxerr.ENODEV
}

// FD implements memmap.File.FD.
func (b *blob) FD() int {
	return -1
}

// blobMapping is the memmap.MappingIdentity of one guest mmap of a blob. It
// holds one blob owner and one reference on file from newBlobMapping until mm
// drops its last reference. mm keeps one reference for each VMA segment that
// names it, so the owner lasts exactly as long as a guest mapping can fault.
type blobMapping struct {
	refs atomicbitops.Int64
	b    *blob
	// file names the mapping in /proc/[pid]/maps: the DRM file in production.
	file memmap.MappingIdentity
}

var _ memmap.MappingIdentity = (*blobMapping)(nil)

// newBlobMapping returns an identity with one reference. It takes a blob owner
// and a reference on file. The caller must hold an owner of b or the lock that
// keeps a handle of b in its table (wp6b.md invariant I-6b.2).
func newBlobMapping(b *blob, file memmap.MappingIdentity) *blobMapping {
	b.incOwner()
	file.IncRef()
	bm := &blobMapping{
		b:    b,
		file: file,
	}
	bm.refs.Store(1)
	return bm
}

// IncRef implements memmap.MappingIdentity.IncRef.
func (m *blobMapping) IncRef() {
	m.refs.Add(1)
}

// DecRef implements memmap.MappingIdentity.DecRef.
func (m *blobMapping) DecRef(ctx context.Context) {
	n := m.refs.Add(-1)
	if n < 0 {
		panic(fmt.Sprintf("virtgpu: blobMapping ref count %d", n))
	}
	if n == 0 {
		m.b.decOwner()
		m.file.DecRef(ctx)
	}
}

// MappedName implements memmap.MappingIdentity.MappedName.
func (m *blobMapping) MappedName(ctx context.Context) string {
	return m.file.MappedName(ctx)
}

// DeviceID implements memmap.MappingIdentity.DeviceID.
func (m *blobMapping) DeviceID() uint64 {
	return m.file.DeviceID()
}

// InodeID implements memmap.MappingIdentity.InodeID.
func (m *blobMapping) InodeID() uint64 {
	return m.file.InodeID()
}

// Msync implements memmap.MappingIdentity.Msync.
func (m *blobMapping) Msync(context.Context, memmap.MappableRange) error {
	return nil
}

// BlobBytes returns the sum of the accounted host bytes of live blobs on d.
// Each Device counts its own blobs.
func (d *Device) BlobBytes() uint64 {
	return d.budget.bytes.Load()
}

// ReleaseBlobViews drops the device's claim on every blob that is still alive
// after the sandbox stopped. A blob without page references unmaps now. A blob
// that a leaked address space still references unmaps when that last page
// reference drops, never before. Precondition: no guest task of the sandbox
// can run, so no fault can translate a blob again.
func (d *Device) ReleaseBlobViews() {
	d.blobsMu.Lock()
	blobs := slices.Collect(maps.Keys(d.blobs))
	d.blobsMu.Unlock()
	for _, b := range blobs {
		b.MmapFileRefs.MappableRelease()
	}
}
