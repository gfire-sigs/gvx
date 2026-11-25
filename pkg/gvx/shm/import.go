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

// Package shm imports untrusted host shared-memory objects into Sentry guest
// address spaces with alignment, sealing, non-executable, and byte-quota
// enforcement.
package shm

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

const (
	// DefaultMaxQuotaBytes caps the default per-sandbox imported shared-memory
	// budget at 4 GiB.
	DefaultMaxQuotaBytes uint64 = 4 << 30
)

var (
	// ErrInvalidRange reports an empty, overflowing, or out-of-bounds region.
	ErrInvalidRange = errors.New("shm: invalid range")
	// ErrMisaligned reports an offset or size that is not a multiple of HostMappingAlign.
	ErrMisaligned = errors.New("shm: offset or size not aligned to host mapping granularity")
	// ErrQuotaExceeded reports that importing a region would exceed the per-sandbox quota.
	ErrQuotaExceeded = errors.New("shm: per-sandbox shared-memory quota exceeded")
	// ErrUnsealedMemory reports that a Linux memfd lacks F_SEAL_SHRINK.
	ErrUnsealedMemory = errors.New("shm: backing memfd requires F_SEAL_SHRINK")
	// ErrUnsupportedBackend reports that the active execution platform has no shm backend yet.
	ErrUnsupportedBackend = errors.New("shm: shared-memory import unsupported on this platform")
	// ErrImporterClosed reports an import attempt after ReleaseAll closed the importer.
	ErrImporterClosed = errors.New("shm: importer closed")
)

// DefaultQuotaBytes returns the default per-sandbox imported shared-memory
// quota: min(4 GiB, 25% of hostRAM). When hostRAM is zero, it returns 4 GiB.
func DefaultQuotaBytes(hostRAM uint64) uint64 {
	if hostRAM == 0 {
		return DefaultMaxQuotaBytes
	}
	quarter := hostRAM / 4
	if quarter == 0 {
		return uint64(hostarch.PageSize)
	}
	return min(DefaultMaxQuotaBytes, quarter)
}

// Options configures one per-sandbox Importer.
type Options struct {
	// PlatformName identifies the active backend ("hvf", "whpx", or "systrap").
	PlatformName string
	// HostMappingAlign is the required offset and size alignment in bytes
	// (16384 on hvf and 16K Linux; 4096 on whpx, 4K Linux, and winsystrap).
	HostMappingAlign uint64
	// QuotaBytes caps total simultaneously mapped imported bytes for one sandbox.
	// Zero defaults to DefaultMaxQuotaBytes.
	QuotaBytes uint64
}

// Importer owns the per-sandbox imported shared-memory quota and tracks active
// sandbox claims.
type Importer struct {
	platformName string
	align        uint64
	quotaBytes   uint64

	mu        sync.Mutex
	usedBytes uint64
	everUsed  bool
	closed    bool
	regions   map[*ImportedRegion]struct{}
}

// NewImporter constructs a per-sandbox Importer.
func NewImporter(opts Options) *Importer {
	align := opts.HostMappingAlign
	if align == 0 {
		align = uint64(hostarch.PageSize)
	}
	quota := opts.QuotaBytes
	if quota == 0 {
		quota = DefaultMaxQuotaBytes
	}
	return &Importer{
		platformName: opts.PlatformName,
		align:        align,
		quotaBytes:   quota,
		regions:      make(map[*ImportedRegion]struct{}),
	}
}

// Alignment returns the required offset and size alignment in bytes.
func (i *Importer) Alignment() uint64 {
	return i.align
}

// QuotaBytes returns the maximum total imported bytes permitted for this sandbox.
func (i *Importer) QuotaBytes() uint64 {
	return i.quotaBytes
}

// UsedBytes returns the currently charged bytes across un-unmapped regions.
func (i *Importer) UsedBytes() uint64 {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.usedBytes
}

// HasImported reports whether at least one region was imported into this
// sandbox. Core uses this to mark checkpointing unsupported.
func (i *Importer) HasImported() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.everUsed
}

// ImportFD validates alignment, sealing, and quota, then maps fd into Sentry
// address space without execute permission. The returned region implements
// memmap.Mappable and memmap.File.
func (i *Importer) ImportFD(fd int, offset, size uint64, writable bool) (*ImportedRegion, error) {
	if size == 0 || offset+size < offset {
		return nil, fmt.Errorf("%w: offset=%#x size=%#x", ErrInvalidRange, offset, size)
	}
	if offset%i.align != 0 || size%i.align != 0 {
		return nil, fmt.Errorf("%w: offset=%#x size=%#x align=%#x", ErrMisaligned, offset, size, i.align)
	}

	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return nil, ErrImporterClosed
	}
	if i.usedBytes+size < i.usedBytes || i.usedBytes+size > i.quotaBytes {
		used := i.usedBytes
		i.mu.Unlock()
		return nil, fmt.Errorf("%w: requested=%d used=%d quota=%d", ErrQuotaExceeded, size, used, i.quotaBytes)
	}
	i.usedBytes += size
	i.mu.Unlock()

	backing, err := mapBackingFD(i.platformName, fd, offset, size, writable)
	if err != nil {
		i.releaseCharge(size)
		return nil, err
	}

	r := &ImportedRegion{
		importer: i,
		backing:  backing,
		size:     size,
		hostSize: size,
		writable: writable,
		claimed:  true,
	}

	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		r.Release()
		return nil, ErrImporterClosed
	}
	i.everUsed = true
	i.regions[r] = struct{}{}
	i.mu.Unlock()
	return r, nil
}

// ImportWholeFD validates an untrusted shared-memory descriptor whose host
// backing size (hostSize) may be rounded up to HostMappingAlign above
// guestSize (a multiple of hostarch.PageSize). It maps the entire hostSize
// view, checks base alignment, charges hostSize against the sandbox quota, and
// limits guest mappings to guestSize.
func (i *Importer) ImportWholeFD(fd int, guestSize, maxHostSize uint64, writable bool) (*ImportedRegion, error) {
	if guestSize == 0 || guestSize%uint64(hostarch.PageSize) != 0 {
		return nil, fmt.Errorf("%w: guest size %d", ErrInvalidRange, guestSize)
	}
	hostSize, err := statBackingFD(fd)
	if err != nil {
		return nil, err
	}
	if hostSize == 0 || hostSize < guestSize || (maxHostSize > 0 && hostSize > maxHostSize) {
		return nil, fmt.Errorf("%w: host size %d, guest size %d, max %d", ErrInvalidRange, hostSize, guestSize, maxHostSize)
	}
	if hostSize%i.align != 0 {
		return nil, fmt.Errorf("%w: host size %#x align %#x", ErrMisaligned, hostSize, i.align)
	}

	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return nil, ErrImporterClosed
	}
	if i.usedBytes+hostSize < i.usedBytes || i.usedBytes+hostSize > i.quotaBytes {
		used := i.usedBytes
		i.mu.Unlock()
		return nil, fmt.Errorf("%w: requested=%d used=%d quota=%d", ErrQuotaExceeded, hostSize, used, i.quotaBytes)
	}
	i.usedBytes += hostSize
	i.mu.Unlock()

	backing, err := mapBackingFD(i.platformName, fd, 0, hostSize, writable)
	if err != nil {
		i.releaseCharge(hostSize)
		return nil, err
	}
	if buf := backing.bytes(); len(buf) > 0 {
		if base := uintptr(unsafe.Pointer(unsafe.SliceData(buf))); uint64(base)%i.align != 0 {
			_ = backing.unmap()
			i.releaseCharge(hostSize)
			return nil, fmt.Errorf("%w: mapped base %#x align %#x", ErrMisaligned, base, i.align)
		}
	}

	r := &ImportedRegion{
		importer: i,
		backing:  backing,
		size:     guestSize,
		hostSize: hostSize,
		writable: writable,
		claimed:  true,
	}

	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		r.Release()
		return nil, ErrImporterClosed
	}
	i.everUsed = true
	i.regions[r] = struct{}{}
	i.mu.Unlock()
	return r, nil
}

// ReleaseAll drops all sandbox claims held by the importer without force-
// unmapping regions that still carry guest page references. Each region unmaps
// its host view only once its claim and all page references reach zero.
func (i *Importer) ReleaseAll() {
	i.mu.Lock()
	i.closed = true
	regs := make([]*ImportedRegion, 0, len(i.regions))
	for r := range i.regions {
		regs = append(regs, r)
	}
	clear(i.regions)
	i.mu.Unlock()

	for _, r := range regs {
		r.dropClaim()
	}
}

func (i *Importer) releaseCharge(size uint64) {
	i.mu.Lock()
	if i.usedBytes >= size {
		i.usedBytes -= size
	} else {
		i.usedBytes = 0
	}
	i.mu.Unlock()
}

func (i *Importer) untrack(r *ImportedRegion) {
	i.mu.Lock()
	delete(i.regions, r)
	i.mu.Unlock()
}

// backingView abstracts the OS-specific host shared-memory mapping owned by one
// ImportedRegion.
type backingView interface {
	bytes() []byte
	fd() int
	unmap() error
}

// ImportedRegion exposes an imported host shared-memory mapping as a non-
// executable memmap.Mappable and memmap.File.
type ImportedRegion struct {
	memmap.DefaultMemoryType
	memmap.NoBufferedIOFallback

	importer *Importer
	size     uint64
	hostSize uint64
	writable bool

	mu          sync.Mutex
	backing     backingView
	claimed     bool
	pageRefs    int64
	mappingRefs int64
	unmapped    bool
}

var (
	_ memmap.File     = (*ImportedRegion)(nil)
	_ memmap.Mappable = (*ImportedRegion)(nil)
)

// Size returns the guest-visible byte length of the imported region.
func (r *ImportedRegion) Size() uint64 {
	return r.size
}

// HostSize returns the host backing byte length charged to the sandbox quota.
func (r *ImportedRegion) HostSize() uint64 {
	if r.hostSize > 0 {
		return r.hostSize
	}
	return r.size
}

// Writable reports whether guest mappings may write to this region.
func (r *ImportedRegion) Writable() bool {
	return r.writable
}

// Bytes returns the underlying host byte slice while the mapping stays alive,
// or nil after the region unmaps.
func (r *ImportedRegion) Bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.unmapped || r.backing == nil {
		return nil
	}
	return r.backing.bytes()
}

// Unmapped reports whether the underlying host view has been unmapped.
func (r *ImportedRegion) Unmapped() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.unmapped
}

// Release drops the caller's claim on r. If no guest page or mapping references
// remain, Release unmaps the host view and returns its byte quota immediately.
func (r *ImportedRegion) Release() {
	r.importer.untrack(r)
	r.dropClaim()
}

func (r *ImportedRegion) dropClaim() {
	r.mu.Lock()
	if !r.claimed {
		r.mu.Unlock()
		return
	}
	r.claimed = false
	r.maybeUnmapLocked()
	r.mu.Unlock()
}

func (r *ImportedRegion) maybeUnmapLocked() {
	if r.unmapped || r.claimed || r.pageRefs > 0 || r.mappingRefs > 0 {
		return
	}
	r.unmapped = true
	b := r.backing
	r.backing = nil
	if b != nil {
		_ = b.unmap()
	}
	r.importer.releaseCharge(r.HostSize())
}

// IncRef implements memmap.File.IncRef.
func (r *ImportedRegion) IncRef(fr memmap.FileRange, _ uint32) {
	if fr.Length() == 0 {
		return
	}
	r.mu.Lock()
	r.pageRefs += int64(fr.Length() / uint64(hostarch.PageSize))
	r.mu.Unlock()
}

// DecRef implements memmap.File.DecRef.
func (r *ImportedRegion) DecRef(fr memmap.FileRange) {
	if fr.Length() == 0 {
		return
	}
	r.mu.Lock()
	pages := int64(fr.Length() / uint64(hostarch.PageSize))
	if r.pageRefs >= pages {
		r.pageRefs -= pages
	} else {
		r.pageRefs = 0
	}
	r.maybeUnmapLocked()
	r.mu.Unlock()
}

// MapInternal implements memmap.File.MapInternal. It refuses execute access.
func (r *ImportedRegion) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	if at.Execute {
		return safemem.BlockSeq{}, linuxerr.EACCES
	}
	if at.Write && !r.writable {
		return safemem.BlockSeq{}, linuxerr.EACCES
	}
	if !fr.WellFormed() || fr.Length() == 0 || fr.End > r.size {
		return safemem.BlockSeq{}, linuxerr.EINVAL
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.unmapped || r.backing == nil {
		return safemem.BlockSeq{}, linuxerr.EIO
	}
	buf := r.backing.bytes()
	return safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf[fr.Start:fr.End])), nil
}

// DataFD implements memmap.File.DataFD.
func (r *ImportedRegion) DataFD(fr memmap.FileRange) (int, error) {
	if !fr.WellFormed() || fr.Length() == 0 || fr.End > r.size {
		return -1, linuxerr.EINVAL
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.unmapped || r.backing == nil {
		return -1, linuxerr.EIO
	}
	fd := r.backing.fd()
	if fd < 0 {
		return -1, linuxerr.ENOSYS
	}
	return fd, nil
}

// FD implements memmap.File.FD.
func (r *ImportedRegion) FD() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.unmapped || r.backing == nil {
		return -1
	}
	return r.backing.fd()
}

// ConfigureMMap enforces the non-executable and writability constraints of r
// on opts before mapping the region into a guest address space. Device
// implementations should call ConfigureMMap alongside vfs.GenericConfigureMMap.
func (r *ImportedRegion) ConfigureMMap(opts *memmap.MMapOpts) error {
	if opts.Perms.Execute {
		return linuxerr.EACCES
	}
	opts.MaxPerms.Execute = false
	if !r.writable {
		if opts.Perms.Write && !opts.Private {
			return linuxerr.EACCES
		}
		if !opts.Private {
			opts.MaxPerms.Write = false
		}
	}
	return nil
}

// AddMapping implements memmap.Mappable.AddMapping.
func (r *ImportedRegion) AddMapping(_ context.Context, _ memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	if writable && !r.writable {
		return linuxerr.EACCES
	}
	end := offset + uint64(ar.Length())
	if end < offset || end > r.size {
		return linuxerr.EINVAL
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.unmapped || r.backing == nil {
		return linuxerr.EIO
	}
	r.mappingRefs++
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (r *ImportedRegion) RemoveMapping(_ context.Context, _ memmap.MappingSpace, _ hostarch.AddrRange, _ uint64, _ bool) {
	r.mu.Lock()
	if r.mappingRefs > 0 {
		r.mappingRefs--
	}
	r.maybeUnmapLocked()
	r.mu.Unlock()
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (r *ImportedRegion) CopyMapping(ctx context.Context, ms memmap.MappingSpace, _ hostarch.AddrRange, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	return r.AddMapping(ctx, ms, dstAR, offset, writable)
}

// Translate implements memmap.Mappable.Translate. It refuses execute access.
func (r *ImportedRegion) Translate(_ context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	if at.Execute {
		return nil, linuxerr.EACCES
	}
	if at.Write && !r.writable {
		return nil, linuxerr.EACCES
	}
	if required.End > r.size {
		return nil, &memmap.BusError{Err: linuxerr.EFAULT}
	}
	end := min(optional.End, r.size)
	r.mu.Lock()
	alive := !r.unmapped && r.backing != nil
	r.mu.Unlock()
	if !alive {
		return nil, &memmap.BusError{Err: linuxerr.EIO}
	}
	perms := hostarch.AccessType{Read: true, Write: r.writable}
	return []memmap.Translation{
		{
			Source: memmap.MappableRange{Start: optional.Start, End: end},
			File:   r,
			Offset: optional.Start,
			Perms:  perms,
		},
	}, nil
}

// MayUseHugepages implements memmap.Mappable.MayUseHugepages.
func (*ImportedRegion) MayUseHugepages() bool {
	return false
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (*ImportedRegion) InvalidateUnsavable(context.Context) error {
	return nil
}
