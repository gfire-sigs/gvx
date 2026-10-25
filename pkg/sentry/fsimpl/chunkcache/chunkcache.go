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

// Package chunkcache provides the shared 64 KiB page-chunk cache and VFS2
// helpers used by hostfs and ext4lite.
package chunkcache

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/kernel/pipe"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

const (
	// ChunkShift is the log2 of the cache granule. The granule is a multiple of
	// every host page size and of the 4 KiB guest page size.
	ChunkShift = 16

	// ChunkSize is the byte size of one cached chunk.
	ChunkSize = 1 << ChunkShift

	// ChunkAlign is the alignment of a chunk in host memory.
	ChunkAlign = 16 << 10

	// MaxReadahead bounds how much of a mapping one Translate call loads.
	MaxReadahead = 64 << 10
)

// ChunkMemory supplies the memory for the chunks of mapped files. A platform
// that runs guest code in another process maps guest pages by file descriptor,
// so it cannot use Go heap memory.
type ChunkMemory interface {
	memmap.File

	// AllocateChunk returns a zeroed range of length bytes. The caller holds
	// one reference, which it drops with DecRef.
	AllocateChunk(length uint64) (memmap.FileRange, error)
}

type chunkMemoryBox struct {
	m ChunkMemory
}

// ChunkMemoryHolder stores a ChunkMemory reference atomically.
type ChunkMemoryHolder struct {
	ptr atomic.Pointer[chunkMemoryBox]
}

// Set stores mem as the active ChunkMemory.
func (h *ChunkMemoryHolder) Set(mem ChunkMemory) {
	h.ptr.Store(&chunkMemoryBox{m: mem})
}

// Get returns the active ChunkMemory, or nil.
func (h *ChunkMemoryHolder) Get() ChunkMemory {
	if b := h.ptr.Load(); b != nil {
		return b.m
	}
	return nil
}

// Chunk holds one 64 KiB cached slice of a regular file.
type Chunk struct {
	Buf   []byte
	Dirty bool

	// Mem and FR locate the chunk in shared memory. They are zero when Buf is
	// Go heap memory.
	Mem ChunkMemory
	FR  memmap.FileRange
}

// Release returns shared memory to its owner. The memory stays valid for the
// mappings that still hold a reference.
func (ch *Chunk) Release() {
	if ch.Mem != nil {
		ch.Mem.DecRef(ch.FR)
		ch.Mem = nil
	}
}

// NewChunk allocates the memory of one chunk. With ChunkMemory, the chunk
// lives in a memory file, which a platform can map into a guest process by
// file descriptor. Without it, the chunk lives on the Go heap.
func NewChunk(mem ChunkMemory) (*Chunk, error) {
	if mem == nil {
		return &Chunk{Buf: newChunkBuf()}, nil
	}
	fr, err := mem.AllocateChunk(ChunkSize)
	if err != nil {
		return nil, err
	}
	bs, err := mem.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		mem.DecRef(fr)
		return nil, err
	}
	if bs.NumBlocks() != 1 || bs.NumBytes() != ChunkSize {
		mem.DecRef(fr)
		return nil, fmt.Errorf("chunkcache: the chunk memory maps %d blocks of %d bytes, want one block of %d", bs.NumBlocks(), bs.NumBytes(), ChunkSize)
	}
	return &Chunk{Buf: bs.Head().ToSlice(), Mem: mem, FR: fr}, nil
}

// newChunkBuf allocates one chunk aligned to ChunkAlign. Go heap memory never
// moves, so slices handed to platforms stay valid for the chunk lifetime.
func newChunkBuf() []byte {
	raw := make([]byte, ChunkSize+ChunkAlign)
	skip := (ChunkAlign - int(uintptr(unsafe.Pointer(&raw[0]))%ChunkAlign)) % ChunkAlign
	return raw[skip : skip+ChunkSize : skip+ChunkSize]
}

// MaxFillRange bounds optional readahead to MaxReadahead while covering required.
func MaxFillRange(required, optional memmap.MappableRange) memmap.MappableRange {
	if required.Length() >= MaxReadahead {
		return required
	}
	if optional.Length() <= MaxReadahead {
		return optional
	}
	optional.Start = required.Start
	if optional.Length() <= MaxReadahead {
		return optional
	}
	optional.End = optional.Start + MaxReadahead
	return optional
}

// Translations describes where the pages of mr live. Heap chunks form one
// translation through heapFile. Chunks in shared memory need one translation
// each because the allocator places chunks apart. Every chunk in mr must exist
// before calling Translations.
func Translations(chunks map[uint64]*Chunk, mr memmap.MappableRange, perms hostarch.AccessType, heapFile memmap.File) []memmap.Translation {
	if chunks[mr.Start>>ChunkShift].Mem == nil {
		return []memmap.Translation{{
			Source: mr,
			File:   heapFile,
			Offset: mr.Start,
			Perms:  perms,
		}}
	}
	var ts []memmap.Translation
	for off := mr.Start; off < mr.End; {
		idx := off >> ChunkShift
		ch := chunks[idx]
		base := idx << ChunkShift
		end := min(mr.End, base+ChunkSize)
		ts = append(ts, memmap.Translation{
			Source: memmap.MappableRange{Start: off, End: end},
			File:   ch.Mem,
			Offset: ch.FR.Start + (off - base),
			Perms:  perms,
		})
		off = end
	}
	return ts
}

// ReadAtToBlocks reads from readAt at off into dsts and returns the number of
// bytes read, the updated offset, and any error.
func ReadAtToBlocks(dsts safemem.BlockSeq, off int64, readAt func(p []byte, off int64) (int, error)) (uint64, int64, error) {
	var done uint64
	var scratch []byte
	for ; !dsts.IsEmpty(); dsts = dsts.Tail() {
		dst := dsts.Head()
		var n int
		var err error
		if !dst.NeedSafecopy() {
			n, err = readAt(dst.ToSlice(), off)
		} else {
			if len(scratch) < dst.Len() {
				scratch = make([]byte, dst.Len())
			}
			var rn int
			rn, err = readAt(scratch[:dst.Len()], off)
			var werr error
			n, werr = safemem.Copy(dst, safemem.BlockFromSafeSlice(scratch[:rn]))
			if werr != nil {
				err = werr
			}
		}
		off += int64(n)
		done += uint64(n)
		if n != dst.Len() {
			if err == nil && done > 0 {
				err = io.EOF
			}
			return done, off, err
		}
	}
	return done, off, nil
}

// SeekRegular computes the new file offset for a regular file description.
func SeekRegular(curOff, offset int64, whence int32, fileSize func() (int64, error)) (int64, error) {
	var newOff int64
	switch whence {
	case linux.SEEK_SET:
		newOff = offset
	case linux.SEEK_CUR:
		newOff = curOff + offset
	case linux.SEEK_END, linux.SEEK_DATA, linux.SEEK_HOLE:
		size, err := fileSize()
		if err != nil {
			return 0, err
		}
		switch whence {
		case linux.SEEK_END:
			newOff = size + offset
		case linux.SEEK_DATA:
			if offset < 0 || offset >= size {
				return 0, linuxerr.ENXIO
			}
			newOff = offset
		default:
			if offset < 0 || offset >= size {
				return 0, linuxerr.ENXIO
			}
			newOff = size
		}
	default:
		return 0, linuxerr.EINVAL
	}
	if newOff < 0 {
		return 0, linuxerr.EINVAL
	}
	return newOff, nil
}

// DirCursor tracks the snapshot and offset of an open directory description.
type DirCursor struct {
	mu       sync.Mutex
	snapshot []vfs.Dirent
	loaded   bool
	off      int64
}

// IterDirents iterates over the directory snapshot, calling load on the first
// read or after a rewind to offset zero.
func (c *DirCursor) IterDirents(cb vfs.IterDirentsCallback, load func() ([]vfs.Dirent, error)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.loaded {
		snap, err := load()
		if err != nil {
			return err
		}
		c.snapshot = snap
		c.loaded = true
	}
	for c.off < int64(len(c.snapshot)) {
		if err := cb.Handle(c.snapshot[c.off]); err != nil {
			return err
		}
		c.off++
	}
	return nil
}

// Seek updates the directory offset and clears the cached snapshot when rewound
// to offset zero.
func (c *DirCursor) Seek(offset int64, whence int32) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var newOff int64
	switch whence {
	case linux.SEEK_SET:
		newOff = offset
	case linux.SEEK_CUR:
		newOff = c.off + offset
	default:
		return 0, linuxerr.EINVAL
	}
	if newOff < 0 {
		return 0, linuxerr.EINVAL
	}
	if newOff == 0 {
		c.loaded = false
		c.snapshot = nil
	}
	c.off = newOff
	return newOff, nil
}

// TryIncRef increments refs when the current count is positive.
func TryIncRef(refs *atomicbitops.Int64) bool {
	for {
		r := refs.Load()
		if r <= 0 {
			return false
		}
		if refs.CompareAndSwap(r, r+1) {
			return true
		}
	}
}

// CheckXattrPrefix accepts the user, trusted, and security extended attribute
// namespaces and rejects all other prefixes with EOPNOTSUPP.
func CheckXattrPrefix(name string) error {
	for _, prefix := range []string{linux.XATTR_USER_PREFIX, linux.XATTR_TRUSTED_PREFIX, linux.XATTR_SECURITY_PREFIX} {
		if strings.HasPrefix(name, prefix) {
			return nil
		}
	}
	return linuxerr.EOPNOTSUPP
}

// FilterXattrList filters extended attribute names for a caller with creds and
// validates that the null-terminated list fits within size when size is non-zero.
func FilterXattrList(all []string, creds *auth.Credentials, size uint64) ([]string, error) {
	haveCap := creds.HasRootCapability(linux.CAP_SYS_ADMIN)
	names := make([]string, 0, len(all))
	listSize := 0
	for _, name := range all {
		if CheckXattrPrefix(name) != nil {
			continue
		}
		if !haveCap && strings.HasPrefix(name, linux.XATTR_TRUSTED_PREFIX) {
			continue
		}
		names = append(names, name)
		listSize += len(name) + 1
	}
	if size != 0 && uint64(listSize) > size {
		return nil, linuxerr.ERANGE
	}
	return names, nil
}

// OpenSpecial opens a FIFO, character device, or block device node and returns
// ENXIO for sockets or unknown file types.
func OpenSpecial(ctx context.Context, rp *vfs.ResolvingPath, d *vfs.Dentry, opts *vfs.OpenOptions, mode uint32, p *pipe.VFSPipe, locks *vfs.FileLocks, major, minor uint32) (*vfs.FileDescription, error) {
	switch mode & linux.S_IFMT {
	case linux.S_IFIFO:
		return p.Open(ctx, rp.Mount(), d, opts.Flags, locks)
	case linux.S_IFCHR, linux.S_IFBLK:
		kind := vfs.CharDevice
		if mode&linux.S_IFMT == linux.S_IFBLK {
			kind = vfs.BlockDevice
		}
		return rp.VirtualFilesystem().OpenDeviceSpecialFile(ctx, rp.Mount(), d, kind, major, minor, opts)
	default:
		return nil, linuxerr.ENXIO
	}
}
