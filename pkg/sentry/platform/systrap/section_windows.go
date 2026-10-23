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

//go:build windows

package systrap

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

// blockSize is the page size of the Windows engine. Views start and end on
// 4KB boundaries.
const blockSize = 0x1000

// addrPtr converts the address of memory that the Go runtime does not manage,
// such as a mapped view, into a pointer.
func addrPtr(addr uint64) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&addr))
}

// secCommit is the SEC_COMMIT allocation attribute of CreateFileMapping.
const secCommit = 0x08000000

// sectionRef is a section object that a stub window can map.
type sectionRef struct {
	h windows.Handle
	// size is the size of the section in bytes.
	size uint64
	// readOnly is true for a section of a file that the Sentry opened without
	// write access, such as an erofs image.
	readOnly bool
}

// sectionCache holds one section for each memory file. The memory file grows
// in steps, and a section covers only the file size at its creation, so the
// cache creates a new section when a mapping reaches past the old one.
//
// WHY: a view that the stub holds keeps its section object alive, but the
// window map keeps the section handle to map a piece of a split view again.
// So the cache closes no handle before the platform closes.
type sectionCache struct {
	mu    sync.Mutex
	files map[windows.Handle]*sectionRef
	all   []*sectionRef
}

// get returns a section of the file that covers [0, end). A caller that needs
// write access gets an error for a file that has none.
func (c *sectionCache) get(file windows.Handle, end uint64, write bool) (*sectionRef, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ref := c.files[file]; ref != nil && ref.size >= end {
		if write && ref.readOnly {
			return nil, errReadOnlyFile
		}
		return ref, nil
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(file, &info); err != nil {
		return nil, fmt.Errorf("GetFileInformationByHandle: %w", err)
	}
	size := uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow)
	if size < end {
		return nil, fmt.Errorf("the file has %d bytes and the mapping needs %d", size, end)
	}
	// A data section of the file needs no execute right: the engine maps the
	// original frames of a guest without execute permission.
	readOnly := false
	h, err := windows.CreateFileMapping(file, nil, windows.PAGE_READWRITE, 0, 0, nil)
	if err != nil {
		if write {
			return nil, fmt.Errorf("CreateFileMapping of the file: %w", err)
		}
		// The handle has no write access. A read-only section serves every
		// mapping without write permission.
		readOnly = true
		if h, err = windows.CreateFileMapping(file, nil, windows.PAGE_READONLY, 0, 0, nil); err != nil {
			return nil, fmt.Errorf("CreateFileMapping of the file: %w", err)
		}
	}
	ref := &sectionRef{h: h, size: size, readOnly: readOnly}
	if c.files == nil {
		c.files = make(map[windows.Handle]*sectionRef)
	}
	c.files[file] = ref
	c.all = append(c.all, ref)
	return ref, nil
}

var errReadOnlyFile = errors.New("the file has no write access")

func (c *sectionCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ref := range c.all {
		_ = windows.CloseHandle(ref.h)
	}
	c.all, c.files = nil, nil
}

// anonSection is a pagefile-backed section that the Sentry maps for writing
// and a stub maps for execution.
type anonSection struct {
	ref   sectionRef
	local []byte
}

// newAnonSection creates a section of size bytes that a view can map as
// read-write-execute, and maps it into the Sentry for writing.
func newAnonSection(size uint64) (*anonSection, error) {
	h, err := windows.CreateFileMapping(windows.InvalidHandle, nil, windows.PAGE_EXECUTE_READWRITE|secCommit, uint32(size>>32), uint32(size), nil)
	if err != nil {
		return nil, fmt.Errorf("CreateFileMapping(anonymous %d bytes): %w", size, err)
	}
	addr, err := windows.MapViewOfFile(h, windows.FILE_MAP_WRITE|windows.FILE_MAP_READ, 0, 0, uintptr(size))
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("MapViewOfFile(anonymous %d bytes): %w", size, err)
	}
	return &anonSection{
		ref:   sectionRef{h: h, size: size},
		local: unsafe.Slice((*byte)(addrPtr(uint64(addr))), size),
	}, nil
}

func (s *anonSection) close() {
	_ = windows.UnmapViewOfFile(uintptr(unsafe.Pointer(&s.local[0])))
	_ = windows.CloseHandle(s.ref.h)
}

// privChunkSize is the size of one chunk of the private page pool.
const privChunkSize = 4 << 20

// privPage is one 4KB page of the private pool.
type privPage struct {
	chunk *anonSection
	off   uint64
}

// bytes returns the Sentry view of the page.
func (pg privPage) bytes() []byte { return pg.chunk.local[pg.off : pg.off+blockSize] }

// privPool hands out the pages that hold patched copies of guest code. A
// released page is zeroed before reuse, so one guest never sees the code of
// another.
type privPool struct {
	mu     sync.Mutex
	chunks []*anonSection
	free   []privPage
	next   uint64
}

func (pp *privPool) alloc() (privPage, error) {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	if n := len(pp.free); n > 0 {
		pg := pp.free[n-1]
		pp.free = pp.free[:n-1]
		return pg, nil
	}
	if len(pp.chunks) == 0 || pp.next == privChunkSize {
		c, err := newAnonSection(privChunkSize)
		if err != nil {
			return privPage{}, err
		}
		pp.chunks = append(pp.chunks, c)
		pp.next = 0
	}
	pg := privPage{chunk: pp.chunks[len(pp.chunks)-1], off: pp.next}
	pp.next += blockSize
	return pg, nil
}

func (pp *privPool) release(pg privPage) {
	clear(pg.bytes())
	pp.mu.Lock()
	pp.free = append(pp.free, pg)
	pp.mu.Unlock()
}

func (pp *privPool) close() {
	pp.mu.Lock()
	defer pp.mu.Unlock()
	for _, c := range pp.chunks {
		c.close()
	}
	pp.chunks, pp.free = nil, nil
}

// copyRange returns an anonymous section that holds a copy of the bytes of fr.
// The memory file has no host handle that a stub could map.
func copyRange(f memmap.File, fr memmap.FileRange) (*anonSection, error) {
	bs, err := f.MapInternal(fr, hostarch.AccessType{Read: true})
	if err != nil {
		return nil, fmt.Errorf("copy the file range %v: %w", fr, err)
	}
	sec, err := newAnonSection(fr.Length())
	if err != nil {
		return nil, err
	}
	off := uint64(0)
	for ; !bs.IsEmpty(); bs = bs.Tail() {
		off += uint64(copy(sec.local[off:], bs.Head().ToSlice()))
	}
	return sec, nil
}
