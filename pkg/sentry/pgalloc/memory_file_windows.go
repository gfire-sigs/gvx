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

package pgalloc

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

const (
	winSecReserve  = 0x04000000 // SEC_RESERVE
	winMemDecommit = 0x4000     // MEM_DECOMMIT
	winMemReset    = 0x80000    // MEM_RESET
)

var (
	modKernel32Pg            = windows.NewLazySystemDLL("kernel32.dll")
	procDiscardVirtualMemory = modKernel32Pg.NewProc("DiscardVirtualMemory")

	nextWinMemFileID atomic.Uintptr
)

type windowsBacking struct {
	mu           sync.RWMutex
	fileID       uintptr
	sections     []windows.Handle
	residencyMu  sync.Mutex
	residencyFns atomic.Pointer[[]*residencyObserver]
}

// NewDefaultMemoryFile creates a Windows MemoryFile backed by anonymous
// virtual memory (or pagefile-backed sections when opts.SharedSection is set).
// The associated placeholder handle stays at zero bytes on disk.
func NewDefaultMemoryFile(opts MemoryFileOpts) (*MemoryFile, error) {
	handle, err := memutil.CreateMemFD("memfile", 0)
	if err != nil {
		return nil, fmt.Errorf("create windows memory file: %w", err)
	}
	f := os.NewFile(uintptr(handle), "gvx-memfile")
	opts.DisableIMAWorkAround = true
	opts.UseHostMemcgPressure = false
	mf, err := NewMemoryFile(f, opts)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return mf, nil
}

// AllocateSharedPages allocates a 4KB-aligned shared pagefile-backed region on Windows.
func AllocateSharedPages(size uint64) ([]byte, error) {
	aligned, ok := hostarch.Addr(size).RoundUp()
	if !ok || aligned == 0 {
		return nil, unix.EINVAL
	}
	return memutil.AllocateAnonymousArena(int(aligned))
}

// RemapSharedPages creates a secondary view of src on Windows.
func RemapSharedPages(src []byte) ([]byte, error) {
	return memutil.RemapAnonymousView(src, 0, len(src))
}

// DecommitSharedPages zeroes region and asks Windows to release its physical pages.
//
// On private memory it uses DiscardVirtualMemory. On pagefile-backed section
// views where DiscardVirtualMemory returns ERROR_INVALID_PARAMETER, it resets
// the pages with VirtualAlloc(MEM_RESET) and trims them from the working set
// with VirtualUnlock.
func DecommitSharedPages(region []byte) error {
	if len(region) == 0 {
		return unix.EINVAL
	}
	clear(region)

	alignedStart, alignedLen := alignedHostPageSpan(region)
	if alignedLen == 0 {
		return nil
	}
	// DiscardVirtualMemory returns a Win32 error code, not a BOOL.
	code, _, _ := procDiscardVirtualMemory.Call(alignedStart, alignedLen)
	if code == 0 {
		return nil
	}
	if syscall.Errno(code) == windows.ERROR_INVALID_PARAMETER {
		if _, err := windows.VirtualAlloc(alignedStart, alignedLen, winMemReset, windows.PAGE_READWRITE); err == nil {
			_ = windows.VirtualUnlock(alignedStart, alignedLen)
			return nil
		}
	}
	return fmt.Errorf("DiscardVirtualMemory %d bytes: %w", alignedLen, syscall.Errno(code))
}

// ReleaseSharedPages unmaps a shared region allocated by AllocateSharedPages.
func ReleaseSharedPages(region []byte) error {
	return memutil.UnmapView(region)
}

func alignedHostPageSpan(region []byte) (uintptr, uintptr) {
	if len(region) == 0 {
		return 0, 0
	}
	page := uintptr(os.Getpagesize())
	start := uintptr(unsafe.Pointer(&region[0]))
	end := start + uintptr(len(region))
	alignedStart := (start + page - 1) &^ (page - 1)
	alignedEnd := end &^ (page - 1)
	if alignedStart >= alignedEnd {
		return 0, 0
	}
	return alignedStart, alignedEnd - alignedStart
}

func outwardHostPageSpan(region []byte) (uintptr, uintptr) {
	if len(region) == 0 {
		return 0, 0
	}
	page := uintptr(os.Getpagesize())
	start := uintptr(unsafe.Pointer(&region[0]))
	end := start + uintptr(len(region))
	alignedStart := start &^ (page - 1)
	alignedEnd := (end + page - 1) &^ (page - 1)
	return alignedStart, alignedEnd - alignedStart
}

func (f *MemoryFile) truncateBackingFile(int64) error {
	// Windows chunks live in anonymous virtual memory or pagefile sections,
	// so the placeholder backing file never grows on disk.
	return nil
}

func (f *MemoryFile) extendBackingChunksLocked(oldFileSize, _ uint64, newChunks []chunkInfo) error {
	if len(newChunks) == 0 {
		return nil
	}
	if !f.opts.SharedSection {
		for i := range newChunks {
			addr, err := windows.VirtualAlloc(0, chunkSize, windows.MEM_RESERVE, windows.PAGE_READWRITE)
			if err != nil {
				for j := range i {
					_ = windows.VirtualFree(newChunks[j].mapping, 0, windows.MEM_RELEASE)
					newChunks[j].mapping = 0
				}
				return err
			}
			newChunks[i].mapping = addr
		}
		return nil
	}

	wb := &f.saveRestore.winBacking
	baseIdx := int(oldFileSize / chunkSize)
	newSecs := make([]windows.Handle, len(newChunks))
	for i := range newChunks {
		sec, err := windows.CreateFileMapping(
			windows.InvalidHandle,
			nil,
			windows.PAGE_READWRITE|winSecReserve,
			uint32(chunkSize>>32),
			uint32(chunkSize),
			nil,
		)
		if err != nil {
			for j := range i {
				_ = windows.UnmapViewOfFile(newChunks[j].mapping)
				_ = windows.CloseHandle(newSecs[j])
				newChunks[j].mapping = 0
			}
			return err
		}
		addr, err := windows.MapViewOfFile(sec, windows.FILE_MAP_WRITE|windows.FILE_MAP_READ, 0, 0, chunkSize)
		if err != nil {
			_ = windows.CloseHandle(sec)
			for j := range i {
				_ = windows.UnmapViewOfFile(newChunks[j].mapping)
				_ = windows.CloseHandle(newSecs[j])
				newChunks[j].mapping = 0
			}
			return err
		}
		newSecs[i] = sec
		newChunks[i].mapping = addr
	}

	wb.mu.Lock()
	if wb.fileID == 0 {
		wb.fileID = nextWinMemFileID.Add(1)
	}
	if baseIdx == 0 {
		for _, old := range wb.sections {
			if old != 0 {
				_ = windows.CloseHandle(old)
			}
		}
		wb.sections = newSecs
	} else {
		wb.sections = append(wb.sections, newSecs...)
	}
	wb.mu.Unlock()
	return nil
}

func (f *MemoryFile) unmapBackingChunks(chunks []chunkInfo) error {
	var errs []error
	if !f.opts.SharedSection {
		for i := range chunks {
			chunk := &chunks[i]
			if chunk.mapping == 0 {
				continue
			}
			if err := windows.VirtualFree(chunk.mapping, 0, windows.MEM_RELEASE); err != nil {
				log.Warningf("Failed to release VirtualAlloc mapping %#x for MemoryFile chunk %d: %v", chunk.mapping, i, err)
				errs = append(errs, fmt.Errorf("chunk %d (%#x): %w", i, chunk.mapping, err))
			}
			chunk.mapping = 0
		}
		return errors.Join(errs...)
	}

	for i := range chunks {
		chunk := &chunks[i]
		if chunk.mapping == 0 {
			continue
		}
		if err := windows.UnmapViewOfFile(chunk.mapping); err != nil {
			log.Warningf("Failed to unmap mapping %#x for MemoryFile chunk %d: %v", chunk.mapping, i, err)
			errs = append(errs, fmt.Errorf("chunk %d (%#x): %w", i, chunk.mapping, err))
		}
		chunk.mapping = 0
	}
	wb := &f.saveRestore.winBacking
	wb.mu.Lock()
	secs := wb.sections
	wb.sections = nil
	wb.mu.Unlock()
	for i, sec := range secs {
		if sec == 0 {
			continue
		}
		if err := windows.CloseHandle(sec); err != nil {
			errs = append(errs, fmt.Errorf("close chunk section %d: %w", i, err))
		}
	}
	return errors.Join(errs...)
}

// ChunkSection returns the pagefile-backed section handle and chunk offset
// metadata covering file offset off when f was created with SharedSection.
func (f *MemoryFile) ChunkSection(off uint64) (section windows.Handle, chunkStart, chunkLen uint64, fileID uintptr, ok bool) {
	if !f.opts.SharedSection {
		return 0, 0, 0, 0, false
	}
	idx := int(off / chunkSize)
	wb := &f.saveRestore.winBacking
	wb.mu.RLock()
	defer wb.mu.RUnlock()
	if idx < 0 || idx >= len(wb.sections) || wb.sections[idx] == 0 {
		return 0, 0, 0, 0, false
	}
	return wb.sections[idx], uint64(idx) * chunkSize, chunkSize, wb.fileID, true
}

// commitFile is a no-op on Windows because commitRange already commits the
// anonymous virtual memory range and the placeholder file stays at zero bytes.
func (*MemoryFile) commitFile(memmap.FileRange) error {
	return nil
}

func (f *MemoryFile) commitRange(fr memmap.FileRange) error {
	if f.file == nil || fr.Length() == 0 {
		return nil
	}
	type committedSpan struct {
		addr   uintptr
		length uintptr
	}
	var (
		committed []committedSpan
		commitErr error
	)
	f.forEachChunk(fr, func(chunk *chunkInfo, chunkFR memmap.FileRange) bool {
		if chunk.mapping == 0 {
			return true
		}
		bs := chunk.sliceAt(chunkFR)
		addr, length := outwardHostPageSpan(bs)
		if length == 0 {
			return true
		}
		if _, err := windows.VirtualAlloc(addr, length, windows.MEM_COMMIT, windows.PAGE_READWRITE); err != nil {
			commitErr = linuxerr.ENOMEM
			return false
		}
		committed = append(committed, committedSpan{addr: addr, length: length})
		return true
	})
	if commitErr != nil && !f.opts.SharedSection {
		for _, span := range committed {
			_ = windows.VirtualFree(span.addr, span.length, winMemDecommit)
		}
	}
	return commitErr
}

// expandReleaseRangeLocked returns fr unchanged on Windows.
func (f *MemoryFile) expandReleaseRangeLocked(fr memmap.FileRange) memmap.FileRange {
	return fr
}

// decommitRange resets still-allocated pages in fr (for example after
// madvise(MADV_DONTNEED) or SaveTo zero scanning) while keeping them committed.
func (f *MemoryFile) decommitRange(fr memmap.FileRange) {
	f.forEachMappingSlice(fr, func(bs []byte) {
		_ = DecommitSharedPages(bs)
	})
}

// decommitOnDestroyLocked is a no-op on Windows because unmapBackingChunks
// immediately releases the anonymous VirtualAlloc regions or closes the
// pagefile-backed sections without any disk backing file.
func (*MemoryFile) decommitOnDestroyLocked(memmap.FileRange) {}

// decommitCommittedSubregions resets only the sub-ranges inside [addr, addr+length)
// that are currently in MEM_COMMIT state so fallback decommit cannot fault on
// pages that an earlier sub-release already decommitted.
func decommitCommittedSubregions(addr, length uintptr) {
	end := addr + length
	for cur := addr; cur < end; {
		var info windows.MemoryBasicInformation
		if err := windows.VirtualQuery(cur, &info, unsafe.Sizeof(info)); err != nil || info.RegionSize == 0 {
			return
		}
		segEnd := min(info.BaseAddress+info.RegionSize, end)
		if info.State == windows.MEM_COMMIT && segEnd > cur {
			sub := unsafe.Slice((*byte)(unsafe.Pointer(cur)), int(segEnd-cur))
			_ = DecommitSharedPages(sub)
		}
		if segEnd <= cur {
			return
		}
		cur = segEnd
	}
}

// decommitReleasedRange releases physical memory and, for private VirtualAlloc
// chunks, commit charge for freed ranges returned to the allocator.
func (f *MemoryFile) decommitReleasedRange(fr memmap.FileRange) {
	if f.opts.SharedSection {
		f.decommitRange(fr)
		return
	}
	f.forEachMappingSlice(fr, func(bs []byte) {
		addr, length := alignedHostPageSpan(bs)
		if length == 0 {
			clear(bs)
			return
		}
		if err := windows.VirtualFree(addr, length, winMemDecommit); err != nil {
			log.Warningf("Failed to decommit MemoryFile range %#x+%#x: %v", addr, length, err)
			decommitCommittedSubregions(addr, length)
		}
	})
}

func (f *MemoryFile) totalUsage() (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.knownCommittedBytes, nil
}

func alignSmallAllocRange(gap memmap.FileRange, length uint64, dir Direction) (memmap.FileRange, bool) {
	if gap.Length() < length {
		return memmap.FileRange{}, false
	}
	if dir == BottomUp {
		return memmap.FileRange{Start: gap.Start, End: gap.Start + length}, true
	}
	return memmap.FileRange{Start: gap.End - length, End: gap.End}, true
}
