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
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

var (
	modKernel32Pg            = windows.NewLazySystemDLL("kernel32.dll")
	procDiscardVirtualMemory = modKernel32Pg.NewProc("DiscardVirtualMemory")
)

// NewDefaultMemoryFile creates a temporary backing file on Windows and returns
// a configured MemoryFile. The file opens with FILE_FLAG_DELETE_ON_CLOSE, so
// Windows deletes it when the MemoryFile closes its handle.
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

// DecommitSharedPages zeroes region and asks Windows to release its physical pages with DiscardVirtualMemory.
//
// DiscardVirtualMemory leaves the contents undefined, so the function zeroes
// region first. The call needs page-aligned memory with PAGE_READWRITE
// protection, so only the pages that region covers completely go to the kernel.
// If Windows rejects the call, region is still zeroed and the error reports the missed reclaim.
func DecommitSharedPages(region []byte) error {
	if len(region) == 0 {
		return unix.EINVAL
	}
	clear(region)

	page := uintptr(os.Getpagesize())
	start := uintptr(unsafe.Pointer(&region[0]))
	end := start + uintptr(len(region))
	alignedStart := (start + page - 1) &^ (page - 1)
	alignedEnd := end &^ (page - 1)
	if alignedStart >= alignedEnd {
		return nil
	}
	// DiscardVirtualMemory returns a Win32 error code, not a BOOL.
	code, _, _ := procDiscardVirtualMemory.Call(alignedStart, alignedEnd-alignedStart)
	if code != 0 {
		return fmt.Errorf("DiscardVirtualMemory %d bytes: %w", alignedEnd-alignedStart, syscall.Errno(code))
	}
	return nil
}

// ReleaseSharedPages unmaps a shared region allocated by AllocateSharedPages.
func ReleaseSharedPages(region []byte) error {
	return memutil.UnmapView(region)
}

// expandReleaseRangeLocked returns fr unchanged on Windows.
func (f *MemoryFile) expandReleaseRangeLocked(fr memmap.FileRange) memmap.FileRange {
	return fr
}

// decommitRange zeroes fr and releases whole host pages with DiscardVirtualMemory.
func (f *MemoryFile) decommitRange(fr memmap.FileRange) {
	f.forEachMappingSlice(fr, func(bs []byte) {
		_ = DecommitSharedPages(bs)
	})
}
