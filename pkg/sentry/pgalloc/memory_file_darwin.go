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

//go:build darwin

package pgalloc

import (
	"fmt"
	"os"
	"unsafe"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/internal/xsys/unix"
)

// The usage scan sizes its mincore vector with one byte per hostarch.PageSize.
// The unix overlay must fill exactly that many bytes. When the two page sizes
// differ, one of the arrays below gets a negative length and the build fails.
var (
	_ [unix.MincorePageSize - hostarch.PageSize]struct{}
	_ [hostarch.PageSize - unix.MincorePageSize]struct{}
)

// NewDefaultMemoryFile creates an unlinked backing file on macOS and returns a
// configured MemoryFile. MemoryFile.Decommit punches holes in the file with
// fcntl(F_PUNCHHOLE), which APFS supports.
func NewDefaultMemoryFile(opts MemoryFileOpts) (*MemoryFile, error) {
	fd, err := memutil.CreateMemFD("memfile", 0)
	if err != nil {
		return nil, fmt.Errorf("create darwin memory file: %w", err)
	}
	f := os.NewFile(uintptr(fd), "gvx-memfile")
	opts.DisableIMAWorkAround = true
	opts.UseHostMemcgPressure = false
	mf, err := NewMemoryFile(f, opts)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return mf, nil
}

// AllocateSharedPages allocates a 4KB-aligned anonymous shared region on macOS.
func AllocateSharedPages(size uint64) ([]byte, error) {
	aligned, ok := hostarch.Addr(size).RoundUp()
	if !ok || aligned == 0 {
		return nil, unix.EINVAL
	}
	return memutil.AllocateAnonymousArena(int(aligned))
}

// RemapSharedPages creates an alias view of src.
func RemapSharedPages(src []byte) ([]byte, error) {
	return memutil.RemapAnonymousView(src, 0, len(src))
}

// DecommitSharedPages zeroes region and lets the kernel reclaim its physical pages with madvise(MADV_FREE).
//
// MADV_FREE alone leaves stale bytes behind, so the function zeroes region first.
// The host page is 16KB, and MADV_FREE works on whole host pages. Only the
// host pages that region covers completely go to the kernel. Bytes that share
// a host page with live neighbours stay mapped. If madvise fails, region is
// still zeroed and the error reports the missed reclaim.
func DecommitSharedPages(region []byte) error {
	if len(region) == 0 {
		return unix.EINVAL
	}
	clear(region)

	hostPage := uintptr(unix.Getpagesize())
	start := uintptr(unsafe.Pointer(&region[0]))
	end := start + uintptr(len(region))
	alignedStart := (start + hostPage - 1) &^ (hostPage - 1)
	alignedEnd := end &^ (hostPage - 1)
	if alignedStart >= alignedEnd {
		return nil
	}
	whole := unsafe.Slice((*byte)(unsafe.Add(unsafe.Pointer(&region[0]), alignedStart-start)), alignedEnd-alignedStart)
	if err := unix.Madvise(whole, unix.MADV_FREE); err != nil {
		return fmt.Errorf("madvise(MADV_FREE) %d bytes: %w", len(whole), err)
	}
	return nil
}

// ReleaseSharedPages unmaps a shared region allocated by AllocateSharedPages.
func ReleaseSharedPages(region []byte) error {
	return memutil.UnmapView(region)
}
