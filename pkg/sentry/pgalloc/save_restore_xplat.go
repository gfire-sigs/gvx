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

package pgalloc

import (
	"errors"
	"fmt"
	"runtime"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/log"
)

// saveRestoreXplat stores per-file save, restore, and destruction state.
type saveRestoreXplat struct {
	// seekFn overrides unix.Seek in hostFileDataSeeker during unit tests.
	seekFn func(fd int, offset int64, whence int) (int64, error)

	// destroyDone reports whether releaserDestroyLocked finished.
	// MemoryFile.mu protects destroyDone.
	destroyDone bool

	// destroyUnmapErr joins chunk unmap errors from releaserDestroyLocked.
	// MemoryFile.mu protects destroyUnmapErr.
	destroyUnmapErr error
}

// isSeekDataUnsupported reports whether err indicates that the host kernel or
// backing filesystem rejects SEEK_DATA or SEEK_HOLE.
func isSeekDataUnsupported(err error) bool {
	return errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.ENOTSUP) ||
		errors.Is(err, unix.EOPNOTSUPP)
}

func (f *MemoryFile) seekFileData(fd int, offset int64, whence int) (int64, error) {
	if f.saveRestore.seekFn != nil {
		return f.saveRestore.seekFn(fd, offset, whence)
	}
	return unix.Seek(fd, offset, whence)
}

// mapMemoryFileChunks maps len(chunks) contiguous 1 GiB chunks of fd starting
// at startOffset and stores each base address in chunks[i].mapping.
//
// Linux and macOS split a single multi-chunk mmap during per-chunk munmap.
// Windows UnmapViewOfFile releases a whole MapViewOfFile view at once and
// rejects partial unmaps, so Windows maps one view per chunk.
func mapMemoryFileChunks(fd uintptr, startOffset uint64, chunks []chunkInfo) error {
	if len(chunks) == 0 {
		return nil
	}
	if runtime.GOOS != "windows" {
		size := uintptr(uint64(len(chunks)) * chunkSize)
		m, _, errno := unix.Syscall6(
			unix.SYS_MMAP,
			0,
			size,
			unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_SHARED,
			fd,
			uintptr(startOffset))
		if errno != 0 {
			return errno
		}
		for i := range chunks {
			chunks[i].mapping = m
			m += chunkSize
		}
		return nil
	}
	for i := range chunks {
		off := startOffset + uint64(i)*chunkSize
		m, _, errno := unix.Syscall6(
			unix.SYS_MMAP,
			0,
			chunkSize,
			unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_SHARED,
			fd,
			uintptr(off))
		if errno != 0 {
			for j := range i {
				_, _, _ = unix.Syscall(unix.SYS_MUNMAP, chunks[j].mapping, chunkSize, 0)
				chunks[j].mapping = 0
			}
			return errno
		}
		chunks[i].mapping = m
	}
	return nil
}

// unmapChunksLocked unmaps every chunk during destruction and wakes waiters on
// f.releaseCond.
//
// Preconditions: caller holds f.mu.
func (f *MemoryFile) unmapChunksLocked(chunks []chunkInfo) {
	var errs []error
	for i := range chunks {
		chunk := &chunks[i]
		if chunk.mapping == 0 {
			continue
		}
		_, _, errno := unix.Syscall(unix.SYS_MUNMAP, chunk.mapping, chunkSize, 0)
		if errno != 0 {
			log.Warningf("Failed to unmap mapping %#x for MemoryFile chunk %d: %v", chunk.mapping, i, errno)
			errs = append(errs, fmt.Errorf("chunk %d (%#x): %w", i, chunk.mapping, errno))
		}
		chunk.mapping = 0
	}
	f.saveRestore.destroyUnmapErr = errors.Join(errs...)
	f.saveRestore.destroyDone = true
	f.releaseCond.Broadcast()
}
