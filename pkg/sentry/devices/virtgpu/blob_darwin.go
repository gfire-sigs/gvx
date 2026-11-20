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
	"fmt"
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/fd"
	"z.gfire.dev/gvx/pkg/log"
)

// blobView is one MAP_SHARED mapping of a renderer shm object. The zero value
// is no mapping.
type blobView struct {
	mem []byte
}

// mapBlobView validates the shm object of shm against guestSize and maps it
// whole for reading and writing. It does not close shm.
func mapBlobView(shm *fd.HostHandle, guestSize uint64) (blobView, uint64, error) {
	raw, err := shm.RawHandle()
	if err != nil {
		return blobView{}, 0, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(raw), &st); err != nil {
		return blobView{}, 0, fmt.Errorf("virtgpu: fstat blob descriptor: %w", err)
	}
	size := st.Size
	if size <= 0 || uint64(size) > maxBlobBytes || uint64(size) < guestSize || uint64(size)%blobAlignment != 0 {
		return blobView{}, 0, fmt.Errorf("%w: host size %d, guest size %d", errBlobSize, size, guestSize)
	}
	mem, err := unix.Mmap(int(raw), 0, int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return blobView{}, 0, fmt.Errorf("virtgpu: mmap blob: %w", err)
	}
	if base := uintptr(unsafe.Pointer(unsafe.SliceData(mem))); base%blobAlignment != 0 {
		if uerr := unix.Munmap(mem); uerr != nil {
			log.Warningf("virtgpu: unmap misaligned blob: %v", uerr)
		}
		return blobView{}, 0, fmt.Errorf("%w: view base %#x is not 16 KiB aligned", errBlobSize, base)
	}
	return blobView{mem: mem}, uint64(size), nil
}

// mapped reports whether v is a mapping.
func (v blobView) mapped() bool {
	return v.mem != nil
}

// base returns the start of the view.
func (v blobView) base() unsafe.Pointer {
	return unsafe.Pointer(unsafe.SliceData(v.mem))
}

// unmap removes the view.
func (v blobView) unmap() error {
	if err := unix.Munmap(v.mem); err != nil {
		return fmt.Errorf("virtgpu: munmap blob: %w", err)
	}
	return nil
}
