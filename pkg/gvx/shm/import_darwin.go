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

package shm

import (
	"fmt"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

type darwinBacking struct {
	data []byte
}

func (b *darwinBacking) bytes() []byte { return b.data }
func (b *darwinBacking) fd() int       { return -1 }

func (b *darwinBacking) unmap() error {
	if len(b.data) == 0 {
		return nil
	}
	err := unix.Munmap(b.data)
	b.data = nil
	return err
}

func statBackingFD(fd int) (uint64, error) {
	if fd < 0 {
		return 0, fmt.Errorf("%w: negative fd %d", ErrInvalidRange, fd)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return 0, fmt.Errorf("shm: fstat fd %d: %w", fd, err)
	}
	if st.Size <= 0 {
		return 0, fmt.Errorf("%w: backing size %d", ErrInvalidRange, st.Size)
	}
	return uint64(st.Size), nil
}

func mapBackingFD(platformName string, fd int, offset, size uint64, writable bool) (backingView, error) {
	if platformName != "" && platformName != "hvf" {
		return nil, fmt.Errorf("%w: darwin only supports hvf, got %q", ErrUnsupportedBackend, platformName)
	}
	if fd < 0 {
		return nil, fmt.Errorf("%w: negative fd %d", ErrInvalidRange, fd)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("shm: fstat fd %d: %w", fd, err)
	}
	if st.Size < 0 || uint64(st.Size) < offset+size {
		return nil, fmt.Errorf("%w: backing size %d smaller than requested end %d", ErrInvalidRange, st.Size, offset+size)
	}
	prot := unix.PROT_READ
	if writable {
		prot |= unix.PROT_WRITE
	}
	data, err := unix.Mmap(fd, int64(offset), int(size), prot, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("shm: mmap fd %d: %w", fd, err)
	}
	return &darwinBacking{data: data}, nil
}
