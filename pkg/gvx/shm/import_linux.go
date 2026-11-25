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

//go:build linux

package shm

import (
	"errors"
	"fmt"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

type linuxBacking struct {
	data  []byte
	dupFD int
}

func (b *linuxBacking) bytes() []byte { return b.data }
func (b *linuxBacking) fd() int       { return b.dupFD }

func (b *linuxBacking) unmap() error {
	var errs []error
	if len(b.data) > 0 {
		if err := unix.Munmap(b.data); err != nil {
			errs = append(errs, err)
		}
		b.data = nil
	}
	if b.dupFD >= 0 {
		if err := unix.Close(b.dupFD); err != nil {
			errs = append(errs, err)
		}
		b.dupFD = -1
	}
	return errors.Join(errs...)
}

func mapBackingFD(platformName string, fd int, offset, size uint64, writable bool) (backingView, error) {
	if platformName != "" && platformName != "systrap" {
		return nil, fmt.Errorf("%w: linux only supports systrap, got %q", ErrUnsupportedBackend, platformName)
	}
	if fd < 0 {
		return nil, fmt.Errorf("%w: negative fd %d", ErrInvalidRange, fd)
	}
	seals, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	if err != nil || seals&unix.F_SEAL_SHRINK == 0 {
		return nil, fmt.Errorf("%w: seals=%#x err=%v", ErrUnsealedMemory, seals, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("shm: fstat fd %d: %w", fd, err)
	}
	if st.Size < 0 || uint64(st.Size) < offset+size {
		return nil, fmt.Errorf("%w: backing size %d smaller than requested end %d", ErrInvalidRange, st.Size, offset+size)
	}
	dupFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("shm: dup fd %d: %w", fd, err)
	}
	prot := unix.PROT_READ
	if writable {
		prot |= unix.PROT_WRITE
	}
	data, err := unix.Mmap(dupFD, int64(offset), int(size), prot, unix.MAP_SHARED)
	if err != nil {
		_ = unix.Close(dupFD)
		return nil, fmt.Errorf("shm: mmap fd %d: %w", fd, err)
	}
	return &linuxBacking{data: data, dupFD: dupFD}, nil
}
