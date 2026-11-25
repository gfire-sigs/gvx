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

package virtgpu

import (
	"fmt"

	"golang.org/x/sys/unix"
	"z.gfire.dev/gvx/pkg/fd"
	"z.gfire.dev/gvx/pkg/memutil"
)

func allocFakeShm(size int64) (*fd.HostHandle, []byte, error) {
	memfd, err := memutil.CreateMemFD("virtgpu-fake-blob", 0)
	if err != nil {
		return nil, nil, fmt.Errorf("CreateMemFD: %w", err)
	}
	if err := unix.Ftruncate(memfd, size); err != nil {
		_ = unix.Close(memfd)
		return nil, nil, fmt.Errorf("Ftruncate(%d): %w", size, err)
	}
	var view []byte
	if size > 0 {
		view, err = unix.Mmap(memfd, 0, int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if err != nil {
			_ = unix.Close(memfd)
			return nil, nil, fmt.Errorf("Mmap(%d): %w", size, err)
		}
	}
	h, err := fd.NewHostHandle(memfd)
	if err != nil {
		if view != nil {
			_ = unix.Munmap(view)
		}
		_ = unix.Close(memfd)
		return nil, nil, fmt.Errorf("NewHostHandle: %w", err)
	}
	return h, view, nil
}

func unmapFakeShm(view []byte) {
	if view != nil {
		_ = unix.Munmap(view)
	}
}
