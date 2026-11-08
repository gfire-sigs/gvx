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

package platform

import (
	"os"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// probeMMapMinAddrLimit bounds measureMMapMinAddr. Go links arm64 programs at
// this address, so a lower minimum changes no guest that the engine runs.
const probeMMapMinAddrLimit = 0x10000

// measureMMapMinAddr returns the lowest page address that this process can
// map, or probeMMapMinAddrLimit when no page below the limit maps. The kernel
// refuses a mapping below vm.mmap_min_addr with EPERM. An address that another
// mapping holds counts as mappable. The Android build uses it, because SELinux
// denies an app the read of vm.mmap_min_addr.
func measureMMapMinAddr() uint64 {
	page := uint64(os.Getpagesize())
	for addr := page; addr < probeMMapMinAddrLimit; addr += page {
		got, _, errno := unix.RawSyscall6(unix.SYS_MMAP, uintptr(addr), uintptr(page),
			unix.PROT_NONE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_FIXED_NOREPLACE, ^uintptr(0), 0)
		switch {
		case errno == unix.EEXIST:
			return addr
		case errno != 0:
			continue
		}
		unix.RawSyscall(unix.SYS_MUNMAP, got, uintptr(page), 0)
		// A kernel without MAP_FIXED_NOREPLACE takes the address as a hint.
		if uint64(got) == addr {
			return addr
		}
	}
	return probeMMapMinAddrLimit
}
