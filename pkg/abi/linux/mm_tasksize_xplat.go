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

package linux

import (
	"fmt"
	"runtime"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// The upstream initializer of TaskSize takes the first size that makes mmap
// return EINVAL. A Sentry as host kernel returns EINVAL for an unaligned
// address before it compares the address with the task size in some versions,
// so that probe picks a size that is too large. A Sentry that obeys the Linux
// order and limits the user space below every listed size makes the probe find
// no size. The initializer then returns 0. This init function replaces the
// value. It runs after the variable initialization of the package and before
// any importing package reads TaskSize. No variable of this package reads
// TaskSize.
func init() {
	TaskSize = probeTaskSize()
}

// probeTaskSize searches the address space size of the host with mmap.
func probeTaskSize() uintptr {
	pageSize := uintptr(unix.Getpagesize())
	return searchTaskSize(pageSize, feasibleTaskSizes, func(size uintptr) bool {
		// mmap returns ENOMEM if addr is greater than TASK_SIZE,
		// otherwise it returns EINVAL, because addr isn't aligned to
		// the page size.
		_, _, errno := unix.RawSyscall6(
			unix.SYS_MMAP,
			size-pageSize-1,
			512,
			uintptr(unix.PROT_NONE),
			uintptr(unix.MAP_ANONYMOUS|unix.MAP_PRIVATE|unix.MAP_FIXED), 0, 0)
		if errno == unix.EINVAL {
			// A Sentry as host kernel reports EINVAL for the unaligned address
			// before it checks the range. Map the last page to find out.
			return pageFits(size - pageSize)
		}
		if errno != unix.ENOMEM {
			panic(fmt.Sprintf("mmap returned unexpected error: %d", errno))
		}
		return false
	})
}

// pageFits reports whether the host maps the page at addr. It removes the page
// again.
func pageFits(addr uintptr) bool {
	if runtime.GOOS != "linux" {
		// Only a Linux host has a size that a Sentry uses. The probe of the
		// unaligned address is the whole answer elsewhere.
		return true
	}
	r, _, errno := unix.RawSyscall6(
		unix.SYS_MMAP,
		addr,
		uintptr(unix.Getpagesize()),
		uintptr(unix.PROT_NONE),
		uintptr(unix.MAP_ANONYMOUS|unix.MAP_PRIVATE|unix.MAP_FIXED_NOREPLACE), 0, 0)
	switch errno {
	case 0:
		unix.RawSyscall(unix.SYS_MUNMAP, r, uintptr(unix.Getpagesize()), 0)
		return true
	case unix.EEXIST:
		return true
	case unix.ENOMEM:
		return false
	}
	panic(fmt.Sprintf("mmap of the last page returned unexpected error: %d", errno))
}

// searchTaskSize returns the address space size of the host.
//
// fits reports whether the host maps an address range that ends at size. The
// answer is true for every size up to the real task size and false above it.
// sizes lists the sizes that real hosts have, from the largest to the
// smallest. A host kernel that limits the user space below the hardware size,
// as a nested Sentry does, has a size outside the list. The search then
// narrows the size, page by page, between the nearest listed size that fits
// and the nearest listed size that does not.
func searchTaskSize(pageSize uintptr, sizes []uintptr, fits func(size uintptr) bool) uintptr {
	var notFit uintptr // The smallest size that does not fit, or 0 if none.
	for _, s := range sizes {
		if fits(s) {
			return narrowTaskSize(pageSize, s, notFit, fits)
		}
		notFit = s
	}
	// The host has less space than the smallest listed size. A host kernel
	// keeps the lowest pages for itself, so start above 4 GiB.
	lo := uintptr(1) << 32
	if !fits(lo) {
		panic("None of the address space sizes could be successfully mmaped")
	}
	return narrowTaskSize(pageSize, lo, notFit, fits)
}

// narrowTaskSize returns the largest page multiple in [fit, notFit) that fits.
// A notFit of 0 means that no larger size exists, so fit is the answer.
func narrowTaskSize(pageSize, fit, notFit uintptr, fits func(size uintptr) bool) uintptr {
	if notFit == 0 {
		return fit
	}
	for notFit-fit > pageSize {
		mid := fit + (notFit-fit)/2
		mid -= mid % pageSize
		if fits(mid) {
			fit = mid
		} else {
			notFit = mid
		}
	}
	return fit
}
