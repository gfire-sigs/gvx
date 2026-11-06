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
	// The host has less space than the smallest listed size.
	lo := 2 * pageSize
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
