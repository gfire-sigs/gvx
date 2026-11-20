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

//go:build arm64

package hostarch

import (
	"math/bits"
	"os"
	"runtime"
)

// hostPageShiftXplat selects PageShift on arm64 hosts. On darwin, Hypervisor.framework
// exposes 4 KB guest pages over 16 KB host pages. On Linux kernels with 16 KB pages,
// systrap emulates 4 KB guest pages via its sub-block layer. In both cases, guest
// page tables stay at MinPageShift (4 KB).
func hostPageShiftXplat() uint {
	size := os.Getpagesize()
	shift, warn := hostPageShiftFor(runtime.GOOS, size)
	if warn {
		println("WARNING: unexpected host page size", size, "- assuming", MinPageSize)
	}
	return shift
}

func hostPageShiftFor(goos string, size int) (shift uint, warn bool) {
	if goos == "darwin" {
		return MinPageShift, false
	}
	// Linux and Android hosts with 16 KB pages keep 4 KB guest pages via systrap's
	// sub-block layer without warning on process startup.
	if (goos == "linux" || goos == "android") && size == 1<<14 {
		return MinPageShift, false
	}
	if IsSupportedPageSize(size) {
		return uint(bits.TrailingZeros(uint(size))), false
	}
	return MinPageShift, true
}
