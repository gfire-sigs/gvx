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

//go:build darwin || windows

package systrap

import "z.gfire.dev/gvx/pkg/hostarch"

// guestRange is one window of the guest address space. A stub reserves the
// whole window before its loader runs.
type guestRange struct {
	// name tells the window apart in error messages.
	name string
	// base and limit bound the window: [base, limit).
	base, limit uint64
}

// windowLayout lists the windows that every stub of a platform reserves, in
// ascending order and without overlap. The layout is fixed while the platform
// runs, because the memory manager reads the guest range when a process starts
// and a fork gives the child the same layout.
type windowLayout []guestRange

// min returns the lowest guest address.
func (l windowLayout) min() uint64 { return l[0].base }

// contains reports whether [va, va+size) lies in one window.
func (l windowLayout) contains(va, size uint64) bool {
	for _, w := range l {
		if va >= w.base && size <= w.limit-w.base && va <= w.limit-size {
			return true
		}
	}
	return false
}

// holes returns the gaps between the windows. The host owns them, and the
// memory manager never maps there.
func (l windowLayout) holes() []hostarch.AddrRange {
	var out []hostarch.AddrRange
	for i := 1; i < len(l); i++ {
		if l[i-1].limit < l[i].base {
			out = append(out, hostarch.AddrRange{Start: hostarch.Addr(l[i-1].limit), End: hostarch.Addr(l[i].base)})
		}
	}
	return out
}
