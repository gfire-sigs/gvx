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

import (
	"slices"
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
)

func TestWindowLayoutHoles(t *testing.T) {
	low := guestRange{"low", 0x10000, 0x7ffe0000}
	mid := guestRange{"mid", 4 << 30, 64 << 30}
	high := guestRange{"high", 1 << 44, 0x7ee000000000}
	hole := func(a, b uint64) hostarch.AddrRange {
		return hostarch.AddrRange{Start: hostarch.Addr(a), End: hostarch.Addr(b)}
	}
	for _, tc := range []struct {
		name   string
		layout windowLayout
		min    uint64
		want   []hostarch.AddrRange
	}{
		{"one window", windowLayout{high}, high.base, nil},
		{"low and high", windowLayout{low, high}, low.base, []hostarch.AddrRange{hole(low.limit, high.base)}},
		{"middle and high", windowLayout{mid, high}, mid.base, []hostarch.AddrRange{hole(mid.limit, high.base)}},
		{"all three", windowLayout{low, mid, high}, low.base, []hostarch.AddrRange{hole(low.limit, mid.base), hole(mid.limit, high.base)}},
		{"adjacent windows", windowLayout{{"a", 0x10000, 0x20000}, {"b", 0x20000, 0x30000}}, 0x10000, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.layout.holes(); !slices.Equal(got, tc.want) {
				t.Errorf("holes() = %v, want %v", got, tc.want)
			}
			if got := tc.layout.min(); got != tc.min {
				t.Errorf("min() = %#x, want %#x", got, tc.min)
			}
		})
	}
}

func TestWindowLayoutContains(t *testing.T) {
	l := windowLayout{{"low", 0x10000, 0x7ffe0000}, {"mid", 4 << 30, 64 << 30}}
	for _, tc := range []struct {
		name     string
		va, size uint64
		want     bool
	}{
		{"first page of the low window", 0x10000, 0x1000, true},
		{"last page of the low window", 0x7ffdf000, 0x1000, true},
		{"crosses the end of the low window", 0x7ffdf000, 0x2000, false},
		{"starts below the low window", 0xf000, 0x2000, false},
		{"inside the first hole", 0x8000_0000, 0x1000, false},
		{"first page of the middle window", 4 << 30, 0x1000, true},
		{"last page of the middle window", 64<<30 - 0x1000, 0x1000, true},
		{"first page above the middle window", 64 << 30, 0x1000, false},
		{"spans the first hole", 0x7ffdf000, 4<<30 - 0x7ffdf000 + 0x1000, false},
		{"a size larger than every window", 4 << 30, 1 << 40, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := l.contains(tc.va, tc.size); got != tc.want {
				t.Errorf("contains(%#x, %#x) = %v, want %v", tc.va, tc.size, got, tc.want)
			}
		})
	}
}
