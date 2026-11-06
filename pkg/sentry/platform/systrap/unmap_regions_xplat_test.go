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

package systrap

import (
	"slices"
	"testing"
)

func TestSubtractRanges(t *testing.T) {
	holes := []mapsRegion{{0x60000, 0x65000}, {0x90000, 0x91000}}
	for _, tc := range []struct {
		name string
		r    mapsRegion
		want []mapsRegion
	}{
		{"no hole in the range", mapsRegion{0x100000, 0x200000}, []mapsRegion{{0x100000, 0x200000}}},
		{"range below the holes", mapsRegion{0, 0x60000}, []mapsRegion{{0, 0x60000}}},
		{"range around both holes", mapsRegion{0, 0x100000}, []mapsRegion{{0, 0x60000}, {0x65000, 0x90000}, {0x91000, 0x100000}}},
		{"range starts inside a hole", mapsRegion{0x62000, 0x70000}, []mapsRegion{{0x65000, 0x70000}}},
		{"range ends inside a hole", mapsRegion{0x50000, 0x62000}, []mapsRegion{{0x50000, 0x60000}}},
		{"range inside a hole", mapsRegion{0x61000, 0x64000}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := subtractRanges(tc.r, holes); !slices.Equal(got, tc.want) {
				t.Errorf("subtractRanges(%#x) = %#x, want %#x", tc.r, got, tc.want)
			}
		})
	}
}

func TestAddRangeJoinsTouchingPages(t *testing.T) {
	var ranges []mapsRegion
	for _, page := range []uintptr{0x62000, 0x60000, 0x61000, 0x90000, 0x63000, 0x61000} {
		ranges = addRange(ranges, mapsRegion{page, page + 0x1000})
	}
	want := []mapsRegion{{0x60000, 0x64000}, {0x90000, 0x91000}}
	if !slices.Equal(ranges, want) {
		t.Errorf("addRange result = %#x, want %#x", ranges, want)
	}
}
