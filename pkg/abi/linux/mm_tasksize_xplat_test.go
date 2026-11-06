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

import "testing"

func TestSearchTaskSize(t *testing.T) {
	const page = 4096
	amd64 := []uintptr{0xfffffffffff000, 0x7ffffffff000}
	arm64 := []uintptr{1 << 52, 1 << 48, 1 << 39}
	// A hardware size needs at most 4 probes, because the probe of the page
	// above it ends the search. A nested size needs a binary search.
	for _, tc := range []struct {
		name     string
		sizes    []uintptr
		limit    uintptr
		maxCalls int
	}{
		{"amd64 with five-level paging", amd64, 0xfffffffffff000, 4},
		{"amd64 with four-level paging", amd64, 0x7ffffffff000, 4},
		{"amd64 nested below the hardware size", amd64, 0x7f0000000000, 64},
		{"amd64 nested with an odd page count", amd64, 0x7efe34567000, 64},
		{"arm64 with 52 bits", arm64, 1 << 52, 4},
		{"arm64 with 48 bits", arm64, 1 << 48, 4},
		{"arm64 with 39 bits", arm64, 1 << 39, 4},
		{"arm64 nested between 39 and 48 bits", arm64, 0xfe0000000000, 64},
		{"arm64 nested below 39 bits", arm64, 0x3f00000000, 64},
		{"smallest supported space", amd64, 1 << 32, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			got := searchTaskSize(page, tc.sizes, func(size uintptr) bool {
				calls++
				return size <= tc.limit
			})
			if got != tc.limit {
				t.Errorf("searchTaskSize() = %#x, want %#x", got, tc.limit)
			}
			if calls > tc.maxCalls {
				t.Errorf("searchTaskSize() called fits %d times, want at most %d", calls, tc.maxCalls)
			}
		})
	}
}

func TestSearchTaskSizeWithoutAnyMapping(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("searchTaskSize() returned for a host without address space")
		}
	}()
	searchTaskSize(4096, []uintptr{1 << 48}, func(uintptr) bool { return false })
}
