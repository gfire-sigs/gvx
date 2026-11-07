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

package mm

import (
	"slices"
	"testing"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// holePlatform is a platform whose guest range has gaps.
type holePlatform struct {
	platform.Platform
	holes []hostarch.AddrRange
}

func (p holePlatform) UserAddressHoles() []hostarch.AddrRange { return p.holes }

// plainPlatform is a platform that has no gap.
type plainPlatform struct{ platform.Platform }

const (
	holeMin    = 0x1_0000
	holeStart  = 0x8000_0000
	holeEnd    = 0x1_0000_0000
	holeMax    = 0x2_0000_0000
	holePage   = hostarch.Addr(hostarch.PageSize)
	holeGiB    = uint64(1) << 30
	holeSmall  = uint64(hostarch.PageSize)
	topDownLow = 0x1_4000_0000 // The part of the range above the hole is 1 GiB.
)

// findAvailable calls findAvailableLocked with mm.mappingMu held for reading.
func findAvailable(mm *MemoryManager, length uint64, opts findAvailableOpts) (hostarch.Addr, error) {
	mm.mappingMu.RLock()
	defer mm.mappingMu.RUnlock()
	return mm.findAvailableLocked(length, opts)
}

func newHoleMM(p platform.Platform, dir arch.MmapDirection, bottomUpBase, topDownBase hostarch.Addr) *MemoryManager {
	return &MemoryManager{
		p: p,
		layout: arch.MmapLayout{
			MinAddr:          holeMin,
			MaxAddr:          holeMax,
			BottomUpBase:     bottomUpBase,
			TopDownBase:      topDownBase,
			DefaultDirection: dir,
		},
	}
}

func holeBlocks(ar hostarch.AddrRange) bool {
	return ar.Overlaps(hostarch.AddrRange{Start: holeStart, End: holeEnd})
}

func TestFixedMappingsNeverOverlapTheAddressHole(t *testing.T) {
	hole := hostarch.AddrRange{Start: holeStart, End: holeEnd}
	mm := newHoleMM(holePlatform{holes: []hostarch.AddrRange{hole}}, arch.MmapTopDown, holeEnd, topDownLow)
	for _, tc := range []struct {
		name string
		addr hostarch.Addr
		size uint64
		ok   bool
	}{
		{"below the hole", holeStart - holePage*4, uint64(holePage) * 4, true},
		{"above the hole", holeEnd, uint64(holePage), true},
		{"the lowest guest address", holeMin, uint64(holePage), true},
		{"starts below and ends inside", holeStart - holePage, uint64(holePage) * 2, false},
		{"starts inside and ends above", holeEnd - holePage, uint64(holePage) * 2, false},
		{"covers the whole hole", holeStart - holePage, uint64(holeEnd-holeStart) + uint64(holePage)*2, false},
		{"inside the hole", holeStart + holePage*16, uint64(holePage), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := findAvailable(mm, tc.size, findAvailableOpts{Addr: tc.addr, Fixed: true})
			if tc.ok {
				if err != nil || got != tc.addr {
					t.Fatalf("fixed mapping at %#x+%#x = (%#x, %v), want the requested address", uint64(tc.addr), tc.size, uint64(got), err)
				}
				return
			}
			if !linuxerr.Equals(linuxerr.ENOMEM, err) {
				t.Fatalf("fixed mapping at %#x+%#x = (%#x, %v), want ENOMEM", uint64(tc.addr), tc.size, uint64(got), err)
			}
		})
	}
}

func TestAddressHintInsideTheHoleMovesOutside(t *testing.T) {
	hole := hostarch.AddrRange{Start: holeStart, End: holeEnd}
	mm := newHoleMM(holePlatform{holes: []hostarch.AddrRange{hole}}, arch.MmapTopDown, holeEnd, topDownLow)
	got, err := findAvailable(mm, holeSmall, findAvailableOpts{Addr: holeStart + holePage*16})
	if err != nil {
		t.Fatalf("hint inside the hole: %v", err)
	}
	if ar := (hostarch.AddrRange{Start: got, End: got + holePage}); holeBlocks(ar) {
		t.Fatalf("hint inside the hole returned %#x, which lies in the hole", uint64(got))
	}
}

func TestTopDownSearchFallsBelowTheHoleOnlyWhenTheHighPartIsTooSmall(t *testing.T) {
	hole := hostarch.AddrRange{Start: holeStart, End: holeEnd}
	mm := newHoleMM(holePlatform{holes: []hostarch.AddrRange{hole}}, arch.MmapTopDown, holeEnd, topDownLow)

	got, err := findAvailable(mm, holeSmall, findAvailableOpts{})
	if err != nil || got != topDownLow-holePage {
		t.Fatalf("small top-down search = (%#x, %v), want the highest page below the base %#x", uint64(got), err, uint64(topDownLow-holePage))
	}

	// 1.5 GiB does not fit in the 1 GiB above the hole, but it fits below it.
	size := holeGiB + holeGiB/2
	got, err = findAvailable(mm, size, findAvailableOpts{})
	if err != nil {
		t.Fatalf("1.5 GiB top-down search: %v", err)
	}
	if got != holeStart-hostarch.Addr(size) {
		t.Fatalf("1.5 GiB top-down search = %#x, want the highest range below the hole, %#x", uint64(got), uint64(holeStart-hostarch.Addr(size)))
	}

	// 3 GiB fits on neither side.
	if _, err := findAvailable(mm, 3*holeGiB, findAvailableOpts{}); !linuxerr.Equals(linuxerr.ENOMEM, err) {
		t.Fatalf("3 GiB top-down search = %v, want ENOMEM", err)
	}
}

func TestBottomUpSearchSkipsTheHole(t *testing.T) {
	hole := hostarch.AddrRange{Start: holeStart, End: holeEnd}
	mm := newHoleMM(holePlatform{holes: []hostarch.AddrRange{hole}}, arch.MmapBottomUp, holeStart-0x1000_0000, topDownLow)

	got, err := findAvailable(mm, holeSmall, findAvailableOpts{})
	if err != nil || got != holeStart-0x1000_0000 {
		t.Fatalf("small bottom-up search = (%#x, %v), want the base %#x", uint64(got), err, uint64(holeStart-0x1000_0000))
	}
	// 512 MiB does not fit in the 256 MiB between the base and the hole.
	got, err = findAvailable(mm, holeGiB/2, findAvailableOpts{})
	if err != nil || got != holeEnd {
		t.Fatalf("512 MiB bottom-up search = (%#x, %v), want the first address above the hole, %#x", uint64(got), err, uint64(holeEnd))
	}
}

func TestPlatformWithoutHoleKeepsEveryAddress(t *testing.T) {
	mm := newHoleMM(plainPlatform{}, arch.MmapTopDown, holeEnd, topDownLow)
	addr := hostarch.Addr(holeStart + holePage*16)
	got, err := findAvailable(mm, holeSmall, findAvailableOpts{Addr: addr, Fixed: true})
	if err != nil || got != addr {
		t.Fatalf("fixed mapping at %#x without a hole = (%#x, %v), want the requested address", uint64(addr), uint64(got), err)
	}
}

// A platform with a middle window has two holes. The windows of these tests
// are [holeMin, 3 GiB), [4 GiB, 6 GiB), and [7 GiB, 8 GiB). The sizes shrink
// toward the top, so each search order reaches a different window.
const (
	twoHolesFirstStart  = 3 << 30
	twoHolesFirstEnd    = 4 << 30
	twoHolesSecondStart = 6 << 30
	twoHolesSecondEnd   = 7 << 30
	twoHolesMax         = 8 << 30
)

func newTwoHolesMM(dir arch.MmapDirection, bottomUpBase hostarch.Addr) *MemoryManager {
	mm := newHoleMM(holePlatform{holes: []hostarch.AddrRange{
		{Start: twoHolesFirstStart, End: twoHolesFirstEnd},
		{Start: twoHolesSecondStart, End: twoHolesSecondEnd},
	}}, dir, bottomUpBase, twoHolesMax)
	mm.layout.MaxAddr = twoHolesMax
	return mm
}

func TestTwoHolesFixedMappingsNeverOverlap(t *testing.T) {
	mm := newTwoHolesMM(arch.MmapTopDown, twoHolesSecondEnd)
	for _, tc := range []struct {
		name string
		addr hostarch.Addr
		size uint64
		ok   bool
	}{
		{"the lowest window", holeMin, uint64(holePage), true},
		{"the middle window", twoHolesFirstEnd, uint64(holePage) * 4, true},
		{"the whole middle window", twoHolesFirstEnd, twoHolesSecondStart - twoHolesFirstEnd, true},
		{"the highest window", twoHolesSecondEnd, uint64(holePage), true},
		{"inside the first hole", twoHolesFirstStart + holePage, uint64(holePage), false},
		{"inside the second hole", twoHolesSecondStart + holePage, uint64(holePage), false},
		{"leaves the middle window upward", twoHolesSecondStart - holePage, uint64(holePage) * 2, false},
		{"enters the middle window from below", twoHolesFirstEnd - holePage, uint64(holePage) * 2, false},
		{"spans the middle window and both holes", twoHolesFirstStart - holePage, twoHolesSecondEnd - twoHolesFirstStart + uint64(holePage)*2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := findAvailable(mm, tc.size, findAvailableOpts{Addr: tc.addr, Fixed: true})
			if tc.ok {
				if err != nil || got != tc.addr {
					t.Fatalf("fixed mapping at %#x+%#x = (%#x, %v), want the requested address", uint64(tc.addr), tc.size, uint64(got), err)
				}
				return
			}
			if !linuxerr.Equals(linuxerr.ENOMEM, err) {
				t.Fatalf("fixed mapping at %#x+%#x = (%#x, %v), want ENOMEM", uint64(tc.addr), tc.size, uint64(got), err)
			}
		})
	}
}

func TestTwoHolesHintInTheMiddleWindowIsHonored(t *testing.T) {
	mm := newTwoHolesMM(arch.MmapTopDown, twoHolesSecondEnd)
	hint := hostarch.Addr(twoHolesFirstEnd + holeGiB/4)
	got, err := findAvailable(mm, holeSmall, findAvailableOpts{Addr: hint})
	if err != nil || got != hint {
		t.Fatalf("hint in the middle window = (%#x, %v), want %#x", uint64(got), err, uint64(hint))
	}
}

func TestTwoHolesTopDownSearchWalksDownThroughTheWindows(t *testing.T) {
	mm := newTwoHolesMM(arch.MmapTopDown, twoHolesSecondEnd)
	for _, tc := range []struct {
		name string
		size uint64
		want hostarch.Addr
	}{
		{"small", holeSmall, twoHolesMax - holePage},
		{"1 GiB and a page leave the top window", holeGiB + holeSmall, twoHolesSecondStart - hostarch.Addr(holeGiB+holeSmall)},
		{"2 GiB and a page leave the middle window", 2*holeGiB + holeSmall, twoHolesFirstStart - hostarch.Addr(2*holeGiB+holeSmall)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := findAvailable(mm, tc.size, findAvailableOpts{})
			if err != nil || got != tc.want {
				t.Fatalf("top-down search of %#x bytes = (%#x, %v), want %#x", tc.size, uint64(got), err, uint64(tc.want))
			}
		})
	}
	if _, err := findAvailable(mm, 3*holeGiB, findAvailableOpts{}); !linuxerr.Equals(linuxerr.ENOMEM, err) {
		t.Fatalf("search that fits no window = %v, want ENOMEM", err)
	}
}

func TestTwoHolesBottomUpSearchVisitsEachWindow(t *testing.T) {
	// The base lies 256 MiB below the first hole.
	mm := newTwoHolesMM(arch.MmapBottomUp, twoHolesFirstStart-hostarch.Addr(holeGiB/4))
	got, err := findAvailable(mm, holeSmall, findAvailableOpts{})
	if err != nil || got != twoHolesFirstStart-hostarch.Addr(holeGiB/4) {
		t.Fatalf("small bottom-up search = (%#x, %v), want the base", uint64(got), err)
	}
	got, err = findAvailable(mm, holeGiB/2, findAvailableOpts{})
	if err != nil || got != twoHolesFirstEnd {
		t.Fatalf("512 MiB bottom-up search = (%#x, %v), want the start of the middle window, %#x", uint64(got), err, uint64(twoHolesFirstEnd))
	}
	// 1.5 GiB fits in the middle window and in no earlier part.
	got, err = findAvailable(mm, holeGiB+holeGiB/2, findAvailableOpts{})
	if err != nil || got != twoHolesFirstEnd {
		t.Fatalf("1.5 GiB bottom-up search = (%#x, %v), want the start of the middle window", uint64(got), err)
	}
	// A base 256 MiB below the second hole leaves the top window for 512 MiB.
	mm = newTwoHolesMM(arch.MmapBottomUp, twoHolesSecondStart-hostarch.Addr(holeGiB/4))
	got, err = findAvailable(mm, holeGiB/2, findAvailableOpts{})
	if err != nil || got != twoHolesSecondEnd {
		t.Fatalf("512 MiB bottom-up search below the second hole = (%#x, %v), want the start of the top window, %#x", uint64(got), err, uint64(twoHolesSecondEnd))
	}
}

func TestAppendRangesAvoidingHoles(t *testing.T) {
	r := func(a, b hostarch.Addr) hostarch.AddrRange { return hostarch.AddrRange{Start: a, End: b} }
	holes := []hostarch.AddrRange{r(10, 20), r(30, 40)}
	for _, tc := range []struct {
		name   string
		bounds hostarch.AddrRange
		want   []hostarch.AddrRange
	}{
		{"no overlap", r(0, 5), []hostarch.AddrRange{r(0, 5)}},
		{"both holes", r(0, 50), []hostarch.AddrRange{r(0, 10), r(20, 30), r(40, 50)}},
		{"starts inside a hole", r(15, 50), []hostarch.AddrRange{r(20, 30), r(40, 50)}},
		{"ends inside a hole", r(0, 35), []hostarch.AddrRange{r(0, 10), r(20, 30)}},
		{"inside one hole", r(12, 18), nil},
		{"between the holes", r(22, 28), []hostarch.AddrRange{r(22, 28)}},
		{"touches a hole", r(20, 30), []hostarch.AddrRange{r(20, 30)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := appendRangesAvoiding(nil, tc.bounds, holes)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("appendRangesAvoiding(%v) = %v, want %v", tc.bounds, got, tc.want)
			}
		})
	}
}

// A search runs for every mmap of a guest, so it must not allocate.
func TestTwoHolesSearchesDoNotAllocate(t *testing.T) {
	hint := hostarch.Addr(twoHolesFirstEnd + holeGiB/4)
	for _, tc := range []struct {
		name string
		dir  arch.MmapDirection
		opts findAvailableOpts
	}{
		{"top-down search", arch.MmapTopDown, findAvailableOpts{}},
		{"bottom-up search", arch.MmapBottomUp, findAvailableOpts{}},
		{"hint in a window", arch.MmapTopDown, findAvailableOpts{Addr: hint}},
		{"fixed mapping", arch.MmapTopDown, findAvailableOpts{Addr: hint, Fixed: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mm := newTwoHolesMM(tc.dir, twoHolesFirstStart-hostarch.Addr(holeGiB/4))
			if _, err := findAvailable(mm, holeSmall, tc.opts); err != nil {
				t.Fatalf("search: %v", err)
			}
			allocs := testing.AllocsPerRun(100, func() {
				if _, err := findAvailable(mm, holeSmall, tc.opts); err != nil {
					t.Fatalf("search: %v", err)
				}
			})
			if allocs != 0 {
				t.Errorf("allocations per search = %v, want 0", allocs)
			}
		})
	}
}

// The Windows systrap layout has 31 holes. A search across that many holes
// still avoids each hole and needs no allocation.
func TestManyHolesSearchesDoNotAllocate(t *testing.T) {
	var holes []hostarch.AddrRange
	for k := range uint64(31) {
		start := hostarch.Addr((2 + 2*k) * holeGiB)
		holes = append(holes, hostarch.AddrRange{Start: start, End: start + hostarch.Addr(holeGiB)})
	}
	top := hostarch.Addr(64 * holeGiB)
	for _, tc := range []struct {
		name         string
		dir          arch.MmapDirection
		bottomUpBase hostarch.Addr
		want         hostarch.Addr
	}{
		{"top-down search", arch.MmapTopDown, holeMin, top - holePage},
		{"bottom-up search from inside a hole", arch.MmapBottomUp, holes[15].Start + holePage, holes[15].End},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mm := newHoleMM(holePlatform{holes: holes}, tc.dir, tc.bottomUpBase, top)
			mm.layout.MaxAddr = top
			got, err := findAvailable(mm, holeSmall, findAvailableOpts{})
			if err != nil || got != tc.want {
				t.Fatalf("search = (%#x, %v), want (%#x, nil)", got, err, tc.want)
			}
			allocs := testing.AllocsPerRun(100, func() {
				if _, err := findAvailable(mm, holeSmall, findAvailableOpts{}); err != nil {
					t.Fatalf("search: %v", err)
				}
			})
			if allocs != 0 {
				t.Errorf("allocations per search = %v, want 0", allocs)
			}
		})
	}
}
