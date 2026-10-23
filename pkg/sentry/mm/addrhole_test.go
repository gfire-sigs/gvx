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
	"testing"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// holePlatform is a platform whose guest range has a gap.
type holePlatform struct {
	platform.Platform
	hole hostarch.AddrRange
}

func (p holePlatform) UserAddressHole() hostarch.AddrRange { return p.hole }

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
	mm := newHoleMM(holePlatform{hole: hole}, arch.MmapTopDown, holeEnd, topDownLow)
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
			got, err := mm.findAvailableLocked(tc.size, findAvailableOpts{Addr: tc.addr, Fixed: true})
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
	mm := newHoleMM(holePlatform{hole: hole}, arch.MmapTopDown, holeEnd, topDownLow)
	got, err := mm.findAvailableLocked(holeSmall, findAvailableOpts{Addr: holeStart + holePage*16})
	if err != nil {
		t.Fatalf("hint inside the hole: %v", err)
	}
	if ar := (hostarch.AddrRange{Start: got, End: got + holePage}); holeBlocks(ar) {
		t.Fatalf("hint inside the hole returned %#x, which lies in the hole", uint64(got))
	}
}

func TestTopDownSearchFallsBelowTheHoleOnlyWhenTheHighPartIsTooSmall(t *testing.T) {
	hole := hostarch.AddrRange{Start: holeStart, End: holeEnd}
	mm := newHoleMM(holePlatform{hole: hole}, arch.MmapTopDown, holeEnd, topDownLow)

	got, err := mm.findAvailableLocked(holeSmall, findAvailableOpts{})
	if err != nil || got != topDownLow-holePage {
		t.Fatalf("small top-down search = (%#x, %v), want the highest page below the base %#x", uint64(got), err, uint64(topDownLow-holePage))
	}

	// 1.5 GiB does not fit in the 1 GiB above the hole, but it fits below it.
	size := holeGiB + holeGiB/2
	got, err = mm.findAvailableLocked(size, findAvailableOpts{})
	if err != nil {
		t.Fatalf("1.5 GiB top-down search: %v", err)
	}
	if got != holeStart-hostarch.Addr(size) {
		t.Fatalf("1.5 GiB top-down search = %#x, want the highest range below the hole, %#x", uint64(got), uint64(holeStart-hostarch.Addr(size)))
	}

	// 3 GiB fits on neither side.
	if _, err := mm.findAvailableLocked(3*holeGiB, findAvailableOpts{}); !linuxerr.Equals(linuxerr.ENOMEM, err) {
		t.Fatalf("3 GiB top-down search = %v, want ENOMEM", err)
	}
}

func TestBottomUpSearchSkipsTheHole(t *testing.T) {
	hole := hostarch.AddrRange{Start: holeStart, End: holeEnd}
	mm := newHoleMM(holePlatform{hole: hole}, arch.MmapBottomUp, holeStart-0x1000_0000, topDownLow)

	got, err := mm.findAvailableLocked(holeSmall, findAvailableOpts{})
	if err != nil || got != holeStart-0x1000_0000 {
		t.Fatalf("small bottom-up search = (%#x, %v), want the base %#x", uint64(got), err, uint64(holeStart-0x1000_0000))
	}
	// 512 MiB does not fit in the 256 MiB between the base and the hole.
	got, err = mm.findAvailableLocked(holeGiB/2, findAvailableOpts{})
	if err != nil || got != holeEnd {
		t.Fatalf("512 MiB bottom-up search = (%#x, %v), want the first address above the hole, %#x", uint64(got), err, uint64(holeEnd))
	}
}

func TestPlatformWithoutHoleKeepsEveryAddress(t *testing.T) {
	mm := newHoleMM(plainPlatform{}, arch.MmapTopDown, holeEnd, topDownLow)
	addr := hostarch.Addr(holeStart + holePage*16)
	got, err := mm.findAvailableLocked(holeSmall, findAvailableOpts{Addr: addr, Fixed: true})
	if err != nil || got != addr {
		t.Fatalf("fixed mapping at %#x without a hole = (%#x, %v), want the requested address", uint64(addr), uint64(got), err)
	}
}
