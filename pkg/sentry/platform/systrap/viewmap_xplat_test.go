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
	"fmt"
	"math/rand/v2"
	"sort"
	"testing"
)

// fakeRegion is one region of the fake host. A nil view marks a placeholder.
type fakeRegion struct {
	size uint64
	view *viewInfo
}

// fakeHost enforces the Windows placeholder rules that the viewHost comment
// states. It fails every call that Windows would reject.
type fakeHost struct {
	regions map[uint64]fakeRegion
	calls   int
}

func newFakeHost(base, limit uint64) *fakeHost {
	return &fakeHost{regions: map[uint64]fakeRegion{base: {size: limit - base}}}
}

func (h *fakeHost) containing(addr uint64) (uint64, fakeRegion, bool) {
	for a, r := range h.regions {
		if addr >= a && addr < a+r.size {
			return a, r, true
		}
	}
	return 0, fakeRegion{}, false
}

func (h *fakeHost) SplitPlaceholder(addr, size uint64) error {
	h.calls++
	a, r, ok := h.containing(addr)
	if !ok || r.view != nil || addr+size > a+r.size {
		return fmt.Errorf("split %#x+%#x: not inside one placeholder", addr, size)
	}
	if a == addr && r.size == size {
		return fmt.Errorf("split %#x+%#x: the range is the whole placeholder", addr, size)
	}
	delete(h.regions, a)
	if a < addr {
		h.regions[a] = fakeRegion{size: addr - a}
	}
	h.regions[addr] = fakeRegion{size: size}
	if a+r.size > addr+size {
		h.regions[addr+size] = fakeRegion{size: a + r.size - addr - size}
	}
	return nil
}

func (h *fakeHost) CoalescePlaceholders(addr, size uint64) error {
	h.calls++
	var parts []uint64
	for a, r := range h.regions {
		if a >= addr && a < addr+size {
			if r.view != nil {
				return fmt.Errorf("coalesce %#x+%#x: includes a view", addr, size)
			}
			parts = append(parts, a)
		}
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i] < parts[j] })
	next := addr
	for _, a := range parts {
		if a != next {
			return fmt.Errorf("coalesce %#x+%#x: gap at %#x", addr, size, next)
		}
		next = a + h.regions[a].size
	}
	if next != addr+size || len(parts) < 2 {
		return fmt.Errorf("coalesce %#x+%#x: parts do not tile the range", addr, size)
	}
	for _, a := range parts {
		delete(h.regions, a)
	}
	h.regions[addr] = fakeRegion{size: size}
	return nil
}

func (h *fakeHost) MapView(addr, size uint64, backing viewBacking, off uint64, prot viewProt) error {
	h.calls++
	r, ok := h.regions[addr]
	if !ok || r.view != nil || r.size != size {
		return fmt.Errorf("map %#x+%#x: no placeholder of exactly this range", addr, size)
	}
	h.regions[addr] = fakeRegion{size: size, view: &viewInfo{backing, off, prot}}
	return nil
}

func (h *fakeHost) UnmapView(addr uint64) error {
	h.calls++
	r, ok := h.regions[addr]
	if !ok || r.view == nil {
		return fmt.Errorf("unmap %#x: no view starts here", addr)
	}
	h.regions[addr] = fakeRegion{size: r.size}
	return nil
}

func (h *fakeHost) ProtectView(addr, size uint64, prot viewProt) error {
	h.calls++
	r, ok := h.regions[addr]
	if !ok || r.view == nil || r.size != size {
		return fmt.Errorf("protect %#x+%#x: not exactly one view", addr, size)
	}
	v := *r.view
	v.prot = prot
	h.regions[addr] = fakeRegion{size: size, view: &v}
	return nil
}

// pageState returns what the fake host maps at addr.
func (h *fakeHost) pageState(addr uint64) (viewInfo, bool) {
	a, r, ok := h.containing(addr)
	if !ok || r.view == nil {
		return viewInfo{}, false
	}
	return viewInfo{r.view.backing, r.view.off + (addr - a), r.view.prot}, true
}

const (
	testBase  = uint64(0x100000000000)
	testPages = 64
	testLimit = testBase + testPages*0x1000
)

func TestWindowMapMatchesReferenceModel(t *testing.T) {
	for seed := range uint64(200) {
		rng := rand.New(rand.NewPCG(seed, 1))
		host := newFakeHost(testBase, testLimit)
		w := newWindowMap(host, testBase, testLimit)
		ref := make(map[uint64]viewInfo)
		for step := range 60 {
			first := rng.IntN(testPages)
			n := 1 + rng.IntN(min(12, testPages-first))
			addr, size := testBase+uint64(first)*0x1000, uint64(n)*0x1000
			var op string
			switch rng.IntN(5) {
			case 0, 1, 2:
				back := fmt.Sprintf("sec%d", rng.IntN(3))
				off := uint64(rng.IntN(100)) * 0x1000
				prot := viewProt(1 + rng.IntN(4))
				op = fmt.Sprintf("Map(%#x,%#x,%s,%#x,%d)", addr, size, back, off, prot)
				if err := w.Map(addr, size, back, off, prot); err != nil {
					t.Fatalf("seed %d step %d %s: %v", seed, step, op, err)
				}
				for p := uint64(0); p < size; p += 0x1000 {
					ref[addr+p] = viewInfo{back, off + p, prot}
				}
			case 3:
				op = fmt.Sprintf("Unmap(%#x,%#x)", addr, size)
				if err := w.Unmap(addr, size); err != nil {
					t.Fatalf("seed %d step %d %s: %v", seed, step, op, err)
				}
				for p := uint64(0); p < size; p += 0x1000 {
					delete(ref, addr+p)
				}
			case 4:
				prot := viewProt(1 + rng.IntN(4))
				op = fmt.Sprintf("Protect(%#x,%#x,%d)", addr, size, prot)
				mapped := true
				for p := uint64(0); p < size; p += 0x1000 {
					if _, ok := ref[addr+p]; !ok {
						mapped = false
					}
				}
				err := w.Protect(addr, size, prot)
				if mapped != (err == nil) {
					t.Fatalf("seed %d step %d %s: mapped=%v err=%v", seed, step, op, mapped, err)
				}
				if mapped {
					for p := uint64(0); p < size; p += 0x1000 {
						v := ref[addr+p]
						v.prot = prot
						ref[addr+p] = v
					}
				}
			}
			for p := uint64(0); p < testPages; p++ {
				a := testBase + p*0x1000
				want, wok := ref[a]
				got, gok := host.pageState(a)
				if wok != gok || want != got {
					t.Fatalf("seed %d step %d after %s: page %#x host=%+v,%v want=%+v,%v", seed, step, op, a, got, gok, want, wok)
				}
				lv, _, lok := w.Lookup(a)
				if lok != wok || (wok && lv != want) {
					t.Fatalf("seed %d step %d after %s: Lookup(%#x)=%+v,%v want=%+v,%v", seed, step, op, a, lv, lok, want, wok)
				}
			}
			// The extents tile the window and match the host regions.
			next := testBase
			for _, e := range w.ext {
				if e.addr != next {
					t.Fatalf("seed %d step %d after %s: extent gap at %#x", seed, step, op, next)
				}
				r, ok := host.regions[e.addr]
				if !ok || r.size != e.size || (r.view == nil) != (e.view == nil) {
					t.Fatalf("seed %d step %d after %s: extent %+v differs from host region %+v", seed, step, op, e, r)
				}
				next = e.end()
			}
			if next != testLimit || len(w.ext) != len(host.regions) {
				t.Fatalf("seed %d step %d after %s: extents end at %#x with %d extents, host has %d regions", seed, step, op, next, len(w.ext), len(host.regions))
			}
		}
	}
}

func TestWindowMapRejectsBadRanges(t *testing.T) {
	host := newFakeHost(testBase, testLimit)
	w := newWindowMap(host, testBase, testLimit)
	for _, c := range []struct{ addr, size uint64 }{
		{testBase + 1, 0x1000},
		{testBase, 0x800},
		{testBase, 0},
		{testBase - 0x1000, 0x1000},
		{testLimit - 0x1000, 0x2000},
	} {
		if err := w.Map(c.addr, c.size, "s", 0, viewRead); err == nil {
			t.Errorf("Map(%#x,%#x) succeeded", c.addr, c.size)
		}
	}
	if host.calls != 0 {
		t.Errorf("rejected ranges made %d host calls", host.calls)
	}
}

type failingHost struct {
	*fakeHost
	failAfter int
}

func (h *failingHost) MapView(addr, size uint64, backing viewBacking, off uint64, prot viewProt) error {
	if h.failAfter--; h.failAfter < 0 {
		return fmt.Errorf("injected failure")
	}
	return h.fakeHost.MapView(addr, size, backing, off, prot)
}

func TestWindowMapBreaksAfterHostFailure(t *testing.T) {
	h := &failingHost{fakeHost: newFakeHost(testBase, testLimit), failAfter: 1}
	w := newWindowMap(h, testBase, testLimit)
	if err := w.Map(testBase, 0x4000, "s", 0, viewReadWrite); err != nil {
		t.Fatal(err)
	}
	if err := w.Map(testBase+0x1000, 0x1000, "s", 0, viewRead); err == nil {
		t.Fatal("Map succeeded after an injected host failure")
	}
	if err := w.Unmap(testBase, 0x1000); err == nil {
		t.Fatal("a broken window accepted another call")
	}
}

const (
	lowTestBase  = uint64(0x400000)
	lowTestLimit = lowTestBase + 16*0x1000
)

// TestGuestWindowsServeTwoWindows checks a stub with a low window and a high
// window. Each mapping goes to the window that owns its address. The memory
// manager unmaps ranges that cross the gap, and the router clears both windows.
func TestGuestWindowsServeTwoWindows(t *testing.T) {
	lowHost := newFakeHost(lowTestBase, lowTestLimit)
	highHost := newFakeHost(testBase, testLimit)
	g := newGuestWindows(newWindowMap(lowHost, lowTestBase, lowTestLimit), newWindowMap(highHost, testBase, testLimit))

	if err := g.Map(lowTestBase, 0x2000, "low", 0, viewReadWrite); err != nil {
		t.Fatalf("map in the low window: %v", err)
	}
	if err := g.Map(testBase+0x1000, 0x1000, "high", 0, viewRead); err != nil {
		t.Fatalf("map in the high window: %v", err)
	}
	if _, ok := lowHost.pageState(lowTestBase + 0x1000); !ok {
		t.Error("the low host has no view at the second page of the low mapping")
	}
	if _, ok := highHost.pageState(lowTestBase); ok {
		t.Error("the high host has a view at a low address")
	}
	if v, start, ok := g.Lookup(lowTestBase + 0x1000); !ok || v.backing != "low" || start != lowTestBase {
		t.Errorf("Lookup in the low window = (%v, %#x, %v), want the low view that starts at %#x", v.backing, start, ok, lowTestBase)
	}
	if v, _, ok := g.Lookup(testBase + 0x1000); !ok || v.backing != "high" {
		t.Errorf("Lookup in the high window = (%v, %v), want the high view", v.backing, ok)
	}
	if _, _, ok := g.Lookup(lowTestLimit + 0x1000); ok {
		t.Error("Lookup in the gap between the windows found a view")
	}

	if err := g.Map(lowTestLimit, 0x1000, "gap", 0, viewRead); err == nil {
		t.Error("a mapping in the gap between the windows succeeded")
	}
	if err := g.Map(lowTestLimit-0x1000, 0x2000, "span", 0, viewRead); err == nil {
		t.Error("a mapping that runs past the end of the low window succeeded")
	}

	if err := g.Unmap(lowTestBase, testLimit-lowTestBase); err != nil {
		t.Fatalf("unmap across the gap: %v", err)
	}
	if _, ok := lowHost.pageState(lowTestBase); ok {
		t.Error("the low view survived an unmap that covers it")
	}
	if _, ok := highHost.pageState(testBase + 0x1000); ok {
		t.Error("the high view survived an unmap that covers it")
	}
}
