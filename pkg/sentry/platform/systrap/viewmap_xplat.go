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
	"errors"
	"fmt"
	"slices"
	"sort"
)

// The Windows engine keeps the guest window of a stub process as one large
// placeholder. A guest mapping replaces part of that placeholder with a view
// of the memory file. Windows allows only these operations on a window:
//
//   - split a placeholder into smaller placeholders,
//   - merge adjacent placeholders into one,
//   - replace one placeholder with one view of the same size,
//   - turn one whole view back into one placeholder,
//   - change the protection of one whole view.
//
// windowMap turns the arbitrary Map, Unmap, and Protect ranges of the Sentry
// into these operations. It runs on darwin only so that the host-independent
// logic has a fast test on the development machine.

// viewProt is the protection of one view.
type viewProt uint8

const (
	viewNone viewProt = iota
	viewRead
	viewReadWrite
	viewReadExec
	viewReadWriteExec
)

// viewBacking names the section that a view maps. The windowMap never reads
// it. The host decodes it.
type viewBacking interface{}

// viewHost performs the host memory calls on one stub window.
type viewHost interface {
	// SplitPlaceholder makes [addr, addr+size) its own placeholder. The range
	// lies inside one placeholder.
	SplitPlaceholder(addr, size uint64) error
	// CoalescePlaceholders merges the adjacent placeholders that tile
	// [addr, addr+size) exactly.
	CoalescePlaceholders(addr, size uint64) error
	// MapView replaces the placeholder [addr, addr+size) with a view of
	// backing at offset off.
	MapView(addr, size uint64, backing viewBacking, off uint64, prot viewProt) error
	// UnmapView turns the whole view that starts at addr into a placeholder.
	UnmapView(addr uint64) error
	// ProtectView changes the protection of the whole view that starts at
	// addr and has the given size.
	ProtectView(addr, size uint64, prot viewProt) error
}

// errWindowBroken reports that a host call failed after the map had changed
// the host state. The stub window is unusable.
var errWindowBroken = errors.New("stub window is in an unknown state after a failed host call")

type viewInfo struct {
	backing viewBacking
	off     uint64
	prot    viewProt
}

type extent struct {
	addr, size uint64
	view       *viewInfo // nil for a placeholder
}

func (e extent) end() uint64 { return e.addr + e.size }

// windowMap tracks the placeholders and views of one stub window. It covers
// [base, limit) without gaps. It is not safe for concurrent use.
type windowMap struct {
	host        viewHost
	base, limit uint64
	ext         []extent
	broken      bool
}

// newWindowMap returns a map whose window is one placeholder.
func newWindowMap(host viewHost, base, limit uint64) *windowMap {
	return &windowMap{host: host, base: base, limit: limit, ext: []extent{{addr: base, size: limit - base}}}
}

func (w *windowMap) checkRange(addr, size, align uint64) error {
	if w.broken {
		return errWindowBroken
	}
	if size == 0 || addr%align != 0 || size%align != 0 || addr < w.base || addr+size > w.limit || addr+size < addr {
		return fmt.Errorf("window range %#x+%#x is empty, unaligned, or outside [%#x, %#x)", addr, size, w.base, w.limit)
	}
	return nil
}

// first returns the index of the extent that contains addr.
func (w *windowMap) first(addr uint64) int {
	return sort.Search(len(w.ext), func(i int) bool { return w.ext[i].end() > addr })
}

// fail marks the window broken and wraps err.
func (w *windowMap) fail(op string, err error) error {
	w.broken = true
	return fmt.Errorf("%s: %w: %w", op, errWindowBroken, err)
}

// splice replaces ext[i:j] with repl.
func (w *windowMap) splice(i, j int, repl ...extent) {
	w.ext = slices.Replace(w.ext, i, j, repl...)
}

// piece is a part of an unmapped view that must map again.
type piece struct {
	addr, size uint64
	view       viewInfo
}

// placeholder makes [addr, addr+size) exactly one placeholder. It unmaps the
// views that overlap the range and returns the parts of those views outside
// the range. The caller maps them again with remap.
func (w *windowMap) placeholder(addr, size uint64) ([]piece, error) {
	end := addr + size
	var keep []piece
	i := w.first(addr)
	for j := i; j < len(w.ext) && w.ext[j].addr < end; j++ {
		e := w.ext[j]
		if e.view == nil {
			continue
		}
		if err := w.host.UnmapView(e.addr); err != nil {
			return nil, w.fail("unmap view", err)
		}
		if e.addr < addr {
			keep = append(keep, piece{e.addr, addr - e.addr, *e.view})
		}
		if e.end() > end {
			keep = append(keep, piece{end, e.end() - end, viewInfo{e.view.backing, e.view.off + (end - e.addr), e.view.prot}})
		}
		w.ext[j].view = nil
	}
	// Every overlapping extent is a placeholder. Trim the ends, then merge.
	i = w.first(addr)
	j := w.first(end - 1)
	if i == j {
		if err := w.splitOut(i, addr, size); err != nil {
			return nil, err
		}
		return keep, nil
	}
	if e := w.ext[i]; e.addr < addr {
		if err := w.splitOut(i, addr, e.end()-addr); err != nil {
			return nil, err
		}
		i++
	}
	j = w.first(end - 1)
	if e := w.ext[j]; e.end() > end {
		if err := w.splitOut(j, e.addr, end-e.addr); err != nil {
			return nil, err
		}
	}
	j = w.first(end - 1)
	if j > i {
		if err := w.host.CoalescePlaceholders(addr, size); err != nil {
			return nil, w.fail("coalesce placeholders", err)
		}
		w.splice(i, j+1, extent{addr: addr, size: size})
	}
	return keep, nil
}

// splitOut makes [addr, addr+size) its own extent inside the placeholder
// extent i. A range that is the whole extent needs no host call.
func (w *windowMap) splitOut(i int, addr, size uint64) error {
	e := w.ext[i]
	if e.addr == addr && e.size == size {
		return nil
	}
	if err := w.host.SplitPlaceholder(addr, size); err != nil {
		return w.fail("split placeholder", err)
	}
	var repl []extent
	if e.addr < addr {
		repl = append(repl, extent{addr: e.addr, size: addr - e.addr})
	}
	repl = append(repl, extent{addr: addr, size: size})
	if e.end() > addr+size {
		repl = append(repl, extent{addr: addr + size, size: e.end() - addr - size})
	}
	w.splice(i, i+1, repl...)
	return nil
}

// remap maps the pieces that placeholder returned.
func (w *windowMap) remap(keep []piece) error {
	for _, p := range keep {
		if err := w.mapAt(p.addr, p.size, p.view); err != nil {
			return err
		}
	}
	return nil
}

// mapAt maps a view over a range that is already part of placeholders.
func (w *windowMap) mapAt(addr, size uint64, v viewInfo) error {
	i := w.first(addr)
	if err := w.splitOut(i, addr, size); err != nil {
		return err
	}
	i = w.first(addr)
	if err := w.host.MapView(addr, size, v.backing, v.off, v.prot); err != nil {
		return w.fail("map view", err)
	}
	vv := v
	w.ext[i].view = &vv
	return nil
}

// Map replaces [addr, addr+size) with a view of backing at off.
func (w *windowMap) Map(addr, size uint64, backing viewBacking, off uint64, prot viewProt) error {
	if err := w.checkRange(addr, size, 0x1000); err != nil {
		return err
	}
	keep, err := w.placeholder(addr, size)
	if err != nil {
		return err
	}
	if err := w.mapAt(addr, size, viewInfo{backing, off, prot}); err != nil {
		return err
	}
	return w.remap(keep)
}

// Unmap turns [addr, addr+size) into placeholders. A range without views is
// a no-op.
func (w *windowMap) Unmap(addr, size uint64) error {
	if err := w.checkRange(addr, size, 0x1000); err != nil {
		return err
	}
	i := w.first(addr)
	mapped := false
	for j := i; j < len(w.ext) && w.ext[j].addr < addr+size; j++ {
		mapped = mapped || w.ext[j].view != nil
	}
	if !mapped {
		return nil
	}
	keep, err := w.placeholder(addr, size)
	if err != nil {
		return err
	}
	return w.remap(keep)
}

// Protect changes the protection of [addr, addr+size). Every page of the
// range must belong to a view.
func (w *windowMap) Protect(addr, size uint64, prot viewProt) error {
	if err := w.checkRange(addr, size, 0x1000); err != nil {
		return err
	}
	end := addr + size
	i := w.first(addr)
	for j, next := i, addr; j < len(w.ext) && w.ext[j].addr < end; j++ {
		if w.ext[j].view == nil || w.ext[j].addr > next {
			return fmt.Errorf("protect %#x+%#x: the range has an unmapped page", addr, size)
		}
		next = w.ext[j].end()
	}
	for j := i; j < len(w.ext) && w.ext[j].addr < end; j++ {
		e := w.ext[j]
		if e.view.prot == prot {
			continue
		}
		lo, hi := max(e.addr, addr), min(e.end(), end)
		if lo == e.addr && hi == e.end() {
			if err := w.host.ProtectView(e.addr, e.size, prot); err != nil {
				return w.fail("protect view", err)
			}
			w.ext[j].view = &viewInfo{e.view.backing, e.view.off, prot}
			continue
		}
		// A partial change splits the view, because one view has one protection.
		old := *e.view
		if err := w.host.UnmapView(e.addr); err != nil {
			return w.fail("unmap view", err)
		}
		w.ext[j].view = nil
		if lo > e.addr {
			if err := w.mapAt(e.addr, lo-e.addr, old); err != nil {
				return err
			}
		}
		mid := viewInfo{old.backing, old.off + (lo - e.addr), prot}
		if err := w.mapAt(lo, hi-lo, mid); err != nil {
			return err
		}
		if hi < e.end() {
			if err := w.mapAt(hi, e.end()-hi, viewInfo{old.backing, old.off + (hi - e.addr), old.prot}); err != nil {
				return err
			}
		}
		// The splice added extents. Restart the scan after them.
		return w.Protect(addr, size, prot)
	}
	return nil
}

// Lookup returns the view that covers addr, with the section offset of addr,
// and the start address of that view. It returns false for a placeholder.
func (w *windowMap) Lookup(addr uint64) (viewInfo, uint64, bool) {
	if addr < w.base || addr >= w.limit {
		return viewInfo{}, 0, false
	}
	e := w.ext[w.first(addr)]
	if e.view == nil {
		return viewInfo{}, 0, false
	}
	return viewInfo{e.view.backing, e.view.off + (addr - e.addr), e.view.prot}, e.addr, true
}

// guestWindows holds the window maps of one stub, which do not overlap. A stub
// has one window, or two when the platform also reserves the low window. The
// host owns the range between two windows, and the memory manager never maps
// there. The memory manager does unmap ranges that cross the gap.
type guestWindows struct {
	maps []*windowMap
}

func newGuestWindows(maps ...*windowMap) *guestWindows {
	return &guestWindows{maps: slices.Clone(maps)}
}

// window returns the map whose window contains addr, or nil.
func (g *guestWindows) window(addr uint64) *windowMap {
	for _, w := range g.maps {
		if addr >= w.base && addr < w.limit {
			return w
		}
	}
	return nil
}

// Map replaces [addr, addr+size) with a view of backing at off. The range must
// lie in one window.
func (g *guestWindows) Map(addr, size uint64, backing viewBacking, off uint64, prot viewProt) error {
	w := g.window(addr)
	if w == nil {
		return fmt.Errorf("window range %#x+%#x starts outside every window", addr, size)
	}
	return w.Map(addr, size, backing, off, prot)
}

// Unmap turns the parts of [addr, addr+size) that lie in a window into
// placeholders. It ignores the parts outside every window.
func (g *guestWindows) Unmap(addr, size uint64) error {
	end := addr + size
	for _, w := range g.maps {
		lo, hi := max(addr, w.base), min(end, w.limit)
		if lo >= hi {
			continue
		}
		if err := w.Unmap(lo, hi-lo); err != nil {
			return err
		}
	}
	return nil
}

// Lookup returns the view that covers addr, as windowMap.Lookup does. It
// returns false for an address outside every window.
func (g *guestWindows) Lookup(addr uint64) (viewInfo, uint64, bool) {
	w := g.window(addr)
	if w == nil {
		return viewInfo{}, 0, false
	}
	return w.Lookup(addr)
}
