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

package blockdev

import (
	"math/bits"
	"sync/atomic"
)

// PageSize is the size of the unit that FirstTouch tracks. The page cache of
// Linux fills a file in pages of 4 KiB.
const PageSize = 4096

// FirstTouch records which pages of an image a reader has touched. A disk that
// sits behind the page cache of the host sees each page once: the first read
// fills the cache, and later reads come from it. Claim tells a reader how many
// bytes of a range are new, so that the counters count a page at its first
// read and not at each mapping or read of it.
//
// The set uses one bit for each page and takes no lock.
type FirstTouch struct {
	size  uint64
	words []atomic.Uint64
}

// NewFirstTouch returns an empty set for an image of size bytes.
func NewFirstTouch(size uint64) *FirstTouch {
	pages := (size + PageSize - 1) / PageSize
	return &FirstTouch{size: size, words: make([]atomic.Uint64, (pages+63)/64)}
}

// Claim marks the pages of the range [off, off+n) as touched. It returns the
// number of bytes of the pages that no earlier call marked. A page counts in
// full, as the page cache reads it in full. A range beyond the end of the
// image counts only up to the last page of the image. Concurrent calls never
// count a page twice.
func (t *FirstTouch) Claim(off, n uint64) uint64 {
	if n == 0 || off >= t.size {
		return 0
	}
	end := min(off+n, t.size)
	first, last := off/PageSize, (end-1)/PageSize // Both pages are in the range.
	var fresh uint64
	for w := first / 64; w <= last/64; w++ {
		lo, hi := max(first, w*64), min(last, w*64+63)
		mask := ^uint64(0) >> (63 - (hi - lo)) << (lo - w*64)
		old := t.words[w].Or(mask)
		fresh += uint64(bits.OnesCount64(mask &^ old))
	}
	return fresh * PageSize
}
