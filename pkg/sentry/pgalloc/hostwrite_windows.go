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

//go:build windows

package pgalloc

import (
	"fmt"
	"sync/atomic"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sync"
)

// The Windows systrap engine runs guest code from patched copies of memory-file
// pages. A write of the Sentry into a page, for example the copy-out of
// read(2) or the write(2) of a file that a guest maps, does not pass through a
// view of the engine, so the engine learns of it only here.
//
// The memory manager reports each write that goes through a cached internal
// mapping with NoteHostWrite after the write. MapInternal reports a request for
// write access before the caller writes, because the caller then holds a raw
// pointer and the file cannot see the store. A caller that keeps such a
// pointer for later writes, for example a page cache, calls NoteHostWrite
// itself.

// hostWriteHooks holds the observers of one memory file.
type hostWriteHooks struct {
	mu  sync.Mutex
	fns atomic.Pointer[[]*hostWriteObserver]
}

type hostWriteObserver struct {
	fn func(memmap.FileRange)
}

// hostWriteObservers counts the observers of all memory files, so that the
// memory manager can skip the work while none exists.
var hostWriteObservers atomic.Int64

// HostWritesObserved reports whether any memory file has an observer of Sentry
// writes.
func HostWritesObserved() bool { return hostWriteObservers.Load() != 0 }

// ObserveHostWrites calls fn with the range of every write that Sentry code
// makes into f, or is about to make. fn runs on the writing goroutine, with the
// locks of the caller held, and it must not call back into f. The returned
// function removes the observer.
func (f *MemoryFile) ObserveHostWrites(fn func(memmap.FileRange)) (stop func()) {
	obs := &hostWriteObserver{fn: fn}
	h := &f.hostWrites
	h.mu.Lock()
	var next []*hostWriteObserver
	if cur := h.fns.Load(); cur != nil {
		next = append(next, *cur...)
	}
	next = append(next, obs)
	h.fns.Store(&next)
	h.mu.Unlock()
	hostWriteObservers.Add(1)
	var once sync.Once
	return func() {
		once.Do(func() {
			h.mu.Lock()
			var rest []*hostWriteObserver
			if cur := h.fns.Load(); cur != nil {
				for _, o := range *cur {
					if o != obs {
						rest = append(rest, o)
					}
				}
			}
			if len(rest) == 0 {
				h.fns.Store(nil)
			} else {
				h.fns.Store(&rest)
			}
			h.mu.Unlock()
			hostWriteObservers.Add(-1)
		})
	}
}

// MapInternalUnreported is MapInternal that does not report a request for
// write access. The memory manager maps a whole pma with its maximum
// permissions before it knows whether the access writes, and it reports each
// write itself.
func (f *MemoryFile) MapInternalUnreported(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	if !fr.WellFormed() || fr.Length() == 0 {
		panic(fmt.Sprintf("invalid range: %v", fr))
	}
	if at.Execute {
		return safemem.BlockSeq{}, linuxerr.EACCES
	}
	if amfl := f.asyncPageLoad.Load(); amfl != nil {
		if err := amfl.awaitLoad(fr); err != nil {
			return safemem.BlockSeq{}, err
		}
	}
	// The tail of MapInternal.
	chunks := ((fr.End + chunkMask) / chunkSize) - (fr.Start / chunkSize)
	if chunks == 1 {
		var seq safemem.BlockSeq
		f.forEachMappingSlice(fr, func(bs []byte) {
			seq = safemem.BlockSeqOf(safemem.BlockFromSafeSlice(bs))
		})
		return seq, nil
	}
	blocks := make([]safemem.Block, 0, chunks)
	f.forEachMappingSlice(fr, func(bs []byte) {
		blocks = append(blocks, safemem.BlockFromSafeSlice(bs))
	})
	return safemem.BlockSeqFromSlice(blocks), nil
}

// NoteHostWrite tells the observers of f that Sentry code wrote fr.
func (f *MemoryFile) NoteHostWrite(fr memmap.FileRange) { f.noteHostWrite(fr) }

func (f *MemoryFile) noteHostWrite(fr memmap.FileRange) {
	cur := f.hostWrites.fns.Load()
	if cur == nil || fr.Length() == 0 {
		return
	}
	for _, o := range *cur {
		o.fn(fr)
	}
}
