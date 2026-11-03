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

package systrap

import (
	"sync"
	"sync/atomic"

	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

// The Sentry writes guest memory through its own mapping of the memory file:
// the copy-out of read(2), recv(2), and process_vm_writev(2), a ptrace poke,
// and the write(2) of a file that a guest maps shared. These writes pass no
// view of a stub, so a patched copy of the written frame would stay stale.
// A memory file that reports such writes calls the observer that this file
// registers when the first mapping of the file appears. The observer drops
// every copy of the written frames, in all address spaces, like a write
// through a view does.
//
// The memory manager reports a write after it completes, so a copy that the
// engine builds during the write is poisoned or dropped. A caller that holds a
// raw pointer from MapInternal for write access is reported when it asks for
// the pointer, before it writes. A fetch that copies the page between that
// request and the store can keep the old bytes until the next report. The
// callers of MapInternal for write access that guests can observe are the
// Sentry file systems, and they write within the same call.

// hostWriteSource is a memory file that reports the writes of Sentry code.
// pgalloc.MemoryFile implements it on Windows. A wrapper that embeds the file,
// such as the chunk memory of hostfs, implements it too, so the platform keys
// its observers by the host handle of the file and not by the value.
type hostWriteSource interface {
	ObserveHostWrites(fn func(memmap.FileRange)) (stop func())
}

// hostWriteWatch holds the observers that the platform registered.
type hostWriteWatch struct {
	mu     sync.Mutex
	stops  map[uintptr]func()
	closed bool
}

// watchHostWrites registers the platform as the observer of the writes into
// f, the memory file with the host handle file. It does nothing for a file
// that does not report writes, and for a file that it already watches.
func (p *Platform) watchHostWrites(f memmap.File, file uintptr) {
	src, ok := f.(hostWriteSource)
	if !ok {
		return
	}
	w := &p.hostWrites
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	if _, ok := w.stops[file]; ok {
		return
	}
	copies := p.alias.copyCount(file)
	stop := src.ObserveHostWrites(func(fr memmap.FileRange) { p.hostWrote(file, copies, fr) })
	if w.stops == nil {
		w.stops = make(map[uintptr]func())
	}
	w.stops[file] = stop
}

// stopHostWrites removes every observer of the platform.
func (p *Platform) stopHostWrites() {
	w := &p.hostWrites
	w.mu.Lock()
	w.closed = true
	stops := w.stops
	w.stops = nil
	w.mu.Unlock()
	for _, stop := range stops {
		stop()
	}
}

// hostWrote drops every copy of the frames in fr of the file with the host
// handle file. copies is the counter of the copies of that file.
func (p *Platform) hostWrote(file uintptr, copies *atomic.Int64, fr memmap.FileRange) {
	// The read-modify-write is a full barrier. The writer made its stores
	// before this call, and a copy that begins after the call reads them.
	if copies.Add(0) == 0 {
		return
	}
	start := blockRound(fr.Start)
	end := blockRound(fr.End + blockSize - 1)
	for _, key := range p.alias.framesIn(file, start, end-start) {
		p.hostWriteDrops.Add(1)
		if err := p.alias.dropAll(key); err != nil {
			// A copy that cannot return to data state belongs to a stub that
			// died or to a broken window. The guest of that stub cannot run on.
			tracef("systrap: drop the copies of frame %#x after a write of the Sentry: %v", key.off, err)
		}
	}
}

// HostWriteDrops returns how many frames lost their copies because Sentry code
// wrote them.
func (p *Platform) HostWriteDrops() uint64 { return p.hostWriteDrops.Load() }
