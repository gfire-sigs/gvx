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

package hostfs

import (
	"cmp"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// pollBackend is the revalidator. One goroutine scans every watched object at
// a fixed interval. The goroutine exists only while a watched object exists.
//
// Linux uses it because the kernel offers no watch call that seccomp can
// confine to the workspace: inotify_add_watch takes a raw path. A scan needs
// only fstatat and getdents64 on the pinned descriptors, and the filter
// already allows both. The code has no platform dependency, so the tests run it
// on every host.
type pollBackend struct {
	noSync
	hw *hostWatcher

	mu      sync.Mutex
	entries map[*watchEntry]struct{}
	stop    chan struct{}
	// running counts the goroutines that have not returned.
	running atomic.Int32
	wg      sync.WaitGroup
}

func newPollBackend(hw *hostWatcher) *pollBackend {
	return &pollBackend{hw: hw, entries: make(map[*watchEntry]struct{})}
}

func (b *pollBackend) holdsPins() bool { return true }

func (b *pollBackend) add(e *watchEntry) error {
	interval := b.hw.pollInterval()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries[e] = struct{}{}
	if b.stop == nil {
		b.stop = make(chan struct{})
		b.running.Add(1)
		b.wg.Add(1)
		go b.run(b.stop, interval)
	}
	return nil
}

func (b *pollBackend) remove(e *watchEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.entries, e)
	if len(b.entries) == 0 && b.stop != nil {
		close(b.stop)
		b.stop = nil
	}
}

func (b *pollBackend) run(stop <-chan struct{}, interval time.Duration) {
	defer func() {
		b.running.Add(-1)
		b.wg.Done()
	}()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
		b.mu.Lock()
		list := make([]*watchEntry, 0, len(b.entries))
		for e := range b.entries {
			list = append(list, e)
		}
		b.mu.Unlock()
		slices.SortFunc(list, func(x, y *watchEntry) int { return cmp.Compare(x.seq, y.seq) })
		b.hw.rescanEntries(list, stop)
	}
}

func (b *pollBackend) close() {
	b.mu.Lock()
	if b.stop != nil {
		close(b.stop)
		b.stop = nil
	}
	clear(b.entries)
	b.mu.Unlock()
	b.wg.Wait()
}

func (b *pollBackend) idle() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entries) == 0 && b.running.Load() == 0
}
