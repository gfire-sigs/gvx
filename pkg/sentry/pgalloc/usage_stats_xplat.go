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

package pgalloc

import (
	"context"
	"errors"
	"runtime"
	"time"
)

// ErrMemoryFileDestroyed reports that a MemoryFile has started asynchronous
// destruction and no longer drains pending releases.
var ErrMemoryFileDestroyed = errors.New("pgalloc: memory file destroyed")

// AllocationStats summarizes logical page ownership inside a MemoryFile.
type AllocationStats struct {
	// AllocatedBytes is the total bytes with a non-zero reference count.
	AllocatedBytes uint64

	// PendingReleaseBytes is the total waste and releasing bytes waiting for
	// asynchronous decommitment.
	PendingReleaseBytes uint64
}

// AllocationStats returns the current logical allocation totals of f.
func (f *MemoryFile) AllocationStats() AllocationStats {
	f.mu.Lock()
	defer f.mu.Unlock()
	var stats AllocationStats
	for seg := f.memAcct.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		if seg.ValuePtr().wasteOrReleasing {
			stats.PendingReleaseBytes += seg.Range().Length()
		} else {
			stats.AllocatedBytes += seg.Range().Length()
		}
	}
	return stats
}

// WaitReleaserIdle waits until f has no waste or releasing pages and its
// releaser goroutine is idle, or until ctx ends.
func (f *MemoryFile) WaitReleaserIdle(ctx context.Context) error {
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for spins := 0; ; spins++ {
		f.mu.Lock()
		destroyed := f.destroyed
		idle := !destroyed && !f.haveWaste && !f.hasPendingReleaseLocked()
		f.mu.Unlock()
		if destroyed {
			return ErrMemoryFileDestroyed
		}
		if idle {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if spins < 4 {
			runtime.Gosched()
			continue
		}
		if timer == nil {
			timer = time.NewTimer(time.Millisecond)
		} else {
			timer.Reset(time.Millisecond)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// +checklocks:f.mu
func (f *MemoryFile) hasPendingReleaseLocked() bool {
	for seg := f.memAcct.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
		if seg.ValuePtr().wasteOrReleasing {
			return true
		}
	}
	return false
}
