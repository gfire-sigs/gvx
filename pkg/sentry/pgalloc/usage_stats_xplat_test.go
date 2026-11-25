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
	"testing"
	"testing/synctest"
	"time"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

func TestAllocationStatsTracksAllocationsAndSubrelease(t *testing.T) {
	mf := newTestMemoryFile(t, MemoryFileOpts{
		DisableMemoryAccounting: true,
		ExpectHugepages:         true,
	})
	var live []memmap.FileRange
	t.Cleanup(func() {
		for _, fr := range live {
			mf.DecRef(fr)
		}
		awaitDestroy(t, mf)
	})

	const (
		firstSize  = uint64(16 << 10)
		secondSize = uint64(32 << 10)
	)
	fr1, err := mf.Allocate(firstSize, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate(%d): %v", firstSize, err)
	}
	live = append(live, fr1)
	fr2, err := mf.Allocate(secondSize, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate(%d): %v", secondSize, err)
	}
	live = append(live, fr2)

	writePattern(t, mf, fr1, 1)
	writePattern(t, mf, fr2, 2)

	want := AllocationStats{AllocatedBytes: firstSize + secondSize}
	if got := mf.AllocationStats(); got != want {
		t.Fatalf("AllocationStats after two allocations = %+v, want %+v", got, want)
	}

	mf.DecRef(fr2)
	live = live[:1]
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := mf.WaitReleaserIdle(ctx); err != nil {
		t.Fatalf("WaitReleaserIdle after first DecRef: %v", err)
	}
	want = AllocationStats{AllocatedBytes: firstSize}
	if got := mf.AllocationStats(); got != want {
		t.Fatalf("AllocationStats after releasing second range = %+v, want %+v", got, want)
	}

	// Verify sub-released pages inside a hugepage allocation leave both
	// AllocatedBytes and PendingReleaseBytes once the releaser drains them.
	hugeSize := uint64(hostarch.HugePageSize)
	pageSize := uint64(hostarch.PageSize)
	hugeFR, err := mf.Allocate(hugeSize, AllocOpts{Kind: usage.Anonymous, Huge: true})
	if err != nil {
		t.Fatalf("Allocate(%d, Huge): %v", hugeSize, err)
	}
	live = append(live, hugeFR)
	subFR := memmap.FileRange{Start: hugeFR.Start, End: hugeFR.Start + pageSize}
	remFR := memmap.FileRange{Start: hugeFR.Start + pageSize, End: hugeFR.End}
	mf.DecRef(subFR)
	live[len(live)-1] = remFR
	if err := mf.WaitReleaserIdle(ctx); err != nil {
		t.Fatalf("WaitReleaserIdle after hugepage sub-release: %v", err)
	}
	want = AllocationStats{AllocatedBytes: firstSize + hugeSize - pageSize}
	if got := mf.AllocationStats(); got != want {
		t.Fatalf("AllocationStats after hugepage sub-release = %+v, want %+v", got, want)
	}

	mf.DecRef(remFR)
	mf.DecRef(fr1)
	live = nil
	if err := mf.WaitReleaserIdle(ctx); err != nil {
		t.Fatalf("WaitReleaserIdle after final DecRef: %v", err)
	}
	if got := mf.AllocationStats(); got != (AllocationStats{}) {
		t.Fatalf("AllocationStats after releasing all ranges = %+v, want zero", got)
	}
}

func TestWaitReleaserIdleReturnsDestroyedAfterDestroy(t *testing.T) {
	mf := newTestMemoryFile(t, MemoryFileOpts{DisableMemoryAccounting: true})
	awaitDestroy(t, mf)

	err := mf.WaitReleaserIdle(t.Context())
	if !errors.Is(err, ErrMemoryFileDestroyed) {
		t.Fatalf("WaitReleaserIdle after Destroy = %v, want %v", err, ErrMemoryFileDestroyed)
	}
}

func TestWaitReleaserIdleHonorsContextWhilePending(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			activeEnd  = uint64(8 << 10)
			pendingEnd = uint64(20 << 10)
		)
		var mf MemoryFile
		mf.mu.Lock()
		mf.memAcct.Insert(mf.memAcct.FindGap(0), memmap.FileRange{Start: 0, End: activeEnd}, memAcctInfo{
			kind: usage.Anonymous,
		})
		mf.memAcct.Insert(mf.memAcct.FindGap(activeEnd), memmap.FileRange{Start: activeEnd, End: pendingEnd}, memAcctInfo{
			kind:             usage.System,
			wasteOrReleasing: true,
		})
		mf.haveWaste = true
		mf.mu.Unlock()

		want := AllocationStats{
			AllocatedBytes:      activeEnd,
			PendingReleaseBytes: pendingEnd - activeEnd,
		}
		if got := mf.AllocationStats(); got != want {
			t.Fatalf("AllocationStats with active and pending segments = %+v, want %+v", got, want)
		}

		cancelCtx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := mf.WaitReleaserIdle(cancelCtx); !errors.Is(err, context.Canceled) {
			t.Fatalf("WaitReleaserIdle with canceled context = %v, want %v", err, context.Canceled)
		}

		timeoutCtx, timeoutCancel := context.WithTimeout(t.Context(), 5*time.Millisecond)
		defer timeoutCancel()
		if err := mf.WaitReleaserIdle(timeoutCtx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("WaitReleaserIdle with expired context = %v, want %v", err, context.DeadlineExceeded)
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			time.Sleep(2 * time.Millisecond)
			mf.mu.Lock()
			mf.memAcct.RemoveRange(memmap.FileRange{Start: activeEnd, End: pendingEnd})
			mf.haveWaste = false
			mf.mu.Unlock()
		}()
		if err := mf.WaitReleaserIdle(t.Context()); err != nil {
			t.Fatalf("WaitReleaserIdle once waste drains = %v, want nil", err)
		}
		<-done

		// Verify concurrent Destroy unblocks WaitReleaserIdle with
		// ErrMemoryFileDestroyed while waste is still pending.
		mf.mu.Lock()
		mf.haveWaste = true
		mf.mu.Unlock()
		destroyDone := make(chan struct{})
		go func() {
			defer close(destroyDone)
			time.Sleep(2 * time.Millisecond)
			mf.mu.Lock()
			mf.destroyed = true
			mf.mu.Unlock()
		}()
		if err := mf.WaitReleaserIdle(t.Context()); !errors.Is(err, ErrMemoryFileDestroyed) {
			t.Fatalf("WaitReleaserIdle during concurrent Destroy = %v, want %v", err, ErrMemoryFileDestroyed)
		}
		<-destroyDone
	})
}
