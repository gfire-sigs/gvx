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
	"runtime"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

func TestCanSkipUsageScan(t *testing.T) {
	cgroups := map[uint32]struct{}{1: {}}
	if !canSkipUsageScan(nil) {
		t.Error("canSkipUsageScan(nil) = false, want true: a scan of all memory trusts the block count")
	}
	if got, want := canSkipUsageScan(cgroups), runtime.GOOS == "linux" || runtime.GOOS == "android"; got != want {
		t.Errorf("canSkipUsageScan(one cgroup) on %s = %t, want %t", runtime.GOOS, got, want)
	}
}

func TestCoalesceScanRangeBridgesSmallCommittedIslands(t *testing.T) {
	var f MemoryFile
	f.mu.Lock()
	defer f.mu.Unlock()

	const stride = 64 << 10
	const page = 4 << 10
	insert := func(r memmap.FileRange, committed bool) {
		f.memAcct.Insert(f.memAcct.FindGap(r.Start), r, memAcctInfo{
			kind:           usage.Anonymous,
			knownCommitted: committed,
		})
	}
	for i := uint64(0); i < 8; i++ {
		base := i * stride
		insert(memmap.FileRange{Start: base, End: base + page}, true)
		insert(memmap.FileRange{Start: base + page, End: base + stride}, false)
	}
	// Add a large committed region (> 64 KiB) followed by another uncommitted page.
	largeStart := uint64(8 * stride)
	largeEnd := largeStart + (128 << 10)
	insert(memmap.FileRange{Start: largeStart, End: largeEnd}, true)
	insert(memmap.FileRange{Start: largeEnd, End: largeEnd + page}, false)

	firstUncommitted := f.memAcct.LowerBoundSegment(page)
	got := f.coalesceScanRangeLocked(firstUncommitted, 0, nil)
	want := memmap.FileRange{Start: page, End: largeStart}
	if got != want {
		t.Fatalf("coalesceScanRangeLocked = %v, want %v", got, want)
	}
}

func TestFlushCommitScanResetsNextScanTime(t *testing.T) {
	var f MemoryFile
	f.nextCommitScan = time.Now().Add(time.Minute)
	f.FlushCommitScan()
	if !f.nextCommitScan.IsZero() {
		t.Fatalf("nextCommitScan = %v after FlushCommitScan, want zero time", f.nextCommitScan)
	}
}
