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
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

func TestObserveResidencyUpdatesAccountingAndHonorsDecommit(t *testing.T) {
	acct := usage.NewMemoryLocked()
	mf, err := NewDefaultMemoryFile(MemoryFileOpts{
		SharedSection: true,
		Accounting:    acct,
	})
	if err != nil {
		t.Fatalf("NewDefaultMemoryFile: %v", err)
	}
	defer mf.Destroy()

	const cgID = uint32(11)
	pageBytes := uint64(hostarch.PageSize)
	fr, err := mf.Allocate(2*pageBytes, AllocOpts{Kind: usage.Anonymous, MemCgID: cgID})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer mf.DecRef(fr)

	markPage0 := true
	stop := mf.ObserveResidency(func(scanFR memmap.FileRange, resident []byte) {
		if !markPage0 {
			return
		}
		if scanFR.Start <= fr.Start && scanFR.End > fr.Start {
			idx := int((fr.Start - scanFR.Start) >> hostarch.PageShift)
			if idx < len(resident) {
				resident[idx] |= 1
			}
		}
	})

	mf.FlushCommitScan()
	if got := acct.TotalPerCg(cgID); got != pageBytes {
		t.Fatalf("TotalPerCg after first scan = %d, want %d", got, pageBytes)
	}

	ranges, seq := mf.UncommittedRanges(fr)
	wantPage1 := memmap.FileRange{Start: fr.Start + pageBytes, End: fr.End}
	if len(ranges) != 1 || ranges[0] != wantPage1 {
		t.Fatalf("UncommittedRanges(%v) = %v, want [%v]", fr, ranges, wantPage1)
	}

	// A concurrent Decommit before MarkCommittedPages must win via commitSeq.
	mf.Decommit(wantPage1)
	mf.MarkCommittedPages(wantPage1, []byte{1}, seq)
	if got := acct.TotalPerCg(cgID); got != pageBytes {
		t.Fatalf("TotalPerCg after raced Decommit + MarkCommittedPages = %d, want %d", got, pageBytes)
	}

	ranges2, seq2 := mf.UncommittedRanges(wantPage1)
	if len(ranges2) != 1 || ranges2[0] != wantPage1 {
		t.Fatalf("second UncommittedRanges(%v) = %v, want [%v]", wantPage1, ranges2, wantPage1)
	}
	mf.MarkCommittedPages(wantPage1, []byte{1}, seq2)
	if got := acct.TotalPerCg(cgID); got != 2*pageBytes {
		t.Fatalf("TotalPerCg after fresh MarkCommittedPages = %d, want %d", got, 2*pageBytes)
	}

	if none, _ := mf.UncommittedRanges(fr); len(none) != 0 {
		t.Fatalf("UncommittedRanges on fully committed range = %v, want empty", none)
	}

	stop()
	markPage0 = false
	fr2, err := mf.Allocate(pageBytes, AllocOpts{Kind: usage.Anonymous, MemCgID: cgID})
	if err != nil {
		t.Fatalf("second Allocate: %v", err)
	}
	defer mf.DecRef(fr2)
	mf.FlushCommitScan()
	if got := acct.TotalPerCg(cgID); got != 2*pageBytes {
		t.Fatalf("TotalPerCg after stop() = %d, want %d", got, 2*pageBytes)
	}
}

func TestMarkCommittedPagesWithoutAccountingSink(t *testing.T) {
	pageBytes := uint64(hostarch.PageSize)

	t.Run("nil_global_accounting_is_noop", func(t *testing.T) {
		if usage.MemoryAccounting != nil {
			t.Skip("usage.MemoryAccounting is already initialized in this test binary")
		}
		mf, err := NewDefaultMemoryFile(MemoryFileOpts{SharedSection: true})
		if err != nil {
			t.Fatalf("NewDefaultMemoryFile: %v", err)
		}
		defer mf.Destroy()

		fr, err := mf.Allocate(pageBytes, AllocOpts{Kind: usage.Anonymous})
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		defer mf.DecRef(fr)

		if ranges, _ := mf.UncommittedRanges(fr); len(ranges) != 0 {
			t.Fatalf("UncommittedRanges without accounting sink = %v, want empty", ranges)
		}
		mf.MarkCommittedPages(fr, []byte{1}, 0)
		total, err := mf.TotalUsage()
		if err != nil {
			t.Fatalf("TotalUsage: %v", err)
		}
		if total != 0 {
			t.Fatalf("TotalUsage after no-op MarkCommittedPages = %d, want 0", total)
		}
		mf.Decommit(fr)
	})

	t.Run("disabled_accounting_updates_total_usage", func(t *testing.T) {
		mf, err := NewDefaultMemoryFile(MemoryFileOpts{
			SharedSection:           true,
			DisableMemoryAccounting: true,
		})
		if err != nil {
			t.Fatalf("NewDefaultMemoryFile: %v", err)
		}
		defer mf.Destroy()

		fr, err := mf.Allocate(pageBytes, AllocOpts{Kind: usage.Anonymous})
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		released := false
		defer func() {
			if !released {
				mf.DecRef(fr)
			}
		}()

		ranges, seq := mf.UncommittedRanges(fr)
		if len(ranges) != 1 || ranges[0] != fr {
			t.Fatalf("UncommittedRanges(%v) = %v, want [%v]", fr, ranges, fr)
		}
		mf.MarkCommittedPages(fr, []byte{1}, seq)
		total, err := mf.TotalUsage()
		if err != nil {
			t.Fatalf("TotalUsage after MarkCommittedPages: %v", err)
		}
		if total != pageBytes {
			t.Fatalf("TotalUsage after MarkCommittedPages = %d, want %d", total, pageBytes)
		}

		mf.Decommit(fr)
		mf.DecRef(fr)
		released = true
		total, err = mf.TotalUsage()
		if err != nil {
			t.Fatalf("TotalUsage after Decommit+DecRef: %v", err)
		}
		if total != 0 {
			t.Fatalf("TotalUsage after Decommit+DecRef = %d, want 0", total)
		}
	})
}
