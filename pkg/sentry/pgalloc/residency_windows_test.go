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
