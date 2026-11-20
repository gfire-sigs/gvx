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
	"sync"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

type residencyObserver struct {
	fn func(memmap.FileRange, []byte)
}

func hasZeroResidencyBit(b []byte) bool {
	for _, v := range b {
		if v&1 == 0 {
			return true
		}
	}
	return false
}

// ObserveResidency registers fn to inspect pages that appear non-resident in
// the Sentry mapping of f. The callback runs with no f.mu held and sets bit 0
// in resident for pages confirmed resident in another address space. The
// returned function unregisters fn idempotently.
func (f *MemoryFile) ObserveResidency(fn func(fr memmap.FileRange, resident []byte)) (stop func()) {
	obs := &residencyObserver{fn: fn}
	wb := &f.saveRestore.winBacking
	wb.residencyMu.Lock()
	var next []*residencyObserver
	if cur := wb.residencyFns.Load(); cur != nil {
		next = append(next, *cur...)
	}
	next = append(next, obs)
	wb.residencyFns.Store(&next)
	wb.residencyMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			wb.residencyMu.Lock()
			var rest []*residencyObserver
			if cur := wb.residencyFns.Load(); cur != nil {
				for _, o := range *cur {
					if o != obs {
						rest = append(rest, o)
					}
				}
			}
			if len(rest) == 0 {
				wb.residencyFns.Store(nil)
			} else {
				wb.residencyFns.Store(&rest)
			}
			wb.residencyMu.Unlock()
		})
	}
}

func (f *MemoryFile) scanExternalResidency(fr memmap.FileRange, resident []byte) {
	cur := f.saveRestore.winBacking.residencyFns.Load()
	if cur == nil || len(resident) == 0 || !hasZeroResidencyBit(resident) {
		return
	}
	for _, o := range *cur {
		o.fn(fr, resident)
		if !hasZeroResidencyBit(resident) {
			return
		}
	}
}

// UncommittedRanges returns the coalesced uncommitted sub-ranges of fr along
// with the commit sequence number needed by MarkCommittedPages.
func (f *MemoryFile) UncommittedRanges(fr memmap.FileRange) ([]memmap.FileRange, uint64) {
	if !fr.WellFormed() || fr.Length() == 0 || (!f.opts.DisableMemoryAccounting && f.Accounting() == nil) {
		return nil, 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.isSaving {
		return nil, 0
	}
	var ranges []memmap.FileRange
	for maseg := f.memAcct.LowerBoundSegment(fr.Start); maseg.Ok() && maseg.Start() < fr.End; maseg = maseg.NextSegment() {
		ma := maseg.ValuePtr()
		if ma.wasteOrReleasing || ma.knownCommitted {
			continue
		}
		r := maseg.Range().Intersect(fr)
		if n := len(ranges); n > 0 && ranges[n-1].End == r.Start {
			ranges[n-1].End = r.End
		} else {
			ranges = append(ranges, r)
		}
	}
	if len(ranges) == 0 {
		return nil, 0
	}
	seq := f.commitSeq
	f.commitSeq++
	return ranges, seq
}

// MarkCommittedPages marks pages in fr whose bit 0 in resident is set as
// committed unless a newer decommit invalidated lastCommitSeq.
func (f *MemoryFile) MarkCommittedPages(fr memmap.FileRange, resident []byte, lastCommitSeq uint64) {
	if !fr.WellFormed() || fr.Length() == 0 || len(resident) == 0 {
		return
	}
	var acct *usage.MemoryLocked
	if !f.opts.DisableMemoryAccounting {
		acct = f.Accounting()
		if acct == nil {
			return
		}
	}
	bufLen := min(len(resident), int(fr.Length()>>hostarch.PageShift))
	if bufLen == 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.isSaving {
		return
	}
	changedAny := false
	defer func() {
		if changedAny && !f.isSaving {
			f.memAcct.MergeAll()
		}
	}()

	maseg := f.memAcct.LowerBoundSegment(fr.Start)
	for i := 0; i < bufLen; {
		if resident[i]&0x1 == 0 {
			i++
			continue
		}
		j := i + 1
		for ; j < bufLen; j++ {
			if resident[j]&0x1 == 0 {
				break
			}
		}
		commitFR := memmap.FileRange{
			Start: fr.Start + uint64(i)<<hostarch.PageShift,
			End:   fr.Start + uint64(j)<<hostarch.PageShift,
		}
		for maseg.Ok() && maseg.End() <= commitFR.Start {
			maseg = maseg.NextSegment()
		}
		for maseg.Ok() && maseg.Start() < commitFR.End {
			if ma := maseg.ValuePtr(); !ma.wasteOrReleasing && !ma.knownCommitted && ma.commitSeq <= lastCommitSeq {
				maseg = f.memAcct.Isolate(maseg, commitFR)
				ma := maseg.ValuePtr()
				amount := maseg.Range().Length()
				ma.knownCommitted = true
				ma.commitSeq = 0
				f.knownCommittedBytes += amount
				if acct != nil {
					acct.Inc(amount, ma.kind, ma.memCgID)
				}
				changedAny = true
			}
			maseg = maseg.NextSegment()
		}
		i = j + 1
	}
}
