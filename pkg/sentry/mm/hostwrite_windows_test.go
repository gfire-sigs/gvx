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

package mm

import (
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

// chunkLike wraps a memory file as the chunk memory of hostfs and ext4lite does.
type chunkLike struct{ *pgalloc.MemoryFile }

func newWatchedPMA(t *testing.T) (*MemoryManager, hostarch.AddrRange, memmap.FileRange, *[]memmap.FileRange, *pgalloc.MemoryFile) {
	t.Helper()
	mf, err := pgalloc.NewDefaultMemoryFile(pgalloc.MemoryFileOpts{})
	if err != nil {
		t.Fatalf("NewDefaultMemoryFile: %v", err)
	}
	t.Cleanup(mf.Destroy)
	fr, err := mf.Allocate(2*hostarch.PageSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	got := new([]memmap.FileRange)
	stop := mf.ObserveHostWrites(func(r memmap.FileRange) { *got = append(*got, r) })
	t.Cleanup(stop)
	ar := hostarch.AddrRange{Start: 0x10000, End: 0x10000 + 2*hostarch.PageSize}
	mm := &MemoryManager{}
	mm.pmas.Insert(mm.pmas.FirstGap(), ar, pma{file: chunkLike{mf}, off: fr.Start})
	return mm, ar, fr, got, mf
}

// TestHostWriteWrapReportsThroughAWrappedMemoryFile checks that a write into the
// second page of a pma reaches the observer of the file under a wrapper, with
// the file range of that page.
func TestHostWriteWrapReportsThroughAWrappedMemoryFile(t *testing.T) {
	mm, ar, fr, got, _ := newWatchedPMA(t)
	second := hostarch.AddrRange{Start: ar.Start + hostarch.PageSize, End: ar.End}
	ran := false
	f := mm.hostWriteWrap(second, func(safemem.BlockSeq) (uint64, error) { ran = true; return 0, nil })
	if _, err := f(safemem.BlockSeq{}); err != nil || !ran {
		t.Fatalf("the wrapped function ran = %v, err = %v", ran, err)
	}
	want := memmap.FileRange{Start: fr.Start + hostarch.PageSize, End: fr.End}
	if len(*got) != 1 || (*got)[0] != want {
		t.Errorf("reported writes = %v, want [%v]", *got, want)
	}
}

// TestHostWriteWrapReportsEachRangeOfAVector covers a writev-style sequence.
func TestHostWriteWrapReportsEachRangeOfAVector(t *testing.T) {
	mm, ar, fr, got, _ := newWatchedPMA(t)
	first := hostarch.AddrRange{Start: ar.Start, End: ar.Start + hostarch.PageSize}
	second := hostarch.AddrRange{Start: ar.Start + hostarch.PageSize, End: ar.End}
	ars := hostarch.AddrRangeSeqFromSlice([]hostarch.AddrRange{second, first})
	f := mm.hostWriteWrapVec(ars, func(safemem.BlockSeq) (uint64, error) { return 0, nil })
	if _, err := f(safemem.BlockSeq{}); err != nil {
		t.Fatal(err)
	}
	want := []memmap.FileRange{
		{Start: fr.Start + hostarch.PageSize, End: fr.End},
		{Start: fr.Start, End: fr.Start + hostarch.PageSize},
	}
	if len(*got) != 2 || (*got)[0] != want[0] || (*got)[1] != want[1] {
		t.Errorf("reported writes = %v, want %v", *got, want)
	}
}

// TestMappingAPMAReportsNoWrite checks that the mapping of a pma for reading
// and writing, which every read of a writable mapping needs, is not a write.
func TestMappingAPMAReportsNoWrite(t *testing.T) {
	_, _, fr, got, mf := newWatchedPMA(t)
	if _, err := mapInternalOf(chunkLike{mf}, fr, hostarch.ReadWrite); err != nil {
		t.Fatalf("mapInternalOf: %v", err)
	}
	if len(*got) != 0 {
		t.Errorf("mapping a pma reported %v", *got)
	}
	if _, err := mf.MapInternal(fr, hostarch.Write); err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	if len(*got) != 1 {
		t.Errorf("a direct request for write access reported %v, want one range", *got)
	}
}
