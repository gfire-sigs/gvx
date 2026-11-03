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
	"reflect"
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

func newObservedFile(t *testing.T) (*MemoryFile, memmap.FileRange) {
	t.Helper()
	mf, err := NewDefaultMemoryFile(MemoryFileOpts{})
	if err != nil {
		t.Fatalf("NewDefaultMemoryFile: %v", err)
	}
	t.Cleanup(mf.Destroy)
	fr, err := mf.Allocate(4*hostarch.PageSize, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	return mf, fr
}

func TestHostWriteObserverSeesWritesAndNotReads(t *testing.T) {
	mf, fr := newObservedFile(t)
	var got []memmap.FileRange
	stop := mf.ObserveHostWrites(func(r memmap.FileRange) { got = append(got, r) })
	defer stop()

	if _, err := mf.MapInternal(fr, hostarch.Read); err != nil {
		t.Fatalf("MapInternal(read): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("a read mapping reported %v", got)
	}
	sub := memmap.FileRange{Start: fr.Start + hostarch.PageSize, End: fr.Start + 2*hostarch.PageSize}
	if _, err := mf.MapInternal(sub, hostarch.Write); err != nil {
		t.Fatalf("MapInternal(write): %v", err)
	}
	mf.NoteHostWrite(fr)
	if want := []memmap.FileRange{sub, fr}; !reflect.DeepEqual(got, want) {
		t.Errorf("observed writes = %v, want %v", got, want)
	}
}

func TestHostWriteObserverStops(t *testing.T) {
	mf, fr := newObservedFile(t)
	if HostWritesObserved() {
		t.Skip("another test of this process holds an observer")
	}
	calls := 0
	stop := mf.ObserveHostWrites(func(memmap.FileRange) { calls++ })
	if !HostWritesObserved() {
		t.Error("HostWritesObserved = false with an observer")
	}
	mf.NoteHostWrite(fr)
	stop()
	stop()
	mf.NoteHostWrite(fr)
	if calls != 1 {
		t.Errorf("the observer ran %d times, want 1", calls)
	}
	if HostWritesObserved() {
		t.Error("HostWritesObserved = true after the observer stopped")
	}
}

func TestHostWriteObserversOfOneFileAreIndependent(t *testing.T) {
	mf, fr := newObservedFile(t)
	var first, second int
	stopFirst := mf.ObserveHostWrites(func(memmap.FileRange) { first++ })
	stopSecond := mf.ObserveHostWrites(func(memmap.FileRange) { second++ })
	defer stopSecond()
	mf.NoteHostWrite(fr)
	stopFirst()
	mf.NoteHostWrite(fr)
	if first != 1 || second != 2 {
		t.Errorf("observers ran %d and %d times, want 1 and 2", first, second)
	}
}
