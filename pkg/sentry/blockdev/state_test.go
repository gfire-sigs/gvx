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

package blockdev

import (
	"bytes"
	"context"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/state"
)

const testDynamicSectorsHandler SectorsHandlerID = 1001

func init() {
	RegisterSectorsHandler(testDynamicSectorsHandler, func(d *Device) uint64 {
		return uint64(d.Minor)*4 + 128
	})
}

func TestRegistryStatsAndHandlerStateRoundTrip(t *testing.T) {
	ctx := context.Background()

	var reg Registry
	statsA, clockA := newStats()
	req := statsA.Begin()
	clockA.Advance(6 * time.Millisecond)
	statsA.End(Read, req, 8192)
	req = statsA.Begin()
	clockA.Advance(4 * time.Millisecond)
	statsA.End(Write, req, 4096)
	req = statsA.Begin()
	clockA.Advance(2 * time.Millisecond)
	statsA.End(Discard, req, 16384)
	req = statsA.Begin()
	clockA.Advance(3 * time.Millisecond)
	statsA.End(Flush, req, 0)

	devA, err := reg.Add(Options{
		Stats:        statsA,
		SectorsCount: 2048,
		ReadOnly:     true,
	})
	if err != nil {
		t.Fatalf("Add vda: %v", err)
	}

	statsB, clockB := newStats()
	statsB.Add(Read, 512)
	clockB.Advance(time.Millisecond)
	devB, err := reg.Add(Options{
		Stats:          statsB,
		SectorsHandler: testDynamicSectorsHandler,
		ReadOnly:       false,
	})
	if err != nil {
		t.Fatalf("Add vdb: %v", err)
	}
	if got, want := devA.Sectors(), uint64(2048); got != want {
		t.Fatalf("pre-save vda Sectors() = %d, want %d", got, want)
	}
	if got, want := devB.Sectors(), uint64(16*4+128); got != want {
		t.Fatalf("pre-save vdb Sectors() = %d, want %d", got, want)
	}

	wantSnapA := statsA.Snapshot()
	wantSnapB := statsB.Snapshot()

	var buf bytes.Buffer
	if _, err := state.Save(ctx, &buf, &reg); err != nil {
		t.Fatalf("state.Save Registry: %v", err)
	}

	var restored Registry
	if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load Registry: %v", err)
	}

	restoredVFS := new(vfs.VirtualFilesystem)
	Bind(restoredVFS, &restored)
	if got := Of(restoredVFS); got != &restored {
		t.Fatalf("Of(restoredVFS) = %p, want %p", got, &restored)
	}

	gotA := restored.Find("vda")
	gotB := restored.Find("vdb")
	if gotA == nil || gotB == nil {
		t.Fatalf("restored devices missing: vda=%v vdb=%v", gotA, gotB)
	}
	if gotA.Major != Major || gotA.Minor != 0 || !gotA.ReadOnly || gotA.Sectors() != 2048 {
		t.Fatalf("restored vda = %+v (sectors=%d)", gotA, gotA.Sectors())
	}
	if gotB.Major != Major || gotB.Minor != 16 || gotB.ReadOnly || gotB.Sectors() != 192 {
		t.Fatalf("restored vdb = %+v (sectors=%d)", gotB, gotB.Sectors())
	}
	if gotSnapA := gotA.Stats.Snapshot(); gotSnapA != wantSnapA {
		t.Fatalf("restored vda Snapshot = %+v, want %+v", gotSnapA, wantSnapA)
	}
	if gotSnapB := gotB.Stats.Snapshot(); gotSnapB != wantSnapB {
		t.Fatalf("restored vdb Snapshot = %+v, want %+v", gotSnapB, wantSnapB)
	}

	// Verify restored Stats continues counting with a rebased clock.
	postClock := &fakeClock{now: int64(time.Millisecond)}
	gotA.Stats.SetClock(postClock.Clock)
	postReq := gotA.Stats.Begin()
	postClock.Advance(5 * time.Millisecond)
	gotA.Stats.End(Read, postReq, 4096)

	afterSnap := gotA.Stats.Snapshot()
	if afterSnap.ReadsCompleted != wantSnapA.ReadsCompleted+1 ||
		afterSnap.SectorsRead != wantSnapA.SectorsRead+8 ||
		afterSnap.ReadMillis != wantSnapA.ReadMillis+5 ||
		afterSnap.IOMillis != wantSnapA.IOMillis+5 {
		t.Fatalf("post-restore Snapshot = %+v, baseline was %+v", afterSnap, wantSnapA)
	}

	// Verify next Registry.Add assigns index 2 (vdc).
	devC, err := restored.Add(Options{Stats: NewStats(nil), SectorsCount: 64})
	if err != nil {
		t.Fatalf("post-restore Add: %v", err)
	}
	if devC.Name != "vdc" || devC.Minor != 32 {
		t.Fatalf("post-restore disk = %s (%d), want vdc (32)", devC.Name, devC.Minor)
	}
}

func TestFirstTouchStateRoundTrip(t *testing.T) {
	ctx := context.Background()
	ft := NewFirstTouch(130 * PageSize)

	// Touch pages across two 64-bit bitmap words before saving.
	if got := ft.Claim(0, 3*PageSize); got != 3*PageSize {
		t.Fatalf("initial Claim(0, 3p) = %d, want %d", got, 3*PageSize)
	}
	if got := ft.Claim(63*PageSize, 2*PageSize); got != 2*PageSize {
		t.Fatalf("initial Claim(63p, 2p) = %d, want %d", got, 2*PageSize)
	}
	if got := ft.Claim(128*PageSize, 10*PageSize); got != 2*PageSize {
		t.Fatalf("initial tail Claim = %d, want %d", got, 2*PageSize)
	}

	var buf bytes.Buffer
	if _, err := state.Save(ctx, &buf, ft); err != nil {
		t.Fatalf("state.Save FirstTouch: %v", err)
	}

	var restored FirstTouch
	if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load FirstTouch: %v", err)
	}

	// Previously claimed pages must report 0 fresh bytes after restore.
	if got := restored.Claim(0, 3*PageSize); got != 0 {
		t.Fatalf("re-claim [0, 3p) after restore = %d, want 0", got)
	}
	if got := restored.Claim(63*PageSize, 2*PageSize); got != 0 {
		t.Fatalf("re-claim [63p, 65p) after restore = %d, want 0", got)
	}
	if got := restored.Claim(128*PageSize, 2*PageSize); got != 0 {
		t.Fatalf("re-claim [128p, 130p) after restore = %d, want 0", got)
	}

	// Overlapping range [2p, 5p) has 1 touched page and 2 fresh pages.
	if got := restored.Claim(2*PageSize, 3*PageSize); got != 2*PageSize {
		t.Fatalf("partial overlap Claim(2p, 3p) after restore = %d, want %d", got, 2*PageSize)
	}
}
