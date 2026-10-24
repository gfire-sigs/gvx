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

package ext4lite

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"testing"
)

// replica is the target image of a pre-copy migration. It holds the blocks
// that the test copied from the source volume.
type replica struct {
	data []byte
}

// copyFrom reads the runs from the host file of v and stores them.
func (r *replica) copyFrom(t testing.TB, v *volume, runs []BlockExtent) {
	t.Helper()
	for _, run := range runs {
		end := int((run.Block + run.Count) * blockSize)
		if end > len(r.data) {
			r.data = append(r.data, make([]byte, end-len(r.data))...)
		}
		buf := r.data[int(run.Block*blockSize):end]
		if _, err := v.hf.ReadAt(buf, int64(run.Block*blockSize)); err != nil {
			t.Fatalf("read the blocks %d+%d: %v", run.Block, run.Count, err)
		}
	}
}

// migrationHarness runs a source volume against a replica.
type migrationHarness struct {
	t   *testing.T
	v   *volume
	api *Volume
	rep replica
}

func newMigrationHarness(t *testing.T, tier storageTier) *migrationHarness {
	v, _ := newTestVolume(t, tier)
	t.Cleanup(func() { _ = v.close() })
	return &migrationHarness{t: t, v: v, api: &Volume{v: v}}
}

// start turns the tracking on and copies the allocated blocks, in the order that
// a migration uses.
func (h *migrationHarness) start() {
	h.t.Helper()
	h.api.EnableMigrationTracking()
	h.rep.copyFrom(h.t, h.v, h.api.AllocatedBlocks())
}

// drain copies the blocks of one drain to the replica and returns the runs.
func (h *migrationHarness) drain() []BlockExtent {
	h.t.Helper()
	runs, err := h.api.DrainDirtyBlocks()
	if err != nil {
		h.t.Fatalf("DrainDirtyBlocks: %v", err)
	}
	h.rep.copyFrom(h.t, h.v, runs)
	return runs
}

// verify checks that every allocated block of the source equals the replica
// after a drain of a quiet volume, and that the replica mounts with the files
// of the source.
func (h *migrationHarness) verify() {
	h.t.Helper()
	for _, run := range h.api.AllocatedBlocks() {
		for blk := run.Block; blk < run.Block+run.Count; blk++ {
			var want [blockSize]byte
			if _, err := h.v.hf.ReadAt(want[:], int64(blk*blockSize)); err != nil {
				h.t.Fatal(err)
			}
			lo := int(blk * blockSize)
			if lo+blockSize > len(h.rep.data) || !bytes.Equal(h.rep.data[lo:lo+blockSize], want[:]) {
				h.t.Fatalf("block %d differs between the source and the replica", blk)
			}
		}
	}
	groups := int(h.v.numGroups())
	image := make([]byte, groups*groupBytes)
	copy(image, h.rep.data)
	path := filepath.Join(h.t.TempDir(), "replica.ext4")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		h.t.Fatal(err)
	}
	// The replica is a complete image, so e2fsck accepts it before any mount.
	if _, err := exec.LookPath("e2fsck"); err == nil {
		runE2fsck(h.t, path)
	}
	rv := reopenVolume(h.t, path)
	defer rv.close()
	compareTrees(h.t, h.v, mustRoot(h.t, h.v), rv, mustRoot(h.t, rv), "")
	_ = os.Remove(path)
}

// compareTrees compares the names, sizes, and bytes of two directory trees.
func compareTrees(t *testing.T, av *volume, a *node, bv *volume, b *node, path string) {
	t.Helper()
	an, bn := listNames(t, a), listNames(t, b)
	if fmt.Sprint(an) != fmt.Sprint(bn) {
		t.Fatalf("directory %q: source has %v, replica has %v", path, an, bn)
	}
	for _, name := range an {
		ac, bc := lookupNode(t, av, a, name), lookupNode(t, bv, b, name)
		p := path + "/" + name
		if ac.isDir() {
			compareTrees(t, av, ac, bv, bc, p)
			continue
		}
		if ac.isRegular() {
			if !bytes.Equal(readAll(t, ac), readAll(t, bc)) {
				t.Fatalf("file %q differs between the source and the replica", p)
			}
		}
	}
}

func listNames(t *testing.T, dir *node) []string {
	t.Helper()
	ents, err := dir.entries()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		if e.name != "." && e.name != ".." {
			names = append(names, e.name)
		}
	}
	slices.Sort(names)
	return names
}

func blocksIn(runs []BlockExtent, blk uint64) bool {
	for _, r := range runs {
		if blk >= r.Block && blk < r.Block+r.Count {
			return true
		}
	}
	return false
}

func TestAllocatedBlocksCoverTheUsedBlocksOnly(t *testing.T) {
	v, _ := newTestVolume(t, platformTier)
	defer v.close()
	api := &Volume{v: v}
	root := mustRoot(t, v)
	f := createChild(t, v, root, "f", modeRegular|0o644)
	writeAll(t, f, 0, pattern(1, 3*blockSize+17))

	runs := api.AllocatedBlocks()
	v.mu.Lock()
	defer v.mu.Unlock()
	var used uint64
	for gi, g := range v.groups {
		for i := uint32(0); i < blocksPerGroup; i++ {
			blk := groupStart(uint32(gi)) + uint64(i)
			if got := blocksIn(runs, blk); got != g.blocks.test(i) {
				t.Fatalf("block %d: in the snapshot = %v, allocated = %v", blk, got, g.blocks.test(i))
			}
			if g.blocks.test(i) {
				used++
			}
		}
		for b := uint32(0); b < metaBlocksOf(uint32(gi)); b++ {
			if !blocksIn(runs, groupStart(uint32(gi))+uint64(b)) {
				t.Fatalf("metadata block %d of group %d is missing", b, gi)
			}
		}
	}
	var total uint64
	for i, r := range runs {
		total += r.Count
		if r.Count == 0 || (i > 0 && runs[i-1].Block+runs[i-1].Count >= r.Block) {
			t.Fatalf("runs are not ascending and separate: %v", runs)
		}
	}
	if total != used {
		t.Fatalf("the runs hold %d blocks, the bitmaps mark %d", total, used)
	}
	if free := uint64(blocksPerGroup) - used; free == 0 {
		t.Fatal("the test volume has no free block")
	}
	for _, e := range f.exts {
		for blk := e.pblk; blk < e.pblk+uint64(e.n); blk++ {
			if !blocksIn(runs, blk) {
				t.Fatalf("data block %d of the file is missing", blk)
			}
		}
	}
}

func TestAppendBitmapRunsJoinsAcrossGroups(t *testing.T) {
	var a, b bitmap
	a.set(blocksPerGroup - 2)
	a.set(blocksPerGroup - 1)
	b.set(0)
	b.set(1)
	b.set(5)
	var out []BlockExtent
	out = appendBitmapRuns(out, 0, &a)
	out = appendBitmapRuns(out, blocksPerGroup, &b)
	want := []BlockExtent{{Block: blocksPerGroup - 2, Count: 4}, {Block: blocksPerGroup + 5, Count: 1}}
	if fmt.Sprint(out) != fmt.Sprint(want) {
		t.Fatalf("runs = %v, want %v", out, want)
	}
}

func TestDrainNeedsTracking(t *testing.T) {
	v, _ := newTestVolume(t, platformTier)
	defer v.close()
	api := &Volume{v: v}
	if _, err := api.DrainDirtyBlocks(); !errors.Is(err, ErrMigrationTrackingOff) {
		t.Fatalf("DrainDirtyBlocks before the tracking = %v, want ErrMigrationTrackingOff", err)
	}
	root := mustRoot(t, v)
	f := createChild(t, v, root, "f", modeRegular|0o644)
	writeAll(t, f, 0, pattern(2, 2*blockSize))
	if v.migOn.Load() {
		t.Fatal("a write before EnableMigrationTracking turned the tracking on")
	}
	v.mu.Lock()
	for _, g := range v.groups {
		if g.migDirty != nil {
			v.mu.Unlock()
			t.Fatal("a write before EnableMigrationTracking marked a block")
		}
	}
	v.mu.Unlock()
}

func TestDrainReturnsTheWrittenBlocksOnceAndClearsThem(t *testing.T) {
	h := newMigrationHarness(t, platformTier)
	root := mustRoot(t, h.v)
	f := createChild(t, h.v, root, "f", modeRegular|0o644)
	writeAll(t, f, 0, pattern(3, 4*blockSize))
	h.api.EnableMigrationTracking()
	h.drain()
	if runs := h.drain(); len(runs) != 0 {
		t.Fatalf("a quiet volume drained %v", runs)
	}

	// Rewrite the second block of the file only.
	phys, ok := f.physBlock(1)
	if !ok {
		t.Fatal("the file has no block 1")
	}
	writeAll(t, f, blockSize+10, []byte("changed"))
	runs, err := h.api.DrainDirtyBlocks()
	if err != nil {
		t.Fatal(err)
	}
	if !blocksIn(runs, phys) {
		t.Fatalf("the drain %v misses the data block %d", runs, phys)
	}
	if blocksIn(runs, phys-1) || blocksIn(runs, phys+1) {
		t.Fatalf("the drain %v holds the neighbors of the written block %d", runs, phys)
	}
	if again := h.drain(); len(again) != 0 {
		t.Fatalf("the second drain returned %v, want nothing", again)
	}
}

// TestMigrationReplicatesEveryWriteSite runs one scenario for each place that
// writes to the host file. Each scenario copies the allocated blocks, mutates
// the volume, drains, and compares the replica with the source.
func TestMigrationReplicatesEveryWriteSite(t *testing.T) {
	type scenario struct {
		name   string
		setup  func(t *testing.T, v *volume, root *node)
		mutate func(t *testing.T, v *volume, root *node)
	}
	chunk := pattern(4, 1<<20)
	scenarios := []scenario{
		{
			name: "mapped write",
			setup: func(t *testing.T, v *volume, root *node) {
				writeAll(t, createChild(t, v, root, "f", modeRegular|0o644), 0, pattern(5, 5*blockSize))
			},
			mutate: func(t *testing.T, v *volume, root *node) {
				f := lookupNode(t, v, root, "f")
				writeAll(t, f, 100, []byte("overwrite inside the first block"))
				writeAll(t, f, 5*blockSize, pattern(6, 2*blockSize+9))
			},
		},
		{
			name: "inline file grows into an extent",
			setup: func(t *testing.T, v *volume, root *node) {
				writeAll(t, createChild(t, v, root, "small", modeRegular|0o644), 0, []byte("inline bytes"))
			},
			mutate: func(t *testing.T, v *volume, root *node) {
				writeAll(t, lookupNode(t, v, root, "small"), 0, pattern(7, 3*blockSize))
			},
		},
		{
			name: "write that leaves partial edges in a new extent",
			setup: func(t *testing.T, v *volume, root *node) {
				createChild(t, v, root, "sparse", modeRegular|0o644)
			},
			mutate: func(t *testing.T, v *volume, root *node) {
				f := lookupNode(t, v, root, "sparse")
				writeAll(t, f, 5*blockSize+300, pattern(8, 4*blockSize))
			},
		},
		{
			name: "truncate clears the tail of the last block",
			setup: func(t *testing.T, v *volume, root *node) {
				writeAll(t, createChild(t, v, root, "t", modeRegular|0o644), 0, bytes.Repeat([]byte{0xAA}, 3*blockSize))
			},
			mutate: func(t *testing.T, v *volume, root *node) {
				f := lookupNode(t, v, root, "t")
				if err := f.truncate(blockSize + 50); err != nil {
					t.Fatal(err)
				}
				if err := f.truncate(3 * blockSize); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "punch hole clears the edge blocks",
			setup: func(t *testing.T, v *volume, root *node) {
				writeAll(t, createChild(t, v, root, "p", modeRegular|0o644), 0, bytes.Repeat([]byte{0xBB}, 6*blockSize))
			},
			mutate: func(t *testing.T, v *volume, root *node) {
				if err := lookupNode(t, v, root, "p").punchHole(blockSize/2, 4*blockSize); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "preallocate zero-fills new blocks",
			setup: func(t *testing.T, v *volume, root *node) {
				createChild(t, v, root, "a", modeRegular|0o644)
			},
			mutate: func(t *testing.T, v *volume, root *node) {
				if err := lookupNode(t, v, root, "a").preallocate(0, 3<<20, false); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "attribute block",
			setup: func(t *testing.T, v *volume, root *node) {
				createChild(t, v, root, "x", modeRegular|0o644)
			},
			mutate: func(t *testing.T, v *volume, root *node) {
				if err := lookupNode(t, v, root, "x").setXattr("user.big", pattern(9, 2000), false, false); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "directory blocks",
			setup: func(t *testing.T, v *volume, root *node) {
				createChild(t, v, root, "d", modeDir|0o755)
			},
			mutate: func(t *testing.T, v *volume, root *node) {
				d := lookupNode(t, v, root, "d")
				for i := range 300 {
					createChild(t, v, d, fmt.Sprintf("entry-with-a-long-name-%04d", i), modeRegular|0o644)
				}
			},
		},
		{
			name: "new groups",
			setup: func(t *testing.T, v *volume, root *node) {
				createChild(t, v, root, "big", modeRegular|0o644)
			},
			mutate: func(t *testing.T, v *volume, root *node) {
				f := lookupNode(t, v, root, "big")
				for i := range 40 {
					writeAll(t, f, int64(i)<<20, chunk)
				}
				if v.numGroups() < 3 {
					t.Fatalf("the volume has %d groups, want at least 3", v.numGroups())
				}
			},
		},
		{
			name: "compaction relocates blocks",
			setup: func(t *testing.T, v *volume, root *node) {
				drop := createChild(t, v, root, "drop", modeRegular|0o644)
				keep := createChild(t, v, root, "keep", modeRegular|0o644)
				for i := range 20 {
					writeAll(t, drop, int64(i)<<20, chunk)
				}
				for i := range 6 {
					writeAll(t, keep, int64(i)<<20, chunk)
				}
			},
			mutate: func(t *testing.T, v *volume, root *node) {
				unlink(t, v, root, "drop", lookupNode(t, v, root, "drop"))
				v.destroyUnlinkedNodes()
				v.flushMu.Lock()
				defer v.flushMu.Unlock()
				if err := v.compactLocked(); err != nil {
					t.Fatalf("compactLocked: %v", err)
				}
			},
		},
	}
	for _, tier := range []storageTier{platformTier, tierFallback} {
		for _, sc := range scenarios {
			t.Run(fmt.Sprintf("%v/%s", tier, sc.name), func(t *testing.T) {
				h := newMigrationHarness(t, tier)
				root := mustRoot(t, h.v)
				sc.setup(t, h.v, root)
				h.start()
				sc.mutate(t, h.v, root)
				if runs := h.drain(); len(runs) == 0 {
					t.Fatal("the scenario wrote to the volume and the drain is empty")
				}
				h.verify()
			})
		}
	}
}

func TestMigrationDrainsInRounds(t *testing.T) {
	h := newMigrationHarness(t, platformTier)
	root := mustRoot(t, h.v)
	f := createChild(t, h.v, root, "f", modeRegular|0o644)
	writeAll(t, f, 0, pattern(10, 8*blockSize))
	h.start()
	for round := range 5 {
		writeAll(t, f, int64(round*blockSize+round), pattern(byte(20+round), 3*blockSize))
		g := createChild(t, h.v, root, fmt.Sprintf("n%d", round), modeRegular|0o644)
		writeAll(t, g, 0, pattern(byte(30+round), 200))
		h.drain()
	}
	h.drain()
	h.verify()
}

// TestMigrationWithConcurrentWriters lets writers run while drains copy the
// blocks. A block that a write marks after a drain must reach the next drain.
// The final drain runs when the writers have stopped.
func TestMigrationWithConcurrentWriters(t *testing.T) {
	h := newMigrationHarness(t, platformTier)
	root := mustRoot(t, h.v)
	const writers = 4
	files := make([]*node, writers)
	for i := range files {
		files[i] = createChild(t, h.v, root, fmt.Sprintf("w%d", i), modeRegular|0o644)
		writeAll(t, files[i], 0, pattern(byte(40+i), 6*blockSize))
	}
	h.start()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := range files {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for round := 0; ; round++ {
				select {
				case <-stop:
					return
				default:
				}
				off := int64((round*7+i)%20) * 997
				if _, err := files[i].writeAt(pattern(byte(round), 1500+round%3000), off); err != nil {
					t.Errorf("writer %d: %v", i, err)
					return
				}
			}
		}()
	}
	for range 25 {
		h.drain()
	}
	close(stop)
	wg.Wait()
	h.drain()
	h.verify()
}
