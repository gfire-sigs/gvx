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
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
	"strings"
	"testing"
)

var auSizes = []int{0, 1, 59, 60, 61, 128, 129, 1000, 4095, 4096, 4097, 9000, 40_000, 150_000}

// auPick returns the paths of the model that match keep, sorted.
func auPick(m *auModel, keep func(p string, n *auMNode) bool) []string {
	var out []string
	for p, n := range m.nodes {
		if p != "/" && keep(p, n) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func auChoose(rng *rand.Rand, s []string) (string, bool) {
	if len(s) == 0 {
		return "", false
	}
	return s[rng.IntN(len(s))], true
}

// auRandomOps runs n random valid operations. Every operation succeeds on a
// correct file system, so the driver stops the test at the first error. When
// withSync is true, the run also calls fsync and sync at random points.
func auRandomOps(d *auDrv, rng *rand.Rand, n int, withSync bool) {
	d.t.Helper()
	fresh := func() string { d.rd++; return fmt.Sprintf("n%d", d.rd) }
	dirs := func() []string {
		out := []string{"/"}
		return append(out, auPick(d.m, func(_ string, n *auMNode) bool { return n.dir })...)
	}
	files := func() []string {
		return auPick(d.m, func(_ string, n *auMNode) bool { return !n.dir && !n.sym })
	}
	for range n {
		switch r := rng.IntN(100); {
		case r < 18: // create
			dir, _ := auChoose(rng, dirs())
			d.create(auJoin(dir, fresh()), auSizes[rng.IntN(len(auSizes))])
		case r < 24: // mkdir
			dir, _ := auChoose(rng, dirs())
			if strings.Count(dir, "/") < 4 {
				d.mkdir(auJoin(dir, fresh()))
			}
		case r < 44: // pwrite
			if p, ok := auChoose(rng, files()); ok {
				size := len(d.m.nodes[p].data)
				off := 0
				if size > 0 && rng.IntN(3) > 0 {
					off = rng.IntN(size + 1)
				} else if rng.IntN(4) == 0 {
					off = size + rng.IntN(20_000)
				}
				d.pwrite(p, off, 1+rng.IntN(12_000))
			}
		case r < 52: // truncate
			if p, ok := auChoose(rng, files()); ok {
				size := len(d.m.nodes[p].data)
				d.truncate(p, max(0, size+rng.IntN(40_000)-20_000))
			}
		case r < 60: // unlink
			if p, ok := auChoose(rng, auPick(d.m, func(_ string, n *auMNode) bool { return !n.dir })); ok {
				d.unlink(p)
			}
		case r < 63: // rmdir
			empty := auPick(d.m, func(p string, n *auMNode) bool { return n.dir && len(d.m.entries(p)) == 0 })
			if p, ok := auChoose(rng, empty); ok {
				d.rmdir(p)
			}
		case r < 72: // rename a file or a link, maybe over another file
			src, ok := auChoose(rng, auPick(d.m, func(_ string, n *auMNode) bool { return !n.dir }))
			if !ok {
				break
			}
			dir, _ := auChoose(rng, dirs())
			dst := auJoin(dir, fresh())
			if rng.IntN(4) == 0 {
				if over, ok := auChoose(rng, auPick(d.m, func(_ string, n *auMNode) bool { return !n.dir })); ok && d.m.nodes[over] != d.m.nodes[src] {
					dst = over
				}
			}
			d.rename(src, dst)
		case r < 77: // rename a directory
			src, ok := auChoose(rng, auPick(d.m, func(_ string, n *auMNode) bool { return n.dir }))
			if !ok {
				break
			}
			var targets []string
			for _, dir := range dirs() {
				if dir != src && !strings.HasPrefix(dir+"/", src+"/") && strings.Count(dir, "/") < 4 {
					targets = append(targets, dir)
				}
			}
			if dir, ok := auChoose(rng, targets); ok {
				d.rename(src, auJoin(dir, fresh()))
			}
		case r < 82: // link
			if src, ok := auChoose(rng, files()); ok {
				dir, _ := auChoose(rng, dirs())
				d.link(src, auJoin(dir, fresh()))
			}
		case r < 86: // symlink
			dir, _ := auChoose(rng, dirs())
			d.symlink(strings.Repeat("x", 1+rng.IntN(100)), auJoin(dir, fresh()))
		case r < 96:
			if withSync {
				if p, ok := auChoose(rng, append(files(), dirs()...)); ok {
					d.fsync(p)
				}
			}
		default:
			if withSync {
				d.syncAll()
			}
		}
	}
}

// TestAuditRandomDifferential runs seeded random workloads against the engine
// and the model. After the run it checks the live tree, the image after a
// clean unmount, the image that a sync made durable before a crash, and the
// image after a remount.
func TestAuditRandomDifferential(t *testing.T) {
	seeds := 16
	if testing.Short() {
		seeds = 2
	}
	for seed := range seeds {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) {
			rng := rand.New(rand.NewPCG(uint64(seed)+1, 0xA5D17))
			d := newAuDrv(t)
			for round := range 5 {
				auRandomOps(d, rng, 120, true)
				d.verifyLive(fmt.Sprintf("round %d", round))
			}

			// After a sync, a crash must lose nothing.
			d.syncAll()
			res, err := auRecover(t, d.f.snapshot())
			if err != nil {
				t.Fatalf("mount after a crash that follows a sync: %v", err)
			}
			if !res.OK() {
				t.Errorf("image after sync and crash:\n%s", res)
			}
			for _, msg := range auCompareImage(res, d.m) {
				t.Errorf("synced state lost: %s", msg)
			}

			d.e.unmount()
			res = auFsck(d.f.snapshot(), true)
			if !res.OK() {
				t.Fatalf("image after clean unmount:\n%s", res)
			}
			for _, msg := range auCompareImage(res, d.m) {
				t.Errorf("clean image against model: %s", msg)
			}
			d2 := auMount(t, newAuFile(d.f.snapshot()), d.m)
			d2.rd = d.rd
			d2.verifyLive("remount")
			auRandomOps(d2, rng, 60, true)
			d2.verifyLive("after remount")
		})
	}
}

// TestAuditSpaceIsReturned fills a volume with random work, deletes everything,
// and requires that the free counters return to the values of an empty volume.
// A leak of a block or an inode shows as a lower count.
func TestAuditSpaceIsReturned(t *testing.T) {
	empty := func() (uint64, uint64) {
		auNoFlusher(t)
		f := newAuFile(nil)
		if err := formatVolume(f, testNow); err != nil {
			t.Fatal(err)
		}
		r := auFsck(f.snapshot(), true)
		return r.FreeBlocks, r.FreeInodes
	}
	wantB, wantI := empty()

	d := newAuDrv(t)
	rng := rand.New(rand.NewPCG(99, 7))
	auRandomOps(d, rng, 250, true)
	// Remove everything, deepest first.
	paths := auPick(d.m, func(string, *auMNode) bool { return true })
	slices.SortFunc(paths, func(a, b string) int { return strings.Count(b, "/") - strings.Count(a, "/") })
	for _, p := range paths {
		if n := d.m.nodes[p]; n == nil {
			continue
		} else if n.dir {
			d.rmdir(p)
		} else {
			d.unlink(p)
		}
	}
	d.e.unmount()
	res := auFsck(d.f.snapshot(), true)
	if !res.OK() {
		t.Fatalf("image:\n%s", res)
	}
	if res.Groups != 1 {
		t.Errorf("the volume has %d groups after the delete, want the trim to leave 1", res.Groups)
	}
	if res.FreeBlocks != wantB || res.FreeInodes != wantI {
		t.Errorf("free blocks/inodes = %d/%d, want %d/%d as in an empty volume", res.FreeBlocks, res.FreeInodes, wantB, wantI)
	}
}
