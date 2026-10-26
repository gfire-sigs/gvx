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

// The crash tests record every call that a workload sends to the host file.
// They then rebuild the image that a crash leaves after each call and mount
// it. Two crash models apply.
//
//   - Process crash (SIGKILL, a Sentry panic). The host page cache keeps every
//     finished write, in order. The image after the first n calls is a legal
//     state for each n. The engine must mount every such image.
//   - Power loss or host kernel crash. Within the span between two syncs, any
//     subset of the writes can reach the disk, and a write can tear at the
//     sector size. Only the writes before the last finished sync are safe.
//
// After a mount, the recovered image must pass the oracle in strict mode, keep
// every durable file, and show no byte that belongs to another file.

import (
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type auCrashCase struct {
	name string
	// setup builds the durable state. The harness syncs after it.
	setup func(d *auDrv)
	// body is the workload inside the crash window. The unmount that follows is
	// part of the window.
	body func(d *auDrv)
	// check adds case-specific checks of a recovered image.
	check func(res *auResult, durable, final *auModel) []string
}

// auRecoveredProblems checks what every recovered image must satisfy. A relaxed
// check covers a volume without a journal after a power loss. That volume keeps
// no order between its data and its metadata, so only the structure must hold.
func auRecoveredProblems(res *auResult, durable, final *auModel, relaxed bool) []string {
	var out []string
	if !res.OK() {
		out = append(out, "the repaired image fails the oracle: "+strings.ReplaceAll(res.String(), "\n", "; "))
	}
	if relaxed {
		return out
	}
	// A durable object that the window did not touch must survive.
	for p, n := range durable.nodes {
		fn := final.nodes[p]
		if p == "/" || fn == nil || fn.id != n.id || fn.dir != n.dir || string(fn.data) != string(n.data) || fn.target != n.target {
			continue
		}
		e := res.Tree[p]
		switch {
		case e == nil:
			out = append(out, fmt.Sprintf("the durable object %s is gone", p))
		case n.dir:
			if e.mode&0xF000 != 0x4000 {
				out = append(out, fmt.Sprintf("the durable directory %s is not a directory", p))
			}
		case string(e.data) != string(n.data):
			out = append(out, fmt.Sprintf("the durable file %s differs from its synced content at byte %d (size %d, want %d)", p, auFirstDiff(e.data, n.data), len(e.data), len(n.data)))
		}
	}
	// No path appears that never existed, and no file holds foreign bytes.
	for p, e := range res.Tree {
		if p == "/" {
			continue
		}
		ids := final.ids[p]
		if ids == nil {
			out = append(out, fmt.Sprintf("the path %s never existed", p))
			continue
		}
		if e.mode&0xF000 != 0x8000 {
			continue
		}
		ok := false
		for id := range ids {
			if auOwnBytes(e.data, id) {
				ok = true
				break
			}
		}
		if !ok {
			out = append(out, fmt.Sprintf("the file %s holds bytes of no file that lived at that path", p))
		}
	}
	sort.Strings(out)
	return out
}

// auOwnBytes reports whether every non-zero byte of data is a byte of file id.
func auOwnBytes(data []byte, id uint32) bool {
	for i, b := range data {
		if b != 0 && b != auByte(id, uint64(i)) {
			return false
		}
	}
	return true
}

// auRun builds the window of a case and returns it with the models.
func auRun(t *testing.T, c auCrashCase) (w auWindow, durable, final *auModel) {
	t.Helper()
	return auRunOn(t, c, newAuDrv)
}

// auLegacyDrv returns a mounted volume of an older release: no journal. The
// mount does not add one, so the engine runs its legacy mode.
func auLegacyDrv(t *testing.T) *auDrv {
	t.Helper()
	d := newAuDrv(t)
	d.e.unmount()
	legacy := auDowngrade(t, d.f.snapshot())
	disableJournalUpgrade.Store(true)
	t.Cleanup(func() { disableJournalUpgrade.Store(false) })
	return auMount(t, newAuFile(legacy), newAuModel())
}

// auRunOn runs the case on the volume that mk returns and records the window.
func auRunOn(t *testing.T, c auCrashCase, mk func(*testing.T) *auDrv) (w auWindow, durable, final *auModel) {
	t.Helper()
	d := mk(t)
	c.setup(d)
	d.syncAll()
	durable = d.m.clone()
	_, end := d.f.beginWindow()
	c.body(d)
	d.e.unmount()
	w = end()
	return w, durable, d.m
}

// auSummarize groups the problems of many states.
type auSummary struct {
	states  int
	failing int
	first   map[string]int // problem text to the first state that shows it
	count   map[string]int
}

func newAuSummary() *auSummary {
	return &auSummary{first: map[string]int{}, count: map[string]int{}}
}

func (s *auSummary) add(state int, problems []string) {
	s.states++
	if len(problems) == 0 {
		return
	}
	s.failing++
	for _, p := range problems {
		key := p
		// Keep the key short and stable across states.
		if i := strings.IndexAny(key, ":"); i > 0 && strings.HasPrefix(key, "the repaired image") {
			key = key[:i]
		}
		if _, ok := s.first[key]; !ok {
			s.first[key] = state
		}
		s.count[key]++
	}
}

func (s *auSummary) lines() []string {
	var out []string
	for k, n := range s.count {
		out = append(out, fmt.Sprintf("%s (in %d states, first at state %d)", k, n, s.first[k]))
	}
	sort.Strings(out)
	if len(out) > 12 {
		out = append(out[:12], fmt.Sprintf("... and %d more", len(out)-12))
	}
	return out
}

func (s *auSummary) report(t *testing.T, header string) []string {
	t.Helper()
	if s.failing == 0 {
		t.Logf("%s: %d states, all consistent", header, s.states)
		return nil
	}
	return append([]string{fmt.Sprintf("%s: %d of %d states fail", header, s.failing, s.states)}, s.lines()...)
}

// auRecoverState mounts the image and returns all problems of the result.
func auRecoverState(t *testing.T, img *auPages, c auCrashCase, durable, final *auModel, relaxed bool) []string {
	t.Helper()
	res, err := auRecover(t, img)
	if err != nil {
		return []string{"the engine does not mount the image: " + err.Error()}
	}
	out := auRecoveredProblems(res, durable, final, relaxed)
	if c.check != nil && !relaxed {
		out = append(out, c.check(res, durable, final)...)
	}
	return out
}

func auSamples() int {
	if s := os.Getenv("EXT4LITE_AUDIT_SAMPLES"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return 10
}

func auSeed(name string) *rand.Rand {
	h := fnv.New64a()
	h.Write([]byte(name))
	return rand.New(rand.NewPCG(h.Sum64(), 0x5EED))
}

// auCrashTests lists the workloads. Each one stresses a different ordering
// rule of the flush.
var auCrashTests = []auCrashCase{
	{
		name: "create-and-sync",
		setup: func(d *auDrv) {
			d.mkdir("/keep")
			d.create("/keep/a", 70_000)
		},
		body: func(d *auDrv) {
			d.mkdir("/d")
			for i := range 12 {
				d.create(fmt.Sprintf("/d/f%02d", i), 500+i*9000)
				if i == 5 {
					d.fsync("/d/f05")
				}
			}
			d.syncAll()
			d.create("/d/late", 40_000)
		},
	},
	{
		name: "overwrite-and-extend",
		setup: func(d *auDrv) {
			d.create("/db", 1<<20)
			d.create("/wal", 0)
			d.create("/other", 33_000)
		},
		body: func(d *auDrv) {
			for i := range 20 {
				d.pwrite("/wal", i*3000, 3000)
				d.fsync("/wal")
			}
			d.pwrite("/db", 7*blockSize, 2*blockSize)
			d.pwrite("/db", 1<<20, 3*blockSize)
			d.fsync("/db")
			d.truncate("/wal", 100)
		},
	},
	{
		name: "unlink-and-reuse",
		setup: func(d *auDrv) {
			d.create("/old1", 1<<20)
			d.create("/old2", 300_000)
		},
		body: func(d *auDrv) {
			d.unlink("/old1")
			d.create("/new1", 1<<20)
			d.create("/new2", 200_000)
			d.syncAll()
			d.unlink("/new1")
			d.create("/new3", 1<<20)
		},
	},
	{
		name: "replace-by-rename",
		setup: func(d *auDrv) {
			d.mkdir("/etc")
			d.create("/etc/cfg", 20_000)
		},
		body: func(d *auDrv) {
			d.create("/etc/cfg.tmp", 25_000)
			d.fsync("/etc/cfg.tmp")
			d.rename("/etc/cfg.tmp", "/etc/cfg")
			d.fsync("/etc")
		},
		check: func(res *auResult, durable, final *auModel) []string {
			e := res.Tree["/etc/cfg"]
			if e == nil {
				return []string{"/etc/cfg vanished across an atomic replace"}
			}
			if string(e.data) != string(durable.nodes["/etc/cfg"].data) && string(e.data) != string(final.nodes["/etc/cfg"].data) {
				return []string{"/etc/cfg holds neither the old nor the new content"}
			}
			return nil
		},
	},
	{
		name: "rename-across-directories",
		setup: func(d *auDrv) {
			d.mkdir("/a")
			d.mkdir("/b")
			d.create("/a/f", 20_000)
			d.mkdir("/a/sub")
			d.create("/a/sub/inner", 9_000)
		},
		body: func(d *auDrv) {
			d.rename("/a/f", "/b/g")
			d.syncAll()
			d.rename("/b/g", "/a/h")
			d.rename("/a/sub", "/b/sub")
			d.syncAll()
		},
		check: func(res *auResult, durable, final *auModel) []string {
			var out []string
			names := [][]string{{"/a/f", "/b/g", "/a/h"}, {"/a/sub/inner", "/b/sub/inner"}}
			for _, set := range names {
				n := 0
				for _, p := range set {
					if res.Tree[p] != nil {
						n++
					}
				}
				if n != 1 {
					out = append(out, fmt.Sprintf("a renamed object exists under %d of the names %v, want exactly one", n, set))
				}
			}
			return out
		},
	},
	{
		name: "directory-growth",
		setup: func(d *auDrv) {
			d.mkdir("/big")
			for i := range 30 {
				d.create(fmt.Sprintf("/big/keep-%03d", i), 100)
			}
			d.mkdir("/big2")
		},
		body: func(d *auDrv) {
			for i := range 220 {
				d.create(fmt.Sprintf("/big/entry-with-a-rather-long-name-%04d", i), 0)
			}
			for i := 0; i < 220; i += 2 {
				d.unlink(fmt.Sprintf("/big/entry-with-a-rather-long-name-%04d", i))
			}
			d.syncAll()
			for i := 1; i < 40; i += 2 {
				d.rename(fmt.Sprintf("/big/entry-with-a-rather-long-name-%04d", i), fmt.Sprintf("/big2/m%03d", i))
			}
		},
	},
	{
		name: "sparse-and-stale-data",
		setup: func(d *auDrv) {
			d.create("/secret", 200_000)
			d.create("/keep", 12_345)
		},
		body: func(d *auDrv) {
			d.unlink("/secret")
			d.syncAll()
			d.create("/holes", 0)
			d.truncate("/holes", 600_000)
			d.pwrite("/holes", 300_000, 5)
			d.pwrite("/holes", 450_001, 4097)
			d.fsync("/holes")
			d.truncate("/holes", 1000)
		},
	},
	{
		name: "group-growth",
		setup: func(d *auDrv) {
			d.create("/seed", 5000)
		},
		body: func(d *auDrv) {
			d.create("/grow", 0)
			for i := range 6 {
				d.pwrite("/grow", i*(4<<20), 4<<20)
				if i == 2 {
					d.fsync("/grow")
				}
			}
			d.syncAll()
		},
	},
	{
		name: "unmount-compaction",
		setup: func(d *auDrv) {
			d.create("/a", 9<<20)
			d.create("/b", 9<<20)
			d.create("/c", 9<<20)
			d.create("/d", 100_000)
		},
		body: func(d *auDrv) {
			d.unlink("/a")
			d.unlink("/b")
			d.truncate("/c", 1<<20)
		},
	},
	{
		name: "mixed-random",
		setup: func(d *auDrv) {
			d.mkdir("/r")
			d.create("/r/base", 30_000)
		},
		body: func(d *auDrv) {
			auRandomOps(d, auSeed("mixed-random-crash"), 70, true)
		},
	},
}

// TestAuditCrashProcess crashes after every call that reaches the host file.
// The host page cache keeps writes in order, so the engine must mount every
// image and keep what a sync made durable.
func TestAuditCrashProcess(t *testing.T) {
	auCrashProcess(t, newAuDrv, false)
}

// TestAuditCrashProcessLegacy runs the same crashes on a volume without a
// journal. The tolerant fsckLite must mount every image and keep what a sync
// made durable.
func TestAuditCrashProcessLegacy(t *testing.T) {
	auCrashProcess(t, auLegacyDrv, true)
}

// auCrashProcess crashes after every host call. A volume without a journal
// cannot make a rename across directories atomic, so the case checks of the
// atomicity apply only to a journaled volume.
func auCrashProcess(t *testing.T, mk func(*testing.T) *auDrv, legacy bool) {
	for _, c := range auCrashTests {
		t.Run(c.name, func(t *testing.T) {
			w, durable, final := auRunOn(t, c, mk)
			if legacy {
				c.check = nil
			}
			sum := newAuSummary()
			prev := -1
			for n := 0; n <= len(w.ops); n++ {
				if n > 0 && w.ops[n-1].kind == auSync && prev == n-1 {
					continue
				}
				prev = n
				sum.add(n, auRecoverState(t, w.prefix(n), c, durable, final, false))
			}
			if lines := sum.report(t, fmt.Sprintf("%s: %d host calls", c.name, len(w.ops))); len(lines) > 0 {
				t.Errorf("%s", strings.Join(lines, "\n  "))
			}
		})
	}
}

// TestAuditCrashPowerLoss crashes inside a sync epoch, with a random subset of
// the writes and with torn sectors. The ext4lite flush writes all stages and
// syncs once, so it does not order the stages for a power loss. The test
// reports the gap as known defect AUD-01 until a barrier or a journal closes
// it.
func TestAuditCrashPowerLoss(t *testing.T) {
	auCrashPowerLoss(t, newAuDrv, false)
}

// TestAuditCrashPowerLossLegacy crashes a volume without a journal inside a
// sync epoch. The volume keeps no order between its data and its metadata, so
// the test requires only a mountable and consistent image.
func TestAuditCrashPowerLossLegacy(t *testing.T) {
	auCrashPowerLoss(t, auLegacyDrv, true)
}

func auCrashPowerLoss(t *testing.T, mk func(*testing.T) *auDrv, relaxed bool) {
	samples := auSamples()
	for _, c := range auCrashTests {
		t.Run(c.name, func(t *testing.T) {
			w, durable, final := auRunOn(t, c, mk)
			rng := auSeed(c.name)
			sum := newAuSummary()
			state := 0
			for _, ep := range w.epochs() {
				if ep[1] <= ep[0] {
					continue
				}
				for s := range samples {
					keep := []float64{0.3, 0.6, 0.9}[s%3]
					img := w.powerLoss(ep[0], ep[1], rng, keep, s%2 == 1)
					sum.add(state, auRecoverState(t, img, c, durable, final, relaxed))
					state++
				}
			}
			if lines := sum.report(t, fmt.Sprintf("%s: %d epochs", c.name, len(w.epochs()))); len(lines) > 0 {
				t.Errorf("%s", strings.Join(lines, "\n  "))
			}
		})
	}
}
