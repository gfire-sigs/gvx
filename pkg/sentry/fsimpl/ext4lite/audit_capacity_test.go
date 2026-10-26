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
	"testing"
)

// The host file of a volume must never be larger than its groups need. A host
// without sparse files turns every extra byte into disk space, so the journal,
// the extent trees, and the recovery may not grow the file beyond one 16 MiB
// group for each group of the volume. The tests run both storage tiers.

var auTiers = []storageTier{tierNative, tierFallback}

// newAuDrvOn formats a volume on a host file of the given tier and mounts it.
func newAuDrvOn(t *testing.T, tier storageTier) *auDrv {
	t.Helper()
	auNoFlusher(t)
	f := newAuFile(nil)
	f.tier = tier
	return auMount(t, f, newAuModel())
}

// auRecoverOn mounts a crash image on a host file of the given tier. The caller
// closes the volume.
func auRecoverOn(img *auPages, tier storageTier) (*auFile, *volume, error) {
	f := newAuFile(img.clone())
	f.tier = tier
	v, err := mountHostFile(f, VolumeOptions{})
	return f, v, err
}

// TestAuditCapacityJournalWrapDoesNotGrowTheFile makes 1500 commits, which
// takes the log through its end several times. The file stays at one group.
func TestAuditCapacityJournalWrapDoesNotGrowTheFile(t *testing.T) {
	for _, tier := range auTiers {
		t.Run(tier.String(), func(t *testing.T) {
			d := newAuDrvOn(t, tier)
			for i := range 1500 {
				d.create(fmt.Sprintf("/f%04d", i), 10)
				d.syncAll()
			}
			d.e.unmount()
			if d.f.maxSize != groupBytes {
				t.Errorf("the host file reached %d bytes, want %d for one group", d.f.maxSize, groupBytes)
			}
		})
	}
}

// TestAuditCapacityRandomWorkloadStaysWithinTheGroups runs random operations and
// checks the peak size of the host file against the number of groups that the
// volume ever had.
func TestAuditCapacityRandomWorkloadStaysWithinTheGroups(t *testing.T) {
	for _, tier := range auTiers {
		t.Run(tier.String(), func(t *testing.T) {
			d := newAuDrvOn(t, tier)
			rng := rand.New(rand.NewPCG(31, 7))
			peakGroups := 1
			for range 12 {
				auRandomOps(d, rng, 60, true)
				peakGroups = max(peakGroups, int(d.e.fs.v.numGroups()))
			}
			d.e.unmount()
			if limit := int64(peakGroups) * groupBytes; d.f.maxSize > limit {
				t.Errorf("the host file reached %d bytes for at most %d groups, the limit is %d", d.f.maxSize, peakGroups, limit)
			}
		})
	}
}

// TestAuditCapacityRecoveryDoesNotGrowTheFile mounts the crash image of every
// host call of a workload that grows and then shrinks the volume. The recovery
// replays a log, so it must not enlarge the file beyond what the image holds or
// what the volume of the image needs.
func TestAuditCapacityRecoveryDoesNotGrowTheFile(t *testing.T) {
	cases := map[string]auCrashCase{}
	for _, c := range auCrashTests {
		cases[c.name] = c
	}
	for _, tier := range auTiers {
		for _, name := range []string{"group-growth", "unmount-compaction"} {
			t.Run(tier.String()+"/"+name, func(t *testing.T) {
				w, _, _ := auRunOn(t, cases[name], func(t *testing.T) *auDrv { return newAuDrvOn(t, tier) })
				for n := 0; n <= len(w.ops); n++ {
					img := w.prefix(n)
					f, v, err := auRecoverOn(img, tier)
					if err != nil {
						t.Fatalf("mount after %d host calls: %v", n, err)
					}
					groups := int64(len(v.groups))
					if err := (&Volume{v: v}).Close(); err != nil {
						t.Fatalf("close after %d host calls: %v", n, err)
					}
					// The recovery can make the file as large as the groups that the
					// recovered volume has, and never larger.
					limit := max(img.size, groups*groupBytes)
					if f.maxSize > limit {
						t.Fatalf("after %d host calls the recovery grew the host file to %d bytes, the limit is %d", n, f.maxSize, limit)
					}
				}
			})
		}
	}
}

// TestAuditCapacityUpgradeDoesNotGrowTheFile adds a journal to an old volume on
// both tiers. The journal takes blocks that the volume already has.
func TestAuditCapacityUpgradeDoesNotGrowTheFile(t *testing.T) {
	for _, tier := range auTiers {
		t.Run(tier.String(), func(t *testing.T) {
			img, model := auFreshImage(t)
			legacy := auDowngrade(t, img)
			f := newAuFile(legacy)
			f.tier = tier
			size := legacy.size
			d := auMount(t, f, model)
			if d.e.fs.v.j == nil {
				t.Fatal("no journal after the mount")
			}
			d.syncAll()
			d.e.unmount()
			if f.maxSize > size {
				t.Errorf("the upgrade grew the host file from %d to %d bytes", size, f.maxSize)
			}
		})
	}
}
