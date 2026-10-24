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
	"os"
	"testing"
)

// unlink removes name from dir and drops the last reference of its inode.
func unlink(t testing.TB, v *volume, dir *node, name string, n *node) {
	t.Helper()
	if err := dir.removeEntry(name); err != nil {
		t.Fatal(err)
	}
	setLinks(n, 0)
	v.putNode(n)
}

// TestCompactionShrinksHostFile writes 48 MiB, deletes 40 MiB, and expects
// the clean unmount to return every trailing group. The 8 MiB that stay sit
// in the last groups before the unmount, so the unmount has to move them.
func TestCompactionShrinksHostFile(t *testing.T) {
	for _, tier := range []storageTier{platformTier, tierFallback} {
		v, path := newTestVolume(t, tier)
		root := mustRoot(t, v)
		chunk := pattern(3, 1<<20)
		fill := func(n *node, mib int) {
			for i := range mib {
				writeAll(t, n, int64(i)<<20, chunk)
			}
		}
		drop1 := createChild(t, v, root, "drop1", modeRegular|0o644)
		drop2 := createChild(t, v, root, "drop2", modeRegular|0o644)
		keep := createChild(t, v, root, "keep", modeRegular|0o644)
		fill(drop1, 20)
		fill(drop2, 20)
		fill(keep, 8)
		if got := v.numGroups(); got != 4 {
			t.Fatalf("tier %d: %d groups after 48 MiB, want 4", tier, got)
		}
		unlink(t, v, root, "drop1", drop1)
		unlink(t, v, root, "drop2", drop2)
		if err := v.close(); err != nil {
			t.Fatalf("tier %d: close: %v", tier, err)
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Size() != groupBytes {
			t.Errorf("tier %d: host file has %d bytes after the unmount, want %d", tier, fi.Size(), groupBytes)
		}
		runE2fsck(t, path)

		v = reopenVolume(t, path)
		keep = lookupNode(t, v, mustRoot(t, v), "keep")
		want := bytes.Repeat(chunk, 8)
		if got := readAll(t, keep); !bytes.Equal(got, want) {
			t.Errorf("tier %d: the kept file changed during the compaction", tier)
		}
		if err := v.close(); err != nil {
			t.Fatal(err)
		}
	}
}
