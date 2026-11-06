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

//go:build !windows

package erofs_test

import (
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/blockdev"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

func TestErofsFileReadsCountAsDiskReads(t *testing.T) {
	forEachBlockSize(t, runErofsFileReadsCountAsDiskReads)
}

func runErofsFileReadsCountAsDiskReads(t *testing.T, bs int) {
	plain := patternBytes(8*bs, 31)
	path, _ := compileTar(t, bs, buildTar(t, fileEntry("plain", string(plain)), symlinkEntry("link", "plain")))
	s := newSentry(t)
	s.blockStats = blockdev.NewStats(nil)
	root := s.mountErofs(path)
	defer root.DecRef(s.ctx)
	s.root = root

	// A lookup and a stat read no file data.
	if _, err := s.stat("/plain"); err != nil {
		t.Fatalf("stat /plain: %v", err)
	}
	if got := s.blockStats.Snapshot(); got.ReadsCompleted != 0 || got.SectorsRead != 0 {
		t.Fatalf("a stat counted %d reads and %d sectors, want none", got.ReadsCompleted, got.SectorsRead)
	}

	if got := s.read("/plain"); got != string(plain) {
		t.Fatalf("read %d bytes that differ from the file", len(got))
	}
	got := s.blockStats.Snapshot()
	if want := uint64(len(plain) / blockdev.SectorSize); got.SectorsRead < want {
		t.Errorf("sectors read = %d, want at least %d", got.SectorsRead, want)
	}
	if limit := uint64(len(plain)+2*blockdev.PageSize) / blockdev.SectorSize; got.SectorsRead > limit {
		t.Errorf("sectors read = %d, want at most %d: a page counts once", got.SectorsRead, limit)
	}
	if got.ReadsCompleted == 0 {
		t.Errorf("reads completed = 0, want at least 1")
	}
	// The pages are in the page cache now, so a second read counts nothing.
	if again := s.read("/plain"); again != string(plain) {
		t.Fatalf("second read returned %d bytes that differ from the file", len(again))
	}
	if second := s.blockStats.Snapshot(); second.SectorsRead != got.SectorsRead || second.ReadsCompleted != got.ReadsCompleted {
		t.Errorf("a second read of the same file changed the reads from %d requests and %d sectors to %d and %d", got.ReadsCompleted, got.SectorsRead, second.ReadsCompleted, second.SectorsRead)
	}
	if got.SectorsWritten != 0 || got.WritesCompleted != 0 || got.InFlight != 0 {
		t.Errorf("a read changed the write counters or left a request open: %+v", got)
	}
}

func TestErofsHolesAreNotDiskReads(t *testing.T) {
	forEachBlockSize(t, runErofsHolesAreNotDiskReads)
}

func runErofsHolesAreNotDiskReads(t *testing.T, bs int) {
	// The file has 3 MiB of holes and two short runs of data, as in the mount test.
	const sparseSize = 3<<20 + 4097
	sparse := make([]byte, sparseSize)
	copy(sparse[5*bs:], patternBytes(bs, 21))
	copy(sparse[sparseSize-300:], patternBytes(300, 22))
	path, _ := compileTar(t, bs, buildTar(t, fileEntry("sparse", string(sparse))))
	s := newSentry(t)
	s.blockStats = blockdev.NewStats(nil)
	root := s.mountErofs(path)
	defer root.DecRef(s.ctx)
	s.root = root

	if got := s.read("/sparse"); got != string(sparse) {
		t.Fatalf("read %d bytes that differ from the file", len(got))
	}
	got := s.blockStats.Snapshot()
	if got.SectorsRead == 0 {
		t.Fatal("reading the data runs counted no sectors")
	}
	if bytesRead := got.SectorsRead * blockdev.SectorSize; bytesRead >= sparseSize/2 {
		t.Errorf("reading a file that is mostly holes counted %d bytes of %d", bytesRead, sparseSize)
	}
}

func TestOverlayDirectoriesReportTheDiskNumber(t *testing.T) {
	forEachBlockSize(t, runOverlayDirectoriesReportTheDiskNumber)
}

func runOverlayDirectoriesReportTheDiskNumber(t *testing.T, bs int) {
	basePath, _ := compileTar(t, bs, baseLayer(t))
	topPath, _ := compileTar(t, bs, topLayer(t, false))

	s := newSentry(t)
	s.dirDevMajor, s.dirDevMinor = 254, 0
	s.mountOverlay(basePath, topPath)
	// "/dir" exists in both layers, "/dir2" too, and "/dir/sub" only in the base.
	for _, p := range []string{"/", "/dir", "/dir/sub", "/etc"} {
		st, err := s.stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if st.DevMajor != 254 || st.DevMinor != 0 {
			t.Errorf("st_dev of directory %s = %d:%d, want the disk number 254:0", p, st.DevMajor, st.DevMinor)
		}
	}

	other := newSentry(t)
	other.mountOverlay(basePath, topPath)
	st, err := other.stat("/")
	if err != nil {
		t.Fatalf("stat /: %v", err)
	}
	if st.DevMajor != 0 {
		t.Errorf("st_dev of / without disk numbers = %d:%d, want the anonymous major 0", st.DevMajor, st.DevMinor)
	}
}

func TestErofsMappingsCountEachPageOnce(t *testing.T) {
	forEachBlockSize(t, runErofsMappingsCountEachPageOnce)
}

func runErofsMappingsCountEachPageOnce(t *testing.T, bs int) {
	const size = 1 << 20
	if _, ok := layoutFor(layoutPlain, size, bs); !ok {
		t.Skipf("block size %d has no plain layout for %d bytes", bs, size)
	}
	content := layoutContent(layoutPlain, size, bs)
	path, _ := compileTar(t, bs, buildTar(t, fileEntry("plain", string(content))))
	s := newSentry(t)
	s.blockStats = blockdev.NewStats(nil)
	root := s.mountErofs(path)
	defer root.DecRef(s.ctx)
	s.root = root

	// Each fault maps one page. A second pass is a second process that maps
	// the same cached file, such as an exec of a program that ran before.
	fault := func() {
		t.Helper()
		opts, _ := mappableOf(t, s, "/plain", size)
		for pg := uint64(0); pg < size; pg += hostarch.PageSize {
			required := memmap.MappableRange{Start: pg, End: pg + hostarch.PageSize}
			if _, err := opts.Mappable.Translate(s.ctx, required, required, hostarch.Read); err != nil {
				t.Fatalf("Translate(page at %d): %v", pg, err)
			}
		}
	}
	fault()
	first := s.blockStats.Snapshot()
	if want := uint64(size / blockdev.SectorSize); first.SectorsRead != want {
		t.Errorf("sectors read after mapping %d bytes = %d, want %d", size, first.SectorsRead, want)
	}
	if first.ReadsCompleted == 0 || first.InFlight != 0 {
		t.Errorf("after the first pass: %+v, want completed reads and no request in flight", first)
	}
	fault()
	if second := s.blockStats.Snapshot(); second.SectorsRead != first.SectorsRead || second.ReadsCompleted != first.ReadsCompleted {
		t.Errorf("a second mapping of the same pages changed the reads from %d requests and %d sectors to %d and %d", first.ReadsCompleted, first.SectorsRead, second.ReadsCompleted, second.SectorsRead)
	}
}
