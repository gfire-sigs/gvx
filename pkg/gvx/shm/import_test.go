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

package shm

import (
	"bytes"
	"errors"
	"os"
	"runtime"
	"testing"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

func TestDefaultQuotaBytesBoundsAtFourGiBOrQuarterRAM(t *testing.T) {
	if got := DefaultQuotaBytes(0); got != DefaultMaxQuotaBytes {
		t.Fatalf("DefaultQuotaBytes(0) = %d, want %d", got, DefaultMaxQuotaBytes)
	}
	if got := DefaultQuotaBytes(64 << 30); got != DefaultMaxQuotaBytes {
		t.Fatalf("DefaultQuotaBytes(64GiB) = %d, want %d", got, DefaultMaxQuotaBytes)
	}
	if got := DefaultQuotaBytes(8 << 30); got != 2<<30 {
		t.Fatalf("DefaultQuotaBytes(8GiB) = %d, want %d", got, uint64(2<<30))
	}
}

func TestImporterRejectsMisalignmentAndQuotaOverflow(t *testing.T) {
	imp := NewImporter(Options{
		HostMappingAlign: 16384,
		QuotaBytes:       32768,
	})
	if _, err := imp.ImportFD(0, 0, 4096, true); !errors.Is(err, ErrMisaligned) {
		t.Fatalf("unaligned size err = %v, want ErrMisaligned", err)
	}
	if _, err := imp.ImportFD(0, 4096, 16384, true); !errors.Is(err, ErrMisaligned) {
		t.Fatalf("unaligned offset err = %v, want ErrMisaligned", err)
	}
	if _, err := imp.ImportFD(0, 0, 65536, true); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("oversized quota err = %v, want ErrQuotaExceeded", err)
	}
	if _, err := imp.ImportFD(0, 0, 0, true); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("zero size err = %v, want ErrInvalidRange", err)
	}
}

func TestImportedRegionRefusesExecuteAndDelaysUnmapUntilRefsDrop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX FD shm mapping runs on Unix hosts")
	}
	fd, cleanup := createTestBackingFD(t, 32768)
	defer cleanup()

	imp := NewImporter(Options{
		HostMappingAlign: 16384,
		QuotaBytes:       32768,
	})
	reg, err := imp.ImportFD(fd, 0, 16384, true)
	if err != nil {
		t.Fatalf("ImportFD: %v", err)
	}
	if !imp.HasImported() || imp.UsedBytes() != 16384 {
		t.Fatalf("state after import: HasImported=%v UsedBytes=%d", imp.HasImported(), imp.UsedBytes())
	}

	// Refuse PROT_EXEC in both Translate and MapInternal.
	req := memmap.MappableRange{Start: 0, End: uint64(hostarch.PageSize)}
	if _, err := reg.Translate(nil, req, req, hostarch.Execute); !errors.Is(err, linuxerr.EACCES) {
		t.Fatalf("Translate(Execute) err = %v, want EACCES", err)
	}
	fr := memmap.FileRange{Start: 0, End: uint64(hostarch.PageSize)}
	if _, err := reg.MapInternal(fr, hostarch.Execute); !errors.Is(err, linuxerr.EACCES) {
		t.Fatalf("MapInternal(Execute) err = %v, want EACCES", err)
	}

	// Write through MapInternal and read through Bytes().
	reg.IncRef(fr, 0)
	bs, err := reg.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal(ReadWrite): %v", err)
	}
	want := []byte("gvx-shm-zero-copy-check")
	if _, err := safemem.CopySeq(bs, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(want))); err != nil {
		t.Fatalf("safemem.CopySeq: %v", err)
	}
	if !bytes.Equal(reg.Bytes()[:len(want)], want) {
		t.Fatalf("Bytes() = %q, want %q", reg.Bytes()[:len(want)], want)
	}

	// ReleaseAll drops sandbox claim only: view must stay mapped while pageRefs > 0.
	imp.ReleaseAll()
	if reg.Unmapped() {
		t.Fatal("ReleaseAll unmapped region while guest page reference remained active")
	}
	if imp.UsedBytes() != 16384 {
		t.Fatalf("UsedBytes while pinned = %d, want 16384", imp.UsedBytes())
	}
	if !bytes.Equal(reg.Bytes()[:len(want)], want) {
		t.Fatal("host bytes became unreadable before page references dropped")
	}

	// Dropping final page reference unmaps host view and frees quota.
	reg.DecRef(fr)
	if !reg.Unmapped() {
		t.Fatal("region remained mapped after claim and last page reference dropped")
	}
	if imp.UsedBytes() != 0 {
		t.Fatalf("UsedBytes after final DecRef = %d, want 0", imp.UsedBytes())
	}

	// Importer rejects subsequent imports after ReleaseAll.
	if _, err := imp.ImportFD(fd, 0, 16384, true); !errors.Is(err, ErrImporterClosed) {
		t.Fatalf("ImportFD after ReleaseAll err = %v, want ErrImporterClosed", err)
	}
}

func TestLinuxImporterRejectsUnsealedFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("F_SEAL_SHRINK validation applies to Linux hosts")
	}
	f, err := os.CreateTemp(t.TempDir(), "unsealed-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer f.Close()
	if err := f.Truncate(16384); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	imp := NewImporter(Options{HostMappingAlign: 4096, QuotaBytes: 65536})
	if _, err := imp.ImportFD(int(f.Fd()), 0, 16384, true); !errors.Is(err, ErrUnsealedMemory) {
		t.Fatalf("ImportFD(unsealed regular file) err = %v, want ErrUnsealedMemory", err)
	}
}

func TestImportWholeFDSeparatesGuestAndHostSize(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX FD shm mapping runs on Unix hosts")
	}
	hostAlign := uint64(os.Getpagesize())
	hostSize := max(uint64(16384), hostAlign)
	fd, cleanup := createTestBackingFD(t, int64(hostSize))
	defer cleanup()

	imp := NewImporter(Options{
		HostMappingAlign: hostAlign,
		QuotaBytes:       hostSize * 2,
	})
	guestSize := uint64(hostarch.PageSize) // 4096 < hostSize
	reg, err := imp.ImportWholeFD(fd, guestSize, 1<<20, true)
	if err != nil {
		t.Fatalf("ImportWholeFD: %v", err)
	}
	if reg.Size() != guestSize {
		t.Fatalf("Size() = %d, want %d", reg.Size(), guestSize)
	}
	if reg.HostSize() != hostSize {
		t.Fatalf("HostSize() = %d, want %d", reg.HostSize(), hostSize)
	}
	if imp.UsedBytes() != hostSize {
		t.Fatalf("UsedBytes() = %d, want %d", imp.UsedBytes(), hostSize)
	}
	// Guest mapping past guestSize must fault even though hostSize is larger.
	beyond := memmap.MappableRange{Start: guestSize, End: guestSize * 2}
	if _, err := reg.Translate(nil, beyond, beyond, hostarch.Read); err == nil {
		t.Fatal("Translate past guestSize succeeded, want error")
	}
	// Reject hostSize exceeding maxHostSize.
	if _, err := imp.ImportWholeFD(fd, guestSize, hostSize/2, true); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("ImportWholeFD(maxHostSize < hostSize) err = %v, want ErrInvalidRange", err)
	}
	// Reject hostSize that is not aligned to HostMappingAlign.
	strictImp := NewImporter(Options{
		HostMappingAlign: hostSize * 2,
		QuotaBytes:       hostSize * 4,
	})
	if _, err := strictImp.ImportWholeFD(fd, guestSize, hostSize*4, true); !errors.Is(err, ErrMisaligned) {
		t.Fatalf("ImportWholeFD(misaligned hostSize) err = %v, want ErrMisaligned", err)
	}
	reg.Release()
	if !reg.Unmapped() || imp.UsedBytes() != 0 {
		t.Fatalf("after Release: Unmapped=%v UsedBytes=%d", reg.Unmapped(), imp.UsedBytes())
	}
}
