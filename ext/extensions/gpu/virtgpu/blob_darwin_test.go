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

package virtgpu

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fd"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

func newBlobTestDevice(t *testing.T) *Device {
	t.Helper()
	return &Device{
		limits: Limits{}.withDefaults(),
		budget: blobBudget{limit: defaultBlobBytes},
		blobs:  map[*blob]struct{}{},
	}
}

func mustNewBlob(t *testing.T, d *Device, shm *fd.HostHandle, guestSize uint64) *blob {
	t.Helper()
	reserved := roundUpBlobSize(guestSize)
	if err := d.budget.reserve(reserved); err != nil {
		t.Fatalf("budget.reserve(%#x): %v", reserved, err)
	}
	b, err := newBlob(d, shm, guestSize, reserved)
	if err != nil {
		d.budget.release(reserved)
		t.Fatalf("newBlob: %v", err)
	}
	return b
}

// testShm is a shared memory object of size bytes and a second host mapping
// of it. CreateMemFD stands in for the renderer shm in tests that do not need
// the renderer: both are MAP_SHARED host memory with a file descriptor.
type testShm struct {
	handle *fd.HostHandle
	second []byte
}

func (s *testShm) unmapSecond(t *testing.T) {
	t.Helper()
	if s.second == nil {
		return
	}
	mem := s.second
	s.second = nil
	if err := unix.Munmap(mem); err != nil {
		t.Errorf("Munmap second: %v", err)
	}
}

func newTestShm(t *testing.T, size int64) *testShm {
	t.Helper()
	memfd, err := memutil.CreateMemFD("virtgpu-blob", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	if err := unix.Ftruncate(memfd, size); err != nil {
		_ = unix.Close(memfd)
		t.Fatalf("Ftruncate(%d): %v", size, err)
	}
	var second []byte
	if size > 0 {
		second, err = unix.Mmap(memfd, 0, int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if err != nil {
			_ = unix.Close(memfd)
			t.Fatalf("Mmap: %v", err)
		}
	}
	h, err := fd.NewHostHandle(memfd)
	if err != nil {
		if second != nil {
			_ = unix.Munmap(second)
		}
		_ = unix.Close(memfd)
		t.Fatalf("NewHostHandle: %v", err)
	}
	s := &testShm{handle: h, second: second}
	t.Cleanup(func() { s.unmapSecond(t) })
	return s
}

func TestBlobRefusesHostSize(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hostSize  int64
		guestSize uint64
	}{
		{"smaller than the guest size", 0x4000, 0x8000},
		{"not a multiple of 16 KiB", 0x5000, 0x4000},
		{"empty", 0, 0x1000},
		{"above 1 GiB", maxBlobBytes + blobAlignment, 0x1000},
		{"guest size zero", 0x4000, 0},
		{"guest size not page aligned", 0x4000, 0x800},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newBlobTestDevice(t)
			shm := newTestShm(t, tc.hostSize)
			if _, err := newBlob(d, shm.handle, tc.guestSize, 0); !errors.Is(err, errBlobSize) {
				t.Fatalf("newBlob(host %#x, guest %#x) = %v, want errBlobSize", tc.hostSize, tc.guestSize, err)
			}
			if got := d.BlobBytes(); got != 0 {
				t.Errorf("BlobBytes after a refused blob = %d, want 0", got)
			}
			if _, err := shm.handle.RawHandle(); err == nil {
				t.Errorf("newBlob left the descriptor open after an error")
			}
		})
	}
}

func TestBlobClosesDescriptorAndCountsHostSize(t *testing.T) {
	d := newBlobTestDevice(t)
	// Request 0x4000 guest bytes backed by a 0x8000 host object so newBlob
	// exercises settling hostSize > reserved via budget.grow.
	shm := newTestShm(t, 0x8000)
	b := mustNewBlob(t, d, shm.handle, 0x4000)
	if _, err := shm.handle.RawHandle(); err == nil {
		t.Errorf("newBlob kept the descriptor open")
	}
	if got := d.BlobBytes(); got != 0x8000 {
		t.Errorf("BlobBytes = %#x, want the fstat size 0x8000", got)
	}
	b.decOwner()
	if got := d.BlobBytes(); got != 0 {
		t.Errorf("BlobBytes after the last owner = %#x, want 0", got)
	}
}

func TestBlobTranslateObeysContract(t *testing.T) {
	d := newBlobTestDevice(t)
	shm := newTestShm(t, 0x8000)
	b := mustNewBlob(t, d, shm.handle, 0x6000)
	defer b.decOwner()

	ctx := context.Background()
	optional := memmap.MappableRange{Start: 0, End: 0x8000}

	cases := []struct {
		name      string
		required  memmap.MappableRange
		wantCount int
		wantBus   bool
	}{
		{"within guest size", memmap.MappableRange{Start: 0x1000, End: 0x2000}, 1, false},
		{"straddling guest size", memmap.MappableRange{Start: 0x5000, End: 0x7000}, 1, true},
		{"starting at guest size", memmap.MappableRange{Start: 0x6000, End: 0x7000}, 0, true},
		{"past guest size", memmap.MappableRange{Start: 0x7000, End: 0x8000}, 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, err := b.Translate(ctx, tc.required, optional, hostarch.ReadWrite)
			if len(ts) != tc.wantCount {
				t.Errorf("Translate len = %d, want %d (ts=%+v)", len(ts), tc.wantCount, ts)
			}
			var busErr *memmap.BusError
			isBus := errors.As(err, &busErr)
			if isBus != tc.wantBus {
				t.Errorf("Translate err = %v (BusError=%v), want BusError=%v", err, isBus, tc.wantBus)
			}
			if tc.wantBus && isBus && !linuxerr.Equals(linuxerr.EFAULT, busErr.Err) {
				t.Errorf("BusError.Err = %v, want EFAULT", busErr.Err)
			}
			if cerr := memmap.CheckTranslateResult(tc.required, optional, hostarch.ReadWrite, ts, err); cerr != nil {
				t.Errorf("CheckTranslateResult failed: %v", cerr)
			}
		})
	}
}

func TestBlobMapInternalRefusesOutOfRange(t *testing.T) {
	d := newBlobTestDevice(t)
	shm := newTestShm(t, 0x8000)
	b := mustNewBlob(t, d, shm.handle, 0x6000)
	defer b.decOwner()

	for _, tc := range []struct {
		name string
		fr   memmap.FileRange
	}{
		{"tail past guest size", memmap.FileRange{Start: 0x6000, End: 0x8000}},
		{"empty range", memmap.FileRange{Start: 0x2000, End: 0x2000}},
		{"inverted range", memmap.FileRange{Start: 0x3000, End: 0x2000}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := b.MapInternal(tc.fr, hostarch.ReadWrite); !linuxerr.Equals(linuxerr.EINVAL, err) {
				t.Errorf("MapInternal(%+v): got %v, want EINVAL", tc.fr, err)
			}
		})
	}

	fr := memmap.FileRange{Start: 0, End: 0x6000}
	b.IncRef(fr, 0)
	defer b.DecRef(fr)
	bs, err := b.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal([0, 0x6000)): %v", err)
	}
	if bs.NumBlocks() != 1 || bs.NumBytes() != 0x6000 {
		t.Errorf("MapInternal blocks = %d bytes = %#x, want 1 block of 0x6000 bytes", bs.NumBlocks(), bs.NumBytes())
	}
}

func TestBlobDataFDAndFD(t *testing.T) {
	d := newBlobTestDevice(t)
	shm := newTestShm(t, 0x4000)
	b := mustNewBlob(t, d, shm.handle, 0x4000)
	defer b.decOwner()

	if fdNum, err := b.DataFD(memmap.FileRange{Start: 0, End: 0x1000}); fdNum != -1 || !linuxerr.Equals(linuxerr.ENODEV, err) {
		t.Errorf("DataFD = (%d, %v), want (-1, ENODEV)", fdNum, err)
	}
	if fdNum := b.FD(); fdNum != -1 {
		t.Errorf("FD = %d, want -1", fdNum)
	}
}

func TestReleaseBlobViewsWaitsForPageReferences(t *testing.T) {
	d := newBlobTestDevice(t)
	shmA := newTestShm(t, 0x4000)
	blobA := mustNewBlob(t, d, shmA.handle, 0x4000)
	shmB := newTestShm(t, 0x8000)
	blobB := mustNewBlob(t, d, shmB.handle, 0x8000)

	// Both blobs keep their creator owner (leaked GEM handles); blob A also
	// holds an active page reference.
	frA := memmap.FileRange{Start: 0, End: 0x4000}
	blobA.IncRef(frA, 0)

	d.ReleaseBlobViews()
	if got := d.BlobBytes(); got != 0x4000 {
		t.Fatalf("BlobBytes after ReleaseBlobViews = %#x, want 0x4000 (blob B unmapped, blob A waits for page ref)", got)
	}

	blobA.DecRef(frA)
	if got := d.BlobBytes(); got != 0 {
		t.Fatalf("BlobBytes after blob A DecRef = %#x, want 0", got)
	}

	// Late decOwner on both leaked handles must not panic or underflow.
	blobA.decOwner()
	blobB.decOwner()
	if got := d.BlobBytes(); got != 0 {
		t.Errorf("BlobBytes after late decOwner = %#x, want 0", got)
	}
}
