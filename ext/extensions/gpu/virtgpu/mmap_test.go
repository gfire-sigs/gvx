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
	"bytes"
	"sync"
	"testing"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

func mustMapOffset(t *testing.T, node *testNode, fd *vfs.FileDescription, handle uint32) uint64 {
	t.Helper()
	mem := newGuestMem()
	const addr = hostarch.Addr(0x1000)
	mem.put(t, addr, virtgpuMap{Handle: handle})
	if err := node.ioctl(fd, cmdVirtgpuMap, mem, addr); err != nil {
		t.Fatalf("MAP(%d): %v", handle, err)
	}
	var out virtgpuMap
	mem.get(t, addr, &out)
	return out.Offset
}

func TestMapOffsets(t *testing.T) {
	requireBlobHost(t)

	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)

	b1 := mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		Size:      0x4000,
	})
	b2 := mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		Size:      0x4000,
	})
	bNoMap := mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
		BlobMem: virtgpuBlobMemHost3D,
		Size:    0x4000,
	})

	off1 := mustMapOffset(t, node, fd, b1.BoHandle)
	if off1 < 1<<mapSlotShift {
		t.Errorf("MAP(b1) offset = %#x, want >= 1<<32", off1)
	}
	if off1Again := mustMapOffset(t, node, fd, b1.BoHandle); off1Again != off1 {
		t.Errorf("repeated MAP(b1) = %#x, want %#x", off1Again, off1)
	}

	off2 := mustMapOffset(t, node, fd, b2.BoHandle)
	if off2 < 1<<mapSlotShift || off2 == off1 {
		t.Errorf("MAP(b2) offset = %#x, want >= 1<<32 and != %#x", off2, off1)
	}

	mem := newGuestMem()
	const addr = hostarch.Addr(0x1000)
	mem.put(t, addr, virtgpuMap{Handle: 999})
	if err := node.ioctl(fd, cmdVirtgpuMap, mem, addr); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Errorf("MAP(unknown): got %v, want ENOENT", err)
	}

	mem.put(t, addr, virtgpuMap{Handle: bNoMap.BoHandle})
	if err := node.ioctl(fd, cmdVirtgpuMap, mem, addr); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Errorf("MAP(non-mappable): got %v, want EINVAL", err)
	}

	// Closing b1 and creating a new blob reuses handle 1, but MAP must issue a new offset.
	mustGemClose(t, node, fd, b1.BoHandle)
	bReused := mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		Size:      0x4000,
	})
	if bReused.BoHandle != b1.BoHandle {
		t.Fatalf("reused handle = %d, want %d", bReused.BoHandle, b1.BoHandle)
	}
	offReused := mustMapOffset(t, node, fd, bReused.BoHandle)
	if offReused == off1 || offReused == off2 {
		t.Errorf("MAP(reused handle) = %#x, must differ from %#x and %#x", offReused, off1, off2)
	}
}

func TestMmapSelectsBlob(t *testing.T) {
	requireBlobHost(t)

	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)

	b1 := mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		Size:      0x4000,
	})
	b2 := mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		Size:      0x4000,
	})
	_ = mustMapOffset(t, node, fd, b1.BoHandle)
	off2 := mustMapOffset(t, node, fd, b2.BoHandle)

	opts := memmap.MMapOpts{
		Offset: off2 + 0x1000,
		Length: 0x1000,
	}
	if err := fd.ConfigureMMap(node.ctx, &opts); err != nil {
		t.Fatalf("ConfigureMMap: %v", err)
	}
	defer opts.MappingIdentity.DecRef(node.ctx)

	if opts.Offset != 0x1000 {
		t.Fatalf("opts.Offset = %#x, want 0x1000", opts.Offset)
	}
	if opts.Mappable == nil || opts.MappingIdentity == nil {
		t.Fatalf("ConfigureMMap left Mappable or MappingIdentity nil")
	}

	req := memmap.MappableRange{Start: opts.Offset, End: opts.Offset + opts.Length}
	ts, err := opts.Mappable.Translate(node.ctx, req, req, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if len(ts) != 1 || ts[0].Source != req || ts[0].Offset != req.Start || ts[0].Perms != hostarch.ReadWrite {
		t.Fatalf("Translate = %+v, want single ReadWrite range %+v", ts, req)
	}

	fr := memmap.FileRange{Start: ts[0].Offset, End: ts[0].Offset + ts[0].Source.Length()}
	ts[0].File.IncRef(fr, 0)
	defer ts[0].File.DecRef(fr)

	bs, err := ts[0].File.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	pattern := []byte{0xde, 0xad, 0xbe, 0xef, 0x11, 0x22, 0x33, 0x44}
	if _, err := safemem.CopySeq(bs, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(pattern))); err != nil {
		t.Fatalf("CopySeq: %v", err)
	}

	mem2 := fake.blobMemory(b2.ResHandle)
	if !bytes.Equal(mem2[0x1000:0x1000+len(pattern)], pattern) {
		t.Errorf("blob 2 memory at 0x1000 = %x, want %x", mem2[0x1000:0x1000+len(pattern)], pattern)
	}
	mem1 := fake.blobMemory(b1.ResHandle)
	if !bytes.Equal(mem1[0x1000:0x1000+len(pattern)], make([]byte, len(pattern))) {
		t.Errorf("blob 1 memory at 0x1000 was modified: %x", mem1[0x1000:0x1000+len(pattern)])
	}

	if err := opts.MappingIdentity.Msync(node.ctx, req); err != nil {
		t.Errorf("Msync: got %v, want nil", err)
	}
	if got, want := opts.MappingIdentity.MappedName(node.ctx), fd.MappedName(node.ctx); got != want {
		t.Errorf("MappedName = %q, want %q", got, want)
	}
	if got, want := opts.MappingIdentity.DeviceID(), fd.DeviceID(); got != want {
		t.Errorf("DeviceID = %d, want %d", got, want)
	}
	if got, want := opts.MappingIdentity.InodeID(), fd.InodeID(); got != want {
		t.Errorf("InodeID = %d, want %d", got, want)
	}
}

func TestMmapRejects(t *testing.T) {
	requireBlobHost(t)

	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)

	b := mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		Size:      0x4000,
	})
	off := mustMapOffset(t, node, fd, b.BoHandle)

	refsBefore := fd.ReadRefs()
	bytesBefore := node.dev.BlobBytes()

	cases := []struct {
		name string
		opts memmap.MMapOpts
	}{
		{"MAP_PRIVATE", memmap.MMapOpts{Private: true, Offset: off, Length: 0x1000}},
		{"unknown slot", memmap.MMapOpts{Offset: 99 << mapSlotShift, Length: 0x1000}},
		{"past guest size", memmap.MMapOpts{Offset: off + 0x3000, Length: 0x2000}},
		{"offset length overflow", memmap.MMapOpts{Offset: off + 0x1000, Length: ^uint64(0)}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			if err := fd.ConfigureMMap(node.ctx, &opts); !linuxerr.Equals(linuxerr.EINVAL, err) {
				t.Fatalf("ConfigureMMap(%s): got %v, want EINVAL", tc.name, err)
			}
			if got := fd.ReadRefs(); got != refsBefore {
				t.Errorf("fd refs after %s = %d, want %d", tc.name, got, refsBefore)
			}
			if got := node.dev.BlobBytes(); got != bytesBefore {
				t.Errorf("BlobBytes after %s = %#x, want %#x", tc.name, got, bytesBefore)
			}
		})
	}

	// Stale offset after GEM_CLOSE is rejected.
	mustGemClose(t, node, fd, b.BoHandle)
	opts := memmap.MMapOpts{Offset: off, Length: 0x1000}
	if err := fd.ConfigureMMap(node.ctx, &opts); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Fatalf("ConfigureMMap(stale offset): got %v, want EINVAL", err)
	}
	if got := fd.ReadRefs(); got != refsBefore {
		t.Errorf("fd refs after stale offset = %d, want %d", got, refsBefore)
	}
	if got := node.dev.BlobBytes(); got != 0 {
		t.Errorf("BlobBytes after stale offset = %#x, want 0", got)
	}
}

func TestMmapKeepsBlobAfterGEMClose(t *testing.T) {
	requireBlobHost(t)

	t.Run("sequential", func(t *testing.T) {
		fake := newFakeRenderer()
		node := newTestNode(t, fake)
		fd := node.openVenus(t)
		defer fd.DecRef(node.ctx)

		b := mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
			BlobMem:   virtgpuBlobMemHost3D,
			BlobFlags: virtgpuBlobFlagUseMappable,
			Size:      0x4000,
		})
		off := mustMapOffset(t, node, fd, b.BoHandle)

		opts := memmap.MMapOpts{Offset: off, Length: 0x4000}
		if err := fd.ConfigureMMap(node.ctx, &opts); err != nil {
			t.Fatalf("ConfigureMMap: %v", err)
		}

		mustGemClose(t, node, fd, b.BoHandle)
		if got := node.dev.BlobBytes(); got != 0x4000 {
			t.Fatalf("BlobBytes after GEM_CLOSE with active mapping = %#x, want 0x4000", got)
		}

		opts.MappingIdentity.DecRef(node.ctx)
		if got := node.dev.BlobBytes(); got != 0 {
			t.Errorf("BlobBytes after MappingIdentity.DecRef = %#x, want 0", got)
		}
	})

	t.Run("concurrent ConfigureMMap and GEM_CLOSE", func(t *testing.T) {
		fake := newFakeRenderer()
		node := newTestNode(t, fake)
		fd := node.openVenus(t)
		defer fd.DecRef(node.ctx)

		for range 32 {
			b := mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
				BlobMem:   virtgpuBlobMemHost3D,
				BlobFlags: virtgpuBlobFlagUseMappable,
				Size:      0x4000,
			})
			off := mustMapOffset(t, node, fd, b.BoHandle)

			start := make(chan struct{})
			var wg sync.WaitGroup
			var opts memmap.MMapOpts
			var mapErr error

			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				opts = memmap.MMapOpts{Offset: off, Length: 0x4000}
				mapErr = fd.ConfigureMMap(node.ctx, &opts)
			}()
			go func() {
				defer wg.Done()
				<-start
				mustGemClose(t, node, fd, b.BoHandle)
			}()
			close(start)
			wg.Wait()

			if mapErr == nil {
				if got := node.dev.BlobBytes(); got != 0x4000 {
					t.Fatalf("BlobBytes with surviving mapping = %#x, want 0x4000", got)
				}
				opts.MappingIdentity.DecRef(node.ctx)
			} else if !linuxerr.Equals(linuxerr.EINVAL, mapErr) {
				t.Fatalf("concurrent ConfigureMMap: got %v, want nil or EINVAL", mapErr)
			}
			if got := node.dev.BlobBytes(); got != 0 {
				t.Fatalf("BlobBytes after round = %#x, want 0", got)
			}
		}
	})
}
