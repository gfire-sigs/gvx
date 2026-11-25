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
	"errors"
	"fmt"
	"math"
	"testing"

	"z.gfire.dev/gvx/ext/extensions/gpu/gpuproto"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

func mustCreateResource(t *testing.T, node *testNode, fd *vfs.FileDescription, req virtgpuResourceCreate) virtgpuResourceCreate {
	t.Helper()
	mem := newGuestMem()
	const structAddr = hostarch.Addr(0x1000)
	mem.put(t, structAddr, req)
	if err := node.ioctl(fd, cmdVirtgpuResourceCreate, mem, structAddr); err != nil {
		t.Fatalf("RESOURCE_CREATE: %v", err)
	}
	var out virtgpuResourceCreate
	mem.get(t, structAddr, &out)
	return out
}

func TestResourceCreateFields(t *testing.T) {
	requireBlobHost(t)

	fake := newFakeVirglRenderer()
	node := newTestNode(t, fake)
	fd := node.openVirgl(t)
	defer fd.DecRef(node.ctx)
	ctxID := fake.createdCalls()[0].ctxID

	// resourceCreate forwards all 10 GL fields unchanged, ignores input BoHandle,
	// ResHandle, and Stride, and rounds size 0 to 4096.
	out0 := mustCreateResource(t, node, fd, virtgpuResourceCreate{
		Target:    2,
		Format:    67,
		Bind:      0x1a,
		Width:     128,
		Height:    64,
		Depth:     1,
		ArraySize: 2,
		LastLevel: 3,
		NrSamples: 4,
		Flags:     1,
		BoHandle:  999,
		ResHandle: 888,
		Size:      0,
		Stride:    512,
	})
	if out0.BoHandle != 1 || out0.ResHandle == 0 {
		t.Fatalf("out0 handles = (bo=%d, res=%d), want (1, non-zero)", out0.BoHandle, out0.ResHandle)
	}

	// Size 5000 rounds up to 8192.
	out1 := mustCreateResource(t, node, fd, virtgpuResourceCreate{
		Target:    0,
		Format:    64,
		Bind:      1 << 4,
		Width:     5000,
		Height:    1,
		Depth:     1,
		ArraySize: 1,
		Size:      5000,
	})
	if out1.BoHandle != 2 || out1.ResHandle == out0.ResHandle {
		t.Fatalf("out1 handles = (bo=%d, res=%d), want (2, != %d)", out1.BoHandle, out1.ResHandle, out0.ResHandle)
	}

	calls := fake.resCreateCalls()
	if len(calls) != 2 {
		t.Fatalf("CreateResource calls = %d, want 2", len(calls))
	}
	want0 := gpuproto.ResourceCreate{
		CtxID:     ctxID,
		ResID:     out0.ResHandle,
		Target:    2,
		Format:    67,
		Bind:      0x1a,
		Width:     128,
		Height:    64,
		Depth:     1,
		ArraySize: 2,
		LastLevel: 3,
		NrSamples: 4,
		Flags:     1,
		Size:      4096,
	}
	if calls[0] != want0 {
		t.Errorf("calls[0] = %+v, want %+v", calls[0], want0)
	}
	if calls[1].Size != 8192 {
		t.Errorf("calls[1].Size = %d, want 8192", calls[1].Size)
	}

	// RESOURCE_INFO reports blob_mem 0 and the rounded guest size.
	mem := newGuestMem()
	const addr = hostarch.Addr(0x1000)
	for _, tc := range []struct {
		bo       uint32
		res      uint32
		wantSize uint32
	}{
		{out0.BoHandle, out0.ResHandle, 4096},
		{out1.BoHandle, out1.ResHandle, 8192},
	} {
		mem.put(t, addr, virtgpuResourceInfo{BoHandle: tc.bo})
		if err := node.ioctl(fd, cmdVirtgpuResourceInfo, mem, addr); err != nil {
			t.Fatalf("RESOURCE_INFO(%d): %v", tc.bo, err)
		}
		var info virtgpuResourceInfo
		mem.get(t, addr, &info)
		if info.ResHandle != tc.res || info.Size != tc.wantSize || info.BlobMem != 0 {
			t.Errorf("RESOURCE_INFO(%d) = %+v, want res=%d size=%d blob_mem=0", tc.bo, info, tc.res, tc.wantSize)
		}
	}
}

func TestResourceCreateLimits(t *testing.T) {
	const structAddr = hostarch.Addr(0x1000)

	t.Run("size above 1 GiB returns ENOMEM without calling renderer", func(t *testing.T) {
		fake := newFakeVirglRenderer()
		node := newTestNode(t, fake)
		fd := node.openVirgl(t)
		defer fd.DecRef(node.ctx)

		mem := newGuestMem()
		mem.put(t, structAddr, virtgpuResourceCreate{Size: maxBlobBytes + 1})
		if err := node.ioctl(fd, cmdVirtgpuResourceCreate, mem, structAddr); !linuxerr.Equals(linuxerr.ENOMEM, err) {
			t.Fatalf("RESOURCE_CREATE(>1GiB): got %v, want ENOMEM", err)
		}
		if got := len(fake.resCreateCalls()); got != 0 {
			t.Errorf("CreateResource calls = %d, want 0", got)
		}
	})

	t.Run("budget full returns ENOMEM without calling renderer", func(t *testing.T) {
		requireBlobHost(t)
		fake := newFakeVirglRenderer()
		node := newTestNodeWithLimits(t, fake, Limits{BlobBytes: blobAlignment})
		fd := node.openVirgl(t)
		defer fd.DecRef(node.ctx)

		_ = mustCreateResource(t, node, fd, virtgpuResourceCreate{Size: blobAlignment})

		mem := newGuestMem()
		mem.put(t, structAddr, virtgpuResourceCreate{Size: 4096})
		if err := node.ioctl(fd, cmdVirtgpuResourceCreate, mem, structAddr); !linuxerr.Equals(linuxerr.ENOMEM, err) {
			t.Fatalf("RESOURCE_CREATE(budget full): got %v, want ENOMEM", err)
		}
		if got := len(fake.resCreateCalls()); got != 1 {
			t.Errorf("CreateResource calls = %d, want 1", got)
		}
	})

	t.Run("live-blob cap returns ENOMEM without calling renderer", func(t *testing.T) {
		fake := newFakeVirglRenderer()
		node := newTestNode(t, fake)
		fd := node.openVirgl(t)
		defer fd.DecRef(node.ctx)

		node.dev.budget.live.Store(maxLiveBlobs)
		mem := newGuestMem()
		mem.put(t, structAddr, virtgpuResourceCreate{Size: 4096})
		if err := node.ioctl(fd, cmdVirtgpuResourceCreate, mem, structAddr); !linuxerr.Equals(linuxerr.ENOMEM, err) {
			t.Fatalf("RESOURCE_CREATE(live-blob cap): got %v, want ENOMEM", err)
		}
		if got := len(fake.resCreateCalls()); got != 0 {
			t.Errorf("CreateResource calls = %d, want 0", got)
		}
		if got := node.dev.BlobBytes(); got != 0 {
			t.Errorf("BlobBytes = %#x, want 0", got)
		}
	})

	t.Run("handle cap returns ENOMEM and sends one UnrefResource", func(t *testing.T) {
		requireBlobHost(t)
		fake := newFakeVirglRenderer()
		node := newTestNode(t, fake)
		fd := node.openVirgl(t)
		defer fd.DecRef(node.ctx)
		ctxID := fake.createdCalls()[0].ctxID

		rfd := fd.Impl().(*renderFD)
		rfd.gemMu.Lock()
		for i := range maxHandlesPerFile {
			rfd.gem.insert(&gemObject{resID: uint32(1000 + i)})
		}
		rfd.gemMu.Unlock()

		mem := newGuestMem()
		mem.put(t, structAddr, virtgpuResourceCreate{Size: 4096})
		if err := node.ioctl(fd, cmdVirtgpuResourceCreate, mem, structAddr); !linuxerr.Equals(linuxerr.ENOMEM, err) {
			t.Fatalf("RESOURCE_CREATE(handle cap): got %v, want ENOMEM", err)
		}
		created := fake.resCreateCalls()
		if len(created) != 1 {
			t.Fatalf("CreateResource calls = %d, want 1", len(created))
		}
		unrefs := fake.unrefCalls()
		if len(unrefs) != 1 || unrefs[0] != (unrefCall{ctxID: ctxID, resID: created[0].ResID}) {
			t.Errorf("UnrefResource calls = %+v, want [{%d %d}]", unrefs, ctxID, created[0].ResID)
		}
		if got := node.dev.BlobBytes(); got != 0 {
			t.Errorf("BlobBytes after handle-cap rollback = %#x, want 0", got)
		}

		// Clear synthetic handles before fd.Release so cleanup does not emit extra unrefs.
		rfd.gemMu.Lock()
		_ = rfd.gem.takeAll()
		rfd.gemMu.Unlock()
	})
}

func TestResourceCreateErrors(t *testing.T) {
	const structAddr = hostarch.Addr(0x1000)

	cases := []struct {
		name       string
		needDarwin bool
		setup      func(fake *fakeRenderer)
		wantErr    error
		wantUnref  bool
	}{
		{
			name: "renderer StatusInvalid",
			setup: func(fake *fakeRenderer) {
				fake.setResErr(&gpuproto.StatusError{Op: gpuproto.OpResCreate, Status: gpuproto.StatusInvalid})
			},
			wantErr: linuxerr.EINVAL,
		},
		{
			name: "renderer lost",
			setup: func(fake *fakeRenderer) {
				fake.setResErr(fmt.Errorf("disconnected: %w", gpuproto.ErrRendererLost))
			},
			wantErr: linuxerr.EIO,
		},
		{
			name: "renderer lost event before call",
			setup: func(fake *fakeRenderer) {
				fake.emitRendererLost(errors.New("renderer crashed"))
			},
			wantErr: linuxerr.EIO,
		},
		{
			name: "nil Shm",
			setup: func(fake *fakeRenderer) {
				fake.nilResShm = true
			},
			wantErr:   linuxerr.EIO,
			wantUnref: true,
		},
		{
			name:       "wrong fstat size",
			needDarwin: true,
			setup: func(fake *fakeRenderer) {
				fake.shortShm = true
			},
			wantErr:   linuxerr.EIO,
			wantUnref: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.needDarwin {
				requireBlobHost(t)
			}
			fake := newFakeVirglRenderer()
			node := newTestNode(t, fake)
			fd := node.openVirgl(t)
			defer fd.DecRef(node.ctx)
			ctxID := fake.createdCalls()[0].ctxID

			tc.setup(fake)
			mem := newGuestMem()
			mem.put(t, structAddr, virtgpuResourceCreate{Size: blobAlignment})
			if err := node.ioctl(fd, cmdVirtgpuResourceCreate, mem, structAddr); !errors.Is(err, tc.wantErr) {
				t.Fatalf("RESOURCE_CREATE(%s): got %v, want %v", tc.name, err, tc.wantErr)
			}
			if got := node.dev.BlobBytes(); got != 0 {
				t.Errorf("BlobBytes after %s = %#x, want 0", tc.name, got)
			}
			if tc.wantUnref {
				unrefs := fake.unrefCalls()
				if len(unrefs) != 1 || unrefs[0].ctxID != ctxID {
					t.Errorf("UnrefResource calls = %+v, want 1 unref on ctx %d", unrefs, ctxID)
				}
			}
		})
	}
}

func TestResourceCreateInterrupted(t *testing.T) {
	fake := newFakeVirglRenderer()
	fake.resGate = make(chan struct{})
	fake.resEntered = make(chan struct{}, 1)
	node := newTestNode(t, fake)
	fd := node.openVirgl(t)
	defer fd.DecRef(node.ctx)

	mem := newGuestMem()
	const structAddr = hostarch.Addr(0x1000)
	mem.put(t, structAddr, virtgpuResourceCreate{Size: blobAlignment})

	tc := newTestTaskCtx(t, node.ctx)
	errCh := make(chan error, 1)
	go func() {
		errCh <- node.ioctlWithCtx(tc, fd, cmdVirtgpuResourceCreate, mem, structAddr)
	}()

	<-fake.resEntered
	tc.Interrupt()

	if err := <-errCh; !linuxerr.Equals(linuxerr.ERESTARTSYS, err) {
		t.Fatalf("interrupted RESOURCE_CREATE: got %v, want ERESTARTSYS", err)
	}
	if !fake.wasResCanceled() {
		t.Errorf("renderer CreateResource did not observe cancellation")
	}
	if got := node.dev.BlobBytes(); got != 0 {
		t.Errorf("BlobBytes after interrupt = %#x, want 0", got)
	}
	mem.put(t, structAddr, virtgpuResourceInfo{BoHandle: 1})
	if err := node.ioctl(fd, cmdVirtgpuResourceInfo, mem, structAddr); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Errorf("RESOURCE_INFO(1) after interrupt: got %v, want ENOENT", err)
	}
	close(fake.resGate)
}

func TestResourceMapSharesBacking(t *testing.T) {
	requireBlobHost(t)

	fake := newFakeVirglRenderer()
	node := newTestNode(t, fake)
	fd := node.openVirgl(t)
	defer fd.DecRef(node.ctx)

	res := mustCreateResource(t, node, fd, virtgpuResourceCreate{Size: blobAlignment})
	off := mustMapOffset(t, node, fd, res.BoHandle)

	opts := memmap.MMapOpts{Offset: off, Length: blobAlignment}
	if err := fd.ConfigureMMap(node.ctx, &opts); err != nil {
		t.Fatalf("ConfigureMMap: %v", err)
	}
	defer opts.MappingIdentity.DecRef(node.ctx)

	req := memmap.MappableRange{Start: 0, End: blobAlignment}
	ts, err := opts.Mappable.Translate(node.ctx, req, req, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	fr := memmap.FileRange{Start: 0, End: blobAlignment}
	ts[0].File.IncRef(fr, 0)
	defer ts[0].File.DecRef(fr)

	bs, err := ts[0].File.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal: %v", err)
	}

	// Write through guest mapping and verify fake shm view sees the bytes.
	pattern := []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}
	if _, err := safemem.CopySeq(bs, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(pattern))); err != nil {
		t.Fatalf("CopySeq write: %v", err)
	}
	view := fake.blobMemory(res.ResHandle)
	if !bytes.Equal(view[:len(pattern)], pattern) {
		t.Fatalf("fake view[:%d] = %x, want %x", len(pattern), view[:len(pattern)], pattern)
	}

	// TRANSFER_FROM_HOST writes 0xA5 over Box.W bytes; guest mapping reads them back.
	mem := newGuestMem()
	const addr = hostarch.Addr(0x1000)
	mem.put(t, addr, virtgpu3DTransfer{
		BoHandle: res.BoHandle,
		Box:      virtgpu3DBox{W: 32, H: 1, D: 1},
	})
	if err := node.ioctl(fd, cmdVirtgpuTransferFromHost, mem, addr); err != nil {
		t.Fatalf("TRANSFER_FROM_HOST: %v", err)
	}
	readBack := make([]byte, 32)
	if _, err := safemem.CopySeq(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(readBack)), bs); err != nil {
		t.Fatalf("CopySeq read: %v", err)
	}
	if !bytes.Equal(readBack, makeFilled(32, 0xA5)) {
		t.Errorf("guest mapping after TRANSFER_FROM_HOST = %x, want 32 bytes of 0xa5", readBack)
	}
}

func TestTransferErrors(t *testing.T) {
	requireBlobHost(t)

	fake := newFakeVirglRenderer()
	node := newTestNode(t, fake)
	fd := node.openVirgl(t)
	defer fd.DecRef(node.ctx)
	ctxID := fake.createdCalls()[0].ctxID

	res := mustCreateResource(t, node, fd, virtgpuResourceCreate{Size: blobAlignment})
	mem := newGuestMem()
	const addr = hostarch.Addr(0x1000)

	// Valid TO_HOST and FROM_HOST pass all fields and Offset to the renderer.
	wantBox := virtgpu3DBox{X: 1, Y: 2, Z: 3, W: 16, H: 4, D: 1}
	mem.put(t, addr, virtgpu3DTransfer{
		BoHandle: res.BoHandle,
		Box:      wantBox,
		Level:    2,
		Offset:   64,
	})
	if err := node.ioctl(fd, cmdVirtgpuTransferToHost, mem, addr); err != nil {
		t.Fatalf("TRANSFER_TO_HOST: %v", err)
	}
	if err := node.ioctl(fd, cmdVirtgpuTransferFromHost, mem, addr); err != nil {
		t.Fatalf("TRANSFER_FROM_HOST: %v", err)
	}

	calls := fake.transferCalls()
	if len(calls) != 2 {
		t.Fatalf("Transfer calls = %d, want 2", len(calls))
	}
	wantTo := gpuproto.Transfer{
		CtxID:     ctxID,
		ResID:     res.ResHandle,
		Direction: gpuproto.TransferToHost,
		Level:     2,
		Box:       gpuproto.Box{X: 1, Y: 2, Z: 3, W: 16, H: 4, D: 1},
		Offset:    64,
	}
	wantFrom := wantTo
	wantFrom.Direction = gpuproto.TransferFromHost
	if calls[0] != wantTo {
		t.Errorf("calls[0] = %+v, want %+v", calls[0], wantTo)
	}
	if calls[1] != wantFrom {
		t.Errorf("calls[1] = %+v, want %+v", calls[1], wantFrom)
	}

	// Unknown handle returns ENOENT.
	mem.put(t, addr, virtgpu3DTransfer{BoHandle: 999})
	if err := node.ioctl(fd, cmdVirtgpuTransferToHost, mem, addr); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Errorf("TRANSFER(unknown handle): got %v, want ENOENT", err)
	}

	// Non-zero stride or layer stride returns EINVAL.
	mem.put(t, addr, virtgpu3DTransfer{BoHandle: res.BoHandle, Stride: 64})
	if err := node.ioctl(fd, cmdVirtgpuTransferToHost, mem, addr); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Errorf("TRANSFER(stride != 0): got %v, want EINVAL", err)
	}
	mem.put(t, addr, virtgpu3DTransfer{BoHandle: res.BoHandle, LayerStride: 128})
	if err := node.ioctl(fd, cmdVirtgpuTransferFromHost, mem, addr); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Errorf("TRANSFER(layer_stride != 0): got %v, want EINVAL", err)
	}

	// Renderer StatusInvalid returns EINVAL.
	fake.setTransferErr(&gpuproto.StatusError{Op: gpuproto.OpTransfer, Status: gpuproto.StatusInvalid})
	mem.put(t, addr, virtgpu3DTransfer{BoHandle: res.BoHandle})
	if err := node.ioctl(fd, cmdVirtgpuTransferToHost, mem, addr); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Errorf("TRANSFER(StatusInvalid): got %v, want EINVAL", err)
	}
	fake.setTransferErr(nil)

	// Renderer lost returns EIO.
	fake.emitRendererLost(errors.New("renderer crashed"))
	mem.put(t, addr, virtgpu3DTransfer{BoHandle: res.BoHandle})
	if err := node.ioctl(fd, cmdVirtgpuTransferFromHost, mem, addr); !linuxerr.Equals(linuxerr.EIO, err) {
		t.Errorf("TRANSFER(renderer lost): got %v, want EIO", err)
	}
}

func TestReleaseUnrefsVirglResources(t *testing.T) {
	requireBlobHost(t)

	fake := newFakeVirglRenderer()
	node := newTestNode(t, fake)
	fd := node.openVirgl(t)
	ctxID := fake.createdCalls()[0].ctxID

	r1 := mustCreateResource(t, node, fd, virtgpuResourceCreate{Size: blobAlignment})
	r2 := mustCreateResource(t, node, fd, virtgpuResourceCreate{Size: blobAlignment})
	r3 := mustCreateResource(t, node, fd, virtgpuResourceCreate{Size: blobAlignment})
	if got := node.dev.BlobBytes(); got != 3*blobAlignment {
		fd.DecRef(node.ctx)
		t.Fatalf("BlobBytes before close = %#x, want %#x", got, 3*blobAlignment)
	}

	// Keep one mapping alive across fd.DecRef: blobMapping holds a file ref, so
	// Release runs when the mapping drops and unmaps all views.
	off := mustMapOffset(t, node, fd, r1.BoHandle)
	opts := memmap.MMapOpts{Offset: off, Length: blobAlignment}
	if err := fd.ConfigureMMap(node.ctx, &opts); err != nil {
		fd.DecRef(node.ctx)
		t.Fatalf("ConfigureMMap: %v", err)
	}

	fd.DecRef(node.ctx)
	if got := node.dev.BlobBytes(); got != 3*blobAlignment {
		opts.MappingIdentity.DecRef(node.ctx)
		t.Fatalf("BlobBytes while mapping holds file ref = %#x, want %#x", got, 3*blobAlignment)
	}
	opts.MappingIdentity.DecRef(node.ctx)
	if got := node.dev.BlobBytes(); got != 0 {
		t.Errorf("BlobBytes after unmap = %#x, want 0", got)
	}

	unrefs := fake.unrefCalls()
	if len(unrefs) != 3 {
		t.Fatalf("UnrefResource calls = %d, want 3", len(unrefs))
	}
	unrefSet := map[uint32]bool{}
	for _, u := range unrefs {
		if u.ctxID != ctxID {
			t.Errorf("UnrefResource ctxID = %d, want %d", u.ctxID, ctxID)
		}
		unrefSet[u.resID] = true
	}
	for _, id := range []uint32{r1.ResHandle, r2.ResHandle, r3.ResHandle} {
		if !unrefSet[id] {
			t.Errorf("resource %d was not unreferenced on release", id)
		}
	}
	destroyed := fake.destroyedIDs()
	if len(destroyed) != 1 || destroyed[0] != ctxID {
		t.Errorf("DestroyContext calls = %v, want [%d]", destroyed, ctxID)
	}
	ops := fake.opLog()
	if len(ops) == 0 || ops[len(ops)-1].kind != "DestroyContext" {
		t.Errorf("final op = %+v, want DestroyContext after all UnrefResource calls", ops)
	}
}

func TestResourceCreateTextureBudget(t *testing.T) {
	const structAddr = hostarch.Addr(0x1000)

	t.Run("16384x16384 RGBA8 size=0 fails when budget is below 1 GiB", func(t *testing.T) {
		fake := newFakeVirglRenderer()
		node := newTestNodeWithLimits(t, fake, Limits{BlobBytes: 512 << 20})
		fd := node.openVirgl(t)
		defer fd.DecRef(node.ctx)

		mem := newGuestMem()
		mem.put(t, structAddr, virtgpuResourceCreate{
			Target:    pipeTexture2D,
			Format:    virglFormatR8G8B8A8Unorm,
			Width:     16384,
			Height:    16384,
			Depth:     1,
			ArraySize: 1,
			Size:      0,
		})
		if err := node.ioctl(fd, cmdVirtgpuResourceCreate, mem, structAddr); !linuxerr.Equals(linuxerr.ENOMEM, err) {
			t.Fatalf("RESOURCE_CREATE(16384x16384 RGBA8, 512MiB budget): got %v, want ENOMEM", err)
		}
		if got := len(fake.resCreateCalls()); got != 0 {
			t.Errorf("CreateResource calls = %d, want 0", got)
		}
		if got := node.dev.BlobBytes(); got != 0 {
			t.Errorf("BlobBytes = %#x, want 0", got)
		}
	})

	t.Run("16384x16384 RGBA8 size=0 charges 1 GiB and releases on close", func(t *testing.T) {
		requireBlobHost(t)
		fake := newFakeVirglRenderer()
		node := newTestNodeWithLimits(t, fake, Limits{BlobBytes: 2 << 30})
		fd := node.openVirgl(t)

		res := mustCreateResource(t, node, fd, virtgpuResourceCreate{
			Target:    pipeTexture2D,
			Format:    virglFormatR8G8B8A8Unorm,
			Width:     16384,
			Height:    16384,
			Depth:     1,
			ArraySize: 1,
			Size:      0,
		})
		const oneGiB = uint64(1 << 30)
		if got := node.dev.BlobBytes(); got < oneGiB {
			fd.DecRef(node.ctx)
			t.Fatalf("BlobBytes = %#x, want >= %#x", got, oneGiB)
		}

		// Backing shm remains 4 KiB because guest requested size=0.
		calls := fake.resCreateCalls()
		if len(calls) != 1 || calls[0].Size != uint64(hostarch.PageSize) {
			fd.DecRef(node.ctx)
			t.Fatalf("CreateResource calls = %+v, want 1 call with Size=%d", calls, hostarch.PageSize)
		}

		// A second 1 GiB texture fits; a third fails with ENOMEM.
		_ = mustCreateResource(t, node, fd, virtgpuResourceCreate{
			Target:    pipeTexture2D,
			Format:    virglFormatR8G8B8A8Unorm,
			Width:     16384,
			Height:    16384,
			Depth:     1,
			ArraySize: 1,
			Size:      0,
		})
		mem := newGuestMem()
		mem.put(t, structAddr, virtgpuResourceCreate{
			Target:    pipeTexture2D,
			Format:    virglFormatR8G8B8A8Unorm,
			Width:     16384,
			Height:    16384,
			Depth:     1,
			ArraySize: 1,
			Size:      0,
		})
		if err := node.ioctl(fd, cmdVirtgpuResourceCreate, mem, structAddr); !linuxerr.Equals(linuxerr.ENOMEM, err) {
			fd.DecRef(node.ctx)
			t.Fatalf("3rd 1 GiB texture: got %v, want ENOMEM", err)
		}

		mustGemClose(t, node, fd, res.BoHandle)
		if got := node.dev.BlobBytes(); got != oneGiB {
			fd.DecRef(node.ctx)
			t.Fatalf("BlobBytes after closing first 1 GiB texture = %#x, want %#x", got, oneGiB)
		}
		fd.DecRef(node.ctx)
		if got := node.dev.BlobBytes(); got != 0 {
			t.Errorf("BlobBytes after close = %#x, want 0", got)
		}
	})

	t.Run("small texture and explicit size charges max of both", func(t *testing.T) {
		requireBlobHost(t)
		fake := newFakeVirglRenderer()
		node := newTestNode(t, fake)
		fd := node.openVirgl(t)
		defer fd.DecRef(node.ctx)

		// 64x64 RGBA8 = 16384 bytes; size=0 charges 16384 bytes (one host blob page).
		_ = mustCreateResource(t, node, fd, virtgpuResourceCreate{
			Target:    pipeTexture2D,
			Format:    virglFormatR8G8B8A8Unorm,
			Width:     64,
			Height:    64,
			Depth:     1,
			ArraySize: 1,
			Size:      0,
		})
		if got := node.dev.BlobBytes(); got != blobAlignment {
			t.Fatalf("BlobBytes after 64x64 RGBA8 = %#x, want %#x", got, blobAlignment)
		}

		// Explicit Size 65536 exceeds 16x16 RGBA8 (1024), so charge is 65536.
		_ = mustCreateResource(t, node, fd, virtgpuResourceCreate{
			Target:    pipeTexture2D,
			Format:    virglFormatR8G8B8A8Unorm,
			Width:     16,
			Height:    16,
			Depth:     1,
			ArraySize: 1,
			Size:      65536,
		})
		if got := node.dev.BlobBytes(); got != blobAlignment+65536 {
			t.Fatalf("BlobBytes after explicit 64 KiB texture = %#x, want %#x", got, blobAlignment+65536)
		}
	})

	t.Run("PIPE_BUFFER keeps size semantics", func(t *testing.T) {
		requireBlobHost(t)
		fake := newFakeVirglRenderer()
		node := newTestNodeWithLimits(t, fake, Limits{BlobBytes: blobAlignment})
		fd := node.openVirgl(t)
		defer fd.DecRef(node.ctx)

		_ = mustCreateResource(t, node, fd, virtgpuResourceCreate{
			Target:    pipeBuffer,
			Format:    virglFormatR8Unorm,
			Width:     4096,
			Height:    1,
			Depth:     1,
			ArraySize: 1,
			Size:      4096,
		})
		if got := node.dev.BlobBytes(); got != blobAlignment {
			t.Errorf("BlobBytes for PIPE_BUFFER = %#x, want %#x", got, blobAlignment)
		}
	})
}

func TestResourceCreateTextureValidation(t *testing.T) {
	const structAddr = hostarch.Addr(0x1000)

	cases := []struct {
		name string
		req  virtgpuResourceCreate
	}{
		{
			name: "width above max",
			req:  virtgpuResourceCreate{Target: pipeTexture2D, Format: virglFormatR8G8B8A8Unorm, Width: maxTextureDim + 1, Height: 1, Depth: 1, ArraySize: 1},
		},
		{
			name: "height above max",
			req:  virtgpuResourceCreate{Target: pipeTexture2D, Format: virglFormatR8G8B8A8Unorm, Width: 1, Height: maxTextureDim + 1, Depth: 1, ArraySize: 1},
		},
		{
			name: "depth above max",
			req:  virtgpuResourceCreate{Target: pipeTexture3D, Format: virglFormatR8G8B8A8Unorm, Width: 1, Height: 1, Depth: maxTextureDim + 1, ArraySize: 1},
		},
		{
			name: "array size above max",
			req:  virtgpuResourceCreate{Target: pipeTexture2DArray, Format: virglFormatR8G8B8A8Unorm, Width: 1, Height: 1, Depth: 1, ArraySize: maxTextureDim + 1},
		},
		{
			name: "last level above max",
			req:  virtgpuResourceCreate{Target: pipeTexture2D, Format: virglFormatR8G8B8A8Unorm, Width: 64, Height: 64, Depth: 1, ArraySize: 1, LastLevel: maxTextureLastLevel + 1},
		},
		{
			name: "samples above max",
			req:  virtgpuResourceCreate{Target: pipeTexture2D, Format: virglFormatR8G8B8A8Unorm, Width: 64, Height: 64, Depth: 1, ArraySize: 1, NrSamples: maxTextureSamples + 1},
		},
		{
			name: "uint64 product overflow within dimension caps",
			req: virtgpuResourceCreate{
				Target:    pipeTexture3D,
				Format:    virglFormatR8G8B8A8Unorm,
				Width:     maxTextureDim,
				Height:    maxTextureDim,
				Depth:     maxTextureDim,
				ArraySize: maxTextureDim,
				NrSamples: maxTextureSamples,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeVirglRenderer()
			node := newTestNode(t, fake)
			fd := node.openVirgl(t)
			defer fd.DecRef(node.ctx)

			mem := newGuestMem()
			mem.put(t, structAddr, tc.req)
			if err := node.ioctl(fd, cmdVirtgpuResourceCreate, mem, structAddr); !linuxerr.Equals(linuxerr.EINVAL, err) {
				t.Fatalf("RESOURCE_CREATE(%s): got %v, want EINVAL", tc.name, err)
			}
			if got := len(fake.resCreateCalls()); got != 0 {
				t.Errorf("CreateResource calls = %d, want 0", got)
			}
			if got := node.dev.BlobBytes(); got != 0 {
				t.Errorf("BlobBytes = %#x, want 0", got)
			}
		})
	}

	if _, ok := roundUpBlobSizeChecked(math.MaxUint64); ok {
		t.Errorf("roundUpBlobSizeChecked(MaxUint64) succeeded, want overflow false")
	}
}

func TestVirglTextureBytesMath(t *testing.T) {
	cases := []struct {
		name string
		req  virtgpuResourceCreate
		want uint64
	}{
		{
			name: "16384x16384 RGBA8 single level",
			req: virtgpuResourceCreate{
				Target: pipeTexture2D, Format: virglFormatR8G8B8A8Unorm,
				Width: 16384, Height: 16384, Depth: 1, ArraySize: 1,
			},
			want: 1 << 30,
		},
		{
			name: "mipmaps array and samples",
			req: virtgpuResourceCreate{
				Target: pipeTexture2DArray, Format: virglFormatR8G8B8A8Unorm,
				Width: 128, Height: 64, Depth: 1, ArraySize: 2, LastLevel: 3, NrSamples: 4,
			},
			// (128*64 + 64*32 + 32*16 + 16*8) * 2 * 4 * 4 = 10880 * 32
			want: 348160,
		},
		{
			name: "3D mipmap levels clamp each axis to 1",
			req: virtgpuResourceCreate{
				Target: pipeTexture3D, Format: virglFormatR8Unorm,
				Width: 8, Height: 4, Depth: 2, ArraySize: 0, LastLevel: 3, NrSamples: 0,
			},
			// (8*4*2) + (4*2*1) + (2*1*1) + (1*1*1) = 64 + 8 + 2 + 1
			want: 75,
		},
		{
			name: "cube map enforces 6 faces",
			req: virtgpuResourceCreate{
				Target: pipeTextureCube, Format: virglFormatR8G8B8A8Unorm,
				Width: 64, Height: 64, Depth: 1, ArraySize: 1,
			},
			want: 64 * 64 * 6 * 4,
		},
		{
			name: "RGBA16F is 8 bytes per pixel",
			req: virtgpuResourceCreate{
				Target: pipeTexture2D, Format: virglFormatR16G16B16A16Float,
				Width: 32, Height: 32, Depth: 1, ArraySize: 1,
			},
			want: 32 * 32 * 8,
		},
		{
			name: "compressed format uses conservative 4 bytes per pixel",
			req: virtgpuResourceCreate{
				Target: pipeTexture2D, Format: virglFormatDXT1Rgb,
				Width: 32, Height: 32, Depth: 1, ArraySize: 1,
			},
			want: 32 * 32 * virglCompressedBytesPerPixel,
		},
		{
			name: "unknown format uses conservative 16 bytes per pixel",
			req: virtgpuResourceCreate{
				Target: pipeTexture2D, Format: 99999,
				Width: 32, Height: 32, Depth: 1, ArraySize: 1,
			},
			want: 32 * 32 * virglDefaultBytesPerPixel,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := virglTextureBytes(tc.req)
			if err != nil {
				t.Fatalf("virglTextureBytes: %v", err)
			}
			if got != tc.want {
				t.Errorf("virglTextureBytes = %d, want %d", got, tc.want)
			}
		})
	}
}
