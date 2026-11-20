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
	"testing"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

func mustCreateBlob(t *testing.T, node *testNode, fd *vfs.FileDescription, req virtgpuResourceCreateBlob) virtgpuResourceCreateBlob {
	t.Helper()
	mem := newGuestMem()
	const structAddr = hostarch.Addr(0x1000)
	mem.put(t, structAddr, req)
	if err := node.ioctl(fd, cmdVirtgpuResourceCreateBlob, mem, structAddr); err != nil {
		t.Fatalf("RESOURCE_CREATE_BLOB: %v", err)
	}
	var out virtgpuResourceCreateBlob
	mem.get(t, structAddr, &out)
	return out
}

func mustGemClose(t *testing.T, node *testNode, fd *vfs.FileDescription, handle uint32) {
	t.Helper()
	mem := newGuestMem()
	const structAddr = hostarch.Addr(0x1000)
	mem.put(t, structAddr, drmGemClose{Handle: handle})
	if err := node.ioctl(fd, cmdGemClose, mem, structAddr); err != nil {
		t.Fatalf("GEM_CLOSE(%d): %v", handle, err)
	}
}

func TestGEMCreateBlobAndInfo(t *testing.T) {
	requireBlobHost(t)

	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)
	ctxID := fake.createdCalls()[0].ctxID

	out := mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		Size:      0x3064,
		Pad:       0x12345678, // Pad is ignored, as in Linux.
		BlobID:    7,
	})
	if out.BoHandle != 1 {
		t.Fatalf("BoHandle = %d, want 1", out.BoHandle)
	}
	if out.ResHandle == 0 {
		t.Fatalf("ResHandle = 0, want non-zero")
	}

	calls := fake.blobCreateCalls()
	if len(calls) != 1 {
		t.Fatalf("CreateBlob calls = %d, want 1", len(calls))
	}
	wantCall := gpuproto.BlobCreate{
		CtxID:     ctxID,
		ResID:     out.ResHandle,
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		BlobID:    7,
		Size:      0x3064,
	}
	if calls[0] != wantCall {
		t.Errorf("CreateBlob call = %+v, want %+v", calls[0], wantCall)
	}

	mem := newGuestMem()
	const infoAddr = hostarch.Addr(0x1000)
	mem.put(t, infoAddr, virtgpuResourceInfo{BoHandle: out.BoHandle})
	if err := node.ioctl(fd, cmdVirtgpuResourceInfo, mem, infoAddr); err != nil {
		t.Fatalf("RESOURCE_INFO: %v", err)
	}
	var info virtgpuResourceInfo
	mem.get(t, infoAddr, &info)
	if info.ResHandle != out.ResHandle {
		t.Errorf("RESOURCE_INFO.ResHandle = %d, want %d", info.ResHandle, out.ResHandle)
	}
	if info.Size != 0x4000 {
		t.Errorf("RESOURCE_INFO.Size = %#x, want 0x4000", info.Size)
	}
	if info.BlobMem != virtgpuBlobMemHost3D {
		t.Errorf("RESOURCE_INFO.BlobMem = %d, want %d", info.BlobMem, virtgpuBlobMemHost3D)
	}
	if got := node.dev.BlobBytes(); got != 0x4000 {
		t.Errorf("BlobBytes() = %#x, want 0x4000", got)
	}
}

func TestGEMHandlesReuseLowest(t *testing.T) {
	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)

	create := func() uint32 {
		t.Helper()
		out := mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
			BlobMem: virtgpuBlobMemHost3D,
			Size:    0x1000,
		})
		return out.BoHandle
	}

	h1, h2, h3 := create(), create(), create()
	if h1 != 1 || h2 != 2 || h3 != 3 {
		t.Fatalf("initial handles = (%d, %d, %d), want (1, 2, 3)", h1, h2, h3)
	}

	mustGemClose(t, node, fd, 2)
	if got := create(); got != 2 {
		t.Fatalf("handle after closing 2 = %d, want 2", got)
	}

	mustGemClose(t, node, fd, 1)
	mustGemClose(t, node, fd, 3)
	if got := create(); got != 1 {
		t.Fatalf("first handle after closing 1 and 3 = %d, want 1", got)
	}
	if got := create(); got != 3 {
		t.Fatalf("second handle after closing 1 and 3 = %d, want 3", got)
	}
}

func TestGEMCloseUnreferences(t *testing.T) {
	requireBlobHost(t)

	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)
	ctxID := fake.createdCalls()[0].ctxID

	out := mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		Size:      0x4000,
	})
	if got := node.dev.BlobBytes(); got != 0x4000 {
		t.Fatalf("BlobBytes before close = %#x, want 0x4000", got)
	}

	mustGemClose(t, node, fd, out.BoHandle)
	unrefs := fake.unrefCalls()
	if len(unrefs) != 1 || unrefs[0] != (unrefCall{ctxID: ctxID, resID: out.ResHandle}) {
		t.Errorf("UnrefResource calls = %+v, want [{%d %d}]", unrefs, ctxID, out.ResHandle)
	}
	if got := node.dev.BlobBytes(); got != 0 {
		t.Errorf("BlobBytes after close = %#x, want 0", got)
	}

	mem := newGuestMem()
	const addr = hostarch.Addr(0x1000)
	for _, tc := range []struct {
		name   string
		handle uint32
	}{
		{"second close", out.BoHandle},
		{"handle 0", 0},
		{"unknown handle", 999},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mem.put(t, addr, drmGemClose{Handle: tc.handle})
			if err := node.ioctl(fd, cmdGemClose, mem, addr); !linuxerr.Equals(linuxerr.EINVAL, err) {
				t.Errorf("GEM_CLOSE(%s): got %v, want EINVAL", tc.name, err)
			}
		})
	}

	mem.put(t, addr, virtgpuResourceInfo{BoHandle: out.BoHandle})
	if err := node.ioctl(fd, cmdVirtgpuResourceInfo, mem, addr); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Errorf("RESOURCE_INFO of closed handle: got %v, want ENOENT", err)
	}
}

func TestCreateBlobRejects(t *testing.T) {
	const structAddr = hostarch.Addr(0x1000)

	cases := []struct {
		name       string
		needDarwin bool
		noCtx      bool
		setup      func(t *testing.T, fake *fakeRenderer, ctxID uint32)
		req        virtgpuResourceCreateBlob
		wantErr    error
		wantUnref  bool
	}{
		{
			name:    "unknown blob flag",
			req:     virtgpuResourceCreateBlob{BlobMem: virtgpuBlobMemHost3D, BlobFlags: 0x80, Size: 0x1000},
			wantErr: linuxerr.EINVAL,
		},
		{
			name:    "cross device flag",
			req:     virtgpuResourceCreateBlob{BlobMem: virtgpuBlobMemHost3D, BlobFlags: virtgpuBlobFlagUseCrossDevice, Size: 0x1000},
			wantErr: linuxerr.EINVAL,
		},
		{
			name:    "blob mem guest",
			req:     virtgpuResourceCreateBlob{BlobMem: virtgpuBlobMemGuest, Size: 0x1000},
			wantErr: linuxerr.EINVAL,
		},
		{
			name:    "blob mem host3d guest",
			req:     virtgpuResourceCreateBlob{BlobMem: virtgpuBlobMemHost3DGuest, Size: 0x1000},
			wantErr: linuxerr.EINVAL,
		},
		{
			name:    "cmd size not dword multiple",
			req:     virtgpuResourceCreateBlob{BlobMem: virtgpuBlobMemHost3D, Size: 0x1000, CmdSize: 6},
			wantErr: linuxerr.EINVAL,
		},
		{
			name:    "cmd size above max",
			req:     virtgpuResourceCreateBlob{BlobMem: virtgpuBlobMemHost3D, Size: 0x1000, CmdSize: gpuproto.MaxSubmitBytes + 4},
			wantErr: linuxerr.EINVAL,
		},
		{
			name:    "size zero",
			req:     virtgpuResourceCreateBlob{BlobMem: virtgpuBlobMemHost3D, Size: 0},
			wantErr: linuxerr.EINVAL,
		},
		{
			name:    "size above max",
			req:     virtgpuResourceCreateBlob{BlobMem: virtgpuBlobMemHost3D, Size: maxBlobBytes + 1},
			wantErr: linuxerr.EINVAL,
		},
		{
			name:    "no context initialized",
			noCtx:   true,
			req:     virtgpuResourceCreateBlob{BlobMem: virtgpuBlobMemHost3D, Size: 0x1000},
			wantErr: linuxerr.EINVAL,
		},
		{
			name: "context lost",
			setup: func(t *testing.T, fake *fakeRenderer, ctxID uint32) {
				fake.emitContextLost(ctxID)
			},
			req:     virtgpuResourceCreateBlob{BlobMem: virtgpuBlobMemHost3D, Size: 0x1000},
			wantErr: linuxerr.EIO,
		},
		{
			name: "renderer lost",
			setup: func(t *testing.T, fake *fakeRenderer, _ uint32) {
				fake.emitRendererLost(errors.New("renderer exited"))
			},
			req:     virtgpuResourceCreateBlob{BlobMem: virtgpuBlobMemHost3D, Size: 0x1000},
			wantErr: linuxerr.EIO,
		},
		{
			name:    "bad cmd address",
			req:     virtgpuResourceCreateBlob{BlobMem: virtgpuBlobMemHost3D, Size: 0x1000, CmdSize: 8, Cmd: uint64(badGuestAddr)},
			wantErr: linuxerr.EFAULT,
		},
		{
			name: "renderer StatusNoMemory",
			setup: func(t *testing.T, fake *fakeRenderer, _ uint32) {
				fake.setBlobErr(&gpuproto.StatusError{Op: gpuproto.OpBlobCreate, Status: gpuproto.StatusNoMemory})
			},
			req:     virtgpuResourceCreateBlob{BlobMem: virtgpuBlobMemHost3D, Size: 0x1000},
			wantErr: linuxerr.ENOMEM,
		},
		{
			name: "renderer ErrRendererLost",
			setup: func(t *testing.T, fake *fakeRenderer, _ uint32) {
				fake.setBlobErr(fmt.Errorf("disconnected: %w", gpuproto.ErrRendererLost))
			},
			req:     virtgpuResourceCreateBlob{BlobMem: virtgpuBlobMemHost3D, Size: 0x1000},
			wantErr: linuxerr.EIO,
		},
		{
			name:       "mappable reply with short shm",
			needDarwin: true,
			setup: func(t *testing.T, fake *fakeRenderer, _ uint32) {
				fake.shortShm = true
			},
			req:       virtgpuResourceCreateBlob{BlobMem: virtgpuBlobMemHost3D, BlobFlags: virtgpuBlobFlagUseMappable, Size: 0x4000},
			wantErr:   linuxerr.EIO,
			wantUnref: true,
		},
		{
			name: "mappable reply without shm",
			setup: func(t *testing.T, fake *fakeRenderer, _ uint32) {
				fake.nilMappableShm = true
			},
			req:       virtgpuResourceCreateBlob{BlobMem: virtgpuBlobMemHost3D, BlobFlags: virtgpuBlobFlagUseMappable, Size: 0x4000},
			wantErr:   linuxerr.EIO,
			wantUnref: true,
		},
		{
			name:       "non-mappable reply with unexpected shm",
			needDarwin: true,
			setup: func(t *testing.T, fake *fakeRenderer, _ uint32) {
				fake.unexpectedShm = true
			},
			req:       virtgpuResourceCreateBlob{BlobMem: virtgpuBlobMemHost3D, Size: 0x4000},
			wantErr:   linuxerr.EIO,
			wantUnref: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.needDarwin {
				requireBlobHost(t)
			}
			fake := newFakeRenderer()
			node := newTestNode(t, fake)
			var fd *vfs.FileDescription
			var ctxID uint32
			if tc.noCtx {
				fd = node.open(t)
			} else {
				fd = node.openVenus(t)
				ctxID = fake.createdCalls()[0].ctxID
			}
			defer fd.DecRef(node.ctx)

			if tc.setup != nil {
				tc.setup(t, fake, ctxID)
			}

			mem := newGuestMem()
			mem.put(t, structAddr, tc.req)
			err := node.ioctl(fd, cmdVirtgpuResourceCreateBlob, mem, structAddr)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("RESOURCE_CREATE_BLOB(%s): got %v, want %v", tc.name, err, tc.wantErr)
			}

			// Verify no handle was inserted.
			mem.put(t, structAddr, virtgpuResourceInfo{BoHandle: 1})
			if infoErr := node.ioctl(fd, cmdVirtgpuResourceInfo, mem, structAddr); !linuxerr.Equals(linuxerr.ENOENT, infoErr) {
				t.Errorf("RESOURCE_INFO(1) after failed create: got %v, want ENOENT", infoErr)
			}
			if got := node.dev.BlobBytes(); got != 0 {
				t.Errorf("BlobBytes after failed create = %#x, want 0", got)
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

func TestCreateBlobSubmitsCommandFirst(t *testing.T) {
	requireBlobHost(t)

	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)
	ctxID := fake.createdCalls()[0].ctxID

	mem := newGuestMem()
	const (
		structAddr = hostarch.Addr(0x1000)
		cmdAddr    = hostarch.Addr(0x2000)
	)
	cmdBytes := []byte{0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb, 0xcc, 0xdd}
	mem.writeBytes(cmdAddr, cmdBytes)
	mem.put(t, structAddr, virtgpuResourceCreateBlob{
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		Size:      0x4000,
		CmdSize:   uint32(len(cmdBytes)),
		Cmd:       uint64(cmdAddr),
	})
	if err := node.ioctl(fd, cmdVirtgpuResourceCreateBlob, mem, structAddr); err != nil {
		t.Fatalf("RESOURCE_CREATE_BLOB with cmd: %v", err)
	}

	ops := fake.opLog()
	if len(ops) != 2 {
		t.Fatalf("opLog len = %d (%+v), want 2", len(ops), ops)
	}
	if ops[0].kind != "Submit" || ops[0].ctxID != ctxID || !bytes.Equal(ops[0].cmd, cmdBytes) {
		t.Errorf("ops[0] = %+v, want Submit(%d, %x)", ops[0], ctxID, cmdBytes)
	}
	if ops[1].kind != "CreateBlob" || ops[1].ctxID != ctxID {
		t.Errorf("ops[1] = %+v, want CreateBlob on ctx %d", ops[1], ctxID)
	}

	submits := fake.submitCalls()
	if len(submits) != 1 || submits[0].fence != nil {
		t.Errorf("submitCalls = %+v, want 1 submit with nil fence", submits)
	}
}

func TestCreateBlobPreSubmitErrorSkipsCreate(t *testing.T) {
	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)

	fake.setSubmitErr(errors.New("write timeout"))

	mem := newGuestMem()
	const (
		structAddr = hostarch.Addr(0x1000)
		cmdAddr    = hostarch.Addr(0x2000)
	)
	mem.writeBytes(cmdAddr, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	mem.put(t, structAddr, virtgpuResourceCreateBlob{
		BlobMem: virtgpuBlobMemHost3D,
		Size:    0x4000,
		CmdSize: 8,
		Cmd:     uint64(cmdAddr),
	})
	if err := node.ioctl(fd, cmdVirtgpuResourceCreateBlob, mem, structAddr); !linuxerr.Equals(linuxerr.EIO, err) {
		t.Fatalf("RESOURCE_CREATE_BLOB with Submit error: got %v, want EIO", err)
	}
	if got := len(fake.blobCreateCalls()); got != 0 {
		t.Errorf("CreateBlob calls = %d, want 0", got)
	}
	mem.put(t, structAddr, virtgpuResourceInfo{BoHandle: 1})
	if err := node.ioctl(fd, cmdVirtgpuResourceInfo, mem, structAddr); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Errorf("RESOURCE_INFO(1) after pre-submit error: got %v, want ENOENT", err)
	}
	if got := node.dev.BlobBytes(); got != 0 {
		t.Errorf("BlobBytes = %#x, want 0", got)
	}
}

func TestCreateBlobInterruptedRestarts(t *testing.T) {
	requireBlobHost(t)

	fake := newFakeRenderer()
	fake.blobGate = make(chan struct{})
	fake.blobEntered = make(chan struct{}, 1)
	node := newTestNode(t, fake)
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)

	mem := newGuestMem()
	const structAddr = hostarch.Addr(0x1000)
	req := virtgpuResourceCreateBlob{
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		Size:      0x4000,
	}
	mem.put(t, structAddr, req)

	tc := newTestTaskCtx(t, node.ctx)
	errCh := make(chan error, 1)
	go func() {
		errCh <- node.ioctlWithCtx(tc, fd, cmdVirtgpuResourceCreateBlob, mem, structAddr)
	}()

	<-fake.blobEntered
	tc.Interrupt()

	if err := <-errCh; !linuxerr.Equals(linuxerr.ERESTARTSYS, err) {
		t.Fatalf("interrupted RESOURCE_CREATE_BLOB: got %v, want ERESTARTSYS", err)
	}
	if !fake.wasBlobCanceled() {
		t.Errorf("renderer CreateBlob did not observe cancellation")
	}
	if got := node.dev.BlobBytes(); got != 0 {
		t.Errorf("BlobBytes after interrupt = %#x, want 0", got)
	}
	mem.put(t, structAddr, virtgpuResourceInfo{BoHandle: 1})
	if err := node.ioctl(fd, cmdVirtgpuResourceInfo, mem, structAddr); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Errorf("RESOURCE_INFO(1) after interrupt: got %v, want ENOENT", err)
	}

	// Retry succeeds with a new resource handle.
	close(fake.blobGate)
	out := mustCreateBlob(t, node, fd, req)
	if out.BoHandle != 1 {
		t.Errorf("retry BoHandle = %d, want 1", out.BoHandle)
	}
	if out.ResHandle <= 1 {
		t.Errorf("retry ResHandle = %d, want > 1", out.ResHandle)
	}
}

func TestCloseReleasesInLinuxOrder(t *testing.T) {
	requireBlobHost(t)

	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	fd := node.openVenus(t)
	ctxID := fake.createdCalls()[0].ctxID

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
	if got := node.dev.BlobBytes(); got != 0x8000 {
		t.Fatalf("BlobBytes before close = %#x, want 0x8000", got)
	}

	fd.DecRef(node.ctx)

	if got := node.dev.BlobBytes(); got != 0 {
		t.Errorf("BlobBytes after close = %#x, want 0", got)
	}

	ops := fake.opLog()
	// First two ops are CreateBlob; the last three must be two UnrefResource followed by DestroyContext.
	if len(ops) != 5 {
		t.Fatalf("opLog len = %d (%+v), want 5", len(ops), ops)
	}
	unrefSet := map[uint32]bool{}
	for _, op := range ops[2:4] {
		if op.kind != "UnrefResource" || op.ctxID != ctxID {
			t.Errorf("release op = %+v, want UnrefResource on ctx %d", op, ctxID)
		}
		unrefSet[op.resID] = true
	}
	if !unrefSet[b1.ResHandle] || !unrefSet[b2.ResHandle] {
		t.Errorf("unreferenced resources = %v, want %d and %d", unrefSet, b1.ResHandle, b2.ResHandle)
	}
	if ops[4].kind != "DestroyContext" || ops[4].ctxID != ctxID {
		t.Errorf("final release op = %+v, want DestroyContext(%d)", ops[4], ctxID)
	}
}
