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
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
	"z.gfire.dev/gvx/pkg/waiter"
)

func TestExecbufferSubmits(t *testing.T) {
	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)
	ctxID := fake.createdCalls()[0].ctxID

	// Create one handle to verify valid BO handle arrays are accepted.
	bo := mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
		BlobMem: virtgpuBlobMemHost3D,
		Size:    0x1000,
	})

	mem := newGuestMem()
	const (
		structAddr = hostarch.Addr(0x1000)
		cmdAddr    = hostarch.Addr(0x2000)
		boAddr     = hostarch.Addr(0x3000)
	)

	cmd1 := []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}
	mem.writeBytes(cmdAddr, cmd1)
	var boBuf [4]byte
	binary.LittleEndian.PutUint32(boBuf[:], bo.BoHandle)
	mem.writeBytes(boAddr, boBuf[:])

	mem.put(t, structAddr, virtgpuExecbuffer{
		Flags:        virtgpuExecbufRingIdx,
		Size:         uint32(len(cmd1)),
		Command:      uint64(cmdAddr),
		BoHandles:    uint64(boAddr),
		NumBoHandles: 1,
		RingIdx:      3,
	})
	if err := node.ioctl(fd, cmdVirtgpuExecbuffer, mem, structAddr); err != nil {
		t.Fatalf("EXECBUFFER(ring 3): %v", err)
	}

	// Without RING_IDX, ring defaults to 0 even if RingIdx holds a non-zero value.
	cmd2 := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	mem.writeBytes(cmdAddr, cmd2)
	mem.put(t, structAddr, virtgpuExecbuffer{
		Size:    uint32(len(cmd2)),
		Command: uint64(cmdAddr),
		RingIdx: 99,
	})
	if err := node.ioctl(fd, cmdVirtgpuExecbuffer, mem, structAddr); err != nil {
		t.Fatalf("EXECBUFFER(default ring): %v", err)
	}

	calls := fake.submitCalls()
	if len(calls) != 2 {
		t.Fatalf("Submit calls = %d, want 2", len(calls))
	}
	if calls[0].ctxID != ctxID || !bytes.Equal(calls[0].cmd, cmd1) || calls[0].fence != nil {
		t.Errorf("calls[0] = %+v, want ctx %d cmd %x nil fence", calls[0], ctxID, cmd1)
	}
	if calls[1].ctxID != ctxID || !bytes.Equal(calls[1].cmd, cmd2) || calls[1].fence != nil {
		t.Errorf("calls[1] = %+v, want ctx %d cmd %x nil fence", calls[1], ctxID, cmd2)
	}
}

func TestExecbufferRejects(t *testing.T) {
	const (
		structAddr = hostarch.Addr(0x1000)
		boAddr     = hostarch.Addr(0x2000)
	)

	openNoRings := func(t *testing.T, node *testNode) *vfs.FileDescription {
		t.Helper()
		fd := node.open(t)
		mem := newGuestMem()
		params := []virtgpuContextSetParam{
			{Param: virtgpuContextParamCapsetID, Value: virtgpuCapsetVenus},
		}
		putContextInit(t, mem, 0x1000, 0x2000, params)
		if err := node.ioctl(fd, cmdVirtgpuContextInit, mem, 0x1000); err != nil {
			fd.DecRef(node.ctx)
			t.Fatalf("CONTEXT_INIT(0 rings): %v", err)
		}
		return fd
	}

	cases := []struct {
		name    string
		openFD  func(t *testing.T, node *testNode) *vfs.FileDescription
		setup   func(t *testing.T, fake *fakeRenderer, mem *guestMem, ctxID uint32)
		req     virtgpuExecbuffer
		wantErr error
	}{
		{
			name:    "unknown flag",
			req:     virtgpuExecbuffer{Flags: 0x80},
			wantErr: linuxerr.EINVAL,
		},
		{
			name:    "FENCE_FD_IN unsupported",
			req:     virtgpuExecbuffer{Flags: virtgpuExecbufFenceFDIn},
			wantErr: linuxerr.EINVAL,
		},
		{
			name:    "non-zero num_in_syncobjs",
			req:     virtgpuExecbuffer{NumInSyncobjs: 1},
			wantErr: linuxerr.EINVAL,
		},
		{
			name:    "non-zero num_out_syncobjs",
			req:     virtgpuExecbuffer{NumOutSyncobjs: 1},
			wantErr: linuxerr.EINVAL,
		},
		{
			name:    "size not dword aligned",
			req:     virtgpuExecbuffer{Size: 6},
			wantErr: linuxerr.EINVAL,
		},
		{
			name:    "size above MaxSubmitBytes",
			req:     virtgpuExecbuffer{Size: gpuproto.MaxSubmitBytes + 4},
			wantErr: linuxerr.EINVAL,
		},
		{
			name: "no context",
			openFD: func(t *testing.T, node *testNode) *vfs.FileDescription {
				return node.open(t)
			},
			req:     virtgpuExecbuffer{},
			wantErr: linuxerr.EINVAL,
		},
		{
			name:    "RING_IDX on context without NUM_RINGS",
			openFD:  openNoRings,
			req:     virtgpuExecbuffer{Flags: virtgpuExecbufRingIdx, RingIdx: 0},
			wantErr: linuxerr.EINVAL,
		},
		{
			name:    "ring 64 out of range",
			req:     virtgpuExecbuffer{Flags: virtgpuExecbufRingIdx, RingIdx: gpuproto.MaxRings},
			wantErr: linuxerr.EINVAL,
		},
		{
			name: "context lost",
			setup: func(t *testing.T, fake *fakeRenderer, _ *guestMem, ctxID uint32) {
				fake.emitContextLost(ctxID)
			},
			req:     virtgpuExecbuffer{},
			wantErr: linuxerr.EIO,
		},
		{
			name: "renderer lost",
			setup: func(t *testing.T, fake *fakeRenderer, _ *guestMem, _ uint32) {
				fake.emitRendererLost(errors.New("renderer exited"))
			},
			req:     virtgpuExecbuffer{},
			wantErr: linuxerr.EIO,
		},
		{
			name:    "num_bo_handles above maxBoHandles",
			req:     virtgpuExecbuffer{NumBoHandles: maxBoHandles + 1},
			wantErr: linuxerr.EINVAL,
		},
		{
			name:    "bad bo_handles pointer",
			req:     virtgpuExecbuffer{NumBoHandles: 1, BoHandles: uint64(badGuestAddr)},
			wantErr: linuxerr.EFAULT,
		},
		{
			name: "unknown BO handle",
			setup: func(t *testing.T, _ *fakeRenderer, mem *guestMem, _ uint32) {
				var raw [4]byte
				binary.LittleEndian.PutUint32(raw[:], 42)
				mem.writeBytes(boAddr, raw[:])
			},
			req:     virtgpuExecbuffer{NumBoHandles: 1, BoHandles: uint64(boAddr)},
			wantErr: linuxerr.ENOENT,
		},
		{
			name:    "bad command pointer",
			req:     virtgpuExecbuffer{Size: 4, Command: uint64(badGuestAddr)},
			wantErr: linuxerr.EFAULT,
		},
		{
			name:    "FENCE_FD_OUT without fdInstaller",
			req:     virtgpuExecbuffer{Flags: virtgpuExecbufFenceFDOut},
			wantErr: linuxerr.EINVAL,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeRenderer()
			node := newTestNode(t, fake)
			var fd *vfs.FileDescription
			if tc.openFD != nil {
				fd = tc.openFD(t, node)
			} else {
				fd = node.openVenus(t)
			}
			defer fd.DecRef(node.ctx)

			var ctxID uint32
			if calls := fake.createdCalls(); len(calls) > 0 {
				ctxID = calls[0].ctxID
			}
			mem := newGuestMem()
			if tc.setup != nil {
				tc.setup(t, fake, mem, ctxID)
			}
			mem.put(t, structAddr, tc.req)
			err := node.ioctl(fd, cmdVirtgpuExecbuffer, mem, structAddr)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("EXECBUFFER(%s): got %v, want %v", tc.name, err, tc.wantErr)
			}
			if got := len(fake.submitCalls()); got != 0 {
				t.Errorf("EXECBUFFER(%s): fake received %d Submit calls, want 0", tc.name, got)
			}
		})
	}
}

func TestExecbufferFenceFDOut(t *testing.T) {
	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)
	ctxID := fake.createdCalls()[0].ctxID

	tc := newTestTaskCtx(t, node.ctx)
	mem := newGuestMem()
	const structAddr = hostarch.Addr(0x1000)

	mem.put(t, structAddr, virtgpuExecbuffer{
		Flags: virtgpuExecbufFenceFDOut,
	})
	if err := node.ioctlWithCtx(tc, fd, cmdVirtgpuExecbuffer, mem, structAddr); err != nil {
		t.Fatalf("EXECBUFFER(FENCE_FD_OUT): %v", err)
	}
	var out virtgpuExecbuffer
	mem.get(t, structAddr, &out)
	if out.FenceFD != 3 {
		t.Fatalf("FenceFD = %d, want 3", out.FenceFD)
	}
	if !tc.fdFlags(out.FenceFD).CloseOnExec {
		t.Errorf("sync_file FDFlags.CloseOnExec = false, want true")
	}

	calls := fake.submitCalls()
	if len(calls) != 1 || calls[0].fence == nil {
		t.Fatalf("submitCalls = %+v, want 1 call with fence", calls)
	}
	if calls[0].fence.RingIdx != 0 || calls[0].fence.ID == 0 {
		t.Fatalf("submitted fence = %+v, want ring 0 and non-zero ID", *calls[0].fence)
	}

	sf := tc.file(out.FenceFD)
	if sf == nil {
		t.Fatalf("testTaskCtx has no file for FD %d", out.FenceFD)
	}
	if got := sf.Readiness(waiter.ReadableEvents); got != 0 {
		t.Fatalf("Readiness before FenceDone = %#x, want 0", got)
	}

	entry, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	if err := sf.EventRegister(&entry); err != nil {
		t.Fatalf("EventRegister: %v", err)
	}
	defer sf.EventUnregister(&entry)

	fake.emitFenceDone(ctxID, 0, calls[0].fence.ID)

	select {
	case <-ch:
	default:
		t.Fatalf("waiter was not notified on FenceDone")
	}
	if got := sf.Readiness(waiter.ReadableEvents); got != waiter.ReadableEvents {
		t.Errorf("Readiness after FenceDone = %#x, want %#x", got, waiter.ReadableEvents)
	}
}

func TestExecbufferFenceFDOutSubmitErrorRollsBack(t *testing.T) {
	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)
	ctxID := fake.createdCalls()[0].ctxID

	tc := newTestTaskCtx(t, node.ctx)
	filesBefore := node.vfs.NumFiles()
	mem := newGuestMem()
	const structAddr = hostarch.Addr(0x1000)

	fake.setSubmitErr(errors.New("write timeout"))
	mem.put(t, structAddr, virtgpuExecbuffer{
		Flags:   virtgpuExecbufFenceFDOut,
		FenceFD: -1,
	})
	if err := node.ioctlWithCtx(tc, fd, cmdVirtgpuExecbuffer, mem, structAddr); !linuxerr.Equals(linuxerr.EIO, err) {
		t.Fatalf("EXECBUFFER(FENCE_FD_OUT) on Submit error: got %v, want EIO", err)
	}
	var failedOut virtgpuExecbuffer
	mem.get(t, structAddr, &failedOut)
	if failedOut.FenceFD != -1 {
		t.Errorf("FenceFD after Submit error = %d, want -1", failedOut.FenceFD)
	}
	if tc.file(3) != nil {
		t.Fatalf("sync_file FD 3 was installed despite Submit error")
	}
	if got := node.vfs.NumFiles(); got != filesBefore {
		t.Errorf("vfs.NumFiles() after Submit error = %d, want %d", got, filesBefore)
	}

	// Clearing the error leaves ring 0 and FD slot 3 usable for subsequent fenced submits.
	fake.setSubmitErr(nil)
	mem.put(t, structAddr, virtgpuExecbuffer{Flags: virtgpuExecbufFenceFDOut})
	if err := node.ioctlWithCtx(tc, fd, cmdVirtgpuExecbuffer, mem, structAddr); err != nil {
		t.Fatalf("subsequent EXECBUFFER(FENCE_FD_OUT): %v", err)
	}
	var out virtgpuExecbuffer
	mem.get(t, structAddr, &out)
	if out.FenceFD != 3 {
		t.Fatalf("FenceFD = %d, want 3", out.FenceFD)
	}
	calls := fake.submitCalls()
	if len(calls) != 1 || calls[0].fence == nil {
		t.Fatalf("submitCalls = %+v, want 1 fenced submit", calls)
	}
	sf := tc.file(out.FenceFD)
	if sf == nil {
		t.Fatalf("missing sync_file for FD %d", out.FenceFD)
	}
	fake.emitFenceDone(ctxID, 0, calls[0].fence.ID)
	if got := sf.Readiness(waiter.ReadableEvents); got != waiter.ReadableEvents {
		t.Errorf("Readiness after FenceDone = %#x, want %#x", got, waiter.ReadableEvents)
	}
}

func TestExecbufferFenceFDOutEMFILEDoesNotSubmit(t *testing.T) {
	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)

	tc := newTestTaskCtx(t, node.ctx)
	// FDs 0, 1, and 2 are already occupied; RLIMIT_NOFILE=3 exhausts the table.
	tc.setNoFileLimit(t, 3)
	filesBefore := node.vfs.NumFiles()

	mem := newGuestMem()
	const (
		structAddr = hostarch.Addr(0x1000)
		cmdAddr    = hostarch.Addr(0x2000)
	)
	mem.writeBytes(cmdAddr, []byte{1, 2, 3, 4})
	mem.put(t, structAddr, virtgpuExecbuffer{
		Flags:   virtgpuExecbufFenceFDOut,
		Size:    4,
		Command: uint64(cmdAddr),
		FenceFD: -1,
	})
	if err := node.ioctlWithCtx(tc, fd, cmdVirtgpuExecbuffer, mem, structAddr); !linuxerr.Equals(linuxerr.EMFILE, err) {
		t.Fatalf("EXECBUFFER(FENCE_FD_OUT) at RLIMIT_NOFILE: got %v, want EMFILE", err)
	}
	if got := len(fake.submitCalls()); got != 0 {
		t.Errorf("Submit calls after EMFILE = %d, want 0", got)
	}
	var out virtgpuExecbuffer
	mem.get(t, structAddr, &out)
	if out.FenceFD != -1 {
		t.Errorf("FenceFD after EMFILE = %d, want -1", out.FenceFD)
	}
	if tc.file(3) != nil {
		t.Errorf("FD 3 was installed despite EMFILE")
	}
	if got := node.vfs.NumFiles(); got != filesBefore {
		t.Errorf("vfs.NumFiles() after EMFILE = %d, want %d", got, filesBefore)
	}
}

func TestExecbufferVirglRecordsObjectFence(t *testing.T) {
	requireBlobHost(t)

	fake := newFakeVirglRenderer()
	node := newTestNode(t, fake)
	fd := node.openVirgl(t)
	defer fd.DecRef(node.ctx)
	ctxID := fake.createdCalls()[0].ctxID

	res := mustCreateResource(t, node, fd, virtgpuResourceCreate{Size: 4096})

	mem := newGuestMem()
	const (
		structAddr = hostarch.Addr(0x1000)
		boAddr     = hostarch.Addr(0x2000)
	)
	var boBuf [4]byte
	binary.LittleEndian.PutUint32(boBuf[:], res.BoHandle)
	mem.writeBytes(boAddr, boBuf[:])
	mem.put(t, structAddr, virtgpuExecbuffer{
		BoHandles:    uint64(boAddr),
		NumBoHandles: 1,
	})
	if err := node.ioctl(fd, cmdVirtgpuExecbuffer, mem, structAddr); err != nil {
		t.Fatalf("virgl EXECBUFFER with handle: %v", err)
	}

	calls := fake.submitCalls()
	if len(calls) != 1 || calls[0].fence == nil {
		t.Fatalf("submitCalls = %+v, want 1 call with fence", calls)
	}
	if calls[0].fence.RingIdx != 0 || calls[0].fence.ID == 0 {
		t.Fatalf("submitted fence = %+v, want ring 0 and non-zero ID", *calls[0].fence)
	}

	mem.put(t, structAddr, virtgpu3DWait{Handle: res.BoHandle, Flags: virtgpuWaitNoWait})
	if err := node.ioctl(fd, cmdVirtgpuWait, mem, structAddr); !linuxerr.Equals(linuxerr.EBUSY, err) {
		t.Fatalf("WAIT(NOWAIT) before FenceDone: got %v, want EBUSY", err)
	}

	fake.emitFenceDone(ctxID, 0, calls[0].fence.ID)

	mem.put(t, structAddr, virtgpu3DWait{Handle: res.BoHandle})
	if err := node.ioctl(fd, cmdVirtgpuWait, mem, structAddr); err != nil {
		t.Fatalf("WAIT after FenceDone: got %v, want nil", err)
	}
}

func TestExecbufferVirglWithoutHandlesHasNoFence(t *testing.T) {
	fake := newFakeVirglRenderer()
	node := newTestNode(t, fake)
	fd := node.openVirgl(t)
	defer fd.DecRef(node.ctx)

	mem := newGuestMem()
	const structAddr = hostarch.Addr(0x1000)
	mem.put(t, structAddr, virtgpuExecbuffer{})
	if err := node.ioctl(fd, cmdVirtgpuExecbuffer, mem, structAddr); err != nil {
		t.Fatalf("virgl EXECBUFFER without handles: %v", err)
	}

	calls := fake.submitCalls()
	if len(calls) != 1 || calls[0].fence != nil {
		t.Fatalf("submitCalls = %+v, want 1 call with nil fence", calls)
	}
}

func TestExecbufferVenusKeepsNoObjectFence(t *testing.T) {
	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)

	bo := mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
		BlobMem: virtgpuBlobMemHost3D,
		Size:    0x1000,
	})

	mem := newGuestMem()
	const (
		structAddr = hostarch.Addr(0x1000)
		boAddr     = hostarch.Addr(0x2000)
	)
	var boBuf [4]byte
	binary.LittleEndian.PutUint32(boBuf[:], bo.BoHandle)
	mem.writeBytes(boAddr, boBuf[:])
	mem.put(t, structAddr, virtgpuExecbuffer{
		BoHandles:    uint64(boAddr),
		NumBoHandles: 1,
	})
	if err := node.ioctl(fd, cmdVirtgpuExecbuffer, mem, structAddr); err != nil {
		t.Fatalf("venus EXECBUFFER with handle: %v", err)
	}

	calls := fake.submitCalls()
	if len(calls) != 1 || calls[0].fence != nil {
		t.Fatalf("submitCalls = %+v, want 1 call with nil fence", calls)
	}
}

// countingIO records bytes copied from command buffer address cmdAddr.
type countingIO struct {
	usermem.IO
	cmdAddr hostarch.Addr
	copied  *atomic.Int64
}

func (c *countingIO) CopyIn(ctx context.Context, addr hostarch.Addr, dst []byte, opts usermem.IOOpts) (int, error) {
	n, err := c.IO.CopyIn(ctx, addr, dst, opts)
	if err == nil && addr == c.cmdAddr {
		c.copied.Add(int64(n))
	}
	return n, err
}

func ioctlWithIO(ctx context.Context, fd *vfs.FileDescription, cmd uint32, uio usermem.IO, addr hostarch.Addr) error {
	var args arch.SyscallArguments
	args[1] = arch.SyscallArgument{Value: uintptr(cmd)}
	args[2] = arch.SyscallArgument{Value: uintptr(addr)}
	_, err := fd.Ioctl(ctx, uio, 0, args)
	return err
}

func TestExecbufferSubmitByteBound(t *testing.T) {
	const (
		cmdSize    = 16 << 10
		limitBytes = 32 << 10 // room for 2 concurrent 16 KiB command copies
		workers    = 6
		structAddr = hostarch.Addr(0x1000)
		cmdAddr    = hostarch.Addr(0x2000)
	)

	t.Run("one context bounds copied bytes while submits block", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			fake := newFakeRenderer()
			fake.submitGate = make(chan struct{})
			// Limit to one command buffer on one context so 1 worker blocks in
			// Submit and the other 5 block durably in submitBudget.acquire.
			node := newTestNodeWithLimits(t, fake, Limits{SubmitBytes: cmdSize})
			fd := node.openVenus(t)
			defer fd.DecRef(node.ctx)

			var copied atomic.Int64
			errCh := make(chan error, workers)
			var wg sync.WaitGroup
			for range workers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					mem := newGuestMem()
					mem.put(t, structAddr, virtgpuExecbuffer{
						Size:    cmdSize,
						Command: uint64(cmdAddr),
					})
					uio := &countingIO{IO: &mem.BytesIO, cmdAddr: cmdAddr, copied: &copied}
					errCh <- ioctlWithIO(node.ctx, fd, cmdVirtgpuExecbuffer, uio, structAddr)
				}()
			}

			synctest.Wait()
			if got := copied.Load(); got != cmdSize {
				close(fake.submitGate)
				wg.Wait()
				t.Fatalf("in-flight copied command bytes = %d, want %d", got, cmdSize)
			}

			// Release submits one at a time and verify all complete cleanly.
			for range workers {
				fake.submitGate <- struct{}{}
			}
			wg.Wait()
			close(errCh)
			for err := range errCh {
				if err != nil {
					t.Fatalf("concurrent EXECBUFFER: %v", err)
				}
			}
			if got := len(fake.submitCalls()); got != workers {
				t.Errorf("Submit calls = %d, want %d", got, workers)
			}
		})
	})

	t.Run("multiple contexts share per-device bound", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			fake := newFakeRenderer()
			fake.submitGate = make(chan struct{})
			node := newTestNodeWithLimits(t, fake, Limits{SubmitBytes: limitBytes})

			fds := make([]*vfs.FileDescription, workers)
			for i := range fds {
				fds[i] = node.openVenus(t)
				defer fds[i].DecRef(node.ctx)
			}

			var copied atomic.Int64
			errCh := make(chan error, workers)
			var wg sync.WaitGroup
			for i := range workers {
				wg.Add(1)
				go func(fd *vfs.FileDescription) {
					defer wg.Done()
					mem := newGuestMem()
					mem.put(t, structAddr, virtgpuExecbuffer{
						Size:    cmdSize,
						Command: uint64(cmdAddr),
					})
					uio := &countingIO{IO: &mem.BytesIO, cmdAddr: cmdAddr, copied: &copied}
					errCh <- ioctlWithIO(node.ctx, fd, cmdVirtgpuExecbuffer, uio, structAddr)
				}(fds[i])
			}

			synctest.Wait()
			if got := copied.Load(); got > limitBytes {
				close(fake.submitGate)
				wg.Wait()
				t.Fatalf("multi-context copied bytes = %d, want <= %d", got, limitBytes)
			}

			// A second Device (second sandbox) has an independent budget.
			fakeB := newFakeRenderer()
			nodeB := newTestNodeWithLimits(t, fakeB, Limits{SubmitBytes: limitBytes})
			fdB := nodeB.openVenus(t)
			defer fdB.DecRef(nodeB.ctx)
			memB := newGuestMem()
			memB.put(t, structAddr, virtgpuExecbuffer{Size: cmdSize, Command: uint64(cmdAddr)})
			if err := nodeB.ioctl(fdB, cmdVirtgpuExecbuffer, memB, structAddr); err != nil {
				close(fake.submitGate)
				wg.Wait()
				t.Fatalf("second device EXECBUFFER while first is full: %v", err)
			}

			close(fake.submitGate)
			wg.Wait()
			close(errCh)
			for err := range errCh {
				if err != nil {
					t.Fatalf("multi-context EXECBUFFER: %v", err)
				}
			}
		})
	})

	t.Run("interrupted waiter returns ERESTARTSYS without copying", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			fake := newFakeRenderer()
			fake.submitGate = make(chan struct{})
			node := newTestNodeWithLimits(t, fake, Limits{SubmitBytes: cmdSize})
			fd := node.openVenus(t)
			defer fd.DecRef(node.ctx)

			// First worker holds the entire cmdSize budget inside Submit.
			done1 := make(chan error, 1)
			go func() {
				mem := newGuestMem()
				mem.put(t, structAddr, virtgpuExecbuffer{Size: cmdSize, Command: uint64(cmdAddr)})
				done1 <- node.ioctl(fd, cmdVirtgpuExecbuffer, mem, structAddr)
			}()
			synctest.Wait()

			// Second worker blocks in submitBudget.acquire and receives a signal.
			tc := newTestTaskCtx(t, node.ctx)
			var copied2 atomic.Int64
			done2 := make(chan error, 1)
			go func() {
				mem := newGuestMem()
				mem.put(t, structAddr, virtgpuExecbuffer{Size: cmdSize, Command: uint64(cmdAddr)})
				uio := &countingIO{IO: &mem.BytesIO, cmdAddr: cmdAddr, copied: &copied2}
				done2 <- ioctlWithIO(tc, fd, cmdVirtgpuExecbuffer, uio, structAddr)
			}()
			synctest.Wait()

			tc.Interrupt()
			if err := <-done2; !linuxerr.Equals(linuxerr.ERESTARTSYS, err) {
				close(fake.submitGate)
				<-done1
				t.Fatalf("interrupted EXECBUFFER: got %v, want ERESTARTSYS", err)
			}
			if got := copied2.Load(); got != 0 {
				close(fake.submitGate)
				<-done1
				t.Errorf("interrupted worker copied %d bytes, want 0", got)
			}

			close(fake.submitGate)
			if err := <-done1; err != nil {
				t.Fatalf("first EXECBUFFER: %v", err)
			}
		})
	})
}
