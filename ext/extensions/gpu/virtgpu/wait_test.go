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
	"encoding/binary"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

func execVirglWithHandles(t *testing.T, node *testNode, fd *vfs.FileDescription, handles ...uint32) uint64 {
	t.Helper()
	fake := node.dev.renderer.(*fakeRenderer)
	before := len(fake.submitCalls())

	mem := newGuestMem()
	const (
		structAddr = hostarch.Addr(0x1000)
		boAddr     = hostarch.Addr(0x2000)
	)
	raw := make([]byte, len(handles)*4)
	for i, h := range handles {
		binary.LittleEndian.PutUint32(raw[i*4:], h)
	}
	mem.writeBytes(boAddr, raw)
	mem.put(t, structAddr, virtgpuExecbuffer{
		BoHandles:    uint64(boAddr),
		NumBoHandles: uint32(len(handles)),
	})
	if err := node.ioctl(fd, cmdVirtgpuExecbuffer, mem, structAddr); err != nil {
		t.Fatalf("EXECBUFFER(handles=%v): %v", handles, err)
	}
	calls := fake.submitCalls()
	if len(calls) != before+1 || calls[before].fence == nil {
		t.Fatalf("expected 1 new fenced submit, got %d", len(calls)-before)
	}
	return calls[before].fence.ID
}

func TestWaitCases(t *testing.T) {
	requireBlobHost(t)

	const structAddr = hostarch.Addr(0x1000)

	t.Run("unknown handle and handle 0 return ENOENT", func(t *testing.T) {
		node := newTestNode(t, newFakeVirglRenderer())
		fd := node.openVirgl(t)
		defer fd.DecRef(node.ctx)

		mem := newGuestMem()
		for _, h := range []uint32{0, 999} {
			mem.put(t, structAddr, virtgpu3DWait{Handle: h})
			if err := node.ioctl(fd, cmdVirtgpuWait, mem, structAddr); !linuxerr.Equals(linuxerr.ENOENT, err) {
				t.Errorf("WAIT(handle=%d): got %v, want ENOENT", h, err)
			}
		}
	})

	t.Run("idle object and unknown flags return 0", func(t *testing.T) {
		node := newTestNode(t, newFakeVirglRenderer())
		fd := node.openVirgl(t)
		defer fd.DecRef(node.ctx)

		res := mustCreateResource(t, node, fd, virtgpuResourceCreate{Size: 4096})
		mem := newGuestMem()
		mem.put(t, structAddr, virtgpu3DWait{Handle: res.BoHandle, Flags: 0x8000})
		if err := node.ioctl(fd, cmdVirtgpuWait, mem, structAddr); err != nil {
			t.Fatalf("WAIT(idle, unknown flags): got %v, want nil", err)
		}
	})

	t.Run("NOWAIT pending returns EBUSY and signaled returns 0", func(t *testing.T) {
		fake := newFakeVirglRenderer()
		node := newTestNode(t, fake)
		fd := node.openVirgl(t)
		defer fd.DecRef(node.ctx)
		ctxID := fake.createdCalls()[0].ctxID

		res := mustCreateResource(t, node, fd, virtgpuResourceCreate{Size: 4096})
		fenceID := execVirglWithHandles(t, node, fd, res.BoHandle)

		mem := newGuestMem()
		mem.put(t, structAddr, virtgpu3DWait{Handle: res.BoHandle, Flags: virtgpuWaitNoWait})
		if err := node.ioctl(fd, cmdVirtgpuWait, mem, structAddr); !linuxerr.Equals(linuxerr.EBUSY, err) {
			t.Fatalf("WAIT(NOWAIT, pending): got %v, want EBUSY", err)
		}

		fake.emitFenceDone(ctxID, 0, fenceID)
		if err := node.ioctl(fd, cmdVirtgpuWait, mem, structAddr); err != nil {
			t.Fatalf("WAIT(NOWAIT, signaled): got %v, want nil", err)
		}
	})

	t.Run("blocking wait returns 0 when fence signals", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			fake := newFakeVirglRenderer()
			node := newTestNode(t, fake)
			fd := node.openVirgl(t)
			defer fd.DecRef(node.ctx)
			ctxID := fake.createdCalls()[0].ctxID

			res := mustCreateResource(t, node, fd, virtgpuResourceCreate{Size: 4096})
			fenceID := execVirglWithHandles(t, node, fd, res.BoHandle)

			tc := newTestTaskCtx(t, node.ctx)
			errCh := make(chan error, 1)
			go func() {
				mem := newGuestMem()
				mem.put(t, structAddr, virtgpu3DWait{Handle: res.BoHandle})
				errCh <- node.ioctlWithCtx(tc, fd, cmdVirtgpuWait, mem, structAddr)
			}()

			synctest.Wait()
			fake.emitFenceDone(ctxID, 0, fenceID)

			if err := <-errCh; err != nil {
				t.Fatalf("blocking WAIT after FenceDone: got %v, want nil", err)
			}
		})
	})

	t.Run("blocking wait timeout returns EBUSY", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			fake := newFakeVirglRenderer()
			node := newTestNodeWithLimits(t, fake, Limits{WaitTimeout: 50 * time.Millisecond})
			fd := node.openVirgl(t)
			defer fd.DecRef(node.ctx)

			res := mustCreateResource(t, node, fd, virtgpuResourceCreate{Size: 4096})
			_ = execVirglWithHandles(t, node, fd, res.BoHandle)

			tc := newTestTaskCtx(t, node.ctx)
			mem := newGuestMem()
			mem.put(t, structAddr, virtgpu3DWait{Handle: res.BoHandle})
			if err := node.ioctlWithCtx(tc, fd, cmdVirtgpuWait, mem, structAddr); !linuxerr.Equals(linuxerr.EBUSY, err) {
				t.Fatalf("blocking WAIT on timeout: got %v, want EBUSY", err)
			}
		})
	})

	t.Run("default timeout is 15 s", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			fake := newFakeVirglRenderer()
			node := newTestNodeWithLimits(t, fake, Limits{})
			fd := node.openVirgl(t)
			defer fd.DecRef(node.ctx)

			res := mustCreateResource(t, node, fd, virtgpuResourceCreate{Size: 4096})
			_ = execVirglWithHandles(t, node, fd, res.BoHandle)

			tc := newTestTaskCtx(t, node.ctx)
			errCh := make(chan error, 1)
			go func() {
				mem := newGuestMem()
				mem.put(t, structAddr, virtgpu3DWait{Handle: res.BoHandle})
				errCh <- node.ioctlWithCtx(tc, fd, cmdVirtgpuWait, mem, structAddr)
			}()

			time.Sleep(14 * time.Second)
			synctest.Wait()
			select {
			case err := <-errCh:
				t.Fatalf("WAIT returned %v after 14 s, want it still blocked", err)
			default:
			}

			time.Sleep(2 * time.Second)
			if err := <-errCh; !linuxerr.Equals(linuxerr.EBUSY, err) {
				t.Fatalf("WAIT at the default timeout: got %v, want EBUSY", err)
			}
		})
	})

	t.Run("GEM_CLOSE during a blocking wait does not end the wait", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			fake := newFakeVirglRenderer()
			node := newTestNode(t, fake)
			fd := node.openVirgl(t)
			defer fd.DecRef(node.ctx)
			ctxID := fake.createdCalls()[0].ctxID

			res := mustCreateResource(t, node, fd, virtgpuResourceCreate{Size: 4096})
			fenceID := execVirglWithHandles(t, node, fd, res.BoHandle)

			tc := newTestTaskCtx(t, node.ctx)
			errCh := make(chan error, 1)
			go func() {
				mem := newGuestMem()
				mem.put(t, structAddr, virtgpu3DWait{Handle: res.BoHandle})
				errCh <- node.ioctlWithCtx(tc, fd, cmdVirtgpuWait, mem, structAddr)
			}()

			synctest.Wait()
			mustGemClose(t, node, fd, res.BoHandle)
			synctest.Wait()
			select {
			case err := <-errCh:
				t.Fatalf("WAIT returned %v after GEM_CLOSE, want it still blocked", err)
			default:
			}

			fake.emitFenceDone(ctxID, 0, fenceID)
			if err := <-errCh; err != nil {
				t.Fatalf("WAIT after FenceDone: got %v, want nil", err)
			}
		})
	})

	t.Run("blocking wait interrupted returns ERESTARTSYS", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			fake := newFakeVirglRenderer()
			node := newTestNode(t, fake)
			fd := node.openVirgl(t)
			defer fd.DecRef(node.ctx)

			res := mustCreateResource(t, node, fd, virtgpuResourceCreate{Size: 4096})
			_ = execVirglWithHandles(t, node, fd, res.BoHandle)

			tc := newTestTaskCtx(t, node.ctx)
			errCh := make(chan error, 1)
			go func() {
				mem := newGuestMem()
				mem.put(t, structAddr, virtgpu3DWait{Handle: res.BoHandle})
				errCh <- node.ioctlWithCtx(tc, fd, cmdVirtgpuWait, mem, structAddr)
			}()

			synctest.Wait()
			tc.Interrupt()

			if err := <-errCh; !linuxerr.Equals(linuxerr.ERESTARTSYS, err) {
				t.Fatalf("interrupted WAIT: got %v, want ERESTARTSYS", err)
			}
		})
	})

	t.Run("context lost wakes blocking wait with 0", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			fake := newFakeVirglRenderer()
			node := newTestNode(t, fake)
			fd := node.openVirgl(t)
			defer fd.DecRef(node.ctx)
			ctxID := fake.createdCalls()[0].ctxID

			res := mustCreateResource(t, node, fd, virtgpuResourceCreate{Size: 4096})
			_ = execVirglWithHandles(t, node, fd, res.BoHandle)

			tc := newTestTaskCtx(t, node.ctx)
			errCh := make(chan error, 1)
			go func() {
				mem := newGuestMem()
				mem.put(t, structAddr, virtgpu3DWait{Handle: res.BoHandle})
				errCh <- node.ioctlWithCtx(tc, fd, cmdVirtgpuWait, mem, structAddr)
			}()

			synctest.Wait()
			fake.emitContextLost(ctxID)

			if err := <-errCh; err != nil {
				t.Fatalf("WAIT after ContextLost: got %v, want nil", err)
			}
		})
	})

	t.Run("renderer lost wakes blocking wait with 0", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			fake := newFakeVirglRenderer()
			node := newTestNode(t, fake)
			fd := node.openVirgl(t)
			defer fd.DecRef(node.ctx)

			res := mustCreateResource(t, node, fd, virtgpuResourceCreate{Size: 4096})
			_ = execVirglWithHandles(t, node, fd, res.BoHandle)

			tc := newTestTaskCtx(t, node.ctx)
			errCh := make(chan error, 1)
			go func() {
				mem := newGuestMem()
				mem.put(t, structAddr, virtgpu3DWait{Handle: res.BoHandle})
				errCh <- node.ioctlWithCtx(tc, fd, cmdVirtgpuWait, mem, structAddr)
			}()

			synctest.Wait()
			fake.emitRendererLost(errors.New("renderer crashed"))

			if err := <-errCh; err != nil {
				t.Fatalf("WAIT after RendererLost: got %v, want nil", err)
			}
		})
	})
}

func TestWaitNewestFenceWins(t *testing.T) {
	requireBlobHost(t)

	fake := newFakeVirglRenderer()
	node := newTestNode(t, fake)
	fd := node.openVirgl(t)
	defer fd.DecRef(node.ctx)
	ctxID := fake.createdCalls()[0].ctxID

	res := mustCreateResource(t, node, fd, virtgpuResourceCreate{Size: 4096})
	f1 := execVirglWithHandles(t, node, fd, res.BoHandle)
	f2 := execVirglWithHandles(t, node, fd, res.BoHandle, res.BoHandle)
	if f2 <= f1 {
		t.Fatalf("fence IDs = (%d, %d), want f2 > f1", f1, f2)
	}

	fake.emitFenceDone(ctxID, 0, f1)

	mem := newGuestMem()
	const structAddr = hostarch.Addr(0x1000)
	mem.put(t, structAddr, virtgpu3DWait{Handle: res.BoHandle, Flags: virtgpuWaitNoWait})
	if err := node.ioctl(fd, cmdVirtgpuWait, mem, structAddr); !linuxerr.Equals(linuxerr.EBUSY, err) {
		t.Fatalf("WAIT(NOWAIT) after first fence retired: got %v, want EBUSY", err)
	}

	fake.emitFenceDone(ctxID, 0, f2)
	if err := node.ioctl(fd, cmdVirtgpuWait, mem, structAddr); err != nil {
		t.Fatalf("WAIT(NOWAIT) after second fence retired: got %v, want nil", err)
	}
}
