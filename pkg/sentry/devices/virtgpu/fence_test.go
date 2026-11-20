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
	"sync"
	"testing"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/waiter"
)

func mustExecFence(t *testing.T, node *testNode, tc *testTaskCtx, fd *vfs.FileDescription, ring uint32) (*vfs.FileDescription, uint64) {
	t.Helper()
	mem := newGuestMem()
	const addr = hostarch.Addr(0x1000)
	before := len(node.dev.renderer.(*fakeRenderer).submitCalls())
	mem.put(t, addr, virtgpuExecbuffer{
		Flags:   virtgpuExecbufRingIdx | virtgpuExecbufFenceFDOut,
		RingIdx: ring,
	})
	if err := node.ioctlWithCtx(tc, fd, cmdVirtgpuExecbuffer, mem, addr); err != nil {
		t.Fatalf("EXECBUFFER(ring=%d, FENCE_FD_OUT): %v", ring, err)
	}
	var out virtgpuExecbuffer
	mem.get(t, addr, &out)
	calls := node.dev.renderer.(*fakeRenderer).submitCalls()
	if len(calls) != before+1 || calls[before].fence == nil {
		t.Fatalf("expected 1 new fenced submit, got %d", len(calls)-before)
	}
	sf := tc.file(out.FenceFD)
	if sf == nil {
		t.Fatalf("missing sync_file for fd %d", out.FenceFD)
	}
	return sf, calls[before].fence.ID
}

func TestFenceDoneRetiresEarlierFences(t *testing.T) {
	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)
	ctxID := fake.createdCalls()[0].ctxID
	tc := newTestTaskCtx(t, node.ctx)

	sfA, idA := mustExecFence(t, node, tc, fd, 1)
	sfB, idB := mustExecFence(t, node, tc, fd, 1)
	sfC, idC := mustExecFence(t, node, tc, fd, 2)
	if idA >= idB {
		t.Fatalf("fence IDs on ring 1: A=%d, B=%d, want A < B", idA, idB)
	}

	fake.emitFenceDone(ctxID, 1, idB)
	if sfA.Readiness(waiter.ReadableEvents) == 0 {
		t.Errorf("fence A did not signal when later fence B retired on ring 1")
	}
	if sfB.Readiness(waiter.ReadableEvents) == 0 {
		t.Errorf("fence B did not signal on FenceDone")
	}
	if sfC.Readiness(waiter.ReadableEvents) != 0 {
		t.Errorf("fence C on ring 2 signaled when ring 1 retired")
	}

	// Unknown context and out-of-range ring must do nothing.
	fake.emitFenceDone(9999, 2, idC)
	fake.emitFenceDone(ctxID, 99, idC)
	if sfC.Readiness(waiter.ReadableEvents) != 0 {
		t.Errorf("fence C signaled on unknown context or invalid ring")
	}

	fake.emitFenceDone(ctxID, 2, idC)
	if sfC.Readiness(waiter.ReadableEvents) == 0 {
		t.Errorf("fence C did not signal on ring 2 FenceDone")
	}
}

func TestFenceIDsIncreaseInSubmitOrder(t *testing.T) {
	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)
	tc := newTestTaskCtx(t, node.ctx)

	const (
		goroutines = 8
		perWorker  = 100
	)
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*perWorker)

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mem := newGuestMem()
			const addr = hostarch.Addr(0x1000)
			for range perWorker {
				mem.put(t, addr, virtgpuExecbuffer{Flags: virtgpuExecbufFenceFDOut})
				if err := node.ioctlWithCtx(tc, fd, cmdVirtgpuExecbuffer, mem, addr); err != nil {
					errCh <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent EXECBUFFER(FENCE_FD_OUT): %v", err)
	}

	calls := fake.submitCalls()
	if len(calls) != goroutines*perWorker {
		t.Fatalf("Submit calls = %d, want %d", len(calls), goroutines*perWorker)
	}
	var prev uint64
	for i, c := range calls {
		if c.fence == nil {
			t.Fatalf("calls[%d] has nil fence", i)
		}
		if c.fence.ID <= prev {
			t.Fatalf("calls[%d].fence.ID = %d <= previous %d (out of order)", i, c.fence.ID, prev)
		}
		prev = c.fence.ID
	}
}

func TestFencesSignalWhenContextEnds(t *testing.T) {
	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	tc := newTestTaskCtx(t, node.ctx)

	// 1. ContextLost signals pending fences and rejects later fenced submits with EIO.
	fd1 := node.openVenus(t)
	defer fd1.DecRef(node.ctx)
	ctx1 := fake.createdCalls()[0].ctxID
	sf1, _ := mustExecFence(t, node, tc, fd1, 0)
	e1, ch1 := waiter.NewChannelEntry(waiter.ReadableEvents)
	if err := sf1.EventRegister(&e1); err != nil {
		t.Fatalf("EventRegister(sf1): %v", err)
	}
	defer sf1.EventUnregister(&e1)

	fake.emitContextLost(ctx1)
	select {
	case <-ch1:
	default:
		t.Fatalf("sf1 waiter was not notified on ContextLost")
	}
	if sf1.Readiness(waiter.ReadableEvents) == 0 {
		t.Errorf("sf1 readiness = 0 after ContextLost, want readable")
	}
	mem := newGuestMem()
	mem.put(t, 0x1000, virtgpuExecbuffer{Flags: virtgpuExecbufFenceFDOut})
	if err := node.ioctlWithCtx(tc, fd1, cmdVirtgpuExecbuffer, mem, 0x1000); !linuxerr.Equals(linuxerr.EIO, err) {
		t.Errorf("EXECBUFFER after ContextLost: got %v, want EIO", err)
	}

	// 2. Closing a DRM file signals its pending fences.
	fd2 := node.openVenus(t)
	sf2, _ := mustExecFence(t, node, tc, fd2, 0)
	e2, ch2 := waiter.NewChannelEntry(waiter.ReadableEvents)
	if err := sf2.EventRegister(&e2); err != nil {
		t.Fatalf("EventRegister(sf2): %v", err)
	}
	defer sf2.EventUnregister(&e2)

	fd2.DecRef(node.ctx)
	select {
	case <-ch2:
	default:
		t.Fatalf("sf2 waiter was not notified on DRM file close")
	}
	if sf2.Readiness(waiter.ReadableEvents) == 0 {
		t.Errorf("sf2 readiness = 0 after DRM file close, want readable")
	}

	// 3. RendererLost signals pending fences on another open file and rejects later submits with EIO.
	fd3 := node.openVenus(t)
	defer fd3.DecRef(node.ctx)
	sf3, _ := mustExecFence(t, node, tc, fd3, 0)
	e3, ch3 := waiter.NewChannelEntry(waiter.ReadableEvents)
	if err := sf3.EventRegister(&e3); err != nil {
		t.Fatalf("EventRegister(sf3): %v", err)
	}
	defer sf3.EventUnregister(&e3)

	fake.emitRendererLost(errors.New("renderer exited"))
	select {
	case <-ch3:
	default:
		t.Fatalf("sf3 waiter was not notified on RendererLost")
	}
	if sf3.Readiness(waiter.ReadableEvents) == 0 {
		t.Errorf("sf3 readiness = 0 after RendererLost, want readable")
	}
	mem.put(t, 0x1000, virtgpuExecbuffer{Flags: virtgpuExecbufFenceFDOut})
	if err := node.ioctlWithCtx(tc, fd3, cmdVirtgpuExecbuffer, mem, 0x1000); !linuxerr.Equals(linuxerr.EIO, err) {
		t.Errorf("EXECBUFFER after RendererLost: got %v, want EIO", err)
	}
}
