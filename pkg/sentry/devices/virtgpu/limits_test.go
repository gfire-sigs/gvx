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
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/waiter"
)

func TestLimitsContextsPerDevice(t *testing.T) {
	fake := newFakeRenderer()
	node := newTestNode(t, fake)

	fds := make([]*vfs.FileDescription, 0, maxContexts)
	defer func() {
		for _, fd := range fds {
			if fd != nil {
				fd.DecRef(node.ctx)
			}
		}
	}()
	for i := range maxContexts {
		fds = append(fds, node.openVenus(t))
		_ = i
	}
	if got := len(fake.createdCalls()); got != maxContexts {
		t.Fatalf("CreateContext calls = %d, want %d", got, maxContexts)
	}

	// The 65th file fails with ENOSPC without calling CreateContext.
	fdExtra := node.open(t)
	defer fdExtra.DecRef(node.ctx)
	mem := newGuestMem()
	putContextInit(t, mem, 0x1000, 0x2000, mesaVenusParams())
	if err := node.ioctl(fdExtra, cmdVirtgpuContextInit, mem, 0x1000); !linuxerr.Equals(linuxerr.ENOSPC, err) {
		t.Fatalf("65th CONTEXT_INIT: got %v, want ENOSPC", err)
	}
	if got := len(fake.createdCalls()); got != maxContexts {
		t.Errorf("CreateContext calls after ENOSPC = %d, want %d", got, maxContexts)
	}

	// A second Device (second sandbox) has an independent context cap.
	fakeB := newFakeRenderer()
	nodeB := newTestNode(t, fakeB)
	fdB := nodeB.openVenus(t)
	fdB.DecRef(nodeB.ctx)
	if got := len(fakeB.createdCalls()); got != 1 {
		t.Errorf("second device CreateContext calls = %d, want 1", got)
	}

	// Closing one file on the first device frees room for a new context.
	fds[0].DecRef(node.ctx)
	fds[0] = nil
	if err := node.ioctl(fdExtra, cmdVirtgpuContextInit, mem, 0x1000); err != nil {
		t.Fatalf("CONTEXT_INIT after closing one file: %v", err)
	}
	if got := len(fake.createdCalls()); got != maxContexts+1 {
		t.Errorf("CreateContext calls after replacement = %d, want %d", got, maxContexts+1)
	}
}

func TestLimitsBlobBytes(t *testing.T) {
	requireBlobHost(t)

	const limit = 64 << 10
	fake := newFakeRenderer()
	node := newTestNodeWithLimits(t, fake, Limits{BlobBytes: limit})
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)

	var handles [4]uint32
	for i := range handles {
		out := mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
			BlobMem:   virtgpuBlobMemHost3D,
			BlobFlags: virtgpuBlobFlagUseMappable,
			Size:      blobAlignment,
		})
		handles[i] = out.BoHandle
	}
	if got := node.dev.BlobBytes(); got != limit {
		t.Fatalf("BlobBytes = %#x, want %#x", got, limit)
	}

	// Fifth blob fails with ENOMEM and no CreateBlob call.
	mem := newGuestMem()
	mem.put(t, 0x1000, virtgpuResourceCreateBlob{
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		Size:      blobAlignment,
	})
	if err := node.ioctl(fd, cmdVirtgpuResourceCreateBlob, mem, 0x1000); !linuxerr.Equals(linuxerr.ENOMEM, err) {
		t.Fatalf("5th mappable blob: got %v, want ENOMEM", err)
	}
	if got := len(fake.blobCreateCalls()); got != 4 {
		t.Errorf("CreateBlob calls after ENOMEM = %d, want 4", got)
	}

	// Second Device with the same limit has an independent budget.
	fakeB := newFakeRenderer()
	nodeB := newTestNodeWithLimits(t, fakeB, Limits{BlobBytes: limit})
	fdB := nodeB.openVenus(t)
	defer fdB.DecRef(nodeB.ctx)
	for range 4 {
		_ = mustCreateBlob(t, nodeB, fdB, virtgpuResourceCreateBlob{
			BlobMem:   virtgpuBlobMemHost3D,
			BlobFlags: virtgpuBlobFlagUseMappable,
			Size:      blobAlignment,
		})
	}
	if got := nodeB.dev.BlobBytes(); got != limit {
		t.Errorf("second device BlobBytes = %#x, want %#x", got, limit)
	}

	// GEM_CLOSE on an unmapped blob frees 16 KiB and allows the next create.
	mustGemClose(t, node, fd, handles[0])
	if got := node.dev.BlobBytes(); got != limit-blobAlignment {
		t.Fatalf("BlobBytes after GEM_CLOSE = %#x, want %#x", got, limit-blobAlignment)
	}
	_ = mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		Size:      blobAlignment,
	})
	if got := node.dev.BlobBytes(); got != limit {
		t.Errorf("BlobBytes after replacement = %#x, want %#x", got, limit)
	}
}

func TestLimitsBlobBytesHeldByMapping(t *testing.T) {
	requireBlobHost(t)

	const limit = 64 << 10
	fake := newFakeRenderer()
	node := newTestNodeWithLimits(t, fake, Limits{BlobBytes: limit})
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)

	var handles [4]uint32
	for i := range handles {
		out := mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
			BlobMem:   virtgpuBlobMemHost3D,
			BlobFlags: virtgpuBlobFlagUseMappable,
			Size:      blobAlignment,
		})
		handles[i] = out.BoHandle
	}

	off := mustMapOffset(t, node, fd, handles[0])
	opts := memmap.MMapOpts{Offset: off, Length: blobAlignment}
	if err := fd.ConfigureMMap(node.ctx, &opts); err != nil {
		t.Fatalf("ConfigureMMap: %v", err)
	}

	// GEM_CLOSE leaves the view mapped, so the bytes stay charged.
	mustGemClose(t, node, fd, handles[0])
	if got := node.dev.BlobBytes(); got != limit {
		opts.MappingIdentity.DecRef(node.ctx)
		t.Fatalf("BlobBytes after GEM_CLOSE with active mapping = %#x, want %#x", got, limit)
	}

	mem := newGuestMem()
	mem.put(t, 0x1000, virtgpuResourceCreateBlob{
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		Size:      blobAlignment,
	})
	if err := node.ioctl(fd, cmdVirtgpuResourceCreateBlob, mem, 0x1000); !linuxerr.Equals(linuxerr.ENOMEM, err) {
		opts.MappingIdentity.DecRef(node.ctx)
		t.Fatalf("create while mapping holds bytes: got %v, want ENOMEM", err)
	}

	// Dropping the mapping identity unmaps the view and frees the bytes.
	opts.MappingIdentity.DecRef(node.ctx)
	if got := node.dev.BlobBytes(); got != limit-blobAlignment {
		t.Fatalf("BlobBytes after MappingIdentity.DecRef = %#x, want %#x", got, limit-blobAlignment)
	}
	_ = mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		Size:      blobAlignment,
	})
	if got := node.dev.BlobBytes(); got != limit {
		t.Errorf("BlobBytes after replacement = %#x, want %#x", got, limit)
	}
}

func TestLimitsBlobBytesNotMappable(t *testing.T) {
	const limit = 64 << 10
	fake := newFakeRenderer()
	node := newTestNodeWithLimits(t, fake, Limits{BlobBytes: limit})
	fd := node.openVenus(t)

	// Each 4 KiB request rounds up to 16 KiB (blobAlignment) in budget.
	var handles [4]uint32
	for i := range handles {
		out := mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
			BlobMem: virtgpuBlobMemHost3D,
			Size:    uint64(hostarch.PageSize),
		})
		handles[i] = out.BoHandle
	}
	if got := node.dev.BlobBytes(); got != limit {
		fd.DecRef(node.ctx)
		t.Fatalf("BlobBytes = %#x, want %#x", got, limit)
	}

	mem := newGuestMem()
	mem.put(t, 0x1000, virtgpuResourceCreateBlob{
		BlobMem: virtgpuBlobMemHost3D,
		Size:    uint64(hostarch.PageSize),
	})
	if err := node.ioctl(fd, cmdVirtgpuResourceCreateBlob, mem, 0x1000); !linuxerr.Equals(linuxerr.ENOMEM, err) {
		fd.DecRef(node.ctx)
		t.Fatalf("5th non-mappable blob: got %v, want ENOMEM", err)
	}
	if got := len(fake.blobCreateCalls()); got != 4 {
		t.Errorf("CreateBlob calls after ENOMEM = %d, want 4", got)
	}

	// GEM_CLOSE releases the reserved bytes.
	mustGemClose(t, node, fd, handles[0])
	if got := node.dev.BlobBytes(); got != limit-blobAlignment {
		fd.DecRef(node.ctx)
		t.Fatalf("BlobBytes after GEM_CLOSE = %#x, want %#x", got, limit-blobAlignment)
	}
	_ = mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
		BlobMem: virtgpuBlobMemHost3D,
		Size:    uint64(hostarch.PageSize),
	})

	// Closing the file releases all remaining non-mappable reservations.
	fd.DecRef(node.ctx)
	if got := node.dev.BlobBytes(); got != 0 {
		t.Errorf("BlobBytes after file close = %#x, want 0", got)
	}
}

func TestLimitsBlobBytesConcurrent(t *testing.T) {
	requireBlobHost(t)

	const (
		limit      = 1 << 20
		goroutines = 16
		perWorker  = 8
		wantOK     = limit / blobAlignment // 64
	)
	fake := newFakeRenderer()
	node := newTestNodeWithLimits(t, fake, Limits{BlobBytes: limit})
	fd := node.openVenus(t)

	var okCount, enomemCount, otherErrCount atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mem := newGuestMem()
			const addr = hostarch.Addr(0x1000)
			<-start
			for range perWorker {
				mem.put(t, addr, virtgpuResourceCreateBlob{
					BlobMem:   virtgpuBlobMemHost3D,
					BlobFlags: virtgpuBlobFlagUseMappable,
					Size:      blobAlignment,
				})
				err := node.ioctl(fd, cmdVirtgpuResourceCreateBlob, mem, addr)
				switch {
				case err == nil:
					okCount.Add(1)
				case linuxerr.Equals(linuxerr.ENOMEM, err):
					enomemCount.Add(1)
				default:
					otherErrCount.Add(1)
				}
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := otherErrCount.Load(); got != 0 {
		fd.DecRef(node.ctx)
		t.Fatalf("unexpected non-ENOMEM errors = %d", got)
	}
	if got := okCount.Load(); got != wantOK {
		fd.DecRef(node.ctx)
		t.Fatalf("succeeded creates = %d, want %d", got, wantOK)
	}
	if got := enomemCount.Load(); got != goroutines*perWorker-wantOK {
		fd.DecRef(node.ctx)
		t.Fatalf("ENOMEM creates = %d, want %d", got, goroutines*perWorker-wantOK)
	}
	if got := node.dev.BlobBytes(); got != limit {
		fd.DecRef(node.ctx)
		t.Fatalf("BlobBytes = %#x, want %#x", got, limit)
	}

	fd.DecRef(node.ctx)
	if got := node.dev.BlobBytes(); got != 0 {
		t.Errorf("BlobBytes after close = %#x, want 0", got)
	}
}

func TestLimitsLiveBlobs(t *testing.T) {
	b := blobBudget{limit: defaultBlobBytes}
	for i := range maxLiveBlobs {
		if err := b.reserve(blobAlignment); err != nil {
			t.Fatalf("reserve %d: %v", i+1, err)
		}
	}
	// Bytes are 1 GiB (< 4 GiB), so the 65537th fails strictly on maxLiveBlobs.
	if err := b.reserve(blobAlignment); !linuxerr.Equals(linuxerr.ENOMEM, err) {
		t.Fatalf("reserve %d: got %v, want ENOMEM", maxLiveBlobs+1, err)
	}
	b.release(blobAlignment)
	if err := b.reserve(blobAlignment); err != nil {
		t.Fatalf("reserve after release: %v", err)
	}
}

func TestLimitsHandlesPerFile(t *testing.T) {
	tbl := newGemTable()
	for i := range maxHandlesPerFile {
		if h := tbl.insert(&gemObject{resID: uint32(i + 1)}); h == 0 {
			t.Fatalf("insert %d returned 0", i+1)
		}
	}
	if h := tbl.insert(&gemObject{resID: maxHandlesPerFile + 1}); h != 0 {
		t.Fatalf("insert %d = %d, want 0", maxHandlesPerFile+1, h)
	}
	if _, ok := tbl.remove(1); !ok {
		t.Fatalf("remove(1) returned false")
	}
	if h := tbl.insert(&gemObject{resID: maxHandlesPerFile + 2}); h != 1 {
		t.Fatalf("insert after remove(1) = %d, want 1", h)
	}
}

func TestLimitsPendingFences(t *testing.T) {
	fake := newFakeRenderer()
	node := newTestNode(t, fake)
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)
	ctxID := fake.createdCalls()[0].ctxID
	tc := newTestTaskCtx(t, node.ctx)

	mem := newGuestMem()
	const addr = hostarch.Addr(0x1000)
	for i := range maxPendingFences {
		mem.put(t, addr, virtgpuExecbuffer{Flags: virtgpuExecbufFenceFDOut})
		if err := node.ioctlWithCtx(tc, fd, cmdVirtgpuExecbuffer, mem, addr); err != nil {
			t.Fatalf("fenced EXECBUFFER %d: %v", i+1, err)
		}
	}
	if got := len(fake.submitCalls()); got != maxPendingFences {
		t.Fatalf("Submit calls = %d, want %d", got, maxPendingFences)
	}

	// The 4097th pending fence fails with EBUSY without calling Submit.
	mem.put(t, addr, virtgpuExecbuffer{Flags: virtgpuExecbufFenceFDOut})
	if err := node.ioctlWithCtx(tc, fd, cmdVirtgpuExecbuffer, mem, addr); !linuxerr.Equals(linuxerr.EBUSY, err) {
		t.Fatalf("4097th pending fence: got %v, want EBUSY", err)
	}
	if got := len(fake.submitCalls()); got != maxPendingFences {
		t.Errorf("Submit calls after EBUSY = %d, want %d", got, maxPendingFences)
	}

	// Retiring the oldest fence makes room for one more.
	oldestID := fake.submitCalls()[0].fence.ID
	fake.emitFenceDone(ctxID, 0, oldestID)

	mem.put(t, addr, virtgpuExecbuffer{Flags: virtgpuExecbufFenceFDOut})
	if err := node.ioctlWithCtx(tc, fd, cmdVirtgpuExecbuffer, mem, addr); err != nil {
		t.Fatalf("EXECBUFFER after retiring oldest fence: %v", err)
	}
	if got := len(fake.submitCalls()); got != maxPendingFences+1 {
		t.Errorf("Submit calls after retirement = %d, want %d", got, maxPendingFences+1)
	}
}

func TestFenceTimeoutLosesContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := newFakeRenderer()
		node := newTestNode(t, fake)
		fd := node.openVenus(t)
		ctxID := fake.createdCalls()[0].ctxID
		tc := newTestTaskCtx(t, node.ctx)

		sf, _ := mustExecFence(t, node, tc, fd, 0)
		if got := sf.Readiness(waiter.ReadableEvents); got != 0 {
			fd.DecRef(node.ctx)
			t.Fatalf("initial readiness = %#x, want 0", got)
		}

		// 29 s is before the 30 s default FenceTimeout.
		time.Sleep(29 * time.Second)
		synctest.Wait()
		if got := sf.Readiness(waiter.ReadableEvents); got != 0 {
			fd.DecRef(node.ctx)
			t.Fatalf("readiness at 29s = %#x, want 0", got)
		}
		if got := fake.destroyedIDs(); len(got) != 0 {
			fd.DecRef(node.ctx)
			t.Fatalf("DestroyContext calls at 29s = %v, want empty", got)
		}

		// 2 s more crosses 30 s: fence signals, context is lost, CTX_DESTROY sent once.
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if got := sf.Readiness(waiter.ReadableEvents); got != waiter.ReadableEvents {
			fd.DecRef(node.ctx)
			t.Fatalf("readiness at 31s = %#x, want %#x", got, waiter.ReadableEvents)
		}
		if got := fake.destroyedIDs(); len(got) != 1 || got[0] != ctxID {
			fd.DecRef(node.ctx)
			t.Fatalf("DestroyContext calls at 31s = %v, want [%d]", got, ctxID)
		}

		mem := newGuestMem()
		mem.put(t, 0x1000, virtgpuExecbuffer{})
		if err := node.ioctlWithCtx(tc, fd, cmdVirtgpuExecbuffer, mem, 0x1000); !linuxerr.Equals(linuxerr.EIO, err) {
			fd.DecRef(node.ctx)
			t.Fatalf("EXECBUFFER after fence timeout: got %v, want EIO", err)
		}

		// Closing the file does not send a second DestroyContext.
		fd.DecRef(node.ctx)
		if got := fake.destroyedIDs(); len(got) != 1 {
			t.Errorf("DestroyContext calls after close = %v, want 1 call", got)
		}
	})
}

func TestFenceTimeoutStopsWhenRetired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := newFakeRenderer()
		node := newTestNode(t, fake)
		fd := node.openVenus(t)
		defer fd.DecRef(node.ctx)
		ctxID := fake.createdCalls()[0].ctxID
		tc := newTestTaskCtx(t, node.ctx)

		sf, id := mustExecFence(t, node, tc, fd, 0)

		time.Sleep(1 * time.Second)
		synctest.Wait()
		fake.emitFenceDone(ctxID, 0, id)
		if got := sf.Readiness(waiter.ReadableEvents); got != waiter.ReadableEvents {
			t.Fatalf("readiness after FenceDone = %#x, want %#x", got, waiter.ReadableEvents)
		}

		// Advancing past 30 s must not lose the context.
		time.Sleep(31 * time.Second)
		synctest.Wait()
		if got := fake.destroyedIDs(); len(got) != 0 {
			t.Fatalf("DestroyContext calls at 32s = %v, want empty", got)
		}

		mem := newGuestMem()
		mem.put(t, 0x1000, virtgpuExecbuffer{})
		if err := node.ioctlWithCtx(tc, fd, cmdVirtgpuExecbuffer, mem, 0x1000); err != nil {
			t.Errorf("EXECBUFFER after retired fence past timeout: %v", err)
		}
	})
}

func TestFenceTimeoutWokenPollerSeesEIOImmediately(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := newFakeRenderer()
		node := newTestNode(t, fake)
		fd := node.openVenus(t)
		defer fd.DecRef(node.ctx)
		tc := newTestTaskCtx(t, node.ctx)

		sf, _ := mustExecFence(t, node, tc, fd, 0)
		entry, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
		if err := sf.EventRegister(&entry); err != nil {
			t.Fatalf("EventRegister: %v", err)
		}
		defer sf.EventUnregister(&entry)

		// A poller goroutine blocks directly on the waiter channel and issues
		// an EXECBUFFER immediately upon wakeup, without waiting for the timer
		// goroutine to finish anything else.
		pollErrCh := make(chan error, 1)
		go func() {
			<-ch
			mem := newGuestMem()
			mem.put(t, 0x1000, virtgpuExecbuffer{})
			pollErrCh <- node.ioctlWithCtx(tc, fd, cmdVirtgpuExecbuffer, mem, 0x1000)
		}()

		time.Sleep(defaultFenceTimeout)
		synctest.Wait()

		if err := <-pollErrCh; !linuxerr.Equals(linuxerr.EIO, err) {
			t.Fatalf("EXECBUFFER immediately after timeout wakeup: got %v, want EIO", err)
		}
	})
}

func TestFenceTimeoutDuringInFlightCreateBlobReturnsEIO(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fake := newFakeRenderer()
		fake.blobGate = make(chan struct{})
		fake.blobEntered = make(chan struct{}, 1)
		node := newTestNode(t, fake)
		fd := node.openVenus(t)
		defer fd.DecRef(node.ctx)
		tc := newTestTaskCtx(t, node.ctx)

		// Start a pending fence that will time out while CreateBlob is in flight.
		_, _ = mustExecFence(t, node, tc, fd, 0)

		errCh := make(chan error, 1)
		go func() {
			mem := newGuestMem()
			mem.put(t, 0x1000, virtgpuResourceCreateBlob{
				BlobMem: virtgpuBlobMemHost3D,
				Size:    blobAlignment,
			})
			errCh <- node.ioctlWithCtx(tc, fd, cmdVirtgpuResourceCreateBlob, mem, 0x1000)
		}()

		<-fake.blobEntered
		// Simulate server.c replying StatusInvalid after CTX_DESTROY cleared the slot.
		fake.setBlobErr(&gpuproto.StatusError{Op: gpuproto.OpBlobCreate, Status: gpuproto.StatusInvalid})
		time.Sleep(defaultFenceTimeout)
		synctest.Wait()
		close(fake.blobGate)

		if err := <-errCh; !linuxerr.Equals(linuxerr.EIO, err) {
			t.Fatalf("in-flight RESOURCE_CREATE_BLOB across fence timeout: got %v, want EIO", err)
		}
		if got := node.dev.BlobBytes(); got != 0 {
			t.Errorf("BlobBytes after failed in-flight create = %#x, want 0", got)
		}
	})
}
