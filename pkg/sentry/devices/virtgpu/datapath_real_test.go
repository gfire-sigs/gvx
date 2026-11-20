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
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/gpurender"
	"z.gfire.dev/gvx/internal/gpurender/gpurendertest"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/waiter"
)

func waitSyncFileReadable(t *testing.T, sf *vfs.FileDescription, timeout time.Duration) {
	t.Helper()
	entry, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	if err := sf.EventRegister(&entry); err != nil {
		t.Fatalf("EventRegister: %v", err)
	}
	defer sf.EventUnregister(&entry)

	if sf.Readiness(waiter.ReadableEvents) != 0 {
		return
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ch:
	case <-timer.C:
		if sf.Readiness(waiter.ReadableEvents) == 0 {
			t.Fatalf("sync_file did not become readable within %v", timeout)
		}
	}
	if sf.Readiness(waiter.ReadableEvents) == 0 {
		t.Fatalf("sync_file readiness is 0 after notification")
	}
}

func TestExecbufferFenceOnRealRenderer(t *testing.T) {
	client := gpurendertest.New(t)
	node := newTestNode(t, client)
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)

	tc := newTestTaskCtx(t, node.ctx)
	mem := newGuestMem()
	const addr = hostarch.Addr(0x1000)
	mem.put(t, addr, virtgpuExecbuffer{
		Flags: virtgpuExecbufFenceFDOut,
	})
	if err := node.ioctlWithCtx(tc, fd, cmdVirtgpuExecbuffer, mem, addr); err != nil {
		t.Fatalf("EXECBUFFER(ring 0, FENCE_FD_OUT): %v", err)
	}
	var out virtgpuExecbuffer
	mem.get(t, addr, &out)
	sf := tc.file(out.FenceFD)
	if sf == nil {
		t.Fatalf("missing sync_file for fd %d", out.FenceFD)
	}
	waitSyncFileReadable(t, sf, time.Second)
}

func TestExecbufferUnboundRingLosesContext(t *testing.T) {
	client := gpurendertest.New(t)
	node := newTestNode(t, client)
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)

	tc := newTestTaskCtx(t, node.ctx)
	mem := newGuestMem()
	const addr = hostarch.Addr(0x1000)

	// No queue is bound to ring 5. In thread render-server mode, the first
	// SUBMIT still replies OK and the context loss arrives on a later SUBMIT.
	mem.put(t, addr, virtgpuExecbuffer{
		Flags:   virtgpuExecbufRingIdx | virtgpuExecbufFenceFDOut,
		RingIdx: 5,
	})
	if err := node.ioctlWithCtx(tc, fd, cmdVirtgpuExecbuffer, mem, addr); err != nil {
		t.Fatalf("EXECBUFFER(ring 5, FENCE_FD_OUT): %v", err)
	}
	var out virtgpuExecbuffer
	mem.get(t, addr, &out)
	sfA := tc.file(out.FenceFD)
	if sfA == nil {
		t.Fatalf("missing sync_file for fd %d", out.FenceFD)
	}

	// Trigger virgl_renderer_context_create_fence on ring 0 every 10 ms until
	// CTX_LOST retires sfA (or a call returns EIO).
	entry, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	if err := sfA.EventRegister(&entry); err != nil {
		t.Fatalf("EventRegister(sfA): %v", err)
	}
	defer sfA.EventUnregister(&entry)

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()

	probe := func() bool {
		mem.put(t, addr, virtgpuExecbuffer{Flags: virtgpuExecbufFenceFDOut})
		err := node.ioctlWithCtx(tc, fd, cmdVirtgpuExecbuffer, mem, addr)
		if err == nil {
			return false
		}
		if linuxerr.Equals(linuxerr.EIO, err) {
			return true
		}
		t.Fatalf("probe EXECBUFFER(ring 0, FENCE_FD_OUT): got %v, want nil or EIO", err)
		return false
	}

	if sfA.Readiness(waiter.ReadableEvents) == 0 && !probe() {
		for sfA.Readiness(waiter.ReadableEvents) == 0 {
			select {
			case <-ch:
			case <-ticker.C:
				if probe() {
					goto done
				}
			case <-deadline.C:
				t.Fatalf("sfA did not become readable within 1s after unbound ring 5 fence")
			}
		}
	}
done:
	if sfA.Readiness(waiter.ReadableEvents) == 0 {
		waitSyncFileReadable(t, sfA, time.Second)
	}

	// Subsequent EXECBUFFER sees the lost context and returns EIO.
	mem.put(t, addr, virtgpuExecbuffer{})
	if err := node.ioctlWithCtx(tc, fd, cmdVirtgpuExecbuffer, mem, addr); !linuxerr.Equals(linuxerr.EIO, err) {
		t.Errorf("EXECBUFFER after CTX_LOST: got %v, want EIO", err)
	}
}

func TestCreateBlobOnRealRenderer(t *testing.T) {
	client := gpurendertest.New(t)
	node := newTestNode(t, client)
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)

	out := mustCreateBlob(t, node, fd, virtgpuResourceCreateBlob{
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		BlobID:    0,
		Size:      0x3064,
	})

	mem := newGuestMem()
	const addr = hostarch.Addr(0x1000)
	mem.put(t, addr, virtgpuResourceInfo{BoHandle: out.BoHandle})
	if err := node.ioctl(fd, cmdVirtgpuResourceInfo, mem, addr); err != nil {
		t.Fatalf("RESOURCE_INFO: %v", err)
	}
	var info virtgpuResourceInfo
	mem.get(t, addr, &info)
	if info.Size != 0x4000 {
		t.Errorf("RESOURCE_INFO.Size = %#x, want 0x4000", info.Size)
	}
	if got := node.dev.BlobBytes(); got != 0x4000 {
		t.Errorf("BlobBytes = %#x, want 0x4000", got)
	}

	off := mustMapOffset(t, node, fd, out.BoHandle)
	opts := memmap.MMapOpts{Offset: off, Length: 0x4000}
	if err := fd.ConfigureMMap(node.ctx, &opts); err != nil {
		t.Fatalf("ConfigureMMap: %v", err)
	}

	req := memmap.MappableRange{Start: 0, End: 0x4000}
	ts, err := opts.Mappable.Translate(node.ctx, req, req, hostarch.ReadWrite)
	if err != nil {
		opts.MappingIdentity.DecRef(node.ctx)
		t.Fatalf("Translate: %v", err)
	}
	fr := memmap.FileRange{Start: 0, End: 0x4000}
	ts[0].File.IncRef(fr, 0)
	bs, err := ts[0].File.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		ts[0].File.DecRef(fr)
		opts.MappingIdentity.DecRef(node.ctx)
		t.Fatalf("MapInternal: %v", err)
	}
	pattern := []byte{0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04}
	if _, err := safemem.CopySeq(bs, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(pattern))); err != nil {
		ts[0].File.DecRef(fr)
		opts.MappingIdentity.DecRef(node.ctx)
		t.Fatalf("CopySeq write: %v", err)
	}
	readBack := make([]byte, len(pattern))
	if _, err := safemem.CopySeq(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(readBack)), bs); err != nil {
		ts[0].File.DecRef(fr)
		opts.MappingIdentity.DecRef(node.ctx)
		t.Fatalf("CopySeq read: %v", err)
	}
	ts[0].File.DecRef(fr)
	if !bytes.Equal(readBack, pattern) {
		opts.MappingIdentity.DecRef(node.ctx)
		t.Fatalf("readBack = %x, want %x", readBack, pattern)
	}

	mustGemClose(t, node, fd, out.BoHandle)
	if got := node.dev.BlobBytes(); got != 0x4000 {
		t.Errorf("BlobBytes after GEM_CLOSE with mapping held = %#x, want 0x4000", got)
	}
	opts.MappingIdentity.DecRef(node.ctx)
	if got := node.dev.BlobBytes(); got != 0 {
		t.Errorf("BlobBytes after MappingIdentity.DecRef = %#x, want 0", got)
	}
}

func TestFenceTimeoutOnRealRenderer(t *testing.T) {
	client := gpurendertest.NewWithOptions(t, gpurender.Options{StallFences: true})
	const timeout = 300 * time.Millisecond
	node := newTestNodeWithLimits(t, client, Limits{FenceTimeout: timeout})
	fd := node.openVenus(t)
	defer fd.DecRef(node.ctx)

	tc := newTestTaskCtx(t, node.ctx)
	mem := newGuestMem()
	const addr = hostarch.Addr(0x1000)

	start := time.Now()
	mem.put(t, addr, virtgpuExecbuffer{Flags: virtgpuExecbufFenceFDOut})
	if err := node.ioctlWithCtx(tc, fd, cmdVirtgpuExecbuffer, mem, addr); err != nil {
		t.Fatalf("EXECBUFFER(ring 0, FENCE_FD_OUT): %v", err)
	}
	var out virtgpuExecbuffer
	mem.get(t, addr, &out)
	sf := tc.file(out.FenceFD)
	if sf == nil {
		t.Fatalf("missing sync_file for fd %d", out.FenceFD)
	}

	waitSyncFileReadable(t, sf, 2*time.Second)
	elapsed := time.Since(start)
	if elapsed < timeout {
		t.Errorf("sync_file signaled after %v, want >= %v", elapsed, timeout)
	}

	// Subsequent EXECBUFFER on the timed-out context fails with EIO.
	mem.put(t, addr, virtgpuExecbuffer{})
	if err := node.ioctlWithCtx(tc, fd, cmdVirtgpuExecbuffer, mem, addr); !linuxerr.Equals(linuxerr.EIO, err) {
		t.Errorf("EXECBUFFER after fence timeout: got %v, want EIO", err)
	}

	// The renderer stays alive and a new DRM file can create a context.
	fd2 := node.openVenus(t)
	fd2.DecRef(node.ctx)
}
