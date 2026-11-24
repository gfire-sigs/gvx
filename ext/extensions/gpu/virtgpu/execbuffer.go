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

	"z.gfire.dev/gvx/ext/extensions/gpu/gpuproto"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

const (
	// maxBoHandles bounds the guest BO handle array copy in EXECBUFFER (D-6b.4).
	maxBoHandles = 65536

	execbufFlagsKnown = virtgpuExecbufFenceFDIn | virtgpuExecbufFenceFDOut | virtgpuExecbufRingIdx
)

// execbufRefusal names an EXECBUFFER field that the device refuses on purpose
// (D5 day-two features). It indexes renderFD.refusedExecbuf.
type execbufRefusal uint8

const (
	refuseUnknownFlags execbufRefusal = iota // flag bits outside VIRTGPU_EXECBUF_FLAGS
	refuseFenceFDIn                          // VIRTGPU_EXECBUF_FENCE_FD_IN
	refuseInSyncobjs                         // num_in_syncobjs != 0
	refuseOutSyncobjs                        // num_out_syncobjs != 0
)

// execbufRefusalNames are the names in the log line. Each has no space, so the
// gate parser (e2e/gate_gpu_test.go refusedIoctlRE, key name+nr) records each
// one as its own entry of refused-ioctls.json.
var execbufRefusalNames = [...]string{
	refuseUnknownFlags: "DRM_IOCTL_VIRTGPU_EXECBUFFER:UNKNOWN_FLAGS",
	refuseFenceFDIn:    "DRM_IOCTL_VIRTGPU_EXECBUFFER:FENCE_FD_IN",
	refuseInSyncobjs:   "DRM_IOCTL_VIRTGPU_EXECBUFFER:IN_SYNCOBJS",
	refuseOutSyncobjs:  "DRM_IOCTL_VIRTGPU_EXECBUFFER:OUT_SYNCOBJS",
}

// logRefusedExecbuf writes one debug line the first time this file sends an
// EXECBUFFER with field r. The line has the format of logRefused.
func (fd *renderFD) logRefusedExecbuf(ctx context.Context, r execbufRefusal, err error) {
	bit := uint8(1) << r

	fd.refusedMu.Lock()
	already := fd.refusedExecbuf&bit != 0
	fd.refusedExecbuf |= bit
	fd.refusedMu.Unlock()

	if !already {
		ctx.Debugf("virtgpu: refused ioctl %s (nr %#x, cmd %#x): %v", execbufRefusalNames[r], nrVirtgpuExecbuffer, cmdVirtgpuExecbuffer, err)
	}
}

// fdInstaller exposes the descriptor table of the calling task.
// *kernel.Task implements it, and the syscall layer passes the task as the
// ioctl context.
type fdInstaller interface {
	FDTable() *kernel.FDTable
}

var _ fdInstaller = (*kernel.Task)(nil)

// execbuffer serves DRM_IOCTL_VIRTGPU_EXECBUFFER.
func (fd *renderFD) execbuffer(ctx context.Context, uio usermem.IO, arg []byte) error {
	var req virtgpuExecbuffer
	if _, err := binary.Decode(arg, binary.LittleEndian, &req); err != nil {
		return linuxerr.EINVAL
	}
	if req.Flags&^execbufFlagsKnown != 0 {
		fd.logRefusedExecbuf(ctx, refuseUnknownFlags, linuxerr.EINVAL)
		return linuxerr.EINVAL
	}
	if req.Flags&virtgpuExecbufFenceFDIn != 0 {
		fd.logRefusedExecbuf(ctx, refuseFenceFDIn, linuxerr.EINVAL)
		return linuxerr.EINVAL
	}
	if req.NumInSyncobjs != 0 || req.NumOutSyncobjs != 0 {
		kind := refuseOutSyncobjs
		if req.NumInSyncobjs != 0 {
			kind = refuseInSyncobjs
		}
		fd.logRefusedExecbuf(ctx, kind, linuxerr.EINVAL)
		return linuxerr.EINVAL
	}
	if req.Size%4 != 0 || req.Size > gpuproto.MaxSubmitBytes {
		return linuxerr.EINVAL
	}
	c := fd.ctx.Load()
	if c == nil {
		if fd.dev.modes&modeVirgl == 0 {
			return linuxerr.EINVAL
		}
		if req.Flags&virtgpuExecbufRingIdx != 0 {
			return linuxerr.EINVAL
		}
		var err error
		c, err = fd.ensureContext(ctx)
		if err != nil {
			return err
		}
	}

	var ring uint32
	if req.Flags&virtgpuExecbufRingIdx != 0 {
		if req.RingIdx >= c.numRings {
			return linuxerr.EINVAL
		}
		ring = req.RingIdx
	}
	if fd.dev.lost.Load() || c.lost.Load() {
		return linuxerr.EIO
	}
	if req.NumBoHandles > maxBoHandles {
		return linuxerr.EINVAL
	}
	var objs []*gemObject
	if req.NumBoHandles > 0 {
		raw := make([]byte, int(req.NumBoHandles)*4)
		if _, err := uio.CopyIn(ctx, hostarch.Addr(req.BoHandles), raw, usermem.IOOpts{}); err != nil {
			return linuxerr.EFAULT
		}
		collect := c.isVirgl()
		if collect {
			objs = make([]*gemObject, int(req.NumBoHandles))
		}
		fd.gemMu.Lock()
		for i := range int(req.NumBoHandles) {
			h := binary.LittleEndian.Uint32(raw[i*4:])
			o, ok := fd.gem.lookup(h)
			if !ok {
				fd.gemMu.Unlock()
				return linuxerr.ENOENT
			}
			if collect {
				objs[i] = o
			}
		}
		fd.gemMu.Unlock()
	}

	wantFenceFD := req.Flags&virtgpuExecbufFenceFDOut != 0
	var fdt *kernel.FDTable
	if wantFenceFD {
		inst, ok := ctx.(fdInstaller)
		if !ok {
			log.Warningf("virtgpu: EXECBUFFER FENCE_FD_OUT called without fdInstaller context")
			return linuxerr.EINVAL
		}
		fdt = inst.FDTable()
		if fdt == nil {
			log.Warningf("virtgpu: EXECBUFFER FENCE_FD_OUT called with nil FDTable")
			return linuxerr.EINVAL
		}
	}

	var cmd []byte
	if req.Size > 0 {
		cmdSize := uint64(req.Size)
		if err := fd.dev.submitBudget.acquire(ctx, cmdSize); err != nil {
			return err
		}
		defer fd.dev.submitBudget.release(cmdSize)

		cmd = make([]byte, req.Size)
		if _, err := uio.CopyIn(ctx, hostarch.Addr(req.Command), cmd, usermem.IOOpts{}); err != nil {
			return linuxerr.EFAULT
		}
	}

	// Ordering for FENCE_FD_OUT: create the sync_file and reserve its FD slot
	// before submit, then publish req.FenceFD only after submit succeeds.
	// RLIMIT_NOFILE exhaustion returns EMFILE with no renderer side effects.
	// On submit failure, the defer removes only syncFile from fdt and signals
	// preFence so no descriptor leaks and no concurrent waiter blocks.
	var (
		preFence  *fence
		syncFile  *vfs.FileDescription
		fenceFD   int32
		committed bool
	)
	if wantFenceFD {
		preFence = &fence{ring: ring}
		var err error
		syncFile, err = newSyncFile(ctx, fd.dev.vfs, preFence)
		if err != nil {
			return err
		}
		defer syncFile.DecRef(ctx)

		// Linux reserves the fd number without a file, so other threads
		// cannot see it before the ioctl returns. The FDTable has no such
		// reservation, so another guest thread can see, close, or dup this fd
		// while submit runs. That affects only the guest. The rollback below
		// removes only this sync file and signals preFence.
		fenceFD, err = fdt.NewFD(ctx, 0, syncFile, kernel.FDFlags{CloseOnExec: true})
		if err != nil {
			return err
		}
		defer func() {
			if !committed {
				fdt.RemoveIf(ctx, func(candidate *vfs.FileDescription, _ kernel.FDFlags) bool {
					return candidate == syncFile
				})
				preFence.signal()
			}
		}()
	}

	withFence := wantFenceFD || (c.isVirgl() && len(objs) > 0)
	f, err := fd.dev.submit(c, ring, cmd, withFence, preFence)
	if err != nil {
		return err
	}
	if f != nil && len(objs) > 0 {
		fd.gemMu.Lock()
		fd.gem.recordFence(objs, f)
		fd.gemMu.Unlock()
	}
	if !wantFenceFD {
		return nil
	}

	committed = true
	req.FenceFD = fenceFD
	_, _ = binary.Encode(arg, binary.LittleEndian, &req)
	return nil
}

// submit sends cmd on c, with a fence on ring when withFence is set. When f is
// non-nil, submit assigns f.id under c.submitMu and uses f instead of
// allocating a new fence. It holds c.submitMu from fence ID allocation until
// Submit returns, so fence IDs reach the renderer in increasing order on every
// ring of c (I-6b.3). The fence is in the pending list before Submit, so a
// FENCE_DONE that arrives at once finds it.
func (d *Device) submit(c *fileContext, ring uint32, cmd []byte, withFence bool, f *fence) (*fence, error) {
	c.submitMu.Lock()
	defer c.submitMu.Unlock()

	if d.lost.Load() || c.lost.Load() {
		return nil, linuxerr.EIO
	}
	if !withFence {
		return nil, rendererErrno(d.renderer.Submit(c.id, cmd, nil))
	}
	if f == nil {
		f = &fence{ring: ring}
	}
	f.id = d.lastFenceID.Add(1)
	if err := c.addPending(f, d.limits.FenceTimeout, func() { d.fenceTimedOut(c, f) }); err != nil {
		if errors.Is(err, errTooManyFences) {
			return nil, linuxerr.EBUSY
		}
		return nil, linuxerr.EIO
	}
	if err := d.renderer.Submit(c.id, cmd, &gpuproto.Fence{RingIdx: ring, ID: f.id}); err != nil {
		c.removePending(f)
		return nil, rendererErrno(err)
	}
	return f, nil
}
