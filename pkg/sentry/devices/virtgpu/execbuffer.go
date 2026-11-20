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

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
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

// fdInstaller installs a file in the descriptor table of the calling task.
// *kernel.Task implements it, and the syscall layer passes the task as the
// ioctl context.
type fdInstaller interface {
	NewFDFrom(minFD int32, file *vfs.FileDescription, flags kernel.FDFlags) (int32, error)
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

	var cmd []byte
	if req.Size > 0 {
		cmd = make([]byte, req.Size)
		if _, err := uio.CopyIn(ctx, hostarch.Addr(req.Command), cmd, usermem.IOOpts{}); err != nil {
			return linuxerr.EFAULT
		}
	}

	wantFenceFD := req.Flags&virtgpuExecbufFenceFDOut != 0
	var inst fdInstaller
	if wantFenceFD {
		var ok bool
		inst, ok = ctx.(fdInstaller)
		if !ok {
			log.Warningf("virtgpu: EXECBUFFER FENCE_FD_OUT called without fdInstaller context")
			return linuxerr.EINVAL
		}
	}

	withFence := wantFenceFD || (c.isVirgl() && len(objs) > 0)
	f, err := fd.dev.submit(c, ring, cmd, withFence)
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

	file, err := newSyncFile(ctx, fd.dev.vfs, f)
	if err != nil {
		return err
	}
	defer file.DecRef(ctx)

	n, err := inst.NewFDFrom(0, file, kernel.FDFlags{CloseOnExec: true})
	if err != nil {
		return err
	}
	req.FenceFD = n
	_, _ = binary.Encode(arg, binary.LittleEndian, &req)
	return nil
}

// submit sends cmd on c, with a new fence on ring when withFence is set. It
// holds c.submitMu from fence ID allocation until Submit returns, so fence IDs
// reach the renderer in increasing order on every ring of c (I-6b.3). The
// fence is in the pending list before Submit, so a FENCE_DONE that arrives at
// once finds it.
func (d *Device) submit(c *fileContext, ring uint32, cmd []byte, withFence bool) (*fence, error) {
	c.submitMu.Lock()
	defer c.submitMu.Unlock()

	if d.lost.Load() || c.lost.Load() {
		return nil, linuxerr.EIO
	}
	if !withFence {
		return nil, rendererErrno(d.renderer.Submit(c.id, cmd, nil))
	}
	f := &fence{
		id:   d.lastFenceID.Add(1),
		ring: ring,
	}
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
