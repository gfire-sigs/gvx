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
	stdcontext "context"
	"encoding/binary"
	"unsafe"

	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
	"z.gfire.dev/gvx/pkg/sync"
	"z.gfire.dev/gvx/pkg/usermem"
)

// maxContextInitParams is the count of distinct context parameter kinds.
const maxContextInitParams = 4

// fileContext is the renderer context of one DRM file. id, capsetID, and
// numRings never change after construction.
type fileContext struct {
	id       uint32
	capsetID uint32
	numRings uint32 // VIRTGPU_CONTEXT_PARAM_NUM_RINGS; 0 when the guest did not set it

	// lost is set by the event sink when the renderer reports the context
	// lost or the renderer is lost, or when a fence times out. It is never
	// cleared.
	lost atomicbitops.Bool

	// destroyed ensures CTX_DESTROY is sent at most once (on timeout or close).
	destroyed atomicbitops.Bool

	// submitMu serializes fence allocation and submission (I-6b.3).
	submitMu sync.Mutex

	fenceMu sync.Mutex
	// pending holds the unsignaled fences of each ring in increasing ID order.
	// +checklocks:fenceMu
	pending [gpuproto.MaxRings][]*fence
	// pendingCount is the total number of entries across pending.
	// +checklocks:fenceMu
	pendingCount int
	// dead is set when the context is lost or destroyed. No fence is added
	// after that.
	// +checklocks:fenceMu
	dead bool
}

// allocCtxID returns a context ID that is not 0 and that d never returned
// before. It returns 0 once the 32-bit space is exhausted.
func (d *Device) allocCtxID() uint32 {
	for {
		cur := d.lastCtxID.Load()
		if cur == ^uint32(0) {
			return 0
		}
		if d.lastCtxID.CompareAndSwap(cur, cur+1) {
			return cur + 1
		}
	}
}

// sendDestroy sends CTX_DESTROY for c once. Later calls do nothing.
// The error of DestroyContext is logged at debug level only: Linux close(2) on
// a DRM file cannot fail for a host reason.
func (d *Device) sendDestroy(c *fileContext) {
	if !c.destroyed.CompareAndSwap(false, true) {
		return
	}
	if err := d.renderer.DestroyContext(c.id); err != nil {
		log.Debugf("virtgpu: destroy context %d: %v", c.id, err)
	}
}

// destroyContext runs on file close: it removes c from d.contexts, fails its
// pending fences, and sends CTX_DESTROY unless a fence timeout already did.
func (d *Device) destroyContext(c *fileContext) {
	d.mu.Lock()
	delete(d.contexts, c.id)
	d.mu.Unlock()
	c.failFences()
	d.sendDestroy(c)
}

// contextInit serves DRM_IOCTL_VIRTGPU_CONTEXT_INIT.
func (fd *renderFD) contextInit(ctx context.Context, uio usermem.IO, arg []byte) error {
	var req virtgpuContextInit
	if _, err := binary.Decode(arg, binary.LittleEndian, &req); err != nil {
		return linuxerr.EINVAL
	}
	if req.Pad != 0 || req.NumParams == 0 || req.NumParams > maxContextInitParams {
		return linuxerr.EINVAL
	}

	const paramBytes = int(unsafe.Sizeof(virtgpuContextSetParam{}))
	var raw [maxContextInitParams * paramBytes]byte
	buf := raw[:int(req.NumParams)*paramBytes]
	if _, err := uio.CopyIn(ctx, hostarch.Addr(req.CtxSetParams), buf, usermem.IOOpts{}); err != nil {
		return linuxerr.EFAULT
	}
	var params [maxContextInitParams]virtgpuContextSetParam
	if _, err := binary.Decode(buf, binary.LittleEndian, params[:req.NumParams]); err != nil {
		return linuxerr.EINVAL
	}

	fd.initMu.Lock()
	defer fd.initMu.Unlock()

	if fd.ctx.Load() != nil {
		return linuxerr.EEXIST
	}

	var (
		seenCapset    bool
		seenRings     bool
		seenPollMask  bool
		seenDebugName bool
		rings         uint32
		name          string
	)
	for _, p := range params[:req.NumParams] {
		switch p.Param {
		case virtgpuContextParamCapsetID:
			if seenCapset || p.Value > 63 || p.Value != virtgpuCapsetVenus {
				return linuxerr.EINVAL
			}
			seenCapset = true
		case virtgpuContextParamNumRings:
			if seenRings || p.Value > gpuproto.MaxRings {
				return linuxerr.EINVAL
			}
			seenRings = true
			rings = uint32(p.Value)
		case virtgpuContextParamPollRingsMask:
			if seenPollMask || p.Value != 0 {
				return linuxerr.EINVAL
			}
			seenPollMask = true
		case virtgpuContextParamDebugName:
			if seenDebugName {
				return linuxerr.EINVAL
			}
			seenDebugName = true
			s, err := usermem.CopyStringIn(ctx, uio, hostarch.Addr(p.Value), gpuproto.MaxContextNameBytes-1, usermem.IOOpts{})
			if err != nil && !linuxerr.Equals(linuxerr.ENAMETOOLONG, err) {
				return linuxerr.EFAULT
			}
			name = s
		default:
			return linuxerr.EINVAL
		}
	}
	if !seenCapset {
		return linuxerr.EINVAL
	}
	if fd.dev.lost.Load() {
		return linuxerr.EIO
	}
	id := fd.dev.allocCtxID()
	if id == 0 {
		return linuxerr.EIO
	}

	c := &fileContext{
		id:       id,
		capsetID: virtgpuCapsetVenus,
		numRings: rings,
	}
	fd.dev.mu.Lock()
	if fd.dev.lost.Load() {
		fd.dev.mu.Unlock()
		return linuxerr.EIO
	}
	if len(fd.dev.contexts) >= maxContexts {
		fd.dev.mu.Unlock()
		return linuxerr.ENOSPC
	}
	fd.dev.contexts[id] = c
	fd.dev.mu.Unlock()

	err := callRenderer(ctx, func(cc stdcontext.Context) error {
		return fd.dev.renderer.CreateContext(cc, id, virtgpuCapsetVenus, name)
	})
	if err != nil {
		fd.dev.mu.Lock()
		delete(fd.dev.contexts, id)
		fd.dev.mu.Unlock()
		return err
	}
	fd.ctx.Store(c)
	return nil
}
