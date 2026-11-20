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

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
	"z.gfire.dev/gvx/pkg/usermem"
)

// resourceCreate serves DRM_IOCTL_VIRTGPU_RESOURCE_CREATE.
func (fd *renderFD) resourceCreate(ctx context.Context, uio usermem.IO, arg []byte) error {
	var req virtgpuResourceCreate
	if _, err := binary.Decode(arg, binary.LittleEndian, &req); err != nil {
		return linuxerr.EINVAL
	}

	size := uint64(req.Size)
	if size == 0 {
		size = uint64(hostarch.PageSize)
	}
	guestAddr, ok := hostarch.Addr(size).RoundUp()
	if !ok || uint64(guestAddr) > maxBlobBytes {
		return linuxerr.ENOMEM
	}
	guestSize := uint64(guestAddr)

	c, err := fd.ensureContext(ctx)
	if err != nil {
		return err
	}
	if fd.dev.lost.Load() || c.lost.Load() {
		return linuxerr.EIO
	}

	reserved := roundUpBlobSize(guestSize)
	if err := fd.dev.budget.reserve(reserved); err != nil {
		return err
	}
	taken := false
	defer func() {
		if !taken {
			fd.dev.budget.release(reserved)
		}
	}()

	resID := fd.dev.allocResID()
	if resID == 0 {
		return linuxerr.EIO
	}

	var res gpuproto.Blob
	err = callRenderer(ctx, func(cc stdcontext.Context) error {
		var callErr error
		res, callErr = fd.dev.renderer.CreateResource(cc, gpuproto.ResourceCreate{
			CtxID:     c.id,
			ResID:     resID,
			Target:    req.Target,
			Format:    req.Format,
			Bind:      req.Bind,
			Width:     req.Width,
			Height:    req.Height,
			Depth:     req.Depth,
			ArraySize: req.ArraySize,
			LastLevel: req.LastLevel,
			NrSamples: req.NrSamples,
			Flags:     req.Flags,
			Size:      guestSize,
		})
		return callErr
	})
	if err != nil {
		if !linuxerr.Equals(linuxerr.ERESTARTSYS, err) && (fd.dev.lost.Load() || c.lost.Load()) {
			return linuxerr.EIO
		}
		return err
	}

	if res.Shm == nil {
		fd.dev.unrefResource(c.id, resID)
		return linuxerr.EIO
	}
	b, err := newBlob(fd.dev, res.Shm, guestSize, reserved)
	if err != nil {
		fd.dev.unrefResource(c.id, resID)
		log.Warningf("virtgpu: map virgl resource %d: %v", resID, err)
		return linuxerr.EIO
	}
	taken = true

	obj := &gemObject{
		resID:   resID,
		blobMem: 0,
		size:    guestSize,
		blob:    b,
	}
	fd.gemMu.Lock()
	h := fd.gem.insert(obj)
	fd.gemMu.Unlock()
	if h == 0 {
		fd.dev.unrefResource(c.id, resID)
		b.decOwner()
		return linuxerr.ENOMEM
	}

	req.BoHandle = h
	req.ResHandle = resID
	_, _ = binary.Encode(arg, binary.LittleEndian, &req)
	return nil
}

// transferToHost serves DRM_IOCTL_VIRTGPU_TRANSFER_TO_HOST.
func (fd *renderFD) transferToHost(ctx context.Context, uio usermem.IO, arg []byte) error {
	return fd.transfer(ctx, uio, arg, gpuproto.TransferToHost)
}

// transferFromHost serves DRM_IOCTL_VIRTGPU_TRANSFER_FROM_HOST.
func (fd *renderFD) transferFromHost(ctx context.Context, uio usermem.IO, arg []byte) error {
	return fd.transfer(ctx, uio, arg, gpuproto.TransferFromHost)
}

func (fd *renderFD) transfer(ctx context.Context, uio usermem.IO, arg []byte, dir uint32) error {
	var req virtgpu3DTransfer
	if _, err := binary.Decode(arg, binary.LittleEndian, &req); err != nil {
		return linuxerr.EINVAL
	}

	fd.gemMu.Lock()
	o, ok := fd.gem.lookup(req.BoHandle)
	fd.gemMu.Unlock()
	if !ok {
		return linuxerr.ENOENT
	}
	if o.blobMem != 0 {
		return linuxerr.EINVAL
	}
	if req.Stride != 0 || req.LayerStride != 0 {
		return linuxerr.EINVAL
	}

	c, err := fd.ensureContext(ctx)
	if err != nil {
		return err
	}
	if fd.dev.lost.Load() || c.lost.Load() {
		return linuxerr.EIO
	}

	err = callRenderer(ctx, func(cc stdcontext.Context) error {
		return fd.dev.renderer.Transfer(cc, gpuproto.Transfer{
			CtxID:     c.id,
			ResID:     o.resID,
			Direction: dir,
			Level:     req.Level,
			Box: gpuproto.Box{
				X: req.Box.X,
				Y: req.Box.Y,
				Z: req.Box.Z,
				W: req.Box.W,
				H: req.Box.H,
				D: req.Box.D,
			},
			Offset: uint64(req.Offset),
		})
	})
	if err != nil {
		if !linuxerr.Equals(linuxerr.ERESTARTSYS, err) && (fd.dev.lost.Load() || c.lost.Load()) {
			return linuxerr.EIO
		}
		return err
	}
	return nil
}
