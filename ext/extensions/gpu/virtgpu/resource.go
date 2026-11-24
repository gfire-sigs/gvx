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
	"math/bits"

	"z.gfire.dev/gvx/ext/extensions/gpu/gpuproto"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/usermem"
)

// Gallium pipe_texture_target values from virgl_hw.h and Mesa p_defines.h.
const (
	pipeBuffer           = 0
	pipeTexture1D        = 1
	pipeTexture2D        = 2
	pipeTexture3D        = 3
	pipeTextureCube      = 4
	pipeTextureRect      = 5
	pipeTexture1DArray   = 6
	pipeTexture2DArray   = 7
	pipeTextureCubeArray = 8
)

// Texture dimension caps for virgl RESOURCE_CREATE budget accounting.
const (
	// maxTextureDim caps width, height, depth, and array size of a non-buffer
	// virgl resource. Matches the 16384 framebuffer and texture limit of the host.
	maxTextureDim = 16384
	// maxTextureLastLevel equals floor(log2(maxTextureDim)).
	maxTextureLastLevel = 14
	// maxTextureSamples caps multisample counts of a virgl resource.
	maxTextureSamples = 64
	// cubeMapFaces is the face count of a PIPE_TEXTURE_CUBE resource.
	cubeMapFaces = 6

	// virglDefaultBytesPerPixel is the conservative upper bound for formats
	// absent from virglFormatBytesPerPixel.
	virglDefaultBytesPerPixel = 16
	// virglCompressedBytesPerPixel is the conservative upper bound for block-
	// compressed formats, accounting for RGBA8 host software decompression.
	virglCompressedBytesPerPixel = 4
)

// Common Gallium virgl_formats values from virgl_hw.h.
const (
	virglFormatB8G8R8A8Unorm     = 1
	virglFormatB8G8R8X8Unorm     = 2
	virglFormatA8R8G8B8Unorm     = 3
	virglFormatX8R8G8B8Unorm     = 4
	virglFormatB5G5R5A1Unorm     = 5
	virglFormatB4G4R4A4Unorm     = 6
	virglFormatB5G6R5Unorm       = 7
	virglFormatR10G10B10A2Unorm  = 8
	virglFormatL8Unorm           = 9
	virglFormatA8Unorm           = 10
	virglFormatI8Unorm           = 11
	virglFormatL8A8Unorm         = 12
	virglFormatL16Unorm          = 13
	virglFormatUYVY              = 14
	virglFormatYUYV              = 15
	virglFormatZ16Unorm          = 16
	virglFormatZ32Unorm          = 17
	virglFormatZ32Float          = 18
	virglFormatZ24UnormS8Uint    = 19
	virglFormatS8UintZ24Unorm    = 20
	virglFormatZ24X8Unorm        = 21
	virglFormatX8Z24Unorm        = 22
	virglFormatS8Uint            = 23
	virglFormatR64Float          = 24
	virglFormatR64G64Float       = 25
	virglFormatR64G64B64Float    = 26
	virglFormatR64G64B64A64Float = 27
	virglFormatR32Float          = 28
	virglFormatR32G32B32A32Float = 31
	virglFormatR32Unorm          = 32
	virglFormatR32G32B32A32Sscal = 47
	virglFormatR16Unorm          = 48
	virglFormatR16G16B16A16Sscal = 63
	virglFormatR8Unorm           = 64
	virglFormatR8G8Unorm         = 65
	virglFormatR8G8B8Unorm       = 66
	virglFormatR8G8B8A8Unorm     = 67
	virglFormatX8B8G8R8Unorm     = 68
	virglFormatR8Uscaled         = 69
	virglFormatR8G8B8A8Uscaled   = 72
	virglFormatR8Snorm           = 74
	virglFormatR8G8B8A8Snorm     = 77
	virglFormatR8Sscaled         = 82
	virglFormatR8G8B8A8Sscaled   = 85
	virglFormatR16Float          = 91
	virglFormatR16G16Float       = 92
	virglFormatR16G16B16Float    = 93
	virglFormatR16G16B16A16Float = 94
	virglFormatL8Srgb            = 95
	virglFormatL8A8Srgb          = 96
	virglFormatR8G8B8Srgb        = 97
	virglFormatR8G8B8A8Srgb      = 104
	virglFormatDXT1Rgb           = 105
	virglFormatDXT5Srgba         = 112
	virglFormatRGTC1Unorm        = 113
	virglFormatRGTC2Snorm        = 116
	virglFormatR11G11B10Float    = 124
	virglFormatR9G9B9E5Float     = 125
	virglFormatZ32FloatS8X24Uint = 126
	virglFormatR8G8B8X8Unorm     = 134
	virglFormatR8Uint            = 177
	virglFormatR8G8B8A8Uint      = 180
	virglFormatR8Sint            = 181
	virglFormatR8G8B8A8Sint      = 184
	virglFormatR16Uint           = 185
	virglFormatR16G16B16A16Uint  = 188
	virglFormatR16Sint           = 189
	virglFormatR16G16B16A16Sint  = 192
	virglFormatR32Uint           = 193
	virglFormatR32G32B32A32Uint  = 196
	virglFormatR32Sint           = 197
	virglFormatR32G32B32A32Sint  = 200
	virglFormatBPTCRgbaUnorm     = 255
	virglFormatBPTCRgbUfloat     = 258
	virglFormatETC2Rgb8          = 270
	virglFormatETC2Rgba8         = 273
)

// virglFormatBytesPerPixel returns a conservative bytes-per-pixel upper bound
// for a Gallium virgl_formats value. Unknown formats return
// virglDefaultBytesPerPixel (16).
func virglFormatBytesPerPixel(format uint32) uint64 {
	switch {
	case format >= virglFormatB8G8R8A8Unorm && format <= virglFormatX8R8G8B8Unorm:
		return 4
	case format >= virglFormatB5G5R5A1Unorm && format <= virglFormatB5G6R5Unorm:
		return 2
	case format == virglFormatR10G10B10A2Unorm:
		return 4
	case format >= virglFormatL8Unorm && format <= virglFormatI8Unorm:
		return 1
	case format >= virglFormatL8A8Unorm && format <= virglFormatZ16Unorm:
		return 2
	case format >= virglFormatZ32Unorm && format <= virglFormatX8Z24Unorm:
		return 4
	case format == virglFormatS8Uint:
		return 1
	case format == virglFormatR64Float:
		return 8
	case format == virglFormatR64G64Float:
		return 16
	case format == virglFormatR64G64B64Float:
		return 24
	case format == virglFormatR64G64B64A64Float:
		return 32
	case format >= virglFormatR32Float && format <= virglFormatR32G32B32A32Sscal:
		// Four-channel groups: R32, R32G32, R32G32B32, R32G32B32A32.
		return paddedChannels((format-virglFormatR32Float)%4+1) * 4
	case format >= virglFormatR16Unorm && format <= virglFormatR16G16B16A16Sscal:
		// Four-channel groups: R16, R16G16, R16G16B16, R16G16B16A16.
		return paddedChannels((format-virglFormatR16Unorm)%4+1) * 2
	case format == virglFormatR8Unorm:
		return 1
	case format == virglFormatR8G8Unorm:
		return 2
	case format == virglFormatR8G8B8Unorm || format == virglFormatR8G8B8A8Unorm || format == virglFormatX8B8G8R8Unorm:
		return 4
	case format >= virglFormatR8Uscaled && format <= virglFormatR8G8B8A8Uscaled:
		return bytesFor8BitChannels(format - virglFormatR8Uscaled)
	case format >= virglFormatR8Snorm && format <= virglFormatR8G8B8A8Snorm:
		return bytesFor8BitChannels(format - virglFormatR8Snorm)
	case format >= virglFormatR8Sscaled && format <= virglFormatR8G8B8A8Sscaled:
		return bytesFor8BitChannels(format - virglFormatR8Sscaled)
	case format == virglFormatR16Float:
		return 2
	case format == virglFormatR16G16Float:
		return 4
	case format == virglFormatR16G16B16Float || format == virglFormatR16G16B16A16Float:
		return 8
	case format == virglFormatL8Srgb:
		return 1
	case format == virglFormatL8A8Srgb:
		return 2
	case format >= virglFormatR8G8B8Srgb && format <= virglFormatR8G8B8A8Srgb:
		return 4
	case format >= virglFormatDXT1Rgb && format <= virglFormatRGTC2Snorm:
		return virglCompressedBytesPerPixel
	case format == virglFormatR11G11B10Float || format == virglFormatR9G9B9E5Float:
		return 4
	case format == virglFormatZ32FloatS8X24Uint:
		return 8
	case format == virglFormatR8G8B8X8Unorm:
		return 4
	case format >= virglFormatR8Uint && format <= virglFormatR8G8B8A8Uint:
		return bytesFor8BitChannels(format - virglFormatR8Uint)
	case format >= virglFormatR8Sint && format <= virglFormatR8G8B8A8Sint:
		return bytesFor8BitChannels(format - virglFormatR8Sint)
	case format >= virglFormatR16Uint && format <= virglFormatR16G16B16A16Uint:
		return bytesFor16BitChannels(format - virglFormatR16Uint)
	case format >= virglFormatR16Sint && format <= virglFormatR16G16B16A16Sint:
		return bytesFor16BitChannels(format - virglFormatR16Sint)
	case format >= virglFormatR32Uint && format <= virglFormatR32G32B32A32Uint:
		return paddedChannels(format-virglFormatR32Uint+1) * 4
	case format >= virglFormatR32Sint && format <= virglFormatR32G32B32A32Sint:
		return paddedChannels(format-virglFormatR32Sint+1) * 4
	case format >= virglFormatBPTCRgbaUnorm && format <= virglFormatBPTCRgbUfloat:
		return virglCompressedBytesPerPixel
	case format >= virglFormatETC2Rgb8 && format <= virglFormatETC2Rgba8:
		return virglCompressedBytesPerPixel
	default:
		return virglDefaultBytesPerPixel
	}
}

// bytesFor8BitChannels returns padded bytes per pixel for a 1-to-4 channel
// 8-bit format (RGB8 rounds up to 4 bytes on host GPUs).
func bytesFor8BitChannels(idx uint32) uint64 {
	switch idx {
	case 0:
		return 1
	case 1:
		return 2
	default:
		return 4
	}
}

// bytesFor16BitChannels returns padded bytes per pixel for a 1-to-4 channel
// 16-bit format (RGB16 rounds up to 8 bytes on host GPUs).
// paddedChannels returns the channel count that the host allocates for a
// format with n channels. Hosts store a three-channel texel in four channels,
// so the charge stays an upper bound.
func paddedChannels(n uint32) uint64 {
	if n == 3 {
		return 4
	}
	return uint64(n)
}

func bytesFor16BitChannels(idx uint32) uint64 {
	switch idx {
	case 0:
		return 2
	case 1:
		return 4
	default:
		return 8
	}
}

func mulUint64(a, b uint64) (uint64, bool) {
	hi, lo := bits.Mul64(a, b)
	return lo, hi == 0
}

func addUint64(a, b uint64) (uint64, bool) {
	sum, carry := bits.Add64(a, b, 0)
	return sum, carry == 0
}

// virglTextureBytes validates texture dimensions and computes an upper bound
// on host GPU bytes for a non-buffer virgl RESOURCE_CREATE request. It rejects
// out-of-range dimensions and uint64 arithmetic overflow with EINVAL.
func virglTextureBytes(req virtgpuResourceCreate) (uint64, error) {
	if req.Width > maxTextureDim ||
		req.Height > maxTextureDim ||
		req.Depth > maxTextureDim ||
		req.ArraySize > maxTextureDim ||
		req.LastLevel > maxTextureLastLevel ||
		req.NrSamples > maxTextureSamples {
		return 0, linuxerr.EINVAL
	}

	var totalTexels uint64
	for level := uint32(0); level <= req.LastLevel; level++ {
		lw := max(uint64(req.Width>>level), 1)
		lh := max(uint64(req.Height>>level), 1)
		ld := max(uint64(req.Depth>>level), 1)
		wh, ok := mulUint64(lw, lh)
		if !ok {
			return 0, linuxerr.EINVAL
		}
		levelTexels, ok := mulUint64(wh, ld)
		if !ok {
			return 0, linuxerr.EINVAL
		}
		totalTexels, ok = addUint64(totalTexels, levelTexels)
		if !ok {
			return 0, linuxerr.EINVAL
		}
	}

	arraySize := max(uint64(req.ArraySize), 1)
	if req.Target == pipeTextureCube && arraySize < cubeMapFaces {
		arraySize = cubeMapFaces
	}
	samples := max(uint64(req.NrSamples), 1)
	bpp := virglFormatBytesPerPixel(req.Format)

	total, ok := mulUint64(totalTexels, arraySize)
	if !ok {
		return 0, linuxerr.EINVAL
	}
	total, ok = mulUint64(total, samples)
	if !ok {
		return 0, linuxerr.EINVAL
	}
	total, ok = mulUint64(total, bpp)
	if !ok {
		return 0, linuxerr.EINVAL
	}
	return total, nil
}

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

	charge := guestSize
	if req.Target != pipeBuffer {
		texBytes, err := virglTextureBytes(req)
		if err != nil {
			return err
		}
		charge = max(charge, texBytes)
	}
	reserved, ok := roundUpBlobSizeChecked(charge)
	if !ok {
		return linuxerr.EINVAL
	}

	c, err := fd.ensureContext(ctx)
	if err != nil {
		return err
	}
	if fd.dev.lost.Load() || c.lost.Load() {
		return linuxerr.EIO
	}

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
