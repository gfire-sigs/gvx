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

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/usermem"
)

// getParam serves DRM_IOCTL_VIRTGPU_GETPARAM.
func (fd *renderFD) getParam(ctx context.Context, uio usermem.IO, arg []byte) error {
	var req virtgpuGetparam
	if _, err := binary.Decode(arg, binary.LittleEndian, &req); err != nil {
		return linuxerr.EINVAL
	}

	var val uint32
	switch req.Param {
	case virtgpuParam3DFeatures,
		virtgpuParamCapsetQueryFix,
		virtgpuParamResourceBlob,
		virtgpuParamHostVisible,
		virtgpuParamContextInit,
		virtgpuParamExplicitDebugName:
		val = 1
	case virtgpuParamCrossDevice:
		val = 0
	case virtgpuParamSupportedCapsetIDs:
		val = 1 << virtgpuCapsetVenus
	case virtgpuParamBlobAlignment:
		val = blobAlignment
	default:
		return linuxerr.EINVAL
	}

	// Linux writes sizeof(int) bytes; Mesa zeroes the upper half itself.
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], val)
	if _, err := uio.CopyOut(ctx, hostarch.Addr(req.Value), buf[:], usermem.IOOpts{}); err != nil {
		return linuxerr.EFAULT
	}
	return nil
}

// getCaps serves DRM_IOCTL_VIRTGPU_GET_CAPS.
func (fd *renderFD) getCaps(ctx context.Context, uio usermem.IO, arg []byte) error {
	var req virtgpuGetCaps
	if _, err := binary.Decode(arg, binary.LittleEndian, &req); err != nil {
		return linuxerr.EINVAL
	}
	if req.Size == 0 {
		return linuxerr.EINVAL
	}
	data, ok := fd.dev.renderer.Capset(req.CapSetID, req.CapSetVer)
	if !ok {
		return linuxerr.EINVAL
	}
	n := min(uint64(req.Size), uint64(len(data)))
	if _, err := uio.CopyOut(ctx, hostarch.Addr(req.Addr), data[:n], usermem.IOOpts{}); err != nil {
		return linuxerr.EFAULT
	}
	return nil
}
