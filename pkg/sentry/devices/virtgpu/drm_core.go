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

// Driver identity constants matching Linux drivers/gpu/drm/virtio/virtgpu_drv.h.
const (
	driverName       = "virtio_gpu"
	driverDate       = "0"
	driverDesc       = "virtio GPU"
	driverMajor      = 0
	driverMinor      = 1
	driverPatchlevel = 0
)

// copyField writes value to the guest buffer at ptr of *length bytes, matching
// Linux drm_copy_field. It copies min(len(value), *length) bytes without a NUL
// and sets *length to len(value).
func copyField(ctx context.Context, uio usermem.IO, ptr uint64, length *uint64, value string) error {
	n := min(uint64(len(value)), *length)
	*length = uint64(len(value))
	if n > 0 && ptr != 0 {
		if _, err := uio.CopyOut(ctx, hostarch.Addr(ptr), []byte(value[:n]), usermem.IOOpts{}); err != nil {
			return linuxerr.EFAULT
		}
	}
	return nil
}

// version serves DRM_IOCTL_VERSION.
func (fd *renderFD) version(ctx context.Context, uio usermem.IO, arg []byte) error {
	var v drmVersion
	if _, err := binary.Decode(arg, binary.LittleEndian, &v); err != nil {
		return linuxerr.EINVAL
	}
	v.VersionMajor = driverMajor
	v.VersionMinor = driverMinor
	v.VersionPatchlevel = driverPatchlevel

	err := copyField(ctx, uio, v.Name, &v.NameLen, driverName)
	if err == nil {
		err = copyField(ctx, uio, v.Date, &v.DateLen, driverDate)
	}
	if err == nil {
		err = copyField(ctx, uio, v.Desc, &v.DescLen, driverDesc)
	}
	_, _ = binary.Encode(arg, binary.LittleEndian, &v)
	return err
}

// getCap serves DRM_IOCTL_GET_CAP.
func (fd *renderFD) getCap(ctx context.Context, uio usermem.IO, arg []byte) error {
	var req drmGetCap
	if _, err := binary.Decode(arg, binary.LittleEndian, &req); err != nil {
		return linuxerr.EINVAL
	}
	req.Value = 0

	var err error
	switch req.Capability {
	case drmCapPrime, drmCapSyncobj, drmCapSyncobjTimeline:
		req.Value = 0
	case drmCapTimestampMonotonic:
		req.Value = 1
	default:
		err = linuxerr.EINVAL
	}
	_, _ = binary.Encode(arg, binary.LittleEndian, &req)
	return err
}
