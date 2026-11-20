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
	"unsafe"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
)

// Linux DRM and virtio-gpu uAPI (include/uapi/drm/drm.h and virtgpu_drm.h).
// testdata/abi_<arch>.txt holds the values that clang computes from the
// headers, and TestABIMatchesClangTables compares every value below with it.

// drmIoctlBase is the ioctl type of every DRM request.
const drmIoctlBase = 'd'

// blobAlignment is the host page size of macOS on Apple silicon; RegionMap
// maps whole 16 KiB blocks. Tied to gpuproto.HostBlobAlign as one contract.
const blobAlignment = gpuproto.HostBlobAlign

// DRM request numbers that the device serves or reserves for WP6b/virgl.
const (
	nrVersion         = 0x00
	nrGemClose        = 0x09
	nrGetCap          = 0x0c
	nrPrimeHandleToFD = 0x2d
	nrPrimeFDToHandle = 0x2e

	drmCommandBase = 0x40
	drmCommandEnd  = 0xa0

	nrVirtgpuMap                = drmCommandBase + 0x01
	nrVirtgpuExecbuffer         = drmCommandBase + 0x02
	nrVirtgpuGetparam           = drmCommandBase + 0x03
	nrVirtgpuResourceCreate     = drmCommandBase + 0x04
	nrVirtgpuResourceInfo       = drmCommandBase + 0x05
	nrVirtgpuTransferFromHost   = drmCommandBase + 0x06
	nrVirtgpuTransferToHost     = drmCommandBase + 0x07
	nrVirtgpuWait               = drmCommandBase + 0x08
	nrVirtgpuGetCaps            = drmCommandBase + 0x09
	nrVirtgpuResourceCreateBlob = drmCommandBase + 0x0a
	nrVirtgpuContextInit        = drmCommandBase + 0x0b
)

// Core DRM request numbers that the device refuses. A render node refuses
// every core request without DRM_RENDER_ALLOW (Linux 6.12
// drivers/gpu/drm/drm_ioctl.c) with EACCES.
const (
	nrGetUnique             = 0x01
	nrGetMagic              = 0x02
	nrGetClient             = 0x05
	nrGetStats              = 0x06
	nrSetVersion            = 0x07
	nrGemFlink              = 0x0a
	nrGemOpen               = 0x0b
	nrSetClientCap          = 0x0d
	nrSetUnique             = 0x10
	nrAuthMagic             = 0x11
	nrBlock                 = 0x12
	nrUnblock               = 0x13
	nrSetMaster             = 0x1e
	nrDropMaster            = 0x1f
	nrAddDraw               = 0x27
	nrRmDraw                = 0x28
	nrFinish                = 0x2c
	nrWaitVblank            = 0x3a
	nrCrtcGetSequence       = 0x3b
	nrCrtcQueueSequence     = 0x3c
	nrUpdateDraw            = 0x3f
	nrModeGetresources      = 0xa0
	nrModeGetcrtc           = 0xa1
	nrModeSetcrtc           = 0xa2
	nrModeCursor            = 0xa3
	nrModeGetgamma          = 0xa4
	nrModeSetgamma          = 0xa5
	nrModeGetencoder        = 0xa6
	nrModeGetconnector      = 0xa7
	nrModeAttachmode        = 0xa8
	nrModeDetachmode        = 0xa9
	nrModeGetproperty       = 0xaa
	nrModeSetproperty       = 0xab
	nrModeGetpropblob       = 0xac
	nrModeGetfb             = 0xad
	nrModeAddfb             = 0xae
	nrModeRmfb              = 0xaf
	nrModePageFlip          = 0xb0
	nrModeDirtyfb           = 0xb1
	nrModeCreateDumb        = 0xb2
	nrModeMapDumb           = 0xb3
	nrModeDestroyDumb       = 0xb4
	nrModeGetplaneresources = 0xb5
	nrModeGetplane          = 0xb6
	nrModeSetplane          = 0xb7
	nrModeAddfb2            = 0xb8
	nrModeObjGetproperties  = 0xb9
	nrModeObjSetproperty    = 0xba
	nrModeCursor2           = 0xbb
	nrModeAtomic            = 0xbc
	nrModeCreatepropblob    = 0xbd
	nrModeDestroypropblob   = 0xbe
	nrSyncobjCreate         = 0xbf
	nrSyncobjDestroy        = 0xc0
	nrSyncobjHandleToFD     = 0xc1
	nrSyncobjFDToHandle     = 0xc2
	nrSyncobjWait           = 0xc3
	nrSyncobjReset          = 0xc4
	nrSyncobjSignal         = 0xc5
	nrModeCreateLease       = 0xc6
	nrModeListLessees       = 0xc7
	nrModeGetLease          = 0xc8
	nrModeRevokeLease       = 0xc9
	nrSyncobjTimelineWait   = 0xca
	nrSyncobjQuery          = 0xcb
	nrSyncobjTransfer       = 0xcc
	nrSyncobjTimelineSignal = 0xcd
	nrModeGetfb2            = 0xce
	nrSyncobjEventFD        = 0xcf
	nrModeClosefb           = 0xd0
)

// DRM_CAP_* values for DRM_IOCTL_GET_CAP.
const (
	drmCapDumbBuffer         = 0x1
	drmCapPrime              = 0x5
	drmCapTimestampMonotonic = 0x6
	drmCapSyncobj            = 0x13
	drmCapSyncobjTimeline    = 0x14
)

// VIRTGPU_PARAM_* values for DRM_IOCTL_VIRTGPU_GETPARAM.
const (
	virtgpuParam3DFeatures         = 1
	virtgpuParamCapsetQueryFix     = 2
	virtgpuParamResourceBlob       = 3
	virtgpuParamHostVisible        = 4
	virtgpuParamCrossDevice        = 5
	virtgpuParamContextInit        = 6
	virtgpuParamSupportedCapsetIDs = 7
	virtgpuParamExplicitDebugName  = 8
	// virtgpuParamBlobAlignment is not in the Linux headers yet. Mesa venus
	// defines it locally (src/virtio/vulkan/vn_renderer_virtgpu.c) and aligns
	// blob sizes to the value.
	virtgpuParamBlobAlignment = 9
)

// Other virtio-gpu uAPI values.
const (
	virtgpuExecbufFenceFDIn  = 0x01
	virtgpuExecbufFenceFDOut = 0x02
	virtgpuExecbufRingIdx    = 0x04

	virtgpuCapsetVenus = gpuproto.CapsetVenus

	virtgpuBlobMemGuest       = 0x0001
	virtgpuBlobMemHost3D      = 0x0002
	virtgpuBlobMemHost3DGuest = 0x0003

	virtgpuBlobFlagUseMappable    = 0x0001
	virtgpuBlobFlagUseShareable   = 0x0002
	virtgpuBlobFlagUseCrossDevice = 0x0004

	virtgpuContextParamCapsetID      = 0x0001
	virtgpuContextParamNumRings      = 0x0002
	virtgpuContextParamPollRingsMask = 0x0003
	virtgpuContextParamDebugName     = 0x0004
)

// drmVersion is struct drm_version. The pointer fields are guest addresses.
type drmVersion struct {
	VersionMajor      int32
	VersionMinor      int32
	VersionPatchlevel int32
	_                 uint32
	NameLen           uint64
	Name              uint64
	DateLen           uint64
	Date              uint64
	DescLen           uint64
	Desc              uint64
}

// drmGetCap is struct drm_get_cap.
type drmGetCap struct {
	Capability uint64
	Value      uint64
}

// drmGemClose is struct drm_gem_close.
type drmGemClose struct {
	Handle uint32
	Pad    uint32
}

// virtgpuMap is struct drm_virtgpu_map.
type virtgpuMap struct {
	Offset uint64
	Handle uint32
	Pad    uint32
}

// virtgpuExecbuffer is struct drm_virtgpu_execbuffer.
type virtgpuExecbuffer struct {
	Flags          uint32
	Size           uint32
	Command        uint64
	BoHandles      uint64
	NumBoHandles   uint32
	FenceFD        int32
	RingIdx        uint32
	SyncobjStride  uint32
	NumInSyncobjs  uint32
	NumOutSyncobjs uint32
	InSyncobjs     uint64
	OutSyncobjs    uint64
}

// virtgpuGetparam is struct drm_virtgpu_getparam. Value is the guest address
// of the result.
type virtgpuGetparam struct {
	Param uint64
	Value uint64
}

// virtgpuResourceInfo is struct drm_virtgpu_resource_info.
type virtgpuResourceInfo struct {
	BoHandle  uint32
	ResHandle uint32
	Size      uint32
	BlobMem   uint32
}

// virtgpuGetCaps is struct drm_virtgpu_get_caps.
type virtgpuGetCaps struct {
	CapSetID  uint32
	CapSetVer uint32
	Addr      uint64
	Size      uint32
	Pad       uint32
}

// virtgpuResourceCreateBlob is struct drm_virtgpu_resource_create_blob.
type virtgpuResourceCreateBlob struct {
	BlobMem   uint32
	BlobFlags uint32
	BoHandle  uint32
	ResHandle uint32
	Size      uint64
	Pad       uint32
	CmdSize   uint32
	Cmd       uint64
	BlobID    uint64
}

// virtgpuContextSetParam is struct drm_virtgpu_context_set_param.
type virtgpuContextSetParam struct {
	Param uint64
	Value uint64
}

// virtgpuContextInit is struct drm_virtgpu_context_init.
type virtgpuContextInit struct {
	NumParams    uint32
	Pad          uint32
	CtxSetParams uint64
}

// Request numbers as the uAPI header encodes them. The dispatcher reads the
// direction and size bits of these values, as Linux drm_ioctl reads
// drm_ioctl_desc.cmd.
var (
	cmdVersion                   = linux.IOWR(drmIoctlBase, nrVersion, uint32(unsafe.Sizeof(drmVersion{})))
	cmdGemClose                  = linux.IOW(drmIoctlBase, nrGemClose, uint32(unsafe.Sizeof(drmGemClose{})))
	cmdGetCap                    = linux.IOWR(drmIoctlBase, nrGetCap, uint32(unsafe.Sizeof(drmGetCap{})))
	cmdVirtgpuMap                = linux.IOWR(drmIoctlBase, nrVirtgpuMap, uint32(unsafe.Sizeof(virtgpuMap{})))
	cmdVirtgpuExecbuffer         = linux.IOWR(drmIoctlBase, nrVirtgpuExecbuffer, uint32(unsafe.Sizeof(virtgpuExecbuffer{})))
	cmdVirtgpuGetparam           = linux.IOWR(drmIoctlBase, nrVirtgpuGetparam, uint32(unsafe.Sizeof(virtgpuGetparam{})))
	cmdVirtgpuResourceInfo       = linux.IOWR(drmIoctlBase, nrVirtgpuResourceInfo, uint32(unsafe.Sizeof(virtgpuResourceInfo{})))
	cmdVirtgpuGetCaps            = linux.IOWR(drmIoctlBase, nrVirtgpuGetCaps, uint32(unsafe.Sizeof(virtgpuGetCaps{})))
	cmdVirtgpuResourceCreateBlob = linux.IOWR(drmIoctlBase, nrVirtgpuResourceCreateBlob, uint32(unsafe.Sizeof(virtgpuResourceCreateBlob{})))
	cmdVirtgpuContextInit        = linux.IOWR(drmIoctlBase, nrVirtgpuContextInit, uint32(unsafe.Sizeof(virtgpuContextInit{})))
)
