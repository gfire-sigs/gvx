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

package main

import "unsafe"

// Linux DRM and virtio-gpu uAPI constants and structures used by gpuprobe.
// abi_test.go compares every size, offset, and request number, and every
// constant that the uAPI headers define, against the clang tables in
// pkg/sentry/devices/virtgpu/testdata/.

const (
	iocWrite     = 1
	iocRead      = 2
	iocNRBits    = 8
	iocTypeBits  = 8
	iocSizeBits  = 14
	iocNRShift   = 0
	iocTypeShift = iocNRShift + iocNRBits
	iocSizeShift = iocTypeShift + iocTypeBits
	iocDirShift  = iocSizeShift + iocSizeBits
)

func ioc(dir, typ, nr, size uint32) uint32 {
	return (dir << iocDirShift) | (typ << iocTypeShift) | (nr << iocNRShift) | (size << iocSizeShift)
}

func iow(typ, nr, size uint32) uint32 {
	return ioc(iocWrite, typ, nr, size)
}

func iowr(typ, nr, size uint32) uint32 {
	return ioc(iocRead|iocWrite, typ, nr, size)
}

const (
	drmIoctlBase   = 'd'
	drmCommandBase = 0x40

	nrVersion  = 0x00
	nrGemClose = 0x09
	nrGetCap   = 0x0c

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

	drmCapSyncobj = 0x13

	virtgpuParam3DFeatures         = 1 // VIRTGPU_PARAM_3D_FEATURES
	virtgpuParamCapsetQueryFix     = 2 // VIRTGPU_PARAM_CAPSET_QUERY_FIX
	virtgpuParamResourceBlob       = 3 // VIRTGPU_PARAM_RESOURCE_BLOB
	virtgpuParamHostVisible        = 4 // VIRTGPU_PARAM_HOST_VISIBLE
	virtgpuParamCrossDevice        = 5 // VIRTGPU_PARAM_CROSS_DEVICE
	virtgpuParamContextInit        = 6 // VIRTGPU_PARAM_CONTEXT_INIT
	virtgpuParamSupportedCapsetIDs = 7 // VIRTGPU_PARAM_SUPPORTED_CAPSET_IDs
	virtgpuParamExplicitDebugName  = 8 // VIRTGPU_PARAM_EXPLICIT_DEBUG_NAME
	// VIRTGPU_PARAM_BLOB_ALIGNMENT is not in the Linux headers. Mesa venus
	// defines it locally (src/virtio/vulkan/vn_renderer_virtgpu.c), so the
	// clang tables do not hold it, and abi_test.go does not compare it.
	virtgpuParamBlobAlignment = 9

	virtgpuCapsetVirgl  = 1 // VIRTGPU_DRM_CAPSET_VIRGL
	virtgpuCapsetVirgl2 = 2 // VIRTGPU_DRM_CAPSET_VIRGL2
	virtgpuCapsetVenus  = 4 // VIRTGPU_DRM_CAPSET_VENUS

	virtgpuWaitNoWait = 1 // VIRTGPU_WAIT_NOWAIT

	virtgpuBlobMemHost3D       = 0x0002
	virtgpuBlobFlagUseMappable = 0x0001

	virtgpuContextParamCapsetID      = 0x0001
	virtgpuContextParamNumRings      = 0x0002
	virtgpuContextParamPollRingsMask = 0x0003

	virtgpuExecbufFenceFDOut = 0x02
	virtgpuExecbufRingIdx    = 0x04
)

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

type drmGetCap struct {
	Capability uint64
	Value      uint64
}

type drmGemClose struct {
	Handle uint32
	Pad    uint32
}

type virtgpuGetparam struct {
	Param uint64
	Value uint64
}

type virtgpuGetCaps struct {
	CapSetID  uint32
	CapSetVer uint32
	Addr      uint64
	Size      uint32
	Pad       uint32
}

type virtgpuContextSetParam struct {
	Param uint64
	Value uint64
}

type virtgpuContextInit struct {
	NumParams    uint32
	Pad          uint32
	CtxSetParams uint64
}

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

type virtgpuMap struct {
	Offset uint64
	Handle uint32
	Pad    uint32
}

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

// virtgpuResourceCreate is struct drm_virtgpu_resource_create (56 bytes).
type virtgpuResourceCreate struct {
	Target    uint32
	Format    uint32
	Bind      uint32
	Width     uint32
	Height    uint32
	Depth     uint32
	ArraySize uint32
	LastLevel uint32
	NrSamples uint32
	Flags     uint32
	BoHandle  uint32
	ResHandle uint32
	Size      uint32
	Stride    uint32
}

// virtgpuResourceInfo is struct drm_virtgpu_resource_info (16 bytes).
type virtgpuResourceInfo struct {
	BoHandle  uint32
	ResHandle uint32
	Size      uint32
	BlobMem   uint32
}

// virtgpu3DBox is struct drm_virtgpu_3d_box (24 bytes).
type virtgpu3DBox struct {
	X uint32
	Y uint32
	Z uint32
	W uint32
	H uint32
	D uint32
}

// virtgpu3DTransfer is struct drm_virtgpu_3d_transfer_to_host and
// struct drm_virtgpu_3d_transfer_from_host (44 bytes).
type virtgpu3DTransfer struct {
	BoHandle    uint32
	Box         virtgpu3DBox
	Level       uint32
	Offset      uint32
	Stride      uint32
	LayerStride uint32
}

// virtgpu3DWait is struct drm_virtgpu_3d_wait (8 bytes).
type virtgpu3DWait struct {
	Handle uint32
	Flags  uint32
}

var (
	cmdVersion                   = iowr(drmIoctlBase, nrVersion, uint32(unsafe.Sizeof(drmVersion{})))
	cmdGemClose                  = iow(drmIoctlBase, nrGemClose, uint32(unsafe.Sizeof(drmGemClose{})))
	cmdGetCap                    = iowr(drmIoctlBase, nrGetCap, uint32(unsafe.Sizeof(drmGetCap{})))
	cmdVirtgpuMap                = iowr(drmIoctlBase, nrVirtgpuMap, uint32(unsafe.Sizeof(virtgpuMap{})))
	cmdVirtgpuExecbuffer         = iowr(drmIoctlBase, nrVirtgpuExecbuffer, uint32(unsafe.Sizeof(virtgpuExecbuffer{})))
	cmdVirtgpuGetparam           = iowr(drmIoctlBase, nrVirtgpuGetparam, uint32(unsafe.Sizeof(virtgpuGetparam{})))
	cmdVirtgpuResourceCreate     = iowr(drmIoctlBase, nrVirtgpuResourceCreate, uint32(unsafe.Sizeof(virtgpuResourceCreate{})))
	cmdVirtgpuResourceInfo       = iowr(drmIoctlBase, nrVirtgpuResourceInfo, uint32(unsafe.Sizeof(virtgpuResourceInfo{})))
	cmdVirtgpuTransferFromHost   = iowr(drmIoctlBase, nrVirtgpuTransferFromHost, uint32(unsafe.Sizeof(virtgpu3DTransfer{})))
	cmdVirtgpuTransferToHost     = iowr(drmIoctlBase, nrVirtgpuTransferToHost, uint32(unsafe.Sizeof(virtgpu3DTransfer{})))
	cmdVirtgpuWait               = iowr(drmIoctlBase, nrVirtgpuWait, uint32(unsafe.Sizeof(virtgpu3DWait{})))
	cmdVirtgpuGetCaps            = iowr(drmIoctlBase, nrVirtgpuGetCaps, uint32(unsafe.Sizeof(virtgpuGetCaps{})))
	cmdVirtgpuResourceCreateBlob = iowr(drmIoctlBase, nrVirtgpuResourceCreateBlob, uint32(unsafe.Sizeof(virtgpuResourceCreateBlob{})))
	cmdVirtgpuContextInit        = iowr(drmIoctlBase, nrVirtgpuContextInit, uint32(unsafe.Sizeof(virtgpuContextInit{})))
)
