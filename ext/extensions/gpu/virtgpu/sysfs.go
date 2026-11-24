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

import "z.gfire.dev/gvx/pkg/sentry/fsimpl/sys"

// PCI and virtio identity of the virtual GPU, matching a QEMU virtio-gpu-pci
// device (1af4:1050) for libdrm and Mesa venus/virgl discovery.
const (
	pciVendorID      = 0x1af4
	pciDeviceID      = 0x1050
	pciSubVendorID   = 0x1af4
	pciSubDeviceID   = 0x1100
	pciRevision      = 0x01
	pciClassCode     = 0x038000 // display controller (0x03), other (0x80), prog-if 0x00
	virtioGPUDevID   = 0x10     // VIRTIO_ID_GPU
	drmClassVersion  = "drm 1.1.0 20060810\n"
	defaultPCISlot   = "0000:00:01.0"
	defaultVirtioDev = "virtio0"
)

// SysfsTopology returns the declarative sysfs topology for /dev/dri/renderD128
// using the core sys.VirtioPCIDeviceTopology seam.
func SysfsTopology() (sys.TopologyAddition, error) {
	return sys.VirtioPCIDeviceTopology(sys.VirtioPCIDeviceSpec{
		PCISlot:        defaultPCISlot,
		VirtioName:     defaultVirtioDev,
		VendorID:       pciVendorID,
		DeviceID:       pciDeviceID,
		SubVendorID:    pciSubVendorID,
		SubDeviceID:    pciSubDeviceID,
		Revision:       pciRevision,
		ClassCode:      pciClassCode,
		VirtioDeviceID: virtioGPUDevID,
		VirtioDriver:   "virtio_gpu",
		ClassName:      "drm",
		NodeName:       "renderD128",
		DevName:        "dri/renderD128",
		DevType:        "drm_minor",
		Major:          DRMMajor,
		Minor:          RenderMinor,
		ClassFiles: []sys.NodeSpec{
			{Name: "version", Kind: sys.NodeFile, Content: drmClassVersion},
		},
	})
}
