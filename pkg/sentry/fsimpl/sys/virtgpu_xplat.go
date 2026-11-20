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

package sys

import (
	"encoding/binary"
	"fmt"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/kernfs"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
)

// sysfs lists the virtual GPU as a virtio device on a PCI bus. Mesa venus
// accepts only a virtio-gpu PCI device (1af4:1050) or a platform device.
// libdrm reads the files below through /sys/dev/char/<major>:<minor>.
// It follows the "device" link to the virtio device, finds the virtio
// subsystem there, and then reads the PCI identity of the parent directory.

// VirtGPUSysfs describes the render node that sysfs lists as a virtio GPU.
type VirtGPUSysfs struct {
	// DevMajor and DevMinor are the device number of the render node.
	DevMajor uint32
	DevMinor uint32
}

// PCI identity of the virtual GPU. The values are those of a QEMU
// virtio-gpu-pci device.
const (
	virtGPUPCIRoot      = "pci0000:00"
	virtGPUPCISlot      = "0000:00:01.0"
	virtGPUVirtioName   = "virtio0"
	virtGPUVendorID     = 0x1af4
	virtGPUDeviceID     = 0x1050
	virtGPUSubVendorID  = 0x1af4
	virtGPUSubDeviceID  = 0x1100
	virtGPURevision     = 0x01
	virtGPUBaseClass    = 0x03 // display controller
	virtGPUSubClass     = 0x80 // other
	virtGPUProgIF       = 0x00
	virtGPUClass        = virtGPUBaseClass<<16 | virtGPUSubClass<<8 | virtGPUProgIF
	virtGPUVirtioDevice = 0x10 // virtio device ID of a GPU
	drmClassVersion     = "drm 1.1.0 20060810\n"
)

// Offsets in the PCI configuration header (PCI Local Bus 3.0, type 0 header).
const (
	pciConfigHeaderSize  = 64
	pciConfigVendorID    = 0x00
	pciConfigDeviceID    = 0x02
	pciConfigRevision    = 0x08
	pciConfigClass       = 0x09 // three bytes: programming interface, subclass, class
	pciConfigSubVendorID = 0x2c
	pciConfigSubDeviceID = 0x2e
)

// virtGPUPCIConfig returns the 64-byte configuration header that agrees with
// the vendor, device, subsystem, revision, and class files.
func virtGPUPCIConfig() string {
	var b [pciConfigHeaderSize]byte
	binary.LittleEndian.PutUint16(b[pciConfigVendorID:], virtGPUVendorID)
	binary.LittleEndian.PutUint16(b[pciConfigDeviceID:], virtGPUDeviceID)
	b[pciConfigRevision] = virtGPURevision
	b[pciConfigClass] = virtGPUProgIF
	b[pciConfigClass+1] = virtGPUSubClass
	b[pciConfigClass+2] = virtGPUBaseClass
	binary.LittleEndian.PutUint16(b[pciConfigSubVendorID:], virtGPUSubVendorID)
	binary.LittleEndian.PutUint16(b[pciConfigSubDeviceID:], virtGPUSubDeviceID)
	return string(b[:])
}

// virtGPUDirs holds the sysfs entries of the virtual GPU, keyed by the name
// of each entry in its parent directory.
type virtGPUDirs struct {
	devices   map[string]kernfs.Inode // /sys/devices
	busPCI    map[string]kernfs.Inode // /sys/bus/pci/devices
	busVirtio map[string]kernfs.Inode // /sys/bus/virtio
	class     map[string]kernfs.Inode // /sys/class
	devChar   map[string]kernfs.Inode // /sys/dev/char
}

// newVirtGPUSysfs builds the sysfs entries of the render node in g.
func (fs *filesystem) newVirtGPUSysfs(ctx context.Context, creds *auth.Credentials, g *VirtGPUSysfs) virtGPUDirs {
	node := fmt.Sprintf("renderD%d", g.DevMinor)
	devNum := fmt.Sprintf("%d:%d", g.DevMajor, g.DevMinor)
	nodePath := fmt.Sprintf("devices/%s/%s/%s/drm/%s", virtGPUPCIRoot, virtGPUPCISlot, virtGPUVirtioName, node)
	file := func(data string) kernfs.Inode {
		return fs.newStaticFile(ctx, creds, defaultSysMode, data)
	}
	link := func(target string) kernfs.Inode {
		return kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), target)
	}
	dir := func(children map[string]kernfs.Inode) kernfs.Inode {
		return fs.newDir(ctx, creds, defaultSysDirMode, children)
	}

	nodeDir := dir(map[string]kernfs.Inode{
		"dev":       file(devNum + "\n"),
		"device":    link("../.."),
		"subsystem": link("../../../../../../class/drm"),
		"uevent":    file(fmt.Sprintf("MAJOR=%d\nMINOR=%d\nDEVNAME=dri/%s\nDEVTYPE=drm_minor\n", g.DevMajor, g.DevMinor, node)),
	})
	virtioDir := dir(map[string]kernfs.Inode{
		"device":    file(fmt.Sprintf("0x%04x\n", virtGPUVirtioDevice)),
		"vendor":    file(fmt.Sprintf("0x%04x\n", virtGPUVendorID)),
		"drm":       dir(map[string]kernfs.Inode{node: nodeDir}),
		"subsystem": link("../../../../bus/virtio"),
		"uevent":    file(fmt.Sprintf("DRIVER=virtio_gpu\nMODALIAS=virtio:d%08Xv%08X\n", virtGPUVirtioDevice, virtGPUVendorID)),
	})
	pciDir := dir(map[string]kernfs.Inode{
		"vendor":           file(fmt.Sprintf("0x%04x\n", virtGPUVendorID)),
		"device":           file(fmt.Sprintf("0x%04x\n", virtGPUDeviceID)),
		"subsystem_vendor": file(fmt.Sprintf("0x%04x\n", virtGPUSubVendorID)),
		"subsystem_device": file(fmt.Sprintf("0x%04x\n", virtGPUSubDeviceID)),
		"revision":         file(fmt.Sprintf("0x%02x\n", virtGPURevision)),
		"class":            file(fmt.Sprintf("0x%06x\n", virtGPUClass)),
		"config":           file(virtGPUPCIConfig()),
		"subsystem":        link("../../../bus/pci"),
		"uevent": file(fmt.Sprintf("DRIVER=virtio-pci\nPCI_CLASS=%X\nPCI_ID=%04X:%04X\nPCI_SUBSYS_ID=%04X:%04X\nPCI_SLOT_NAME=%s\nMODALIAS=pci:v%08Xd%08Xsv%08Xsd%08Xbc%02Xsc%02Xi%02X\n",
			virtGPUClass, virtGPUVendorID, virtGPUDeviceID, virtGPUSubVendorID, virtGPUSubDeviceID, virtGPUPCISlot,
			virtGPUVendorID, virtGPUDeviceID, virtGPUSubVendorID, virtGPUSubDeviceID,
			virtGPUBaseClass, virtGPUSubClass, virtGPUProgIF)),
		virtGPUVirtioName: virtioDir,
	})

	return virtGPUDirs{
		devices: map[string]kernfs.Inode{
			virtGPUPCIRoot: dir(map[string]kernfs.Inode{virtGPUPCISlot: pciDir}),
		},
		busPCI: map[string]kernfs.Inode{
			virtGPUPCISlot: link(fmt.Sprintf("../../../devices/%s/%s", virtGPUPCIRoot, virtGPUPCISlot)),
		},
		busVirtio: map[string]kernfs.Inode{
			"devices": dir(map[string]kernfs.Inode{
				virtGPUVirtioName: link(fmt.Sprintf("../../../devices/%s/%s/%s", virtGPUPCIRoot, virtGPUPCISlot, virtGPUVirtioName)),
			}),
		},
		class: map[string]kernfs.Inode{
			"drm": dir(map[string]kernfs.Inode{
				node:      link("../../" + nodePath),
				"version": file(drmClassVersion),
			}),
		},
		devChar: map[string]kernfs.Inode{
			devNum: link("../../" + nodePath),
		},
	}
}

// addVirtGPUXplat adds the sysfs entries of the render node g to the
// directory maps of GetFilesystem. A nil g adds nothing.
func (fs *filesystem) addVirtGPUXplat(ctx context.Context, creds *auth.Credentials, g *VirtGPUSysfs, classSub, devicesSub, busSub, pciDevices, charSub map[string]kernfs.Inode) error {
	if g == nil {
		return nil
	}
	if g.DevMajor == 0 || g.DevMinor == 0 {
		return fmt.Errorf("virtual GPU render node needs non-zero major and minor numbers, got %d:%d", g.DevMajor, g.DevMinor)
	}
	if err := virtGPUCollision(g, classSub, devicesSub, busSub, pciDevices, charSub); err != nil {
		return err
	}
	d := fs.newVirtGPUSysfs(ctx, creds, g)
	for _, m := range []struct{ dst, src map[string]kernfs.Inode }{
		{devicesSub, d.devices}, {pciDevices, d.busPCI}, {classSub, d.class}, {charSub, d.devChar},
	} {
		for name, inode := range m.src {
			m.dst[name] = inode
		}
	}
	busSub["virtio"] = fs.newDir(ctx, creds, defaultSysDirMode, d.busVirtio)
	return nil
}

// virtGPUCollision returns an error when another source already populated an
// entry that the render node g needs. Two sealed kernfs subtrees cannot merge,
// so GetFilesystem refuses the mount instead of hiding one of them.
func virtGPUCollision(g *VirtGPUSysfs, classSub, devicesSub, busSub, pciDevices, charSub map[string]kernfs.Inode) error {
	for _, e := range []struct {
		parent string
		dst    map[string]kernfs.Inode
		name   string
	}{
		{"/sys/devices", devicesSub, virtGPUPCIRoot},
		{"/sys/bus/pci/devices", pciDevices, virtGPUPCISlot},
		{"/sys/bus", busSub, "virtio"},
		{"/sys/class", classSub, "drm"},
		{"/sys/dev/char", charSub, fmt.Sprintf("%d:%d", g.DevMajor, g.DevMinor)},
	} {
		if _, ok := e.dst[e.name]; ok {
			return fmt.Errorf("virtual GPU and another source both populate %s/%s", e.parent, e.name)
		}
	}
	return nil
}
