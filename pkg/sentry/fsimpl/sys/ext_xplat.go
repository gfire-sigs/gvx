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
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/kernfs"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
)

// ErrTopologyConflict reports a duplicate or invalid sysfs path across
// registered extension topologies.
var ErrTopologyConflict = errors.New("sysfs: topology path conflict")

// ErrInvalidTopology reports a malformed declarative sysfs node specification.
var ErrInvalidTopology = errors.New("sysfs: invalid topology specification")

// NodeKind selects the inode kind of one declarative sysfs entry.
type NodeKind int

const (
	// NodeDir creates a static directory (or merges with a shared directory).
	NodeDir NodeKind = iota + 1
	// NodeFile creates a static UTF-8 text file.
	NodeFile
	// NodeBinaryFile creates a static binary file (for example PCI config space).
	NodeBinaryFile
	// NodeSymlink creates a static relative symbolic link.
	NodeSymlink
)

// NodeSpec describes one static file, binary file, symlink, or directory in a
// declarative sysfs subtree.
type NodeSpec struct {
	Name     string
	Kind     NodeKind
	Mode     linux.FileMode
	Content  string
	Binary   []byte
	Target   string
	Children []NodeSpec
}

// TopologyAddition contributes declarative entries into standard sysfs
// subtrees (/sys/devices, /sys/class, /sys/bus/pci/devices,
// /sys/bus/pci/drivers, and /sys/dev/char).
type TopologyAddition struct {
	// Devices maps top-level names under /sys/devices (for example "pci0000:00").
	Devices []NodeSpec
	// Class maps subdirectories or entries under /sys/class (for example "drm").
	Class []NodeSpec
	// BusPCIDevices maps entries under /sys/bus/pci/devices.
	BusPCIDevices []NodeSpec
	// BusPCIDrivers maps entries under /sys/bus/pci/drivers.
	BusPCIDrivers []NodeSpec
	// DevChar maps entries under /sys/dev/char (for example "226:128").
	DevChar []NodeSpec
}

// SlotAllocator assigns deterministic, collision-free PCI slots and virtio
// device indices across extensions inside one sandbox.
type SlotAllocator struct {
	nextPCISlot uint8
	nextVirtio  uint32
}

// NewSlotAllocator returns a SlotAllocator starting at PCI slot 1 (0000:00:01.0)
// and virtio0.
func NewSlotAllocator() *SlotAllocator {
	return &SlotAllocator{nextPCISlot: 1}
}

// AllocatePCISlot reserves the next PCI slot on bus 0000:00 (slots 1..31).
func (a *SlotAllocator) AllocatePCISlot() (string, error) {
	if a.nextPCISlot == 0 || a.nextPCISlot > 31 {
		return "", fmt.Errorf("%w: PCI bus 0000:00 slots exhausted", ErrTopologyConflict)
	}
	slot := fmt.Sprintf("0000:00:%02x.0", a.nextPCISlot)
	a.nextPCISlot++
	return slot, nil
}

// AllocateVirtioIndex reserves the next virtio device name ("virtio0", ...).
func (a *SlotAllocator) AllocateVirtioIndex() string {
	name := fmt.Sprintf("virtio%d", a.nextVirtio)
	a.nextVirtio++
	return name
}

// VirtioPCIDeviceSpec describes one synthetic virtio-pci character device
// registered into sysfs via VirtioPCIDeviceTopology.
type VirtioPCIDeviceSpec struct {
	PCISlot     string
	VirtioName  string
	VendorID    uint16
	DeviceID    uint16
	SubVendorID uint16
	SubDeviceID uint16
	ClassCode   uint32 // 24-bit PCI class/subclass/prog-if
	ClassName   string // e.g. "drm"
	NodeName    string // e.g. "renderD128"
	Major       uint32
	Minor       uint32
	ExtraFiles  []NodeSpec
}

// VirtioPCIDeviceTopology builds a Linux-compatible PCI + virtio + class +
// dev/char topology for libdrm/libudev discovery without hardcoded slots.
func VirtioPCIDeviceTopology(spec VirtioPCIDeviceSpec) (TopologyAddition, error) {
	if err := validateNodeName(spec.PCISlot); err != nil {
		return TopologyAddition{}, fmt.Errorf("%w: PCI slot %q: %v", ErrInvalidTopology, spec.PCISlot, err)
	}
	if err := validateNodeName(spec.VirtioName); err != nil {
		return TopologyAddition{}, fmt.Errorf("%w: virtio name %q: %v", ErrInvalidTopology, spec.VirtioName, err)
	}
	if err := validateNodeName(spec.ClassName); err != nil {
		return TopologyAddition{}, fmt.Errorf("%w: class name %q: %v", ErrInvalidTopology, spec.ClassName, err)
	}
	if err := validateNodeName(spec.NodeName); err != nil {
		return TopologyAddition{}, fmt.Errorf("%w: node name %q: %v", ErrInvalidTopology, spec.NodeName, err)
	}

	cfgSpace := buildPCIConfigHeader(spec.VendorID, spec.DeviceID, spec.SubVendorID, spec.SubDeviceID, spec.ClassCode)
	devNum := fmt.Sprintf("%d:%d", spec.Major, spec.Minor)
	devNodeChildren := []NodeSpec{
		{Name: "dev", Kind: NodeFile, Content: devNum + "\n"},
		{Name: "uevent", Kind: NodeFile, Content: fmt.Sprintf("MAJOR=%d\nMINOR=%d\nDEVNAME=%s/%s\n", spec.Major, spec.Minor, spec.ClassName, spec.NodeName)},
		{Name: "device", Kind: NodeSymlink, Target: "../../../" + spec.PCISlot},
	}
	devNodeChildren = append(devNodeChildren, spec.ExtraFiles...)

	pciChildren := []NodeSpec{
		{Name: "vendor", Kind: NodeFile, Content: fmt.Sprintf("0x%04x\n", spec.VendorID)},
		{Name: "device", Kind: NodeFile, Content: fmt.Sprintf("0x%04x\n", spec.DeviceID)},
		{Name: "subsystem_vendor", Kind: NodeFile, Content: fmt.Sprintf("0x%04x\n", spec.SubVendorID)},
		{Name: "subsystem_device", Kind: NodeFile, Content: fmt.Sprintf("0x%04x\n", spec.SubDeviceID)},
		{Name: "class", Kind: NodeFile, Content: fmt.Sprintf("0x%06x\n", spec.ClassCode&0xffffff)},
		{Name: "config", Kind: NodeBinaryFile, Binary: cfgSpace},
		{Name: "uevent", Kind: NodeFile, Content: fmt.Sprintf("PCI_CLASS=%X\nPCI_ID=%04X:%04X\nPCI_SUBSYS_ID=%04X:%04X\nPCI_SLOT_NAME=%s\n",
			spec.ClassCode&0xffffff, spec.VendorID, spec.DeviceID, spec.SubVendorID, spec.SubDeviceID, spec.PCISlot)},
		{
			Name: spec.VirtioName,
			Kind: NodeDir,
			Children: []NodeSpec{
				{Name: "device", Kind: NodeSymlink, Target: "../" + spec.PCISlot},
				{
					Name: spec.ClassName,
					Kind: NodeDir,
					Children: []NodeSpec{
						{
							Name:     spec.NodeName,
							Kind:     NodeDir,
							Children: devNodeChildren,
						},
					},
				},
			},
		},
	}

	return TopologyAddition{
		Devices: []NodeSpec{
			{
				Name: "pci0000:00",
				Kind: NodeDir,
				Children: []NodeSpec{
					{
						Name:     spec.PCISlot,
						Kind:     NodeDir,
						Children: pciChildren,
					},
				},
			},
		},
		Class: []NodeSpec{
			{
				Name: spec.ClassName,
				Kind: NodeDir,
				Children: []NodeSpec{
					{
						Name:   spec.NodeName,
						Kind:   NodeSymlink,
						Target: fmt.Sprintf("../../devices/pci0000:00/%s/%s/%s/%s", spec.PCISlot, spec.VirtioName, spec.ClassName, spec.NodeName),
					},
				},
			},
		},
		BusPCIDevices: []NodeSpec{
			{
				Name:   spec.PCISlot,
				Kind:   NodeSymlink,
				Target: fmt.Sprintf("../../../devices/pci0000:00/%s", spec.PCISlot),
			},
		},
		DevChar: []NodeSpec{
			{
				Name:   devNum,
				Kind:   NodeSymlink,
				Target: fmt.Sprintf("../../devices/pci0000:00/%s/%s/%s/%s", spec.PCISlot, spec.VirtioName, spec.ClassName, spec.NodeName),
			},
		},
	}, nil
}

// buildPCIConfigHeader constructs a standard 64-byte Type 0 PCI configuration
// space header in little-endian byte order.
func buildPCIConfigHeader(vendorID, deviceID, subVendorID, subDeviceID uint16, classCode uint32) []byte {
	hdr := make([]byte, 64)
	binary.LittleEndian.PutUint16(hdr[0x00:0x02], vendorID)
	binary.LittleEndian.PutUint16(hdr[0x02:0x04], deviceID)
	hdr[0x09] = byte(classCode & 0xff)
	hdr[0x0a] = byte((classCode >> 8) & 0xff)
	hdr[0x0b] = byte((classCode >> 16) & 0xff)
	binary.LittleEndian.PutUint16(hdr[0x2c:0x2e], subVendorID)
	binary.LittleEndian.PutUint16(hdr[0x2e:0x30], subDeviceID)
	return hdr
}

type mergedNode struct {
	kind     NodeKind
	mode     linux.FileMode
	content  string
	binary   []byte
	target   string
	children map[string]*mergedNode
}

// ValidateTopologyAdditions verifies that all nodes in additions are well-formed
// and contain no conflicting leaf or directory-vs-file collisions. Callers
// should run this during Sandbox initialization before mounting sysfs.
func ValidateTopologyAdditions(additions []TopologyAddition) error {
	_, err := mergeTopologyAdditions(additions)
	return err
}

type mergedTopology struct {
	devices       map[string]*mergedNode
	class         map[string]*mergedNode
	busPCIDevices map[string]*mergedNode
	busPCIDrivers map[string]*mergedNode
	devChar       map[string]*mergedNode
}

func mergeTopologyAdditions(additions []TopologyAddition) (*mergedTopology, error) {
	mt := &mergedTopology{
		devices:       make(map[string]*mergedNode),
		class:         make(map[string]*mergedNode),
		busPCIDevices: make(map[string]*mergedNode),
		busPCIDrivers: make(map[string]*mergedNode),
		devChar:       make(map[string]*mergedNode),
	}
	for _, add := range additions {
		if err := mergeNodeSpecs(mt.devices, "/sys/devices", add.Devices); err != nil {
			return nil, err
		}
		if err := mergeNodeSpecs(mt.class, "/sys/class", add.Class); err != nil {
			return nil, err
		}
		if err := mergeNodeSpecs(mt.busPCIDevices, "/sys/bus/pci/devices", add.BusPCIDevices); err != nil {
			return nil, err
		}
		if err := mergeNodeSpecs(mt.busPCIDrivers, "/sys/bus/pci/drivers", add.BusPCIDrivers); err != nil {
			return nil, err
		}
		if err := mergeNodeSpecs(mt.devChar, "/sys/dev/char", add.DevChar); err != nil {
			return nil, err
		}
	}
	return mt, nil
}

func validateNodeName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return fmt.Errorf("invalid name %q", name)
	}
	return nil
}

func validateSymlinkTarget(target string) error {
	if target == "" || strings.ContainsRune(target, '\x00') || path.IsAbs(target) {
		return fmt.Errorf("symlink target %q must be a non-empty relative path without NUL", target)
	}
	return nil
}

func mergeNodeSpecs(dst map[string]*mergedNode, prefix string, specs []NodeSpec) error {
	for _, spec := range specs {
		if err := validateNodeName(spec.Name); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrInvalidTopology, prefix, err)
		}
		fullPath := prefix + "/" + spec.Name
		switch spec.Kind {
		case NodeDir:
			if existing, ok := dst[spec.Name]; ok {
				if existing.kind != NodeDir {
					return fmt.Errorf("%w: %s cannot merge directory with non-directory", ErrTopologyConflict, fullPath)
				}
				if err := mergeNodeSpecs(existing.children, fullPath, spec.Children); err != nil {
					return err
				}
				continue
			}
			node := &mergedNode{
				kind:     NodeDir,
				mode:     spec.Mode,
				children: make(map[string]*mergedNode),
			}
			if err := mergeNodeSpecs(node.children, fullPath, spec.Children); err != nil {
				return err
			}
			dst[spec.Name] = node
		case NodeFile:
			if len(spec.Children) > 0 {
				return fmt.Errorf("%w: %s file cannot have children", ErrInvalidTopology, fullPath)
			}
			if _, exists := dst[spec.Name]; exists {
				return fmt.Errorf("%w: duplicate entry %s", ErrTopologyConflict, fullPath)
			}
			dst[spec.Name] = &mergedNode{
				kind:    NodeFile,
				mode:    spec.Mode,
				content: spec.Content,
			}
		case NodeBinaryFile:
			if len(spec.Children) > 0 {
				return fmt.Errorf("%w: %s binary file cannot have children", ErrInvalidTopology, fullPath)
			}
			if _, exists := dst[spec.Name]; exists {
				return fmt.Errorf("%w: duplicate entry %s", ErrTopologyConflict, fullPath)
			}
			dst[spec.Name] = &mergedNode{
				kind:   NodeBinaryFile,
				mode:   spec.Mode,
				binary: slices.Clone(spec.Binary),
			}
		case NodeSymlink:
			if len(spec.Children) > 0 {
				return fmt.Errorf("%w: %s symlink cannot have children", ErrInvalidTopology, fullPath)
			}
			if err := validateSymlinkTarget(spec.Target); err != nil {
				return fmt.Errorf("%w: %s: %v", ErrInvalidTopology, fullPath, err)
			}
			if _, exists := dst[spec.Name]; exists {
				return fmt.Errorf("%w: duplicate entry %s", ErrTopologyConflict, fullPath)
			}
			dst[spec.Name] = &mergedNode{
				kind:   NodeSymlink,
				target: spec.Target,
			}
		default:
			return fmt.Errorf("%w: %s has unsupported node kind %d", ErrInvalidTopology, fullPath, spec.Kind)
		}
	}
	return nil
}

func (fs *filesystem) applyTopologies(
	ctx context.Context,
	creds *auth.Credentials,
	additions []TopologyAddition,
	devicesSub, classSub, pciDevices, pciDrivers, charSub map[string]kernfs.Inode,
) error {
	mt, err := mergeTopologyAdditions(additions)
	if err != nil {
		return err
	}
	if err := fs.mountMergedTree(ctx, creds, "/sys/devices", devicesSub, mt.devices); err != nil {
		return err
	}
	if err := fs.mountMergedTree(ctx, creds, "/sys/class", classSub, mt.class); err != nil {
		return err
	}
	if err := fs.mountMergedTree(ctx, creds, "/sys/bus/pci/devices", pciDevices, mt.busPCIDevices); err != nil {
		return err
	}
	if err := fs.mountMergedTree(ctx, creds, "/sys/bus/pci/drivers", pciDrivers, mt.busPCIDrivers); err != nil {
		return err
	}
	if err := fs.mountMergedTree(ctx, creds, "/sys/dev/char", charSub, mt.devChar); err != nil {
		return err
	}
	return nil
}

func (fs *filesystem) mountMergedTree(ctx context.Context, creds *auth.Credentials, prefix string, target map[string]kernfs.Inode, nodes map[string]*mergedNode) error {
	names := make([]string, 0, len(nodes))
	for name := range nodes {
		names = append(names, name)
	}
	slices.Sort(names)

	for _, name := range names {
		node := nodes[name]
		fullPath := prefix + "/" + name
		if _, exists := target[name]; exists {
			return fmt.Errorf("%w: %s collides with an existing sysfs entry", ErrTopologyConflict, fullPath)
		}
		target[name] = fs.buildMergedInode(ctx, creds, node)
	}
	return nil
}

func (fs *filesystem) buildMergedInode(ctx context.Context, creds *auth.Credentials, node *mergedNode) kernfs.Inode {
	switch node.kind {
	case NodeDir:
		mode := node.mode
		if mode == 0 {
			mode = defaultSysDirMode
		}
		children := make(map[string]kernfs.Inode, len(node.children))
		names := make([]string, 0, len(node.children))
		for name := range node.children {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			children[name] = fs.buildMergedInode(ctx, creds, node.children[name])
		}
		return fs.newDir(ctx, creds, mode, children)
	case NodeFile:
		mode := node.mode
		if mode == 0 {
			mode = defaultSysMode
		}
		return fs.newStaticFile(ctx, creds, mode, node.content)
	case NodeBinaryFile:
		mode := node.mode
		if mode == 0 {
			mode = defaultSysMode
		}
		return fs.newStaticFile(ctx, creds, mode, string(node.binary))
	case NodeSymlink:
		return kernfs.NewStaticSymlink(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), node.target)
	default:
		return fs.newStaticFile(ctx, creds, defaultSysMode, "")
	}
}
