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
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestSlotAllocatorAssignsUniquePCISlotsAndVirtioIndices(t *testing.T) {
	alloc := NewSlotAllocator()
	slot1, err := alloc.AllocatePCISlot()
	if err != nil {
		t.Fatalf("first AllocatePCISlot: %v", err)
	}
	slot2, err := alloc.AllocatePCISlot()
	if err != nil {
		t.Fatalf("second AllocatePCISlot: %v", err)
	}
	if slot1 != "0000:00:01.0" || slot2 != "0000:00:02.0" {
		t.Fatalf("slots = (%q, %q), want (0000:00:01.0, 0000:00:02.0)", slot1, slot2)
	}
	if got := alloc.AllocateVirtioIndex(); got != "virtio0" {
		t.Fatalf("first AllocateVirtioIndex = %q, want virtio0", got)
	}
	if got := alloc.AllocateVirtioIndex(); got != "virtio1" {
		t.Fatalf("second AllocateVirtioIndex = %q, want virtio1", got)
	}

	// Exhaust remaining 29 slots (3..31).
	for i := 3; i <= 31; i++ {
		if _, err := alloc.AllocatePCISlot(); err != nil {
			t.Fatalf("AllocatePCISlot(%d): %v", i, err)
		}
	}
	if _, err := alloc.AllocatePCISlot(); !errors.Is(err, ErrTopologyConflict) {
		t.Fatalf("32nd AllocatePCISlot err = %v, want ErrTopologyConflict", err)
	}
}

func TestVirtioPCIDeviceTopologyMergesTwoDevicesAndEncodesPCIConfig(t *testing.T) {
	alloc := NewSlotAllocator()
	slot1, err := alloc.AllocatePCISlot()
	if err != nil {
		t.Fatalf("AllocatePCISlot 1: %v", err)
	}
	slot2, err := alloc.AllocatePCISlot()
	if err != nil {
		t.Fatalf("AllocatePCISlot 2: %v", err)
	}

	top1, err := VirtioPCIDeviceTopology(VirtioPCIDeviceSpec{
		PCISlot:     slot1,
		VirtioName:  alloc.AllocateVirtioIndex(),
		VendorID:    0x1af4,
		DeviceID:    0x1050,
		SubVendorID: 0x1af4,
		SubDeviceID: 0x1100,
		ClassCode:   0x038000,
		ClassName:   "drm",
		NodeName:    "renderD128",
		Major:       226,
		Minor:       128,
	})
	if err != nil {
		t.Fatalf("VirtioPCIDeviceTopology 1: %v", err)
	}
	top2, err := VirtioPCIDeviceTopology(VirtioPCIDeviceSpec{
		PCISlot:     slot2,
		VirtioName:  alloc.AllocateVirtioIndex(),
		VendorID:    0x1af4,
		DeviceID:    0x1059,
		SubVendorID: 0x1af4,
		SubDeviceID: 0x1100,
		ClassCode:   0x040100,
		ClassName:   "drm",
		NodeName:    "renderD129",
		Major:       226,
		Minor:       129,
	})
	if err != nil {
		t.Fatalf("VirtioPCIDeviceTopology 2: %v", err)
	}

	merged, err := mergeTopologyAdditions([]TopologyAddition{top1, top2})
	if err != nil {
		t.Fatalf("mergeTopologyAdditions: %v", err)
	}
	// Shared pci0000:00 directory must hold both PCI slots.
	pciBus := merged.devices["pci0000:00"]
	if pciBus == nil || len(pciBus.children) != 2 {
		t.Fatalf("pci0000:00 children = %v, want 2 slots", pciBus)
	}
	// Shared class/drm directory must hold both render nodes.
	drmClass := merged.class["drm"]
	if drmClass == nil || len(drmClass.children) != 2 {
		t.Fatalf("class/drm children = %v, want 2 nodes", drmClass)
	}
	// dev/char must hold both 226:128 and 226:129.
	if len(merged.devChar) != 2 || merged.devChar["226:128"] == nil || merged.devChar["226:129"] == nil {
		t.Fatalf("devChar = %v, want 226:128 and 226:129", merged.devChar)
	}

	// Verify 64-byte binary PCI config header payload.
	cfgNode := pciBus.children[slot1].children["config"]
	if cfgNode == nil || cfgNode.kind != NodeBinaryFile {
		t.Fatalf("config node = %+v, want NodeBinaryFile", cfgNode)
	}
	if len(cfgNode.binary) != 64 {
		t.Fatalf("PCI config len = %d, want 64", len(cfgNode.binary))
	}
	if got := binary.LittleEndian.Uint16(cfgNode.binary[0:2]); got != 0x1af4 {
		t.Fatalf("PCI vendor = %#x, want 0x1af4", got)
	}
	if got := binary.LittleEndian.Uint16(cfgNode.binary[2:4]); got != 0x1050 {
		t.Fatalf("PCI device = %#x, want 0x1050", got)
	}
	if got := cfgNode.binary[0x09:0x0c]; !bytes.Equal(got, []byte{0x00, 0x80, 0x03}) {
		t.Fatalf("PCI class bytes = %x, want 008003", got)
	}
}

func TestValidateTopologyAdditionsRejectsConflictsAndMalformedSpecs(t *testing.T) {
	t.Run("duplicate dev char", func(t *testing.T) {
		a := TopologyAddition{DevChar: []NodeSpec{{Name: "226:128", Kind: NodeSymlink, Target: "../../devices/a"}}}
		b := TopologyAddition{DevChar: []NodeSpec{{Name: "226:128", Kind: NodeSymlink, Target: "../../devices/b"}}}
		if err := ValidateTopologyAdditions([]TopologyAddition{a, b}); !errors.Is(err, ErrTopologyConflict) {
			t.Fatalf("err = %v, want ErrTopologyConflict", err)
		}
	})
	t.Run("dir vs file conflict", func(t *testing.T) {
		a := TopologyAddition{Class: []NodeSpec{{Name: "drm", Kind: NodeDir}}}
		b := TopologyAddition{Class: []NodeSpec{{Name: "drm", Kind: NodeFile, Content: "x"}}}
		if err := ValidateTopologyAdditions([]TopologyAddition{a, b}); !errors.Is(err, ErrTopologyConflict) {
			t.Fatalf("err = %v, want ErrTopologyConflict", err)
		}
	})
	t.Run("absolute symlink rejected", func(t *testing.T) {
		a := TopologyAddition{DevChar: []NodeSpec{{Name: "226:128", Kind: NodeSymlink, Target: "/etc/passwd"}}}
		if err := ValidateTopologyAdditions([]TopologyAddition{a}); !errors.Is(err, ErrInvalidTopology) {
			t.Fatalf("err = %v, want ErrInvalidTopology", err)
		}
	})
	t.Run("slash in node name rejected", func(t *testing.T) {
		a := TopologyAddition{Class: []NodeSpec{{Name: "drm/renderD128", Kind: NodeFile, Content: "x"}}}
		if err := ValidateTopologyAdditions([]TopologyAddition{a}); !errors.Is(err, ErrInvalidTopology) {
			t.Fatalf("err = %v, want ErrInvalidTopology", err)
		}
	})
}
