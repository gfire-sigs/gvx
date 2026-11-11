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

package blockdev

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"weak"

	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/sync"
)

const (
	// Major is the block major of the disks. Linux gives virtio disks a
	// dynamic major and uses 254 or 253 on most systems.
	Major = 254
	// partitionBits is the number of minor bits that a disk keeps for its
	// partitions. A virtio disk uses 4 bits, so vda is 254:0 and vdb is 254:16.
	partitionBits = 4
	// maxDisks is the number of disks that fit in the 20 bits of a minor.
	maxDisks = 1 << (20 - partitionBits)
	// registryDeviceMinor is the internal minor number used to anchor a
	// Registry in vfs.VirtualFilesystem's saved device map without exposing a
	// /dev node or /proc/devices entry.
	registryDeviceMinor = ^uint32(0)
)

// ErrFull is the error of Registry.Add when all disk names are in use.
var ErrFull = errors.New("blockdev: no free disk name")

// SectorsHandlerID identifies a registered sector-capacity callback across
// checkpoint and restore. Zero selects the static capacity stored on Device.
//
// +stateify savable
type SectorsHandlerID uint32

const (
	// SectorsStatic selects the fixed sector capacity stored on Device.
	SectorsStatic SectorsHandlerID = 0
)

var sectorsHandlers struct {
	mu sync.RWMutex
	m  map[SectorsHandlerID]func(*Device) uint64
}

// RegisterSectorsHandler binds id to fn so restored Device instances resolve
// dynamic capacity without storing closures in state graphs.
func RegisterSectorsHandler(id SectorsHandlerID, fn func(*Device) uint64) {
	if id == SectorsStatic {
		panic("blockdev: cannot register SectorsStatic handler ID 0")
	}
	if fn == nil {
		panic("blockdev: nil sectors handler")
	}
	sectorsHandlers.mu.Lock()
	defer sectorsHandlers.mu.Unlock()
	if sectorsHandlers.m == nil {
		sectorsHandlers.m = make(map[SectorsHandlerID]func(*Device) uint64)
	}
	sectorsHandlers.m[id] = fn
}

func lookupSectorsHandler(id SectorsHandlerID) func(*Device) uint64 {
	sectorsHandlers.mu.RLock()
	defer sectorsHandlers.mu.RUnlock()
	return sectorsHandlers.m[id]
}

// Device is a disk. Its name and numbers never change. The disk exists from
// Registry.Add to Registry.Remove.
//
// +stateify savable
type Device struct {
	// Name is the kernel name of the disk, such as vda.
	Name string
	// Major and Minor are the device numbers of the disk. The files of the
	// file system on the disk report them as st_dev.
	Major, Minor uint32
	// ReadOnly is true for a disk that the Sentry never writes.
	ReadOnly bool
	// Stats holds the counters of the disk.
	Stats *Stats

	index          int
	sectors        uint64
	sectorsHandler SectorsHandlerID
}

// Sectors returns the capacity of the disk in sectors of 512 bytes.
func (d *Device) Sectors() uint64 {
	if d.sectorsHandler != SectorsStatic {
		if fn := lookupSectorsHandler(d.sectorsHandler); fn != nil {
			return fn(d)
		}
	}
	return d.sectors
}

// SetSectors updates the static sector count and handler ID of d.
func (d *Device) SetSectors(sectors uint64, handler SectorsHandlerID) {
	d.sectors = sectors
	d.sectorsHandler = handler
}

// Options describe a disk for Registry.Add.
type Options struct {
	// Stats holds the counters. The owner of the host file that the disk
	// stands for does the counting.
	Stats *Stats
	// SectorsCount sets the static capacity in sectors of 512 bytes.
	SectorsCount uint64
	// SectorsHandler selects a registered capacity callback across save and
	// restore. Leave zero to report SectorsCount.
	SectorsHandler SectorsHandlerID
	// Sectors computes the initial static capacity when SectorsCount and
	// SectorsHandler are zero. Registry.Add evaluates it once and stores only
	// the resulting sector count on Device.
	Sectors func() uint64
	// ReadOnly marks a disk that the Sentry never writes.
	ReadOnly bool
}

// Registry lists the disks of one kernel.
//
// +stateify savable
type Registry struct {
	mu  sync.Mutex `state:"nosave"`
	vfs *vfs.VirtualFilesystem
	// devices is sorted by index.
	devices []*Device
}

// Open implements vfs.Device.Open so Registry can be anchored in
// vfs.VirtualFilesystem's saved device map without exposing a /dev node.
func (*Registry) Open(gvcontext.Context, *vfs.Mount, *vfs.Dentry, vfs.OpenOptions) (*vfs.FileDescription, error) {
	return nil, linuxerr.ENXIO
}

func (r *Registry) afterLoad(context.Context) {
	if r.vfs != nil {
		Bind(r.vfs, r)
	}
}

func attachToVFS(v *vfs.VirtualFilesystem, r *Registry) {
	if v == nil || r == nil {
		return
	}
	r.vfs = v
	defer func() { _ = recover() }()
	if !v.IsDeviceRegistered(vfs.BlockDevice, Major, registryDeviceMinor) {
		_ = v.RegisterDevice(vfs.BlockDevice, Major, registryDeviceMinor, r, &vfs.RegisterDeviceOptions{})
	}
}

// diskName returns the name of the virtio disk with the given index. It
// follows virtblk_name_format of Linux: vda to vdz, then vdaa, vdab, and so on.
func diskName(index int) string {
	var letters []byte
	for n := index; n >= 0; n = n/26 - 1 {
		letters = append(letters, byte('a'+n%26))
	}
	slices.Reverse(letters)
	return "vd" + string(letters)
}

// Add creates a disk with the lowest free index. The first disk is vda.
func (r *Registry) Add(opts Options) (*Device, error) {
	attachToVFS(r.vfs, r)
	r.mu.Lock()
	defer r.mu.Unlock()
	index := 0
	for _, d := range r.devices {
		if d.index != index {
			break
		}
		index++
	}
	if index >= maxDisks {
		return nil, ErrFull
	}
	sectors := opts.SectorsCount
	if sectors == 0 && opts.SectorsHandler == SectorsStatic && opts.Sectors != nil {
		sectors = opts.Sectors()
	}
	d := &Device{
		Name:           diskName(index),
		Major:          Major,
		Minor:          uint32(index << partitionBits),
		ReadOnly:       opts.ReadOnly,
		Stats:          opts.Stats,
		index:          index,
		sectors:        sectors,
		sectorsHandler: opts.SectorsHandler,
	}
	r.devices = append(r.devices, d)
	slices.SortFunc(r.devices, func(a, b *Device) int { return a.index - b.index })
	return d, nil
}

// Remove deletes the disk d. A second call has no effect.
func (r *Registry) Remove(d *Device) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.devices = slices.DeleteFunc(r.devices, func(o *Device) bool { return o == d })
}

// Devices returns the disks in the order of their device numbers.
func (r *Registry) Devices() []*Device {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.devices)
}

// Find returns the disk with the name, or nil.
func (r *Registry) Find(name string) *Device {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.devices {
		if d.Name == name {
			return d
		}
	}
	return nil
}

// registries holds the registry of each VFS. The map holds the VFS objects
// weakly, so a VFS that a test drops frees its entry.
var registries struct {
	mu sync.Mutex
	m  map[weak.Pointer[vfs.VirtualFilesystem]]*Registry
}

// Of returns the registry of the VFS v. Every file system of a kernel shares
// the registry of the VFS of that kernel.
func Of(v *vfs.VirtualFilesystem) *Registry {
	key := weak.Make(v)
	registries.mu.Lock()
	if r, ok := registries.m[key]; ok {
		registries.mu.Unlock()
		attachToVFS(v, r)
		return r
	}
	if registries.m == nil {
		registries.m = make(map[weak.Pointer[vfs.VirtualFilesystem]]*Registry)
	}
	r := &Registry{vfs: v}
	registries.m[key] = r
	runtime.AddCleanup(v, func(key weak.Pointer[vfs.VirtualFilesystem]) {
		registries.mu.Lock()
		defer registries.mu.Unlock()
		delete(registries.m, key)
	}, key)
	registries.mu.Unlock()
	attachToVFS(v, r)
	return r
}

// Bind associates r with v so subsequent Of(v) calls return r. Restore paths
// call Bind after loading a saved Registry for a restored VirtualFilesystem.
func Bind(v *vfs.VirtualFilesystem, r *Registry) {
	if v == nil || r == nil {
		return
	}
	key := weak.Make(v)
	registries.mu.Lock()
	if registries.m == nil {
		registries.m = make(map[weak.Pointer[vfs.VirtualFilesystem]]*Registry)
	}
	_, existed := registries.m[key]
	registries.m[key] = r
	if !existed {
		runtime.AddCleanup(v, func(key weak.Pointer[vfs.VirtualFilesystem]) {
			registries.mu.Lock()
			defer registries.mu.Unlock()
			delete(registries.m, key)
		}, key)
	}
	registries.mu.Unlock()
	attachToVFS(v, r)
}
