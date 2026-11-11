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

package hvf

import (
	"errors"

	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

var (
	errPlatformClosed = errors.New("hvf: platform closed")
	// errHostBlockRejected reports that Hypervisor.framework refused a host
	// memory region. It wraps the framework error.
	errHostBlockRejected = errors.New("hvf: hv_vm_map rejected the host memory")
	errIPAExhausted      = errors.New("hvf: guest physical address space exhausted")
)

// stage2Backend is the call boundary to the hypervisor and to the host memory
// that backs private copies. Tests replace it to count Stage-2 calls.
type stage2Backend interface {
	// mapHost maps size bytes of host memory at ipa with read, write and
	// execute permission. Host address and size are multiples of the host page.
	mapHost(host uintptr, ipa uint64, size uintptr) error
	// unmapIPA removes the mapping that mapHost created at ipa.
	unmapIPA(ipa uint64, size uintptr) error
	// refusedMemory reports whether err means that the hypervisor refuses
	// this host memory for any request, so a private copy can replace it.
	refusedMemory(err error) bool
	// allocCopy returns zeroed host memory for a private copy.
	allocCopy(size uintptr) ([]byte, error)
	// freeCopy returns memory from allocCopy.
	freeCopy(mem []byte) error
}

type stage2Adapter struct {
	be stage2Backend
}

func (a stage2Adapter) MapHost(host uintptr, gpa uint64, size uintptr, _ bool) error {
	return a.be.mapHost(host, gpa, size)
}

func (a stage2Adapter) UnmapGPA(gpa uint64, size uintptr) error {
	return a.be.unmapIPA(gpa, size)
}

func (a stage2Adapter) RefusedMemory(err error) bool {
	return a.be.refusedMemory(err)
}

func (a stage2Adapter) AllocCopy(size uintptr) ([]byte, error) {
	return a.be.allocCopy(size)
}

func (a stage2Adapter) FreeCopy(mem []byte) error {
	return a.be.freeCopy(mem)
}

// segment is a run of contiguous guest physical memory.
type segment = hvcommon.GPARun

// regionUser is the set of regions that one address space uses.
type regionUser = hvcommon.RegionUser

// regionMap assigns guest physical addresses to host memory and keeps the
// Stage-2 mappings through hvcommon.RegionMap.
type regionMap struct {
	inner *hvcommon.RegionMap
}

func newRegionMap(be stage2Backend, granule uintptr, base, limit uint64) *regionMap {
	return &regionMap{
		inner: hvcommon.NewRegionMap(stage2Adapter{be: be}, hvcommon.RegionMapConfig{
			Granule:      granule,
			Base:         base,
			Limit:        limit,
			LogPrefix:    "hvf",
			ErrClosed:    errPlatformClosed,
			ErrExhausted: errIPAExhausted,
			ErrRejected:  errHostBlockRejected,
		}),
	}
}

func (m *regionMap) setBackend(be stage2Backend) {
	m.inner.SetBackend(stage2Adapter{be: be})
}

func (m *regionMap) resolve(u *regionUser, f memmap.File, bs safemem.BlockSeq, write bool) ([]segment, error) {
	return m.inner.Resolve(u, f, bs, write)
}

func (m *regionMap) release(u *regionUser) {
	m.inner.Release(u)
}

func (m *regionMap) markClosed() {
	m.inner.MarkClosed()
}

func (m *regionMap) freeAfterDestroy() {
	m.inner.FreeAfterDestroy()
}

func (m *regionMap) regionCount() int {
	return m.inner.RegionCount()
}

func (m *regionMap) copyCount() int {
	return m.inner.CopyCount()
}
