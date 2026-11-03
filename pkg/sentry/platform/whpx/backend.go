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

package whpx

import (
	"encoding/binary"
	"errors"
	"unsafe"
)

// ErrUnsupported reports that the host cannot run the WHPX backend. New wraps
// it with the reason: a non-Windows host, a missing hypervisor, or a Windows
// build without the required arm64 support.
var ErrUnsupported = errors.New("whpx: Windows Hypervisor Platform is not available")

// backend is the narrow surface of WinHvPlatform.dll that the platform uses.
// The Windows implementation calls the DLL. Tests substitute a scripted
// implementation, so the logic above this seam runs on every host.
type backend interface {
	// features returns the capability bits that gate startup.
	features() (hostFeatures, error)

	// createPartition creates, configures and sets up the partition. It
	// returns the partition-wide facts that guest bring-up needs.
	createPartition(cfg partitionConfig) (partitionInfo, error)

	// closePartition deletes the partition. All virtual processors must be
	// deleted first.
	closePartition() error

	// allocHost returns zeroed, committed host memory aligned to 64 KiB. The
	// size must be a multiple of the page size.
	allocHost(size uintptr) ([]byte, error)

	// freeHost releases memory from allocHost.
	freeHost(mem []byte) error

	// mapGPA maps size bytes of host memory at host into the guest physical
	// space at gpa. The range must not overlap an existing mapping. No caller
	// replaces a mapping.
	mapGPA(host unsafe.Pointer, gpa, size uint64, flags uint32) error

	// unmapGPA removes the mapping that a call of mapGPA made at gpa. The
	// size must equal the size of that call.
	unmapGPA(gpa, size uint64) error

	createVP(index uint32) error
	deleteVP(index uint32) error

	// run enters the virtual processor and fills exit with the exit context.
	run(index uint32, exit []byte) error

	// cancel asks a running virtual processor to leave run. A cancel that
	// arrives while the processor is not running ends the next run.
	cancel(index uint32) error

	// flushProcessWriteBuffers makes every thread of the Sentry process pass a
	// memory barrier. The threads that run Sentry code need it, because they
	// access guest memory for system calls in progress.
	flushProcessWriteBuffers()

	getRegs(index uint32, b *regBatch) error
	setRegs(index uint32, b *regBatch) error

	// getXsave reads the compacted XSAVE state of an amd64 processor into buf
	// and returns its size. A buffer that is too small returns
	// errXsaveBufferSmall with the required size.
	getXsave(index uint32, buf []byte) (int, error)

	// setXsave loads a compacted XSAVE state into an amd64 processor.
	setXsave(index uint32, buf []byte) error
}

// errXsaveBufferSmall reports that getXsave needs a larger buffer.
var errXsaveBufferSmall = errors.New("whpx: XSAVE state buffer is too small")

// hostFeatures lists the capability facts that gate startup.
type hostFeatures struct {
	hypervisorPresent bool
	arm64Support      bool
	windowsBuild      uint32
	windowsUBR        uint32

	// xsaveFeatures is the WHV_PROCESSOR_XSAVE_FEATURES capability of an
	// amd64 host.
	xsaveFeatures uint64
}

// partitionConfig lists the properties that createPartition sets before
// WHvSetupPartition.
type partitionConfig struct {
	vpCount uint32

	// xsaveFeatures is the ProcessorXsaveFeatures property of an amd64
	// partition.
	xsaveFeatures uint64

	// clearProcFeatures lists the ProcessorFeatures bits that an amd64
	// partition hides from its guests.
	clearProcFeatures uint64
}

// partitionInfo describes a created partition.
type partitionInfo struct {
	vpCount uint32

	// xsaveFeatures is the ProcessorXsaveFeatures property that an amd64
	// partition reports after setup.
	xsaveFeatures uint64
}

// regBatch holds the names and 16-byte values of one register call.
//
// WHV_REGISTER_VALUE is 16-byte aligned, so the values live in one aligned
// buffer that the call can use directly.
type regBatch struct {
	names []uint32
	raw   []byte
	n     int
}

func newRegBatch(capacity int) *regBatch {
	buf := make([]byte, capacity*regValueSize+regValueSize)
	off := 0
	if rem := uintptr(unsafe.Pointer(&buf[0])) & (regValueSize - 1); rem != 0 {
		off = int(regValueSize - rem)
	}
	return &regBatch{
		names: make([]uint32, capacity),
		raw:   buf[off : off+capacity*regValueSize],
	}
}

func (b *regBatch) reset() { b.n = 0 }

func (b *regBatch) slot(name uint32) []byte {
	if b.n >= len(b.names) {
		panic("whpx: register batch overflow")
	}
	i := b.n
	b.n++
	b.names[i] = name
	v := b.raw[i*regValueSize : (i+1)*regValueSize]
	clear(v)
	return v
}

// want appends a register to read. The value area is zeroed.
func (b *regBatch) want(name uint32) { b.slot(name) }

// add64 appends a 64-bit register value.
func (b *regBatch) add64(name uint32, v uint64) {
	binary.LittleEndian.PutUint64(b.slot(name), v)
}

// add128 appends a 128-bit register value.
func (b *regBatch) add128(name uint32, lo, hi uint64) {
	s := b.slot(name)
	binary.LittleEndian.PutUint64(s[0:8], lo)
	binary.LittleEndian.PutUint64(s[8:16], hi)
}

// addSegment appends a WHV_X64_SEGMENT_REGISTER value.
func (b *regBatch) addSegment(name uint32, seg segmentValue) {
	s := b.slot(name)
	binary.LittleEndian.PutUint64(s[segOffBase:], seg.base)
	binary.LittleEndian.PutUint32(s[segOffLimit:], seg.limit)
	binary.LittleEndian.PutUint16(s[segOffSelector:], seg.selector)
	binary.LittleEndian.PutUint16(s[segOffAttr:], seg.attr)
}

// addTable appends a WHV_X64_TABLE_REGISTER value.
func (b *regBatch) addTable(name uint32, base uint64, limit uint16) {
	s := b.slot(name)
	binary.LittleEndian.PutUint16(s[tblOffLimit:], limit)
	binary.LittleEndian.PutUint64(s[tblOffBase:], base)
}

// u64 returns the low 64 bits of value i.
func (b *regBatch) u64(i int) uint64 {
	return binary.LittleEndian.Uint64(b.raw[i*regValueSize:])
}

// u128 returns both halves of value i.
func (b *regBatch) u128(i int) (lo, hi uint64) {
	return binary.LittleEndian.Uint64(b.raw[i*regValueSize:]), binary.LittleEndian.Uint64(b.raw[i*regValueSize+8:])
}

// segment returns value i as a segment register.
func (b *regBatch) segment(i int) segmentValue {
	s := b.raw[i*regValueSize : (i+1)*regValueSize]
	return segmentValue{
		base:     binary.LittleEndian.Uint64(s[segOffBase:]),
		limit:    binary.LittleEndian.Uint32(s[segOffLimit:]),
		selector: binary.LittleEndian.Uint16(s[segOffSelector:]),
		attr:     binary.LittleEndian.Uint16(s[segOffAttr:]),
	}
}

// view returns the names and the raw values of the first n registers.
func (b *regBatch) view() (names []uint32, vals []byte) {
	return b.names[:b.n], b.raw[:b.n*regValueSize]
}

// segmentValue mirrors WHV_X64_SEGMENT_REGISTER.
type segmentValue struct {
	base     uint64
	limit    uint32
	selector uint16
	attr     uint16
}
