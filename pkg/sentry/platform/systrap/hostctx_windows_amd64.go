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

//go:build windows && amd64

package systrap

import (
	"encoding/binary"
	"sync"
	"unsafe"
)

// The vector registers above the first 128 bits are the extended state of the
// thread. A plain CONTEXT record has no room for them. A record that
// InitializeContext allocated with CONTEXT_XSTATE has an XSAVE area behind the
// CONTEXT structure, and LocateXStateFeature finds each component in it.
//
// WHY: a signal handler of the guest can use AVX registers. The Sentry saves
// the interrupted state in the signal frame and restores it at sigreturn.
// Without the extended state, sigreturn would write zeros into the upper
// halves of the vector registers of the interrupted code.

var (
	procInitializeContext        = modKernel32.NewProc("InitializeContext")
	procSetXStateFeaturesMask    = modKernel32.NewProc("SetXStateFeaturesMask")
	procGetXStateFeaturesMask    = modKernel32.NewProc("GetXStateFeaturesMask")
	procLocateXStateFeature      = modKernel32.NewProc("LocateXStateFeature")
	procGetEnabledXStateFeatures = modKernel32.NewProc("GetEnabledXStateFeatures")
)

// xstateComponent describes one extended component: its Windows feature ID,
// its offset in the Linux XSAVE image (the standard, non-compacted layout of
// the Intel SDM), and its size.
type xstateComponent struct {
	id     uint32
	offset int
	size   int
}

var xstateComponents = []xstateComponent{
	{2, 576, 256},   // AVX: YMM_Hi128
	{5, 1088, 64},   // AVX-512: opmask registers
	{6, 1152, 512},  // AVX-512: ZMM_Hi256
	{7, 1664, 1024}, // AVX-512: Hi16_ZMM
}

const xsaveHeaderOffset = 512

// xstateExt is the memory behind an extended record.
type xstateExt struct {
	raw []byte
	// mask is the set of components that the record carries.
	mask uint64
}

// xstateMask returns the extended components that the OS enabled.
var xstateMask = sync.OnceValue(func() uint64 {
	if procGetEnabledXStateFeatures.Find() != nil {
		return 0
	}
	enabled, _, _ := procGetEnabledXStateFeatures.Call()
	var m uint64
	for _, c := range xstateComponents {
		if uint64(enabled)&(1<<c.id) != 0 {
			m |= 1 << c.id
		}
	}
	return m
})

func newHostContext() *hostContext {
	if mask := xstateMask(); mask != 0 {
		if c := newXStateContext(mask); c != nil {
			return c
		}
	}
	raw := make([]byte, hostContextSize+16)
	start := (16 - int(uintptr(unsafe.Pointer(&raw[0]))&15)) & 15
	return &hostContext{buf: raw[start : start+hostContextSize]}
}

// newXStateContext allocates a record with an XSAVE area for mask.
func newXStateContext(mask uint64) *hostContext {
	if procInitializeContext.Find() != nil || procSetXStateFeaturesMask.Find() != nil ||
		procGetXStateFeaturesMask.Find() != nil || procLocateXStateFeature.Find() != nil {
		return nil
	}
	flags := uintptr(ctxFlagGuestAll | ctxFlagXState)
	var length uint32
	// The first call fails and reports the size.
	procInitializeContext.Call(0, flags, 0, uintptr(unsafe.Pointer(&length)))
	if length == 0 {
		return nil
	}
	raw := make([]byte, length)
	var ctxp uintptr
	r, _, _ := procInitializeContext.Call(uintptr(unsafe.Pointer(&raw[0])), flags, uintptr(unsafe.Pointer(&ctxp)), uintptr(unsafe.Pointer(&length)))
	if r == 0 || ctxp == 0 {
		return nil
	}
	c := &hostContext{buf: unsafe.Slice((*byte)(addrPtr(uint64(ctxp))), hostContextSize), ext: &xstateExt{raw: raw, mask: mask}}
	if uintptr(unsafe.Pointer(&c.buf[0]))&15 != 0 {
		return nil
	}
	return c
}

func (c *hostContext) xs() *xstateExt {
	x, _ := c.ext.(*xstateExt)
	return x
}

// guestFlags returns the CONTEXT flags that carry the whole guest state.
func (c *hostContext) guestFlags() uint32 {
	if c.xs() != nil {
		return ctxFlagGuestAll | ctxFlagXState
	}
	return ctxFlagGuestAll
}

// fpFlags returns the CONTEXT flags of the vector state.
func (c *hostContext) fpFlags() uint32 {
	if c.xs() != nil {
		return ctxFlagFloat | ctxFlagXState
	}
	return ctxFlagFloat
}

// prepareGet asks Windows for every component that the record carries.
func (c *hostContext) prepareGet() {
	if x := c.xs(); x != nil {
		procSetXStateFeaturesMask.Call(c.ptr(), uintptr(x.mask))
	}
}

// locate returns the bytes of one component inside the record.
func (c *hostContext) locate(id uint32, size int) []byte {
	var n uint32
	p, _, _ := procLocateXStateFeature.Call(c.ptr(), uintptr(id), uintptr(unsafe.Pointer(&n)))
	if p == 0 || int(n) < size {
		return nil
	}
	return unsafe.Slice((*byte)(addrPtr(uint64(p))), size)
}

// loadXState copies the extended components of the Linux XSAVE image fp into
// the record. A component that the image marks as initial becomes zeros.
func (c *hostContext) loadXState(fp []byte) {
	x := c.xs()
	if x == nil {
		return
	}
	var bv uint64
	if len(fp) >= xsaveHeaderOffset+8 {
		bv = binary.LittleEndian.Uint64(fp[xsaveHeaderOffset:])
	}
	for _, comp := range xstateComponents {
		if x.mask&(1<<comp.id) == 0 {
			continue
		}
		dst := c.locate(comp.id, comp.size)
		if dst == nil {
			continue
		}
		if bv&(1<<comp.id) != 0 && len(fp) >= comp.offset+comp.size {
			copy(dst, fp[comp.offset:comp.offset+comp.size])
		} else {
			clear(dst)
		}
	}
	procSetXStateFeaturesMask.Call(c.ptr(), uintptr(x.mask))
}

// storeXState copies the extended components of the record into the Linux
// XSAVE image fp and sets their bits in the XSTATE_BV header word.
func (c *hostContext) storeXState(fp []byte) {
	x := c.xs()
	if x == nil || len(fp) < xsaveHeaderOffset+8 {
		return
	}
	var have uint64
	procGetXStateFeaturesMask.Call(c.ptr(), uintptr(unsafe.Pointer(&have)))
	bv := binary.LittleEndian.Uint64(fp[xsaveHeaderOffset:])
	for _, comp := range xstateComponents {
		if x.mask&(1<<comp.id) == 0 || len(fp) < comp.offset+comp.size {
			continue
		}
		if have&(1<<comp.id) == 0 {
			// The thread holds the initial state of this component.
			clear(fp[comp.offset : comp.offset+comp.size])
			bv &^= 1 << comp.id
			continue
		}
		if src := c.locate(comp.id, comp.size); src != nil {
			copy(fp[comp.offset:comp.offset+comp.size], src)
			bv |= 1 << comp.id
		}
	}
	binary.LittleEndian.PutUint64(fp[xsaveHeaderOffset:], bv)
}
