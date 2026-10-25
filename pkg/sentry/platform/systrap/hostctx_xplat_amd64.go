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

//go:build (darwin || windows) && amd64

package systrap

import (
	"encoding/binary"
	"unsafe"

	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// hostContext holds one Windows AMD64 CONTEXT record. The record needs
// 16-byte alignment, so the bytes live in a slice that starts on one.
//
// Layout (winnt.h): P1Home to P6Home at 0, ContextFlags at 48, MxCsr at 52,
// EFlags at 68, Rax at 120, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8 to R15, Rip
// at 248, FltSave (an FXSAVE image) at 256.
type hostContext struct {
	buf []byte
	// ext holds the host-specific state of an extended record: the memory
	// that backs the XSTATE area on Windows. It is nil for a plain record.
	ext any
}

const (
	hostContextSize = 1232

	ctxOffFlags  = 48
	ctxOffMxCsr  = 52
	ctxOffSegCs  = 56
	ctxOffSegSs  = 66
	ctxOffEFlags = 68
	ctxOffRax    = 120
	ctxOffRcx    = 128
	ctxOffRdx    = 136
	ctxOffRbx    = 144
	ctxOffRsp    = 152
	ctxOffRbp    = 160
	ctxOffRsi    = 168
	ctxOffRdi    = 176
	ctxOffR8     = 184
	ctxOffRip    = 248
	ctxOffFlt    = 256

	// CONTEXT_AMD64 and its component flags. The record keeps the segment
	// registers and the debug registers of the thread.
	// Windows user-mode selectors of a 64-bit thread. A CONTEXT_CONTROL record
	// with a zero SegCs makes Windows put the thread in 32-bit compatibility
	// mode, which drops the upper half of RIP and RSP.
	userSegCs = hvcommon.SelUserCS64
	userSegSs = hvcommon.SelUserSS

	ctxAMD64        = 0x00100000
	ctxFlagControl  = ctxAMD64 | 0x1
	ctxFlagInteger  = ctxAMD64 | 0x2
	ctxFlagFloat    = ctxAMD64 | 0x8
	ctxFlagGuestAll = ctxFlagControl | ctxFlagInteger | ctxFlagFloat
	// ctxFlagXState adds the extended state (AVX and wider vector registers).
	ctxFlagXState = ctxAMD64 | 0x40

	eflagsTrap = 1 << 8
)

// xstateComponent describes one extended component: its XSAVE feature ID, its
// offset in the Linux XSAVE image (the standard, non-compacted layout of the
// Intel SDM), and its size.
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

// xsaveHeaderOffset is the offset of the XSAVE header. The first word of the
// header is XSTATE_BV, which names the components that hold live state.
const xsaveHeaderOffset = 512

// loadXStateComponents copies the extended components of the Linux XSAVE image
// fp enabled by mask into the slices returned by locate, and returns the
// bitmask of components that were present and non-initial in fp.
func loadXStateComponents(fp []byte, mask uint64, locate func(comp xstateComponent) []byte) uint64 {
	var bv uint64
	if len(fp) >= xsaveHeaderOffset+8 {
		bv = binary.LittleEndian.Uint64(fp[xsaveHeaderOffset:])
	}
	var loaded uint64
	for _, comp := range xstateComponents {
		bit := uint64(1) << comp.id
		if mask&bit == 0 {
			continue
		}
		dst := locate(comp)
		if dst == nil {
			continue
		}
		if bv&bit != 0 && len(fp) >= comp.offset+comp.size {
			copy(dst, fp[comp.offset:comp.offset+comp.size])
			loaded |= bit
		} else {
			clear(dst)
		}
	}
	return loaded
}

// storeXStateComponents copies the extended components from locate into the
// Linux XSAVE image fp and updates the XSTATE_BV header word.
func storeXStateComponents(fp []byte, mask, have uint64, locate func(comp xstateComponent) []byte) {
	if len(fp) < xsaveHeaderOffset+8 {
		return
	}
	bv := binary.LittleEndian.Uint64(fp[xsaveHeaderOffset:])
	for _, comp := range xstateComponents {
		bit := uint64(1) << comp.id
		if mask&bit == 0 || len(fp) < comp.offset+comp.size {
			continue
		}
		dst := fp[comp.offset : comp.offset+comp.size]
		if have&bit == 0 {
			clear(dst)
			bv &^= bit
			continue
		}
		if src := locate(comp); src != nil {
			copy(dst, src)
			bv |= bit
		}
	}
	binary.LittleEndian.PutUint64(fp[xsaveHeaderOffset:], bv)
}

// ptr returns the address to pass to GetThreadContext and SetThreadContext.
func (c *hostContext) ptr() uintptr { return uintptr(unsafe.Pointer(&c.buf[0])) }

func (c *hostContext) u32(off int) uint32 { return binary.LittleEndian.Uint32(c.buf[off:]) }
func (c *hostContext) u64(off int) uint64 { return binary.LittleEndian.Uint64(c.buf[off:]) }
func (c *hostContext) put32(off int, v uint32) {
	binary.LittleEndian.PutUint32(c.buf[off:], v)
}
func (c *hostContext) put64(off int, v uint64) {
	binary.LittleEndian.PutUint64(c.buf[off:], v)
}

func (c *hostContext) setFlags(f uint32) { c.put32(ctxOffFlags, f) }

func (c *hostContext) pc() uint64     { return c.u64(ctxOffRip) }
func (c *hostContext) setPC(v uint64) { c.put64(ctxOffRip, v) }
func (c *hostContext) sp() uint64     { return c.u64(ctxOffRsp) }
func (c *hostContext) setSP(v uint64) { c.put64(ctxOffRsp, v) }

// setSingleStep sets or clears the trap flag of EFLAGS.
func (c *hostContext) setSingleStep(on bool) {
	v := c.u32(ctxOffEFlags)
	if on {
		v |= eflagsTrap
	} else {
		v &^= eflagsTrap
	}
	c.put32(ctxOffEFlags, v)
}

// loadFrom copies the guest registers of ac into the record. It sets the
// context flags to gprFlags, or to guestFlags when fp is true and the record
// also carries the vector state. The FS base is not part of CONTEXT.
func (c *hostContext) loadFrom(ac *arch.Context64, fp bool) {
	r := &ac.StateData().Regs
	if fp {
		c.setFlags(c.guestFlags())
	} else {
		c.setFlags(c.gprFlags())
	}
	binary.LittleEndian.PutUint16(c.buf[ctxOffSegCs:], userSegCs)
	binary.LittleEndian.PutUint16(c.buf[ctxOffSegSs:], userSegSs)
	c.put32(ctxOffEFlags, uint32(r.Eflags))
	c.put64(ctxOffRax, r.Rax)
	c.put64(ctxOffRcx, r.Rcx)
	c.put64(ctxOffRdx, r.Rdx)
	c.put64(ctxOffRbx, r.Rbx)
	c.put64(ctxOffRsp, r.Rsp)
	c.put64(ctxOffRbp, r.Rbp)
	c.put64(ctxOffRsi, r.Rsi)
	c.put64(ctxOffRdi, r.Rdi)
	c.put64(ctxOffR8+0*8, r.R8)
	c.put64(ctxOffR8+1*8, r.R9)
	c.put64(ctxOffR8+2*8, r.R10)
	c.put64(ctxOffR8+3*8, r.R11)
	c.put64(ctxOffR8+4*8, r.R12)
	c.put64(ctxOffR8+5*8, r.R13)
	c.put64(ctxOffR8+6*8, r.R14)
	c.put64(ctxOffR8+7*8, r.R15)
	c.put64(ctxOffRip, r.Rip)
	if !fp {
		return
	}
	// The first 512 bytes of the Linux xsave image are an FXSAVE image, the
	// same layout as XSAVE_FORMAT in CONTEXT.
	state := *ac.FloatingPointData()
	if len(state) >= 512 {
		copy(c.buf[ctxOffFlt:ctxOffFlt+512], state[:512])
		c.put32(ctxOffMxCsr, binary.LittleEndian.Uint32(state[24:]))
	}
	c.loadXState(state)
}

// storeTo copies the general-purpose state of the record into ac. The record
// must hold gprFlags. Fs_base is not part of CONTEXT and stays unchanged.
func (c *hostContext) storeTo(ac *arch.Context64) {
	r := &ac.StateData().Regs
	r.Eflags = uint64(c.u32(ctxOffEFlags))
	r.Rax = c.u64(ctxOffRax)
	r.Rcx = c.u64(ctxOffRcx)
	r.Rdx = c.u64(ctxOffRdx)
	r.Rbx = c.u64(ctxOffRbx)
	r.Rsp = c.u64(ctxOffRsp)
	r.Rbp = c.u64(ctxOffRbp)
	r.Rsi = c.u64(ctxOffRsi)
	r.Rdi = c.u64(ctxOffRdi)
	r.R8 = c.u64(ctxOffR8 + 0*8)
	r.R9 = c.u64(ctxOffR8 + 1*8)
	r.R10 = c.u64(ctxOffR8 + 2*8)
	r.R11 = c.u64(ctxOffR8 + 3*8)
	r.R12 = c.u64(ctxOffR8 + 4*8)
	r.R13 = c.u64(ctxOffR8 + 5*8)
	r.R14 = c.u64(ctxOffR8 + 6*8)
	r.R15 = c.u64(ctxOffR8 + 7*8)
	r.Rip = c.u64(ctxOffRip)
}

// storeFP copies the vector state of the record into ac. The record must hold
// fpFlags.
func (c *hostContext) storeFP(ac *arch.Context64) {
	state := *ac.FloatingPointData()
	if len(state) >= 512 {
		copy(state[:512], c.buf[ctxOffFlt:ctxOffFlt+512])
	}
	c.storeXState(state)
}

// gprFlags returns the CONTEXT flags of the integer registers, the stack
// pointer, the instruction pointer, and the flags.
func (c *hostContext) gprFlags() uint32 { return ctxFlagControl | ctxFlagInteger }
