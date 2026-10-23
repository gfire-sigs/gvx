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

//go:build (darwin || windows) && arm64

package systrap

import (
	"encoding/binary"
	"unsafe"

	"z.gfire.dev/gvx/pkg/sentry/arch"
)

// hostContext holds one Windows ARM64_NT_CONTEXT record. The record needs
// 16-byte alignment, so the bytes live in a slice that starts on one.
//
// Layout (winnt.h): ContextFlags at 0, Cpsr at 4, X0 to X28, Fp, Lr at 8 to
// 255, Sp at 256, Pc at 264, V0 to V31 at 272, Fpcr at 784, Fpsr at 788.
type hostContext struct {
	buf []byte
}

const (
	hostContextSize = 912

	ctxOffFlags = 0
	ctxOffCpsr  = 4
	ctxOffX     = 8
	ctxOffSP    = 256
	ctxOffPC    = 264
	ctxOffV     = 272
	ctxOffFpcr  = 784
	ctxOffFpsr  = 788

	// CONTEXT_ARM64 and its component flags. CONTEXT_X18 asks Windows to read
	// and write the x18 slot. Without it Windows keeps the thread's own x18,
	// which holds the TEB address.
	ctxARM64        = 0x00400000
	ctxFlagControl  = ctxARM64 | 0x1
	ctxFlagInteger  = ctxARM64 | 0x2
	ctxFlagFloat    = ctxARM64 | 0x4
	ctxFlagX18      = ctxARM64 | 0x10
	ctxFlagGuestAll = ctxFlagControl | ctxFlagInteger | ctxFlagFloat | ctxFlagX18

	// pstateSS is the software single-step bit of PSTATE. pstateNZCV selects
	// the condition flags, the only PSTATE bits that user code owns.
	pstateSS   = 1 << 21
	pstateNZCV = 0xf0000000
)

func newHostContext() *hostContext {
	raw := make([]byte, hostContextSize+16)
	start := (16 - int(uintptr(unsafe.Pointer(&raw[0]))&15)) & 15
	return &hostContext{buf: raw[start : start+hostContextSize]}
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

// guestFlags returns the CONTEXT flags that carry the whole guest state.
func (c *hostContext) guestFlags() uint32 { return ctxFlagGuestAll }

// gprFlags returns the CONTEXT flags of the general-purpose registers, the
// stack pointer, the program counter, and the condition flags.
func (c *hostContext) gprFlags() uint32 { return ctxFlagControl | ctxFlagInteger | ctxFlagX18 }

// fpFlags returns the CONTEXT flags of the vector state.
func (c *hostContext) fpFlags() uint32 { return ctxFlagFloat }

// prepareGet is a no-op: an ARM64 record has no extended area.
func (c *hostContext) prepareGet() {}

func (c *hostContext) pc() uint64     { return c.u64(ctxOffPC) }
func (c *hostContext) setPC(v uint64) { c.put64(ctxOffPC, v) }
func (c *hostContext) sp() uint64     { return c.u64(ctxOffSP) }
func (c *hostContext) setSP(v uint64) { c.put64(ctxOffSP, v) }

// reg returns general register n (0 to 30).
func (c *hostContext) reg(n int) uint64 { return c.u64(ctxOffX + 8*n) }

// setReg sets general register n (0 to 30).
func (c *hostContext) setReg(n int, v uint64) { c.put64(ctxOffX+8*n, v) }

// setSingleStep sets or clears the software single-step bit.
func (c *hostContext) setSingleStep(on bool) {
	v := c.u32(ctxOffCpsr)
	if on {
		v |= pstateSS
	} else {
		v &^= pstateSS
	}
	c.put32(ctxOffCpsr, v)
}

// fpsimdOffV is the offset of V0 inside the Linux fpsimd_context that
// arch.Context64 keeps. The head has the magic and the size, then Fpsr and
// Fpcr follow.
const (
	fpStateOffFpsr = 8
	fpStateOffFpcr = 12
	fpStateOffV    = 16
)

// loadFrom copies the guest registers of ac into the record. It sets the
// context flags to gprFlags, or to guestFlags when fp is true and the record
// also carries the vector state.
func (c *hostContext) loadFrom(ac *arch.Context64, fp bool) {
	st := ac.StateData()
	regs := &st.Regs
	if fp {
		c.setFlags(c.guestFlags())
	} else {
		c.setFlags(c.gprFlags())
	}
	c.put32(ctxOffCpsr, uint32(regs.Pstate&pstateNZCV))
	for i := 0; i < 31; i++ {
		c.put64(ctxOffX+8*i, regs.Regs[i])
	}
	c.put64(ctxOffSP, regs.Sp)
	c.put64(ctxOffPC, regs.Pc)
	if !fp {
		return
	}
	state := *ac.FloatingPointData()
	if len(state) >= fpStateOffV+32*16 {
		copy(c.buf[ctxOffV:ctxOffV+32*16], state[fpStateOffV:fpStateOffV+32*16])
		c.put32(ctxOffFpsr, binary.LittleEndian.Uint32(state[fpStateOffFpsr:]))
		c.put32(ctxOffFpcr, binary.LittleEndian.Uint32(state[fpStateOffFpcr:]))
	}
}

// storeTo copies the general-purpose state of the record into ac. The record
// must hold gprFlags.
func (c *hostContext) storeTo(ac *arch.Context64) {
	st := ac.StateData()
	regs := &st.Regs
	for i := 0; i < 31; i++ {
		regs.Regs[i] = c.u64(ctxOffX + 8*i)
	}
	regs.Sp = c.u64(ctxOffSP)
	regs.Pc = c.u64(ctxOffPC)
	regs.Pstate = regs.Pstate&^pstateNZCV | uint64(c.u32(ctxOffCpsr))&pstateNZCV
}

// storeFP copies the vector state of the record into ac. The record must hold
// fpFlags.
func (c *hostContext) storeFP(ac *arch.Context64) {
	state := *ac.FloatingPointData()
	if len(state) >= fpStateOffV+32*16 {
		copy(state[fpStateOffV:fpStateOffV+32*16], c.buf[ctxOffV:ctxOffV+32*16])
		binary.LittleEndian.PutUint32(state[fpStateOffFpsr:], c.u32(ctxOffFpsr))
		binary.LittleEndian.PutUint32(state[fpStateOffFpcr:], c.u32(ctxOffFpcr))
	}
}
