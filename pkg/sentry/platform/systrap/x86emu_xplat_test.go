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
	"fmt"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

// x86Machine runs the machine code of the slot and the spill routine. It
// decodes each instruction with the x86asm decoder and executes the forms that
// the generator emits. Any other instruction stops the run with an error.
type x86Machine struct {
	r      [16]uint64
	rflags uint64

	code     []byte
	codeBase uint64
	pc       uint64

	mem    map[uint64]byte
	gsBase uint64
	fsBase uint64
	// vec holds the vector registers as an XSAVE image.
	vec [winXsaveSize]byte

	onYield func(m *x86Machine)
	onFence func(m *x86Machine)
	onCall  func(m *x86Machine, target uint64)

	pauses, fences, steps int
	exit                  x86Exit
}

type x86Exit struct {
	// trap is 3 after INT3, otherwise 0.
	trap int
	// jump is the target of a jump that left the code.
	jump uint64
}

func newX86Machine(code []byte, base uint64) *x86Machine {
	m := &x86Machine{code: code, codeBase: base, pc: base, mem: make(map[uint64]byte), rflags: 2}
	for i, b := range code {
		m.mem[base+uint64(i)] = b
	}
	return m
}

func (m *x86Machine) read(addr uint64, n int) uint64 {
	var v uint64
	for i := range n {
		v |= uint64(m.mem[addr+uint64(i)]) << (8 * i)
	}
	return v
}

func (m *x86Machine) write(addr uint64, n int, v uint64) {
	for i := range n {
		m.mem[addr+uint64(i)] = byte(v >> (8 * i))
	}
}

func (m *x86Machine) put64(addr, v uint64)     { m.write(addr, 8, v) }
func (m *x86Machine) get64(addr uint64) uint64 { return m.read(addr, 8) }
func (m *x86Machine) put32(addr uint64, v uint32) {
	m.write(addr, 4, uint64(v))
}
func (m *x86Machine) get32(addr uint64) uint32 { return uint32(m.read(addr, 4)) }

var x86RegNames = func() map[string]int {
	names := map[string]int{
		"RAX": 0, "RCX": 1, "RDX": 2, "RBX": 3, "RSP": 4, "RBP": 5, "RSI": 6, "RDI": 7,
		"EAX": 0, "ECX": 1, "EDX": 2, "EBX": 3, "ESP": 4, "EBP": 5, "ESI": 6, "EDI": 7,
	}
	for i := 8; i < 16; i++ {
		names[fmt.Sprintf("R%d", i)] = i
		names[fmt.Sprintf("R%dL", i)] = i
	}
	return names
}()

// regOf returns the register number of a general register and its width in
// bytes.
func regOf(r x86asm.Reg) (n int, size int, ok bool) {
	s := strings.ToUpper(r.String())
	n, ok = x86RegNames[s]
	size = 8
	if strings.HasPrefix(s, "E") || strings.HasSuffix(s, "L") {
		size = 4
	}
	return n, size, ok
}

func (m *x86Machine) memAddr(mem x86asm.Mem) (uint64, error) {
	if mem.Index != 0 || mem.Scale > 1 {
		return 0, fmt.Errorf("indexed operand %v", mem)
	}
	var addr uint64
	switch mem.Base {
	case 0:
	case x86asm.RIP:
		// The displacement is relative to the end of the instruction, which the
		// caller adds through next.
		return 0, fmt.Errorf("rip operand without an instruction end")
	default:
		n, _, ok := regOf(mem.Base)
		if !ok {
			return 0, fmt.Errorf("base register %v", mem.Base)
		}
		addr = m.r[n]
	}
	addr += uint64(mem.Disp)
	switch mem.Segment {
	case 0:
	case x86asm.GS:
		addr += m.gsBase
	default:
		return 0, fmt.Errorf("segment %v", mem.Segment)
	}
	return addr, nil
}

// operandAddr resolves a memory operand of the instruction that ends at next.
func (m *x86Machine) operandAddr(mem x86asm.Mem, next uint64) (uint64, error) {
	if mem.Base == x86asm.RIP {
		// The hardware sign-extends the 32-bit displacement. x86asm reports a
		// negative displacement as a large positive value.
		return next + uint64(int64(int32(mem.Disp))), nil
	}
	return m.memAddr(mem)
}

func (m *x86Machine) value(arg x86asm.Arg, size int, next uint64) (uint64, error) {
	switch a := arg.(type) {
	case x86asm.Reg:
		n, sz, ok := regOf(a)
		if !ok {
			return 0, fmt.Errorf("register %v", a)
		}
		v := m.r[n]
		if sz == 4 {
			v &= 0xffffffff
		}
		return v, nil
	case x86asm.Imm:
		v := uint64(a)
		if size == 4 {
			v &= 0xffffffff
		}
		return v, nil
	case x86asm.Mem:
		addr, err := m.operandAddr(a, next)
		if err != nil {
			return 0, err
		}
		return m.read(addr, size), nil
	}
	return 0, fmt.Errorf("operand %v", arg)
}

func (m *x86Machine) setValue(arg x86asm.Arg, size int, v uint64, next uint64) error {
	switch a := arg.(type) {
	case x86asm.Reg:
		n, sz, ok := regOf(a)
		if !ok {
			return fmt.Errorf("register %v", a)
		}
		if sz == 4 {
			v &= 0xffffffff
		}
		m.r[n] = v
		return nil
	case x86asm.Mem:
		addr, err := m.operandAddr(a, next)
		if err != nil {
			return err
		}
		m.write(addr, size, v)
		return nil
	}
	return fmt.Errorf("destination %v", arg)
}

// operandSize returns the width in bytes of the first register operand, or of
// the instruction when it names no register.
func operandSize(inst x86asm.Inst) int {
	for _, a := range inst.Args {
		if r, ok := a.(x86asm.Reg); ok {
			if _, sz, ok := regOf(r); ok {
				return sz
			}
		}
	}
	return 4
}

const (
	x86FlagCF = 1 << 0
	x86FlagZF = 1 << 6
	x86FlagSF = 1 << 7
	x86FlagOF = 1 << 11
)

func (m *x86Machine) setFlag(bit uint64, on bool) {
	if on {
		m.rflags |= bit
	} else {
		m.rflags &^= bit
	}
}

func (m *x86Machine) subFlags(a, b uint64, size int) {
	bits := uint(size * 8)
	mask := uint64(1)<<bits - 1
	if size == 8 {
		mask = ^uint64(0)
	}
	a, b = a&mask, b&mask
	res := (a - b) & mask
	sign := uint64(1) << (bits - 1)
	m.setFlag(x86FlagZF, res == 0)
	m.setFlag(x86FlagSF, res&sign != 0)
	m.setFlag(x86FlagCF, a < b)
	m.setFlag(x86FlagOF, (a^b)&(a^res)&sign != 0)
}

func (m *x86Machine) cond(op string) (bool, error) {
	switch op {
	case "JE":
		return m.rflags&x86FlagZF != 0, nil
	case "JNE":
		return m.rflags&x86FlagZF == 0, nil
	case "JB":
		return m.rflags&x86FlagCF != 0, nil
	case "JAE":
		return m.rflags&x86FlagCF == 0, nil
	}
	return false, fmt.Errorf("jump %s", op)
}

// run executes until a jump leaves the code, an INT3 runs, or maxSteps passes.
func (m *x86Machine) run(maxSteps int) error {
	for ; m.steps < maxSteps; m.steps++ {
		off := m.pc - m.codeBase
		if m.pc < m.codeBase || off >= uint64(len(m.code)) {
			m.exit.jump = m.pc
			return nil
		}
		inst, err := x86asm.Decode(m.code[off:], 64)
		if err != nil {
			return fmt.Errorf("decode at %#x: %v", off, err)
		}
		done, err := m.step(inst)
		if err != nil {
			return fmt.Errorf("at offset %#x (%v): %w", off, inst, err)
		}
		if done {
			return nil
		}
	}
	return fmt.Errorf("no exit within %d steps", maxSteps)
}

func (m *x86Machine) step(inst x86asm.Inst) (done bool, err error) {
	next := m.pc + uint64(inst.Len)
	defer func() {
		if err == nil && !done {
			m.pc = next
		}
	}()
	op := inst.Op.String()
	args := inst.Args
	switch op {
	case "MOV":
		size := operandSize(inst)
		v, err := m.value(args[1], size, next)
		if err != nil {
			return false, err
		}
		return false, m.setValue(args[0], size, v, next)
	case "LEA":
		mem, ok := args[1].(x86asm.Mem)
		if !ok {
			return false, fmt.Errorf("lea operand %v", args[1])
		}
		addr, err := m.operandAddr(mem, next)
		if err != nil {
			return false, err
		}
		return false, m.setValue(args[0], 8, addr, next)
	case "CMP":
		size := operandSize(inst)
		a, err := m.value(args[0], size, next)
		if err != nil {
			return false, err
		}
		b, err := m.value(args[1], size, next)
		if err != nil {
			return false, err
		}
		if imm, ok := args[1].(x86asm.Imm); ok {
			b = uint64(int64(imm))
		}
		m.subFlags(a, b, size)
		return false, nil
	case "XOR":
		size := operandSize(inst)
		a, err := m.value(args[0], size, next)
		if err != nil {
			return false, err
		}
		b, err := m.value(args[1], size, next)
		if err != nil {
			return false, err
		}
		res := a ^ b
		m.setFlag(x86FlagZF, res == 0)
		m.setFlag(x86FlagCF, false)
		return false, m.setValue(args[0], size, res, next)
	case "DEC":
		size := operandSize(inst)
		a, err := m.value(args[0], size, next)
		if err != nil {
			return false, err
		}
		keep := m.rflags & x86FlagCF
		m.subFlags(a, 1, size)
		m.setFlag(x86FlagCF, keep != 0)
		return false, m.setValue(args[0], size, a-1, next)
	case "PUSHF", "PUSHFQ":
		m.r[4] -= 8
		m.put64(m.r[4], m.rflags)
		return false, nil
	case "POPF", "POPFQ":
		m.rflags = m.get64(m.r[4])
		m.r[4] += 8
		return false, nil
	case "PUSH":
		v, err := m.value(args[0], 8, next)
		if err != nil {
			return false, err
		}
		m.r[4] -= 8
		m.put64(m.r[4], v)
		return false, nil
	case "POP":
		v := m.get64(m.r[4])
		m.r[4] += 8
		return false, m.setValue(args[0], 8, v, next)
	case "CALL":
		target, err := m.value(args[0], 8, next)
		if err != nil {
			return false, err
		}
		if m.onCall == nil {
			return false, fmt.Errorf("call to %#x", target)
		}
		if m.r[4]%16 != 0 {
			return false, fmt.Errorf("call with the stack pointer %#x not aligned", m.r[4])
		}
		m.onCall(m, target)
		return false, nil
	case "JMP":
		switch a := args[0].(type) {
		case x86asm.Rel:
			next = next + uint64(int64(a))
			return false, nil
		case x86asm.Mem:
			addr, err := m.operandAddr(a, next)
			if err != nil {
				return false, err
			}
			target := m.get64(addr)
			if target >= m.codeBase && target < m.codeBase+uint64(len(m.code)) {
				next = target
				return false, nil
			}
			m.exit.jump = target
			return true, nil
		}
		return false, fmt.Errorf("jump operand %v", args[0])
	case "JE", "JNE", "JB", "JAE":
		ok, err := m.cond(op)
		if err != nil {
			return false, err
		}
		if ok {
			next = next + uint64(int64(args[0].(x86asm.Rel)))
		}
		return false, nil
	case "NOP":
		return false, nil
	case "PAUSE":
		m.pauses++
		if m.onYield != nil {
			m.onYield(m)
		}
		return false, nil
	case "MFENCE":
		m.fences++
		if m.onFence != nil {
			m.onFence(m)
		}
		return false, nil
	case "WRFSBASE":
		v, err := m.value(args[0], 8, next)
		m.fsBase = v
		return false, err
	case "XSAVE64", "XRSTOR64":
		return false, m.xstate(inst, next)
	case "INT", "INT3":
		m.exit.trap = 3
		return true, nil
	}
	return false, fmt.Errorf("instruction %v is not in the emulated set", inst)
}

// x86VectorRanges returns the byte ranges of an XSAVE image that the spill
// routine saves: the legacy region, the header, and the extended components.
func x86VectorRanges() [][2]int {
	ranges := [][2]int{{0, xsaveHeaderOffset}, {xsaveHeaderOffset, xsaveHeaderOffset + 64}}
	for _, comp := range xstateComponents {
		ranges = append(ranges, [2]int{comp.offset, comp.offset + comp.size})
	}
	return ranges
}

// xstate runs XSAVE64 and XRSTOR64 on the vector registers of the machine. It
// stops the run where the processor raises a fault: an address that is not
// 64-byte aligned, a feature mask other than the one that the routine owns,
// and a header that is not valid for the standard format.
func (m *x86Machine) xstate(inst x86asm.Inst, next uint64) error {
	mem, ok := inst.Args[0].(x86asm.Mem)
	if !ok {
		return fmt.Errorf("%v operand %v", inst.Op, inst.Args[0])
	}
	addr, err := m.operandAddr(mem, next)
	if err != nil {
		return err
	}
	if addr%64 != 0 {
		return fmt.Errorf("%v at %#x is not 64-byte aligned", inst.Op, addr)
	}
	if m.r[x86RAX]&0xFFFF_FFFF != winXsaveMask || m.r[x86RDX]&0xFFFF_FFFF != 0 {
		return fmt.Errorf("%v with the feature mask %#x:%#x, want %#x", inst.Op, m.r[x86RDX]&0xFFFF_FFFF, m.r[x86RAX]&0xFFFF_FFFF, uint64(winXsaveMask))
	}
	ranges := x86VectorRanges()
	if inst.Op.String() == "XSAVE64" {
		for _, rg := range ranges {
			for i := rg[0]; i < rg[1]; i++ {
				m.mem[addr+uint64(i)] = m.vec[i]
			}
		}
		return nil
	}
	var header [64]byte
	for i := range header {
		header[i] = m.mem[addr+xsaveHeaderOffset+uint64(i)]
	}
	if bv := binary.LittleEndian.Uint64(header[:]); bv&^winXsaveMask != 0 {
		return fmt.Errorf("XRSTOR64 with XSTATE_BV %#x, XCR0 enables %#x", bv, uint64(winXsaveMask))
	}
	for _, b := range header[8:] {
		if b != 0 {
			return fmt.Errorf("XRSTOR64 with a header that is not in the standard format: % x", header[8:])
		}
	}
	for _, rg := range ranges {
		for i := rg[0]; i < rg[1]; i++ {
			m.vec[i] = m.mem[addr+uint64(i)]
		}
	}
	return nil
}
