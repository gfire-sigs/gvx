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
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
)

// a64Machine runs the machine code of the spill routine. It decodes each word
// with the arm64asm decoder and executes the instruction forms that the
// routine uses. An instruction outside that set stops the run with an error,
// so a change of the generator that adds a new form fails loudly.
type a64Machine struct {
	x    [31]uint64
	sp   uint64
	n, z bool
	c, v bool

	code     []byte
	codeBase uint64
	// pc is an absolute address.
	pc uint64

	mem map[uint64]byte

	tpidr uint64
	// cntvct is the virtual counter. Each read returns it and then adds one, so
	// a spin window of n ticks lasts n polls.
	cntvct uint64
	// v holds V0 to V31 as two words each. fpsr and fpcr are the FP registers.
	vec        [32][2]uint64
	fpsr, fpcr uint64

	// Hooks. A nil hook does nothing.
	onYield func(m *a64Machine)
	onFence func(m *a64Machine)
	// onCall serves a BLR. The hook returns after the callee ran.
	onCall func(m *a64Machine, target uint64)

	yields, fences int
	steps          int
	// exit describes how the run ended.
	exit a64Exit
}

type a64Exit struct {
	// brk is the immediate of a BRK, or -1.
	brk int
	// jump is the address of a BR that left the code.
	jump uint64
}

// regOrImm returns the value of a register operand, or of an immediate.
func (m *a64Machine) regOrImm(arg string) (uint64, error) {
	if strings.HasPrefix(arg, "#") {
		return m.imm(arg)
	}
	return m.getReg(arg)
}

func newA64Machine(code []byte, base uint64) *a64Machine {
	return &a64Machine{code: code, codeBase: base, pc: base, mem: make(map[uint64]byte), exit: a64Exit{brk: -1}}
}

func (m *a64Machine) read(addr uint64, n int) uint64 {
	var v uint64
	for i := range n {
		v |= uint64(m.mem[addr+uint64(i)]) << (8 * i)
	}
	return v
}

func (m *a64Machine) write(addr uint64, n int, v uint64) {
	for i := range n {
		m.mem[addr+uint64(i)] = byte(v >> (8 * i))
	}
}

func (m *a64Machine) put64(addr, v uint64) { m.write(addr, 8, v) }
func (m *a64Machine) get64(addr uint64) uint64 {
	return m.read(addr, 8)
}
func (m *a64Machine) put32(addr uint64, v uint32) { m.write(addr, 4, uint64(v)) }
func (m *a64Machine) get32(addr uint64) uint32    { return uint32(m.read(addr, 4)) }

var (
	a64MemRe = regexp.MustCompile(`^\[(\w+)(?:,#(-?\w+))?\]$`)
	a64ImmRe = regexp.MustCompile(`^#(-?(?:0x)?[0-9a-f]+)$`)
)

func a64Num(s string) (int64, error) { return strconv.ParseInt(s, 0, 64) }

// reg parses a register name. It returns the register number, whether it is
// a 64-bit register, and whether the name is SP or ZR.
func a64ParseReg(s string) (n int, wide bool, special bool, ok bool) {
	switch s {
	case "SP":
		return 31, true, true, true
	case "XZR":
		return 31, true, true, true
	case "WZR":
		return 31, false, true, true
	}
	if len(s) < 2 || (s[0] != 'X' && s[0] != 'W') {
		return 0, false, false, false
	}
	v, err := strconv.Atoi(s[1:])
	if err != nil || v < 0 || v > 30 {
		return 0, false, false, false
	}
	return v, s[0] == 'X', false, true
}

func (m *a64Machine) getReg(s string) (uint64, error) {
	n, wide, special, ok := a64ParseReg(s)
	if !ok {
		return 0, fmt.Errorf("register %q", s)
	}
	var v uint64
	switch {
	case s == "SP":
		v = m.sp
	case special:
		v = 0
	default:
		v = m.x[n]
	}
	if !wide {
		v &= 0xffffffff
	}
	return v, nil
}

func (m *a64Machine) setReg(s string, v uint64) error {
	n, wide, special, ok := a64ParseReg(s)
	if !ok {
		return fmt.Errorf("register %q", s)
	}
	if !wide {
		v &= 0xffffffff
	}
	switch {
	case s == "SP":
		m.sp = v
	case special:
	default:
		m.x[n] = v
	}
	return nil
}

func (m *a64Machine) memAddr(s string) (uint64, error) {
	g := a64MemRe.FindStringSubmatch(s)
	if g == nil {
		return 0, fmt.Errorf("memory operand %q", s)
	}
	base, err := m.getReg(g[1])
	if err != nil {
		return 0, err
	}
	if g[2] != "" {
		off, err := a64Num(g[2])
		if err != nil {
			return 0, err
		}
		base += uint64(off)
	}
	return base, nil
}

func (m *a64Machine) imm(s string) (uint64, error) {
	g := a64ImmRe.FindStringSubmatch(s)
	if g == nil {
		return 0, fmt.Errorf("immediate %q", s)
	}
	v, err := a64Num(g[1])
	return uint64(v), err
}

func (m *a64Machine) setCmp(a, b uint64, wide bool) {
	bits := 64
	if !wide {
		bits = 32
		a &= 0xffffffff
		b &= 0xffffffff
	}
	res := a - b
	if !wide {
		res &= 0xffffffff
	}
	m.z = res == 0
	m.n = res>>(bits-1)&1 == 1
	m.c = a >= b
	sa, sb, sr := a>>(bits-1)&1, b>>(bits-1)&1, res>>(bits-1)&1
	m.v = sa != sb && sr != sa
}

func (m *a64Machine) cond(name string) (bool, error) {
	switch name {
	case "EQ":
		return m.z, nil
	case "NE":
		return !m.z, nil
	case "HS", "CS":
		return m.c, nil
	case "LO", "CC":
		return !m.c, nil
	}
	return false, fmt.Errorf("condition %q", name)
}

func (m *a64Machine) nzcvWord() uint64 {
	var v uint64
	if m.n {
		v |= 1 << 31
	}
	if m.z {
		v |= 1 << 30
	}
	if m.c {
		v |= 1 << 29
	}
	if m.v {
		v |= 1 << 28
	}
	return v
}

func (m *a64Machine) setNZCV(v uint64) {
	m.n, m.z, m.c, m.v = v>>31&1 == 1, v>>30&1 == 1, v>>29&1 == 1, v>>28&1 == 1
}

// branchOffset parses the ".+0x18" operand of a branch.
func a64BranchOffset(s string) (int64, error) {
	s = strings.TrimPrefix(s, ".")
	if strings.HasPrefix(s, "+") {
		v, err := strconv.ParseUint(strings.TrimPrefix(s, "+0x"), 16, 64)
		return int64(v), err
	}
	return 0, fmt.Errorf("branch operand %q", s)
}

// run executes until the routine leaves the code, raises a BRK, or reaches
// maxSteps.
func (m *a64Machine) run(maxSteps int) error {
	for ; m.steps < maxSteps; m.steps++ {
		off := m.pc - m.codeBase
		if m.pc < m.codeBase || off+4 > uint64(len(m.code)) {
			// A branch left the code.
			m.exit.jump = m.pc
			return nil
		}
		inst, err := arm64asm.Decode(m.code[off : off+4])
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

func (m *a64Machine) step(inst arm64asm.Inst) (done bool, err error) {
	text := inst.String()
	op, rest, _ := strings.Cut(text, " ")
	// Split the operands at commas that are outside brackets.
	var args []string
	depth, start := 0, 0
	for i := 0; i <= len(rest); i++ {
		if i == len(rest) || (rest[i] == ',' && depth == 0) {
			if a := strings.TrimSpace(rest[start:i]); a != "" {
				args = append(args, a)
			}
			start = i + 1
			continue
		}
		switch rest[i] {
		case '[':
			depth++
		case ']':
			depth--
		}
	}
	// A memory operand prints without a space, but the immediate of a shifted
	// operand keeps one. Rejoin "ADD SP, X19, #0x2, LSL #12" below.
	next := m.pc + 4
	defer func() {
		if err == nil && !done {
			m.pc = next
		}
	}()
	need := func(n int) error {
		if len(args) < n {
			return fmt.Errorf("operands %v", args)
		}
		return nil
	}
	switch op {
	case "MRS":
		if err := need(2); err != nil {
			return false, err
		}
		switch args[1] {
		case "S3_3_C13_C0_2":
			return false, m.setReg(args[0], m.tpidr)
		case "S3_3_C14_C0_2", "CNTVCT_EL0":
			v := m.cntvct
			m.cntvct++
			return false, m.setReg(args[0], v)
		case "S3_3_C4_C4_1", "FPSR":
			return false, m.setReg(args[0], m.fpsr)
		case "S3_3_C4_C4_0", "FPCR":
			return false, m.setReg(args[0], m.fpcr)
		case "S3_3_C4_C2_0":
			return false, m.setReg(args[0], m.nzcvWord())
		}
		return false, fmt.Errorf("system register %q", args[1])
	case "MSR":
		if err := need(2); err != nil {
			return false, err
		}
		switch args[0] {
		case "S3_3_C4_C2_0":
			v, err := m.getReg(args[1])
			m.setNZCV(v)
			return false, err
		case "S3_3_C4_C4_1", "FPSR":
			v, err := m.getReg(args[1])
			m.fpsr = v
			return false, err
		case "S3_3_C4_C4_0", "FPCR":
			v, err := m.getReg(args[1])
			m.fpcr = v
			return false, err
		}
		return false, fmt.Errorf("system register %q", args[0])
	case "LDR", "LDAR":
		if err := need(2); err != nil {
			return false, err
		}
		var addr uint64
		var err error
		if strings.HasPrefix(args[1], ".") {
			// A literal load names an offset from the instruction.
			var off int64
			if off, err = a64BranchOffset(args[1]); err == nil {
				addr = m.pc + uint64(off)
			}
		} else {
			addr, err = m.memAddr(args[1])
		}
		if err != nil {
			return false, err
		}
		_, wide, _, _ := a64ParseReg(args[0])
		n := 4
		if wide {
			n = 8
		}
		return false, m.setReg(args[0], m.read(addr, n))
	case "STR", "STLR":
		if err := need(2); err != nil {
			return false, err
		}
		addr, err := m.memAddr(args[1])
		if err != nil {
			return false, err
		}
		v, err := m.getReg(args[0])
		if err != nil {
			return false, err
		}
		_, wide, _, _ := a64ParseReg(args[0])
		n := 4
		if wide {
			n = 8
		}
		m.write(addr, n, v)
		return false, nil
	case "LDP", "STP":
		if err := need(3); err != nil {
			return false, err
		}
		addr, err := m.memAddr(args[2])
		if err != nil {
			return false, err
		}
		if strings.HasPrefix(args[0], "Q") {
			for i := range 2 {
				n, err := strconv.Atoi(args[i][1:])
				if err != nil || n < 0 || n > 31 {
					return false, fmt.Errorf("vector register %q", args[i])
				}
				for h := range 2 {
					a := addr + uint64(16*i+8*h)
					if op == "LDP" {
						m.vec[n][h] = m.read(a, 8)
					} else {
						m.write(a, 8, m.vec[n][h])
					}
				}
			}
			return false, nil
		}
		for i := range 2 {
			if op == "LDP" {
				err = m.setReg(args[i], m.read(addr+uint64(8*i), 8))
			} else {
				var v uint64
				if v, err = m.getReg(args[i]); err == nil {
					m.write(addr+uint64(8*i), 8, v)
				}
			}
			if err != nil {
				return false, err
			}
		}
		return false, nil
	case "MOV":
		if err := need(2); err != nil {
			return false, err
		}
		if strings.HasPrefix(args[1], "#") {
			v, err := m.imm(args[1])
			if err != nil {
				return false, err
			}
			return false, m.setReg(args[0], v)
		}
		v, err := m.getReg(args[1])
		if err != nil {
			return false, err
		}
		return false, m.setReg(args[0], v)
	case "ADD":
		// "ADD SP, X19, #0x2, LSL #12" splits into four operands.
		if err := need(3); err != nil {
			return false, err
		}
		v, err := m.getReg(args[1])
		if err != nil {
			return false, err
		}
		imm, err := m.regOrImm(args[2])
		if err != nil {
			return false, err
		}
		if len(args) == 4 {
			if args[3] != "LSL #12" {
				return false, fmt.Errorf("shift %q", args[3])
			}
			imm <<= 12
		}
		return false, m.setReg(args[0], v+imm)
	case "CMP", "SUBS":
		var dst, src, immArg string
		if op == "CMP" {
			if err := need(2); err != nil {
				return false, err
			}
			src, immArg = args[0], args[1]
		} else {
			if err := need(3); err != nil {
				return false, err
			}
			dst, src, immArg = args[0], args[1], args[2]
		}
		a, err := m.getReg(src)
		if err != nil {
			return false, err
		}
		b, err := m.regOrImm(immArg)
		if err != nil {
			return false, err
		}
		_, wide, _, _ := a64ParseReg(src)
		m.setCmp(a, b, wide)
		if dst != "" {
			return false, m.setReg(dst, a-b)
		}
		return false, nil
	case "ADR":
		if err := need(2); err != nil {
			return false, err
		}
		off, err := a64BranchOffset(args[1])
		if err != nil {
			return false, err
		}
		return false, m.setReg(args[0], m.pc+uint64(off))
	case "CBZ":
		if err := need(2); err != nil {
			return false, err
		}
		v, err := m.getReg(args[0])
		if err != nil {
			return false, err
		}
		if v != 0 {
			return false, nil
		}
		off, err := a64BranchOffset(args[1])
		next = m.pc + uint64(off)
		return false, err
	case "CBNZ":
		if err := need(2); err != nil {
			return false, err
		}
		v, err := m.getReg(args[0])
		if err != nil {
			return false, err
		}
		if v == 0 {
			return false, nil
		}
		off, err := a64BranchOffset(args[1])
		next = m.pc + uint64(off)
		return false, err
	case "B":
		if len(args) == 1 {
			off, err := a64BranchOffset(args[0])
			next = m.pc + uint64(off)
			return false, err
		}
		if err := need(2); err != nil {
			return false, err
		}
		ok, err := m.cond(args[0])
		if err != nil {
			return false, err
		}
		off, err := a64BranchOffset(args[1])
		if err != nil {
			return false, err
		}
		if ok {
			next = m.pc + uint64(off)
		}
		return false, nil
	case "BLR":
		if err := need(1); err != nil {
			return false, err
		}
		target, err := m.getReg(args[0])
		if err != nil {
			return false, err
		}
		if m.onCall == nil {
			return false, fmt.Errorf("call to %#x", target)
		}
		m.onCall(m, target)
		return false, nil
	case "BR":
		if err := need(1); err != nil {
			return false, err
		}
		target, err := m.getReg(args[0])
		if err != nil {
			return false, err
		}
		m.exit.jump = target
		return true, nil
	case "DMB":
		m.fences++
		if m.onFence != nil {
			m.onFence(m)
		}
		return false, nil
	case "YIELD":
		m.yields++
		if m.onYield != nil {
			m.onYield(m)
		}
		return false, nil
	case "BRK":
		if err := need(1); err != nil {
			return false, err
		}
		v, err := m.imm(args[0])
		m.exit.brk = int(v)
		return true, err
	}
	return false, fmt.Errorf("instruction %q is not in the emulated set", text)
}
