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

//go:build darwin && arm64

package systrap

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"sync"

	"golang.org/x/arch/arm64/arm64asm"

	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// The kernel of macOS zeroes x18 whenever a thread returns from an exception.
// Timer interrupts and page faults are exceptions, so no guest value survives
// in the real x18. Linux compilers use x18 as an ordinary temporary, and the
// dynamic loader of musl does too. The guest x18 therefore lives in the
// sysmsg, and every instruction that names x18 runs in a slot that swaps the
// word of the sysmsg for a borrowed scratch register.
//
// A slot never keeps a value in the real x18 across an instruction that can
// be interrupted without a way to recover. It uses the real x18 only to hold
// the sysmsg pointer for one load or store. An interrupt that zeroes the
// pointer makes that load or store fault at an address below 4KB, and the
// Sentry restarts the phase. Every phase is idempotent for that reason.

const (
	// x18Reg is the register that the kernel clobbers.
	x18Reg = 18

	// x18SlotHead is the byte size of the phase that borrows a scratch register.
	x18SlotHead = 16
	// x18SlotTail is the byte size of the phase that stores the result and
	// returns the scratch register, without the closing branch.
	x18SlotTail = 16

	// x18CondSlotSize is the byte size of a slot for cbz, cbnz, tbz and tbnz.
	x18CondSlotSize = 52
	// x18CondTaken and x18CondFall are the offsets of the two restore phases.
	x18CondFall  = 20
	x18CondTaken = 36

	// x18MaxBody is the longest body that planX18 produces: the four words of
	// a 64-bit constant and a load.
	x18MaxBody = 5

	// faultLowLimit bounds a fault address that the Sentry attributes to a
	// zeroed x18. Every sysmsg offset is below it.
	faultLowLimit = 4096
)

// siteKind values of the x18 classes.
const (
	// siteX18 is an instruction that names x18 and runs in a body slot.
	siteX18 siteKind = iota + 100
	// siteX18Cond is a compare-and-branch or test-and-branch on x18.
	siteX18Cond
	// siteX18Jump is br, blr or ret through x18. The Sentry takes the branch.
	siteX18Jump
)

// x18Plan describes the slot of one instruction that names x18.
type x18Plan struct {
	kind siteKind
	// scratch is the register that stands in for x18.
	scratch uint8
	// body holds the instruction words that run between the two phases.
	body []uint32
	// test is the branch word of a siteX18Cond slot, rewritten for the scratch
	// register and with its offset field cleared.
	test uint32
	// target is the destination of the branch of a siteX18Cond slot.
	target uint64
	// link is true for blr, which also writes the return address.
	link bool
}

// x18RegX, x18RegW and regAny find the general-purpose registers in the text of
// a decoded instruction.
var (
	x18RegX = regexp.MustCompile(`\bX18\b`)
	x18RegW = regexp.MustCompile(`\bW18\b`)
	regAny  = regexp.MustCompile(`\b[XW]([0-9]+)\b`)
)

// x18FieldShifts are the bit positions of the five-bit register fields that
// an A64 instruction uses.
var x18FieldShifts = [...]uint{0, 5, 10, 16}

// lseFieldShifts are the register fields of an atomic operation. Bits 14:10
// of such an instruction hold an opcode.
var lseFieldShifts = [...]uint{0, 5, 16}

func fieldAt(w uint32, shift uint) uint32 { return (w >> shift) & 0x1f }

// isLSEAtomic reports whether w is a compare-and-swap, swap or atomic
// read-modify-write instruction. The decoder of x/arch does not know them, and
// all three of their register fields name general-purpose registers.
func isLSEAtomic(w uint32) bool {
	switch {
	case w&0x3f200c00 == 0x38200000: // LDADD, LDCLR, LDEOR, LDSET, LDSMAX, ..., SWP
		return true
	case w&0x3fa07c00 == 0x08a07c00: // CAS
		return true
	case w&0xbfa07c00 == 0x08207c00: // CASP
		return true
	}
	return false
}

// movConst returns the words that load v into register rd.
func movConst(rd uint8, v uint64) []uint32 {
	return hvcommon.MovConstCompact(int(rd), v)
}

// decodeMu serializes decodeARM64. Decode of x/arch sets a flag in a package
// level coverage array on every call, so two address spaces that patch at the
// same time race on that array.
var decodeMu sync.Mutex

// decodeARM64 decodes one instruction. It is safe for concurrent use.
func decodeARM64(b []byte) (arm64asm.Inst, error) {
	decodeMu.Lock()
	defer decodeMu.Unlock()
	return arm64asm.Decode(b)
}

// planX18 decides whether the instruction w at address site names x18 and
// returns the slot that replaces it. It returns nil for every other word.
//
// WHY: the decoder of x/arch serves as the oracle for the register fields. A
// field that holds 18 can also be an immediate, so planX18 rewrites a field
// only when the decoded instruction of the rewritten word equals the decoded
// original with x18 renamed.
func planX18(w uint32, site uint64) *x18Plan {
	mayNameX18 := false
	for _, sh := range x18FieldShifts {
		if fieldAt(w, sh) == x18Reg {
			mayNameX18 = true
		}
	}
	if !mayNameX18 {
		return nil
	}
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], w)
	inst, err := decodeARM64(raw[:])
	if err != nil {
		if isLSEAtomic(w) {
			return planAtomic(w)
		}
		return nil
	}
	text := inst.String()
	if !x18RegX.MatchString(text) && !x18RegW.MatchString(text) {
		return nil
	}
	switch inst.Op {
	case arm64asm.BR, arm64asm.BLR, arm64asm.RET:
		if r, ok := inst.Args[0].(arm64asm.Reg); ok && r == arm64asm.X18 {
			return &x18Plan{kind: siteX18Jump, link: inst.Op == arm64asm.BLR}
		}
		return nil
	case arm64asm.CBZ, arm64asm.CBNZ, arm64asm.TBZ, arm64asm.TBNZ:
		return planCond(w, site, inst, text)
	case arm64asm.ADR, arm64asm.ADRP:
		return planAddress(site, inst)
	}
	for _, a := range inst.Args {
		if _, pc := a.(arm64asm.PCRel); pc {
			return planLiteral(site, inst)
		}
	}
	return planGeneric(w, text)
}

// scratchFor returns a register that the instruction does not name.
func scratchFor(w uint32, text string) (uint8, bool) {
	var used [32]bool
	for _, sh := range x18FieldShifts {
		used[fieldAt(w, sh)] = true
	}
	for _, m := range regAny.FindAllStringSubmatch(text, -1) {
		if n, err := strconv.Atoi(m[1]); err == nil && n < 32 {
			used[n] = true
		}
	}
	for r := 17; r >= 0; r-- {
		if !used[r] {
			return uint8(r), true
		}
	}
	return 0, false
}

// renameX18 returns the text of an instruction with x18 renamed to register r.
func renameX18(text string, r uint8) string {
	n := strconv.Itoa(int(r))
	text = x18RegX.ReplaceAllString(text, "X"+n)
	return x18RegW.ReplaceAllString(text, "W"+n)
}

// planGeneric renames x18 in the instruction.
func planGeneric(w uint32, text string) *x18Plan {
	scratch, ok := scratchFor(w, text)
	if !ok {
		return nil
	}
	var positions []uint
	for _, sh := range x18FieldShifts {
		if fieldAt(w, sh) == x18Reg {
			positions = append(positions, sh)
		}
	}
	rewrite := func(mask int) uint32 {
		out := w
		for i, sh := range positions {
			if mask&(1<<i) != 0 {
				out = out&^(0x1f<<sh) | uint32(scratch)<<sh
			}
		}
		return out
	}
	want := renameX18(text, scratch)
	// Try the largest sets of fields first, because most instructions name x18
	// in every field that holds 18.
	full := 1<<len(positions) - 1
	for size := len(positions); size >= 1; size-- {
		for mask := full; mask > 0; mask-- {
			if popcount(mask) != size {
				continue
			}
			cand := rewrite(mask)
			var raw [4]byte
			binary.LittleEndian.PutUint32(raw[:], cand)
			got, err := decodeARM64(raw[:])
			if err == nil && got.String() == want {
				return &x18Plan{kind: siteX18, scratch: scratch, body: []uint32{cand}}
			}
		}
	}
	return nil
}

// planAtomic renames x18 in an atomic operation that the decoder does not
// know. All three register fields of such an instruction name registers.
func planAtomic(w uint32) *x18Plan {
	scratch, ok := scratchFor(w, "")
	if !ok {
		return nil
	}
	out := w
	for _, sh := range lseFieldShifts {
		if fieldAt(w, sh) == x18Reg {
			out = out&^(0x1f<<sh) | uint32(scratch)<<sh
		}
	}
	if out == w {
		return nil
	}
	return &x18Plan{kind: siteX18, scratch: scratch, body: []uint32{out}}
}

func popcount(n int) int {
	c := 0
	for ; n != 0; n &= n - 1 {
		c++
	}
	return c
}

// planCond builds the slot of a compare-and-branch or test-and-branch.
func planCond(w uint32, site uint64, inst arm64asm.Inst, text string) *x18Plan {
	if r, ok := inst.Args[0].(arm64asm.Reg); !ok || (r != arm64asm.X18 && r != arm64asm.W18) {
		return nil
	}
	scratch, ok := scratchFor(w, text)
	if !ok {
		return nil
	}
	rel, ok := lastPCRel(inst)
	if !ok {
		return nil
	}
	test := w&^0x1f | uint32(scratch)
	switch inst.Op {
	case arm64asm.CBZ, arm64asm.CBNZ:
		test &^= 0x7ffff << 5
	default:
		test &^= 0x3fff << 5
	}
	// The slot branches forward from the test word to the taken path.
	test |= (x18CondTaken - x18SlotHead) / 4 << 5
	return &x18Plan{kind: siteX18Cond, scratch: scratch, test: test, target: uint64(int64(site) + int64(rel))}
}

func lastPCRel(inst arm64asm.Inst) (arm64asm.PCRel, bool) {
	for _, a := range inst.Args {
		if p, ok := a.(arm64asm.PCRel); ok {
			return p, true
		}
	}
	return 0, false
}

// planAddress builds the slot of adr and adrp with x18 as destination. The
// slot loads the address that the instruction would compute at its own site.
func planAddress(site uint64, inst arm64asm.Inst) *x18Plan {
	if r, ok := inst.Args[0].(arm64asm.Reg); !ok || r != arm64asm.X18 {
		return nil
	}
	rel, ok := lastPCRel(inst)
	if !ok {
		return nil
	}
	base := site
	if inst.Op == arm64asm.ADRP {
		base = site &^ 0xfff
	}
	const scratch = 17
	return &x18Plan{kind: siteX18, scratch: scratch, body: movConst(scratch, uint64(int64(base)+int64(rel)))}
}

// planLiteral builds the slot of a load from a literal pool into x18.
func planLiteral(site uint64, inst arm64asm.Inst) *x18Plan {
	dst, ok := inst.Args[0].(arm64asm.Reg)
	if !ok || (dst != arm64asm.X18 && dst != arm64asm.W18) {
		return nil
	}
	rel, ok := lastPCRel(inst)
	if !ok {
		return nil
	}
	const scratch = 17
	body := movConst(scratch, uint64(int64(site)+int64(rel)))
	var load uint32
	switch {
	case inst.Op == arm64asm.LDRSW:
		load = 0xb9800000
	case dst == arm64asm.X18:
		load = 0xf9400000
	default:
		load = 0xb9400000
	}
	body = append(body, load|scratch<<5|scratch)
	return &x18Plan{kind: siteX18, scratch: scratch, body: body}
}

// planTPIDRRead builds the slot of `mrs x18, tpidr_el0`. The slot loads the
// virtual TLS word of the thread.
func planTPIDRRead() *x18Plan {
	const scratch = 17
	return &x18Plan{kind: siteX18, scratch: scratch, body: []uint32{
		arm64MRSTPIDRRO | scratch,
		arm64ANDxMinus8 | scratch<<5 | scratch,
		hvcommon.LDRX(scratch, scratch, tlsOffset),
	}}
}

// planCTRRead builds the slot of `mrs x18, ctr_el0`. The slot loads the CTR_EL0
// value that the guest sees.
func planCTRRead() *x18Plan {
	const scratch = 17
	ws := ctrWords(scratch)
	return &x18Plan{kind: siteX18, scratch: scratch, body: ws[:]}
}

// slotSize returns the byte size of the slot that p needs.
func (p *x18Plan) slotSize() int {
	switch p.kind {
	case siteX18Cond:
		return x18CondSlotSize
	case siteX18Jump:
		return trapSlotSize
	}
	return x18SlotHead + 4*len(p.body) + x18SlotTail + 4
}

// sysmsgPointer returns the two words that load the sysmsg pointer into x18.
func sysmsgPointer() [2]uint32 {
	return [2]uint32{
		arm64MRSTPIDRRO | x18Reg,
		arm64ANDxMinus8 | x18Reg<<5 | x18Reg,
	}
}

func strFromSysmsg(reg uint8, off uint32) uint32 {
	return hvcommon.STRX(x18Reg, int(reg), int(off))
}

func ldrFromSysmsg(reg uint8, off uint32) uint32 {
	return hvcommon.LDRX(x18Reg, int(reg), int(off))
}

// encodeX18Slot writes the slot of p at slotVA into buf. The instruction of
// the guest sits at site, and the slot returns to site+4.
func encodeX18Slot(buf []byte, slotVA, site uint64, p *x18Plan) error {
	if p.kind == siteX18Jump {
		return fmt.Errorf("a jump through x18 uses a trap slot")
	}
	size := p.slotSize()
	if len(buf) < size {
		return fmt.Errorf("x18 slot buffer has %d bytes, need %d", len(buf), size)
	}
	ptr := sysmsgPointer()
	var words []uint32
	words = append(words, ptr[0], ptr[1],
		strFromSysmsg(p.scratch, spillOffset),
		ldrFromSysmsg(p.scratch, x18Offset))
	switch p.kind {
	case siteX18:
		words = append(words, p.body...)
		words = append(words, ptr[0], ptr[1],
			strFromSysmsg(p.scratch, x18Offset),
			ldrFromSysmsg(p.scratch, spillOffset))
		back, err := encodeBranch(slotVA+uint64(4*len(words)), site+4)
		if err != nil {
			return err
		}
		words = append(words, back)
	case siteX18Cond:
		words = append(words, p.test)
		words = append(words, ptr[0], ptr[1], ldrFromSysmsg(p.scratch, spillOffset))
		back, err := encodeBranch(slotVA+uint64(4*len(words)), site+4)
		if err != nil {
			return err
		}
		words = append(words, back)
		words = append(words, ptr[0], ptr[1], ldrFromSysmsg(p.scratch, spillOffset))
		jump, err := encodeBranch(slotVA+uint64(4*len(words)), p.target)
		if err != nil {
			return err
		}
		words = append(words, jump)
	default:
		return fmt.Errorf("unknown x18 slot kind %d", p.kind)
	}
	if len(words)*4 != size {
		return fmt.Errorf("x18 slot has %d bytes, planned %d", len(words)*4, size)
	}
	for i, w := range words {
		binary.LittleEndian.PutUint32(buf[i*4:], w)
	}
	return nil
}

// x18Restart reports where the Sentry restarts a slot after a fault. A fault
// at an address below faultLowLimit inside a phase that uses the real x18
// means that an interrupt zeroed the sysmsg pointer. Each phase is idempotent,
// so the thread continues at the phase start. body is true when the fault
// happened inside the guest instruction, where the Sentry rewinds to the site.
func x18Restart(kind siteKind, bodyWords int, off uint32) (restart uint32, body, ok bool) {
	switch kind {
	case siteX18:
		bodyEnd := uint32(x18SlotHead + 4*bodyWords)
		switch {
		case off < x18SlotHead:
			return 0, false, true
		case off < bodyEnd:
			return 0, true, true
		case off < bodyEnd+x18SlotTail:
			return bodyEnd, false, true
		}
	case siteX18Cond:
		switch {
		case off < x18SlotHead:
			return 0, false, true
		case off >= x18CondFall && off < x18CondFall+12:
			return x18CondFall, false, true
		case off >= x18CondTaken && off < x18CondTaken+12:
			return x18CondTaken, false, true
		}
	}
	return 0, false, false
}

// literalWords marks the words of code that a literal load reads, so that the
// scan keeps data in a literal pool intact.
func literalWords(code []byte) map[int]struct{} {
	var marks map[int]struct{}
	for off := 0; off+4 <= len(code); off += 4 {
		w := binary.LittleEndian.Uint32(code[off:])
		// LDR, LDRSW and PRFM with a literal address.
		if w&0x3b000000 != 0x18000000 {
			continue
		}
		imm := int64(int32(w>>5&0x7ffff) << 13 >> 13)
		target := off + int(imm)*4
		if target < 0 || target >= len(code) {
			continue
		}
		size := 4
		switch opc, vec := w>>30, w>>26&1; {
		case vec == 0 && opc == 1:
			size = 8
		case vec == 1 && opc == 1:
			size = 8
		case vec == 1 && opc == 2:
			size = 16
		}
		if marks == nil {
			marks = make(map[int]struct{})
		}
		for d := 0; d < size; d += 4 {
			marks[target+d] = struct{}{}
		}
	}
	return marks
}

// x18Site is one instruction that names x18.
type x18Site struct {
	// Offset is the byte offset of the instruction inside the scanned code.
	Offset uint32
	Plan   *x18Plan
}

// scanX18 returns the x18 sites of one code block. base is the guest address
// of code[0]. The scan skips every word for which skip returns true, and the
// words that a literal load reads.
func scanX18(code []byte, base uint64, skip func(off int) bool) []x18Site {
	var sites []x18Site
	lits := literalWords(code)
	for off := 0; off+4 <= len(code); off += 4 {
		if skip(off) {
			continue
		}
		if _, data := lits[off]; data {
			continue
		}
		w := binary.LittleEndian.Uint32(code[off:])
		if p := planX18(w, base+uint64(off)); p != nil {
			sites = append(sites, x18Site{Offset: uint32(off), Plan: p})
		}
	}
	return sites
}
