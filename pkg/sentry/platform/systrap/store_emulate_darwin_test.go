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
	"bytes"
	"testing"
)

// runStore decodes insn and runs it against a state with fixed register values.
// It returns the written bytes by address, the registers after the run, and
// the address of the first stored byte.
func runStore(t *testing.T, insn uint32) (writes map[uint64][]byte, ss armThreadState, addr uint64) {
	t.Helper()
	st, ok := decodeStore(insn)
	if !ok {
		t.Fatalf("decodeStore(%#08x) refused a store that the Sentry must run", insn)
	}
	ss.X[1], ss.X[2], ss.X[3], ss.X[4] = 0x1122334455667788, 0x1000, 3, 0x2000
	ss.X[5], ss.X[10] = 0xdead, 0x4000
	ss.SP = 0x3000
	var ns armNeonState
	for i := range ns.V[0] {
		ns.V[0][i] = byte(0xa0 + i)
		ns.V[1][i] = byte(0xb0 + i)
		ns.V[2][i] = byte(0xc0 + i)
	}
	var x18 uint64 = 0x1800
	writes = map[uint64][]byte{}
	addr, ok = st.execute(storeRegs{ss: &ss, ns: &ns, x18: &x18},
		func(uint64, int) bool { return true },
		func(a uint64, b []byte) { writes[a] = append([]byte(nil), b...) })
	if !ok {
		t.Fatalf("execute(%#08x) failed although the check accepts every range", insn)
	}
	return writes, ss, addr
}

func TestStoreEmulationWritesTheBytesAndTheWriteback(t *testing.T) {
	le := func(v uint64, n int) []byte {
		b := make([]byte, 8)
		for i := range b {
			b[i] = byte(v >> (8 * i))
		}
		return b[:n]
	}
	// The words come from an assembler. The comment names the instruction.
	for _, tc := range []struct {
		name       string
		insn       uint32
		wantWrites map[uint64][]byte
		wantBase   map[int]uint64 // register number to value after the run
	}{
		{"str x1, [x2, #16]", 0xf9000841, map[uint64][]byte{0x1010: le(0x1122334455667788, 8)}, map[int]uint64{2: 0x1000}},
		{"strb w1, [x2, #3]", 0x39000c41, map[uint64][]byte{0x1003: {0x88}}, nil},
		{"strh w1, [x2, #2]", 0x79000441, map[uint64][]byte{0x1002: {0x88, 0x77}}, nil},
		{"str w1, [x2], #4", 0xb8004441, map[uint64][]byte{0x1000: le(0x55667788, 4)}, map[int]uint64{2: 0x1004}},
		{"str x1, [x2, #-8]!", 0xf81f8c41, map[uint64][]byte{0xff8: le(0x1122334455667788, 8)}, map[int]uint64{2: 0xff8}},
		{"stur x1, [x2, #-3]", 0xf81fd041, map[uint64][]byte{0xffd: le(0x1122334455667788, 8)}, nil},
		{"str x1, [x2, x3, lsl #3]", 0xf8237841, map[uint64][]byte{0x1018: le(0x1122334455667788, 8)}, nil},
		{"str w1, [x2, w3, sxtw]", 0xb823c841, map[uint64][]byte{0x1003: le(0x55667788, 4)}, nil},
		{"str x1, [x2, w3, uxtw #3]", 0xf8235841, map[uint64][]byte{0x1018: le(0x1122334455667788, 8)}, nil},
		{"strb w1, [x2, x3]", 0x38236841, map[uint64][]byte{0x1003: {0x88}}, nil},
		{"stp x1, x3, [x4, #16]", 0xa9010c81, map[uint64][]byte{0x2010: le(0x1122334455667788, 8), 0x2018: le(3, 8)}, map[int]uint64{4: 0x2000}},
		{"stp w1, w3, [x4], #8", 0x28810c81, map[uint64][]byte{0x2000: le(0x55667788, 4), 0x2004: le(3, 4)}, map[int]uint64{4: 0x2008}},
		{"stp x1, x3, [x4, #-16]!", 0xa9bf0c81, map[uint64][]byte{0x1ff0: le(0x1122334455667788, 8), 0x1ff8: le(3, 8)}, map[int]uint64{4: 0x1ff0}},
		{"stnp x1, x3, [x4]", 0xa8000c81, map[uint64][]byte{0x2000: le(0x1122334455667788, 8), 0x2008: le(3, 8)}, nil},
		{"str xzr, [x2]", 0xf900005f, map[uint64][]byte{0x1000: le(0, 8)}, nil},
		{"str x1, [sp, #8]", 0xf90007e1, map[uint64][]byte{0x3008: le(0x1122334455667788, 8)}, nil},
		{"str q0, [x2, #16]", 0x3d800440, map[uint64][]byte{0x1010: {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf}}, nil},
		{"str d0, [x2]", 0xfd000040, map[uint64][]byte{0x1000: {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7}}, nil},
		{"str s0, [x2, #4]", 0xbd000440, map[uint64][]byte{0x1004: {0xa0, 0xa1, 0xa2, 0xa3}}, nil},
		{"stur q2, [x2, #-1]", 0x3c9ff042, map[uint64][]byte{0xfff: {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf}}, nil},
		{"stp d0, d1, [x2, #16]", 0x6d010440, map[uint64][]byte{0x1010: {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7}, 0x1018: {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7}}, nil},
		{"stxr w5, w4, [x10]", 0x88057d44, map[uint64][]byte{0x4000: le(0x2000, 4)}, map[int]uint64{5: 0}},
		{"stlxr w5, x1, [x2]", 0xc805fc41, map[uint64][]byte{0x1000: le(0x1122334455667788, 8)}, map[int]uint64{5: 0}},
		{"stxrb w5, w1, [x2]", 0x08057c41, map[uint64][]byte{0x1000: {0x88}}, map[int]uint64{5: 0}},
		{"stxp w5, w1, w3, [x4]", 0x88250c81, map[uint64][]byte{0x2000: le(0x55667788, 4), 0x2004: le(3, 4)}, map[int]uint64{5: 0}},
		{"stlxp w5, x1, x3, [x4]", 0xc8258c81, map[uint64][]byte{0x2000: le(0x1122334455667788, 8), 0x2008: le(3, 8)}, map[int]uint64{5: 0}},
		{"stlr x1, [x2]", 0xc89ffc41, map[uint64][]byte{0x1000: le(0x1122334455667788, 8)}, map[int]uint64{5: 0xdead}},
		{"stlrb w1, [x2]", 0x089ffc41, map[uint64][]byte{0x1000: {0x88}}, map[int]uint64{5: 0xdead}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writes, ss, _ := runStore(t, tc.insn)
			if len(writes) != len(tc.wantWrites) {
				t.Fatalf("wrote %d ranges %v, want %d ranges", len(writes), writes, len(tc.wantWrites))
			}
			for a, want := range tc.wantWrites {
				if got := writes[a]; !bytes.Equal(got, want) {
					t.Errorf("bytes at %#x = % x, want % x", a, got, want)
				}
			}
			for reg, want := range tc.wantBase {
				if ss.X[reg] != want {
					t.Errorf("x%d = %#x after the store, want %#x", reg, ss.X[reg], want)
				}
			}
		})
	}
}

func TestDecodeStoreRefusesWhatTheSentryCannotRun(t *testing.T) {
	for _, tc := range []struct {
		name string
		insn uint32
	}{
		{"ldr x0, [x1, #8]", 0xf9400420},
		{"ldp x0, x1, [x2]", 0xa9400440},
		{"swp x1, x2, [x3]", 0xf8218062},
		{"add x0, x1, x2", 0x8b020020},
	} {
		if _, ok := decodeStore(tc.insn); ok {
			t.Errorf("decodeStore accepted %s", tc.name)
		}
	}
}

func TestStoreEmulationRefusesARangeThatTheCheckRejects(t *testing.T) {
	st, ok := decodeStore(0xf9000841) // str x1, [x2, #16]
	if !ok {
		t.Fatal("decodeStore refused str")
	}
	var ss armThreadState
	var ns armNeonState
	var x18 uint64
	ss.X[2] = 0x1000
	wrote := false
	_, ok = st.execute(storeRegs{ss: &ss, ns: &ns, x18: &x18},
		func(uint64, int) bool { return false },
		func(uint64, []byte) { wrote = true })
	if ok || wrote {
		t.Errorf("execute = %v and wrote = %v, want a refusal with no write", ok, wrote)
	}
}

func TestEmulateAtomicOrCacheOp(t *testing.T) {
	mem := make([]byte, 128)
	for i := range mem {
		mem[i] = 0xff
	}
	var ss armThreadState
	var ns armNeonState
	var x18 uint64
	regs := storeRegs{ss: &ss, ns: &ns, x18: &x18}
	check := func(addr uint64, n int) bool {
		return addr >= 0x1000 && addr+uint64(n) <= 0x1000+uint64(len(mem))
	}
	read := func(addr uint64, n int) []byte {
		off := addr - 0x1000
		out := make([]byte, n)
		copy(out, mem[off:int(off)+n])
		return out
	}
	write := func(addr uint64, b []byte) {
		off := addr - 0x1000
		copy(mem[off:], b)
	}

	// dc zva, x2 zeroes the 64-byte cache line containing x2.
	ss.X[2] = 0x1018
	if _, ok := emulateAtomicOrCacheOp(0xd50b7422, regs, check, read, write); !ok {
		t.Fatal("emulateAtomicOrCacheOp refused dc zva")
	}
	for i := 0; i < 64; i++ {
		if mem[i] != 0 {
			t.Fatalf("mem[%d] = %#x after dc zva, want 0", i, mem[i])
		}
	}
	if mem[64] != 0xff {
		t.Fatalf("mem[64] = %#x, want 0xff outside the cache line", mem[64])
	}

	// ldadd x1, x0, [x2] at 0x1000: old=0, add 42 -> mem=42, x0=0; then add 8 -> mem=50, x0=42.
	ss.X[2] = 0x1000
	ss.X[1] = 42
	if _, ok := emulateAtomicOrCacheOp(0xf8210040, regs, check, read, write); !ok {
		t.Fatal("emulateAtomicOrCacheOp refused ldadd")
	}
	if ss.X[0] != 0 {
		t.Fatalf("x0 = %d after first ldadd, want 0", ss.X[0])
	}
	ss.X[1] = 8
	if _, ok := emulateAtomicOrCacheOp(0xf8210040, regs, check, read, write); !ok {
		t.Fatal("emulateAtomicOrCacheOp refused second ldadd")
	}
	if ss.X[0] != 42 || decodeLEUint(mem[:8]) != 50 {
		t.Fatalf("after second ldadd: x0=%d mem=%d, want 42 and 50", ss.X[0], decodeLEUint(mem[:8]))
	}

	// cas x3, x4, [x2] at 0x1000: compare x3=50, swap with x4=99.
	ss.X[3] = 50
	ss.X[4] = 99
	if _, ok := emulateAtomicOrCacheOp(0xc8a37c44, regs, check, read, write); !ok {
		t.Fatal("emulateAtomicOrCacheOp refused cas")
	}
	if ss.X[3] != 50 || decodeLEUint(mem[:8]) != 99 {
		t.Fatalf("after cas: x3=%d mem=%d, want 50 and 99", ss.X[3], decodeLEUint(mem[:8]))
	}
}
