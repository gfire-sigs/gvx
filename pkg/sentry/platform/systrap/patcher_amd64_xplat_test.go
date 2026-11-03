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

//go:build darwin || windows

package systrap

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"reflect"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// syscallSite returns the expected amd64 SYSCALL site at off.
func syscallSite(off int) amd64Site {
	return amd64Site{Offset: off, Len: 2, Kind: amd64SiteSyscall}
}

// nops returns n NOP bytes.
func nops(n int) []byte {
	return bytes.Repeat([]byte{0x90}, n)
}

// catBytes joins byte slices into a new slice.
func catBytes(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

func TestScanAMD64FindsSyscall(t *testing.T) {
	// mov eax, 39; syscall; ret
	code := []byte{0xb8, 0x27, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3}
	for _, lead := range []int{0, 1, 7} {
		page := catBytes(nops(lead), code)
		got := scanAMD64(nil, page, nil)
		want := []amd64Site{syscallSite(lead + 5)}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("lead %d: scanAMD64 = %+v, want %+v", lead, got, want)
		}
	}
}

func TestScanAMD64IgnoresPatternInsideInstruction(t *testing.T) {
	cases := []struct {
		name string
		code []byte
	}{
		{"imm32", []byte{0xb8, 0x00, 0x0f, 0x05, 0x00, 0xc3}},                        // mov eax, 0x00050f00
		{"disp32 of rip-relative", []byte{0x8b, 0x05, 0x00, 0x0f, 0x05, 0x00, 0xc3}}, // mov eax, [rip+0x00050f00]
		{"disp32 of absolute", []byte{0x8b, 0x04, 0x25, 0x00, 0x0f, 0x05, 0x00, 0xc3}},
		{"modrm before opcode", []byte{0x8b, 0x0f, 0x05, 0x01, 0x00, 0x00, 0x00, 0xc3}}, // mov ecx, [rdi]; add eax, 1
		{"sib before disp8", []byte{0x8b, 0x44, 0x0f, 0x05, 0xc3}},                      // mov eax, [rdi+rcx+5]
		{"imm64", []byte{0x48, 0xb8, 0x11, 0x0f, 0x05, 0x44, 0x55, 0x66, 0x77, 0x88, 0xc3}},
	}
	for _, c := range cases {
		for _, lead := range []int{0, 3} {
			page := catBytes(nops(lead), c.code)
			if got := scanAMD64(nil, page, nil); len(got) != 0 {
				t.Errorf("%s, lead %d: scanAMD64 = %+v, want none", c.name, lead, got)
			}
		}
	}
}

func TestAMD64SyscallAcrossPageBoundary(t *testing.T) {
	pageA := nops(amd64PageSize)
	pageA[amd64PageSize-1] = 0x0f
	pageB := catBytes([]byte{0x05, 0xc3}, nops(amd64PageSize-2))
	beforeA := nops(15)
	afterA := pageB[:15]
	beforeB := pageA[amd64PageSize-15:]

	sitesA := scanAMD64(beforeA, pageA, afterA)
	if want := []amd64Site{syscallSite(amd64PageSize - 1)}; !reflect.DeepEqual(sitesA, want) {
		t.Fatalf("page A sites = %+v, want %+v", sitesA, want)
	}
	sitesB := scanAMD64(beforeB, pageB, nops(15))
	if want := []amd64Site{syscallSite(-1)}; !reflect.DeepEqual(sitesB, want) {
		t.Fatalf("page B sites = %+v, want %+v", sitesB, want)
	}

	spill, err := patchAMD64(pageA, sitesA)
	if err != nil || spill != 1 {
		t.Fatalf("patch page A = %d, %v, want spill 1", spill, err)
	}
	spill, err = patchAMD64(pageB, sitesB)
	if err != nil || spill != 0 {
		t.Fatalf("patch page B = %d, %v, want spill 0", spill, err)
	}
	if got := []byte{pageA[amd64PageSize-1], pageB[0]}; !bytes.Equal(got, amd64Trap[:]) {
		t.Fatalf("combined bytes = % x, want % x", got, amd64Trap)
	}
	if pageB[1] != 0xc3 {
		t.Fatalf("patch changed the ret that follows the site: % x", pageB[:2])
	}
}

func TestScanAMD64PageStartsInsideInstruction(t *testing.T) {
	// The page starts with the last four bytes of `mov rax, imm64`.
	insnHead := []byte{0x48, 0xb8, 0x01, 0x02, 0x03, 0x04}
	tail := []byte{0x05, 0x00, 0x00, 0x00}
	page := catBytes(tail, nops(2), []byte{0x0f, 0x05, 0xc3})
	want := []amd64Site{syscallSite(6)}

	if got := scanAMD64(insnHead, page, nil); !reflect.DeepEqual(got, want) {
		t.Errorf("with before: scanAMD64 = %+v, want %+v", got, want)
	}
	if got := scanAMD64(nil, page, nil); !reflect.DeepEqual(got, want) {
		t.Errorf("without before: scanAMD64 = %+v, want %+v", got, want)
	}
}

func TestScanAMD64SweepsOutvoteWrongStart(t *testing.T) {
	// The stream is a run of `mov eax, imm32` whose immediates hold 0f 05.
	// The page starts two bytes into a `mov`. A single sweep from the page
	// start reports a SYSCALL at offset 0 that does not exist. The sweeps
	// that start in before and decode from a real boundary out-vote it.
	mov := []byte{0xb8, 0x00, 0x0f, 0x05, 0x00}
	stream := catBytes(bytes.Repeat(mov, 67), []byte{0x0f, 0x05, 0xc3})
	const split = 17
	page := stream[split:]
	want := []amd64Site{syscallSite(len(stream) - 3 - split)}

	if got := scanAMD64(nil, page, nil); reflect.DeepEqual(got, want) {
		t.Fatalf("a single sweep from the page start found only the real site: the test input is too easy")
	}
	if got := scanAMD64(stream[split-15:split], page, nil); !reflect.DeepEqual(got, want) {
		t.Fatalf("scanAMD64 = %+v, want %+v", got, want)
	}
}

func TestScanAMD64LeadFindsBoundariesBeforePage(t *testing.T) {
	// The end of one page and the start of the next in the node binary of
	// node:20-alpine on amd64. The page starts with `movzx edx, word [rax+0x28]`,
	// and `lea rsp, [rbp-0x28]` (48 8d 65 d8) follows at offset 11. Sweeps that
	// start in the last 15 bytes of the lead mostly decode `8b 90 00 00 00 0f`
	// as one instruction, and they out-vote the real boundaries. They then report
	// a GS instruction at the 65 byte of the lea. Its patch made the lea an
	// illegal instruction.
	lead := []byte{
		0x89, 0xc6, 0x6a, 0x00, 0xe8, 0xc7, 0xf0, 0xff, 0xff, 0x48, 0x83, 0xc4, 0x20, 0x41, 0x80, 0x3c,
		0x24, 0x00, 0x74, 0x4c, 0x48, 0x8b, 0x53, 0x38, 0x31, 0xc9, 0x48, 0x89, 0x02, 0x48, 0x8d, 0x50,
		0x18, 0x48, 0x89, 0x53, 0x38, 0x0f, 0xb7, 0x50, 0x28, 0x66, 0x85, 0xd2, 0x79, 0x0c, 0x83, 0xe2,
		0x0f, 0x83, 0xea, 0x07, 0x80, 0xfa, 0x03, 0x0f, 0x96, 0xc1, 0x08, 0x8b, 0x90, 0x00, 0x00, 0x00,
	}
	page := catBytes([]byte{
		0x0f, 0xb7, 0x50, 0x28, 0x80, 0xce, 0x04, 0x66, 0x89, 0x50, 0x28, 0x48, 0x8d, 0x65, 0xd8, 0x5b,
		0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0xc3,
	}, nops(64))
	if len(lead) != amd64ScanLead {
		t.Fatalf("lead has %d bytes, want amd64ScanLead = %d", len(lead), amd64ScanLead)
	}
	if got := scanAMD64GS(lead[len(lead)-amd64MaxInsnLen:], page, nil, true); len(got) == 0 {
		t.Fatalf("a lead of %d bytes found no site: the test input is too easy", amd64MaxInsnLen)
	}
	if got := scanAMD64GS(lead, page, nil, true); len(got) != 0 {
		t.Fatalf("scanAMD64GS = %+v, want no site", got)
	}
}

func TestScanAMD64PrefixedSyscall(t *testing.T) {
	// The decoder counts the prefix as part of the instruction.
	// The site is still the pair 0f 05, so the prefix stays in place.
	page := catBytes([]byte{0x90, 0xf3, 0x48, 0x0f, 0x05, 0xc3})
	got := scanAMD64(nil, page, nil)
	if want := []amd64Site{syscallSite(3)}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scanAMD64 = %+v, want %+v", got, want)
	}
	if _, err := patchAMD64(page, got); err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x90, 0xf3, 0x48, 0xcc, 0x90, 0xc3}; !bytes.Equal(page, want) {
		t.Fatalf("page = % x, want % x", page, want)
	}
}

func TestScanAMD64RandomPages(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	fill := func(n int) []byte {
		b := make([]byte, n)
		rng.Read(b)
		for i := 0; i+1 < n; i++ {
			switch rng.Intn(40) {
			case 0:
				b[i], b[i+1] = 0x0f, 0x05
			case 1:
				b[i], b[i+1] = 0xf3, 0x48
			case 2:
				b[i], b[i+1] = 0x0f, 0xae
			}
		}
		return b
	}
	for iter := 0; iter < 200; iter++ {
		var before, after []byte
		if iter%4 != 0 {
			before = fill(rng.Intn(16))
		}
		if iter%5 != 0 {
			after = fill(rng.Intn(16))
		}
		page := fill(amd64PageSize)
		orig := append([]byte(nil), page...)
		sites := scanAMD64(before, page, after)

		view := catBytes(before, page, after)
		base := len(before)
		end := 0
		for _, s := range sites {
			if s.Offset < end {
				t.Fatalf("iter %d: site %+v overlaps the previous site that ends at %d", iter, s, end)
			}
			end = s.Offset + s.Len
			if s.Offset+base < 0 || end+base > len(view) {
				t.Fatalf("iter %d: site %+v leaves the known bytes", iter, s)
			}
			if s.Kind == amd64SiteSyscall && (view[base+s.Offset] != 0x0f || view[base+s.Offset+1] != 0x05) {
				t.Fatalf("iter %d: syscall site %+v has bytes % x", iter, s, view[base+s.Offset:base+end])
			}
			if s.Kind == amd64SiteRDFSBASE && (view[base+end-3] != 0x0f || view[base+end-2] != 0xae || view[base+end-1]>>6 != 3) {
				t.Fatalf("iter %d: rdfsbase site %+v has bytes % x", iter, s, view[base+s.Offset:base+end])
			}
		}
		if _, err := patchAMD64(page, sites); err != nil {
			t.Fatalf("iter %d: patchAMD64: %v", iter, err)
		}
		// Only site bytes change.
		covered := make([]bool, len(page))
		for _, s := range sites {
			for i := max(s.Offset, 0); i < min(s.Offset+s.Len, len(page)); i++ {
				covered[i] = true
			}
		}
		for i := range page {
			if !covered[i] && page[i] != orig[i] {
				t.Fatalf("iter %d: patch changed byte %d outside every site", iter, i)
			}
		}
	}
}

func TestScanAMD64RDFSBASE(t *testing.T) {
	cases := []struct {
		name string
		code []byte
		want amd64Site
	}{
		{"rax", []byte{0xf3, 0x48, 0x0f, 0xae, 0xc0}, amd64Site{Len: 5, Kind: amd64SiteRDFSBASE, Reg: 0, Wide: true}},
		{"rdi", []byte{0xf3, 0x48, 0x0f, 0xae, 0xc7}, amd64Site{Len: 5, Kind: amd64SiteRDFSBASE, Reg: 7, Wide: true}},
		{"r9", []byte{0xf3, 0x49, 0x0f, 0xae, 0xc1}, amd64Site{Len: 5, Kind: amd64SiteRDFSBASE, Reg: 9, Wide: true}},
		{"r15", []byte{0xf3, 0x49, 0x0f, 0xae, 0xc7}, amd64Site{Len: 5, Kind: amd64SiteRDFSBASE, Reg: 15, Wide: true}},
		{"edi", []byte{0xf3, 0x0f, 0xae, 0xc7}, amd64Site{Len: 4, Kind: amd64SiteRDFSBASE, Reg: 7}},
		{"r9d", []byte{0xf3, 0x41, 0x0f, 0xae, 0xc1}, amd64Site{Len: 5, Kind: amd64SiteRDFSBASE, Reg: 9}},
	}
	for _, c := range cases {
		page := catBytes(nops(3), c.code, []byte{0xc3})
		c.want.Offset = 3
		if got := scanAMD64(nil, page, nil); !reflect.DeepEqual(got, []amd64Site{c.want}) {
			t.Errorf("%s: scanAMD64 = %+v, want %+v", c.name, got, c.want)
		}
	}

	// RDGSBASE and the memory form are not sites.
	for _, code := range [][]byte{
		{0xf3, 0x0f, 0xae, 0xc8}, // rdgsbase eax
		{0xf3, 0x0f, 0xae, 0x00}, // not rdfsbase
		{0xf3, 0x0f, 0xae, 0xd0}, // wrfsbase eax
	} {
		if got := scanAMD64(nil, catBytes(code, []byte{0xc3}), nil); len(got) != 0 {
			t.Errorf("% x: scanAMD64 = %+v, want none", code, got)
		}
	}
}

func TestPatchAMD64RDFSBASE(t *testing.T) {
	page := catBytes([]byte{0x55}, []byte{0xf3, 0x48, 0x0f, 0xae, 0xc0}, []byte{0xc3})
	sites := scanAMD64(nil, page, nil)
	spill, err := patchAMD64(page, sites)
	if err != nil || spill != 0 {
		t.Fatalf("patchAMD64 = %d, %v", spill, err)
	}
	want := []byte{0x55, 0xcc, 0x90, 0x90, 0x90, 0x90, 0xc3}
	if !bytes.Equal(page, want) {
		t.Fatalf("page = % x, want % x", page, want)
	}
}

func TestScanAMD64RDFSBASEAcrossPageBoundary(t *testing.T) {
	// rdfsbase rdi has 5 bytes. Three lie in page A and two in page B.
	pageA := catBytes(nops(amd64PageSize-3), []byte{0xf3, 0x48, 0x0f})
	pageB := catBytes([]byte{0xae, 0xc7, 0xc3}, nops(amd64PageSize-3))
	sitesA := scanAMD64(nops(15), pageA, pageB[:15])
	wantA := []amd64Site{{Offset: amd64PageSize - 3, Len: 5, Kind: amd64SiteRDFSBASE, Reg: 7, Wide: true}}
	if !reflect.DeepEqual(sitesA, wantA) {
		t.Fatalf("page A sites = %+v, want %+v", sitesA, wantA)
	}
	sitesB := scanAMD64(pageA[amd64PageSize-15:], pageB, nil)
	wantB := []amd64Site{{Offset: -3, Len: 5, Kind: amd64SiteRDFSBASE, Reg: 7, Wide: true}}
	if !reflect.DeepEqual(sitesB, wantB) {
		t.Fatalf("page B sites = %+v, want %+v", sitesB, wantB)
	}
	if spill, err := patchAMD64(pageA, sitesA); err != nil || spill != 2 {
		t.Fatalf("patch page A = %d, %v, want spill 2", spill, err)
	}
	if spill, err := patchAMD64(pageB, sitesB); err != nil || spill != 0 {
		t.Fatalf("patch page B = %d, %v, want spill 0", spill, err)
	}
	if got, want := catBytes(pageA[amd64PageSize-3:], pageB[:2]), []byte{0xcc, 0x90, 0x90, 0x90, 0x90}; !bytes.Equal(got, want) {
		t.Fatalf("combined bytes = % x, want % x", got, want)
	}
	if pageB[2] != 0xc3 {
		t.Fatalf("patch changed the ret that follows the site")
	}
}

func TestScanAMD64LibcWrappers(t *testing.T) {
	cases := []struct {
		name string
		code []byte
		want []int
	}{
		{
			"glibc syscall()",
			[]byte{
				0x48, 0x89, 0xf8, // mov %rdi,%rax
				0x48, 0x89, 0xf7, // mov %rsi,%rdi
				0x48, 0x89, 0xd6, // mov %rdx,%rsi
				0x48, 0x89, 0xca, // mov %rcx,%rdx
				0x4d, 0x89, 0xc2, // mov %r8,%r10
				0x4d, 0x89, 0xc8, // mov %r9,%r8
				0x4c, 0x8b, 0x4c, 0x24, 0x08, // mov 0x8(%rsp),%r9
				0x0f, 0x05, // syscall
				0x48, 0x3d, 0x01, 0xf0, 0xff, 0xff, // cmp $-4095,%rax
				0x73, 0x01, // jae +1
				0xc3, // ret
			},
			[]int{23},
		},
		{
			"musl _exit",
			[]byte{
				0xb8, 0x3c, 0x00, 0x00, 0x00, // mov $0x3c,%eax
				0x0f, 0x05, // syscall
				0xf4, // hlt
			},
			[]int{5},
		},
		{
			"glibc getpid",
			[]byte{
				0xb8, 0x27, 0x00, 0x00, 0x00, // mov $0x27,%eax
				0x0f, 0x05, // syscall
				0xc3, // ret
			},
			[]int{5},
		},
		{
			"glibc read",
			[]byte{
				0x64, 0x8b, 0x04, 0x25, 0x18, 0x00, 0x00, 0x00, // mov %fs:0x18,%eax
				0x85, 0xc0, // test %eax,%eax
				0x75, 0x10, // jne +16
				0xb8, 0x00, 0x00, 0x00, 0x00, // mov $0,%eax
				0x0f, 0x05, // syscall
				0x48, 0x3d, 0x00, 0xf0, 0xff, 0xff, // cmp $-4096,%rax
				0x77, 0x01, // ja +1
				0xc3, // ret
			},
			[]int{17},
		},
		{
			"musl restore_rt",
			[]byte{
				0x48, 0xc7, 0xc0, 0x0f, 0x00, 0x00, 0x00, // mov $0xf,%rax
				0x0f, 0x05, // syscall
				0x0f, 0x0b, // ud2
			},
			[]int{7},
		},
		{
			"vfork tail",
			[]byte{
				0x5f,                         // pop %rdi
				0xb8, 0x3a, 0x00, 0x00, 0x00, // mov $0x3a,%eax
				0x0f, 0x05, // syscall
				0x57,                               // push %rdi
				0x48, 0x3d, 0x01, 0xf0, 0xff, 0xff, // cmp $-4095,%rax
				0xc3, // ret
			},
			[]int{6},
		},
		{
			"two calls",
			[]byte{
				0xb8, 0xe4, 0x00, 0x00, 0x00, // mov $0xe4,%eax
				0x0f, 0x05, // syscall
				0x48, 0x89, 0xc7, // mov %rax,%rdi
				0xb8, 0xe7, 0x00, 0x00, 0x00, // mov $0xe7,%eax
				0x0f, 0x05, // syscall
			},
			[]int{5, 15},
		},
	}
	for _, c := range cases {
		var want []amd64Site
		for _, off := range c.want {
			want = append(want, syscallSite(off))
		}
		if got := scanAMD64(nil, c.code, nil); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: scanAMD64 = %+v, want %+v", c.name, got, want)
		}
		// The same code at an odd offset behind other code.
		lead := []byte{0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3, 0x90} // push; mov; pop; ret; nop
		var shifted []amd64Site
		for _, off := range c.want {
			shifted = append(shifted, syscallSite(off+len(lead)))
		}
		page := catBytes(lead, c.code)
		if got := scanAMD64(nil, page, nil); !reflect.DeepEqual(got, shifted) {
			t.Errorf("%s shifted: scanAMD64 = %+v, want %+v", c.name, got, shifted)
		}
	}
}

func TestPatchAMD64Errors(t *testing.T) {
	good := func() []byte { return []byte{0x90, 0x0f, 0x05, 0x90} }
	cases := []struct {
		name  string
		page  []byte
		sites []amd64Site
	}{
		{"past end", good(), []amd64Site{syscallSite(4)}},
		{"before page", good(), []amd64Site{syscallSite(-2)}},
		{"wrong length", good(), []amd64Site{{Offset: 1, Len: 3, Kind: amd64SiteSyscall}}},
		{"wrong bytes", good(), []amd64Site{syscallSite(0)}},
		{"wrong tail byte", []byte{0x90}, []amd64Site{syscallSite(-1)}},
		{"short rdfsbase", good(), []amd64Site{{Offset: 0, Len: 3, Kind: amd64SiteRDFSBASE}}},
		{"unknown kind", good(), []amd64Site{{Offset: 0, Len: 2}}},
	}
	for _, c := range cases {
		orig := append([]byte(nil), c.page...)
		if _, err := patchAMD64(c.page, c.sites); err == nil {
			t.Errorf("%s: patchAMD64 succeeded", c.name)
		}
		if !bytes.Equal(c.page, orig) {
			t.Errorf("%s: patchAMD64 changed the page on error", c.name)
		}
	}
}

// TestEmulateSegMemInsnFSAccesses runs the %fs instructions that faulted in
// Node.js guests on windows/amd64 after Windows reset the FS base: the stack
// canary load and check, and glibc TLS loads at negative offsets.
func TestEmulateSegMemInsnFSAccesses(t *testing.T) {
	const fsBase = 0x7f0000001000
	tls := make([]byte, 0x2000) // guest memory [fsBase-0x1000, fsBase+0x1000)
	lo := uint64(fsBase - 0x1000)
	binary.LittleEndian.PutUint64(tls[0x1000+0x28:], 0x1122334455667788)  // fs:[0x28]
	binary.LittleEndian.PutUint64(tls[0x1000-0x1b8:], 0xaaaabbbbccccdddd) // fs:[-0x1b8]
	binary.LittleEndian.PutUint32(tls[0x1000+0x2d0:], 0x80000001)         // fs:[0x2d0]
	readMem := func(addr uint64, buf []byte) bool {
		if addr < lo || addr+uint64(len(buf)) > lo+uint64(len(tls)) {
			return false
		}
		copy(buf, tls[addr-lo:])
		return true
	}
	writeMem := func(addr uint64, buf []byte) bool {
		if addr < lo || addr+uint64(len(buf)) > lo+uint64(len(tls)) {
			return false
		}
		copy(tls[addr-lo:], buf)
		return true
	}
	const (
		rax = 0
		rdx = 2
		rbx = 3
		rbp = 5
		r12 = 12
	)
	cases := []struct {
		name    string
		code    []byte
		set     map[int]uint64
		reg     int
		want    uint64
		wantZF  bool
		checkZF bool
	}{
		{name: "mov rax, fs:[0x28]", code: []byte{0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00}, reg: rax, want: 0x1122334455667788},
		{name: "mov rdx, fs:[r12] with a negative r12", code: []byte{0x64, 0x49, 0x8b, 0x14, 0x24}, set: map[int]uint64{r12: 0xfffffffffffffe48}, reg: rdx, want: 0xaaaabbbbccccdddd},
		{name: "mov eax, fs:[0x2d0] clears the upper half", code: []byte{0x64, 0x8b, 0x04, 0x25, 0xd0, 0x02, 0x00, 0x00}, set: map[int]uint64{rax: ^uint64(0)}, reg: rax, want: 0x80000001},
		{name: "mov ebp, fs:[rbx]", code: []byte{0x64, 0x8b, 0x2b}, set: map[int]uint64{rbx: 0x28}, reg: rbp, want: 0x55667788},
		{name: "sub rax, fs:[0x28] with an intact canary", code: []byte{0x64, 0x48, 0x2b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00}, set: map[int]uint64{rax: 0x1122334455667788}, reg: rax, want: 0, checkZF: true, wantZF: true},
		{name: "sub rax, fs:[0x28] with a smashed canary", code: []byte{0x64, 0x48, 0x2b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00}, set: map[int]uint64{rax: 0x1122334455667789}, reg: rax, want: 1, checkZF: true, wantZF: false},
	}
	for _, c := range cases {
		var regs [16]uint64
		for r, v := range c.set {
			regs[r] = v
		}
		var eflags uint32
		out := emulateSegMemInsn(c.code, x86asm.FS, fsBase, &regs, &eflags, readMem, writeMem)
		if !out.ok || out.fault {
			t.Errorf("%s: outcome %+v, want ok", c.name, out)
			continue
		}
		if regs[c.reg] != c.want {
			t.Errorf("%s: register %d = %#x, want %#x", c.name, c.reg, regs[c.reg], c.want)
		}
		if c.checkZF && (eflags&eflagZF != 0) != c.wantZF {
			t.Errorf("%s: ZF = %v, want %v", c.name, eflags&eflagZF != 0, c.wantZF)
		}
	}

	// A GS instruction does not address memory through %fs.
	var regs [16]uint64
	var eflags uint32
	gsLoad := []byte{0x65, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00}
	if out := emulateSegMemInsn(gsLoad, x86asm.FS, fsBase, &regs, &eflags, readMem, writeMem); out.ok {
		t.Errorf("mov rax, gs:[0x28] emulated through %%fs")
	}
}

// TestIsAtomicMemInsn verifies that the FS repair leaves bus-locked
// instructions to the hardware.
func TestIsAtomicMemInsn(t *testing.T) {
	cases := []struct {
		name string
		code []byte
		want bool
	}{
		{"mov rax, fs:[0x28]", []byte{0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00}, false},
		{"add fs:[rax], ecx", []byte{0x64, 0x01, 0x08}, false},
		{"lock add fs:[rax], ecx", []byte{0xf0, 0x64, 0x01, 0x08}, true},
		{"fs lock add [rax], ecx", []byte{0x64, 0xf0, 0x01, 0x08}, true},
		{"xchg fs:[rax], rcx", []byte{0x64, 0x48, 0x87, 0x08}, true},
		{"lock cmpxchg fs:[rdx], rcx", []byte{0xf0, 0x64, 0x48, 0x0f, 0xb1, 0x0a}, true},
		{"xadd fs:[rdx], ecx", []byte{0x64, 0x0f, 0xc1, 0x0a}, true},
	}
	for _, c := range cases {
		inst, err := decodeX86(c.code)
		if err != nil {
			t.Fatalf("%s: decode: %v", c.name, err)
		}
		if got := isAtomicMemInsn(inst); got != c.want {
			t.Errorf("%s: isAtomicMemInsn = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestScanAMD64GSAndEmulateSegMemInsn(t *testing.T) {
	// Wine64 TEB sequence:
	//   rdgsbase r8                (f3 49 0f ae c8, len 5)
	//   mov rax, gs:[0x30]         (65 48 8b 04 25 30 00 00 00, len 9)
	//   mov gs:[rcx+0x1480], rdx   (65 48 89 91 80 14 00 00, len 8)
	//   add qword ptr gs:[0x10], 7 (65 48 83 04 25 10 00 00 00 07, len 10)
	//   ret                        (c3)
	code := []byte{
		0xf3, 0x49, 0x0f, 0xae, 0xc8,
		0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,
		0x65, 0x48, 0x89, 0x91, 0x80, 0x14, 0x00, 0x00,
		0x65, 0x48, 0x83, 0x04, 0x25, 0x10, 0x00, 0x00, 0x00, 0x07,
		0xc3,
	}
	if got := scanAMD64(nil, code, nil); len(got) != 0 {
		t.Fatalf("scanAMD64 without gsMem found %+v, want none", got)
	}
	sites := scanAMD64GS(nil, code, nil, true)
	want := []amd64Site{
		{Offset: 0, Len: 5, Kind: amd64SiteRDGSBASE, Reg: 8, Wide: true},
		{Offset: 5, Len: 9, Kind: amd64SiteGSMem},
		{Offset: 14, Len: 8, Kind: amd64SiteGSMem},
		{Offset: 22, Len: 10, Kind: amd64SiteGSMem},
	}
	if !reflect.DeepEqual(sites, want) {
		t.Fatalf("scanAMD64GS = %+v, want %+v", sites, want)
	}

	teb := make([]byte, 0x2000)
	const gsBase = 0x7fff00000000
	// Populate TEB->Self at offset 0x30 and a counter at 0x10.
	binary.LittleEndian.PutUint64(teb[0x30:], gsBase)
	binary.LittleEndian.PutUint64(teb[0x10:], 35)

	readMem := func(addr uint64, buf []byte) bool {
		if addr < gsBase || addr+uint64(len(buf)) > gsBase+uint64(len(teb)) {
			return false
		}
		copy(buf, teb[addr-gsBase:])
		return true
	}
	writeMem := func(addr uint64, buf []byte) bool {
		if addr < gsBase || addr+uint64(len(buf)) > gsBase+uint64(len(teb)) {
			return false
		}
		copy(teb[addr-gsBase:], buf)
		return true
	}

	var regs [16]uint64
	var eflags uint32
	regs[1] = 8                  // RCX = 8 (TlsSlots[1])
	regs[2] = 0xfeedfacecafebabe // RDX

	// 1. mov rax, gs:[0x30]
	if out := emulateSegMemInsn(code[5:14], x86asm.GS, gsBase, &regs, &eflags, readMem, writeMem); !out.ok || out.fault {
		t.Fatalf("emulate mov load = %+v", out)
	}
	if regs[0] != gsBase {
		t.Fatalf("RAX after mov rax, gs:[0x30] = %#x, want %#x", regs[0], gsBase)
	}

	// 2. mov gs:[rcx+0x1480], rdx
	if out := emulateSegMemInsn(code[14:22], x86asm.GS, gsBase, &regs, &eflags, readMem, writeMem); !out.ok || out.fault {
		t.Fatalf("emulate mov store = %+v", out)
	}
	// Verify with mov r9, gs:[0x1488] (65 4c 8b 0c 25 88 14 00 00)
	loadSlot1 := []byte{0x65, 0x4c, 0x8b, 0x0c, 0x25, 0x88, 0x14, 0x00, 0x00}
	if out := emulateSegMemInsn(loadSlot1, x86asm.GS, gsBase, &regs, &eflags, readMem, writeMem); !out.ok || out.fault {
		t.Fatalf("emulate mov slot1 load = %+v", out)
	}
	if regs[9] != 0xfeedfacecafebabe {
		t.Fatalf("R9 = %#x, want 0xfeedfacecafebabe", regs[9])
	}

	// 3. add qword ptr gs:[0x10], 7
	if out := emulateSegMemInsn(code[22:32], x86asm.GS, gsBase, &regs, &eflags, readMem, writeMem); !out.ok || out.fault {
		t.Fatalf("emulate add = %+v", out)
	}
	if teb[0x10] != 42 {
		t.Fatalf("teb[0x10] = %d, want 42", teb[0x10])
	}

	// 4. Out-of-bounds access reports a fault at the target address.
	badLoad := []byte{0x65, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x40, 0x00, 0x00}
	if out := emulateSegMemInsn(badLoad, x86asm.GS, gsBase, &regs, &eflags, readMem, writeMem); !out.fault || out.faultAddr != gsBase+0x4000 {
		t.Fatalf("emulate out-of-bounds load = %+v, want fault at %#x", out, gsBase+0x4000)
	}
}

// TestScanAMD64SkipsWrongSweepsInVectorCode verifies the start of a page in
// herdr, a Rust program. A MOVABS with the ASCII immediate "or table" crosses
// the page start. Ten of the sixteen sweeps start in or next to the immediate.
// The bytes of the text make those sweeps agree on a GS memory instruction one
// byte before the page. The sweeps that start on a boundary decode every byte,
// and the others skip bytes.
func TestScanAMD64SkipsWrongSweepsInVectorCode(t *testing.T) {
	before := []byte{
		0xb3, 0x00, 0x0f, 0x11, 0x00, // tail of a displacement; movups [rax], xmm0
		0x48, 0xb9, 0x6f, 0x72, 0x20, 0x74, 0x61, 0x62, 0x6c, 0x65, // movabs rcx, "or table"
	}
	page := []byte{
		0x48, 0x89, 0x48, 0x0e, 0x0f, 0x10, 0x84, 0x24, 0x70, 0x01, 0x00, 0x00, 0x0f, 0x29, 0x44, 0x24,
		0x20, 0x48, 0x8b, 0x8c, 0x24, 0x80, 0x01, 0x00, 0x00, 0x48, 0x89, 0x4c, 0x24, 0x30, 0x48, 0xc7,
		0x44, 0x24, 0x38, 0x16, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x40, 0x48, 0xc7, 0x44, 0x24,
		0x48, 0x16, 0x00, 0x00, 0x00, 0x48, 0xc7, 0x44, 0x24, 0x50, 0x00, 0x00, 0x00, 0x00, 0x48, 0xc7,
		0x44, 0x24, 0x58, 0x08, 0x00, 0x00, 0x00, 0x48, 0xc7, 0x44, 0x24, 0x60, 0x00, 0x00, 0x00, 0x00,
		0x48, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x48, 0xff, 0xc8, 0x48, 0x89, 0x44,
		0x24, 0x68, 0x48, 0x8b, 0x84, 0x24, 0xa0, 0x00, 0x00, 0x00, 0x48, 0x83, 0xe8, 0x08, 0x48, 0x0f,
		0x43, 0xd8, 0x48, 0x85, 0xdb, 0x0f, 0x84, 0xf6, 0x01, 0x00, 0x00, 0x48, 0x83, 0xfb, 0x01,
	}
	if got := scanAMD64GS(before, page, nil, true); len(got) != 0 {
		t.Errorf("scanAMD64GS = %+v, want none", got)
	}
}

// TestScanAMD64KeepsSitesWhenEverySweepSkips verifies that the fewest-skips rule
// does not drop a real site. The byte 0xD6 does not decode in 64-bit mode, so
// every sweep skips it before the SYSCALL. The sweeps tie, and they all vote.
func TestScanAMD64KeepsSitesWhenEverySweepSkips(t *testing.T) {
	if d := decodeAMD64([]byte{0xd6, 0x90, 0x90, 0x90}); d.size != 0 {
		t.Fatalf("the byte 0xd6 decodes with length %d, and the test needs a byte that does not decode", d.size)
	}
	// mov eax, 39; db 0xd6; syscall; ret
	page := []byte{0xb8, 0x27, 0x00, 0x00, 0x00, 0xd6, 0x0f, 0x05, 0xc3}
	got := scanAMD64(nil, page, nil)
	if want := syscallSite(6); len(got) != 1 || got[0] != want {
		t.Errorf("scanAMD64 = %+v, want %+v", got, want)
	}
}
