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
	"math/rand"
	"reflect"
	"testing"
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
