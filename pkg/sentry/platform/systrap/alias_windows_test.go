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

//go:build windows

package systrap

import (
	"reflect"
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
)

const (
	// rwVA and rxVA are the two views of one frame in the alias tests.
	rwVA = dataVA
	rxVA = dataVA + 0x10_0000
	// stepOff is the offset in the code page of the second guest step.
	stepOff = 0x800
)

// storeCode returns guest code that writes code at va, eight bytes at a time.
func storeCode(va uint64, code []byte) []byte {
	var out []byte
	for i := 0; i < len(code); i += 8 {
		var chunk [8]byte
		copy(chunk[:], code[i:])
		out = append(out, gStoreTo(va+uint64(i), load64(chunk[:]))...)
	}
	return out
}

// TestWriteThroughAnotherViewReplacesExecutedCode maps one frame twice, runs a
// function through the execute view, rewrites it through the write view, and
// runs it again. The second run must execute the new bytes. The cases differ in
// the order of the two mappings and in the address space of the write view.
func TestWriteThroughAnotherViewReplacesExecutedCode(t *testing.T) {
	for _, c := range []struct {
		name          string
		otherSpace    bool
		writeViewLate bool
	}{
		{"same address space", false, false},
		{"another address space", true, false},
		{"write view mapped after the copy, same address space", false, true},
		{"write view mapped after the copy, another address space", true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			runner := newRig(t, newPlatform(t))
			writer := runner
			if c.otherSpace {
				writer = newRigOn(t, runner.p, runner.mf)
			}
			fr, _ := runner.allocFrames(1, gSyscall(41))
			runner.mapRange(rxVA, fr, execAccess)
			if !c.writeViewLate {
				writer.mapRange(rwVA, fr, hostarch.ReadWrite)
			}
			rewriter := storeCode(rwVA, gSyscall(42))
			code := runner.program(gJump(rxVA))
			if c.otherSpace {
				writer.program(rewriter, gSyscall(99))
			} else {
				copy(code[stepOff:], append(rewriter, gJump(rxVA)...))
			}

			si, _, err := runner.run()
			mustSyscall(t, si, err, 41, runner.ac)
			if c.writeViewLate {
				writer.mapRange(rwVA, fr, hostarch.ReadWrite)
			}
			if c.otherSpace {
				si, _, err = writer.run()
				mustSyscall(t, si, err, 99, writer.ac)
				runner.ac.SetIP(codeVA)
			} else {
				runner.ac.SetIP(codeVA + stepOff)
			}
			si, _, err = runner.run()
			mustSyscall(t, si, err, 42, runner.ac)
			if got := writer.as.AliasFaults(); got != 1 {
				t.Errorf("writes that dropped a copy = %d, want 1", got)
			}
		})
	}
}

// TestWriteViewFaultsOnlyWhileACopyExists counts the writes that the engine
// intercepts. A write through the second view of a frame costs nothing while no
// copy of the frame exists, so a shared-memory workload that never runs the
// frame pays no extra fault.
func TestWriteViewFaultsOnlyWhileACopyExists(t *testing.T) {
	r := newRig(t, newPlatform(t))
	fr, _ := r.allocFrames(1, gSyscall(41))
	r.mapRange(rxVA, fr, execAccess)
	r.mapRange(rwVA, fr, hostarch.ReadWrite)
	same := storeCode(rwVA, gSyscall(41))
	code := r.program(same, gSyscall(10))
	copy(code[stepOff:], gJump(rxVA))

	step := func(ip uint64, wantCall uint64, wantFaults uint64, what string) {
		t.Helper()
		r.ac.SetIP(uintptr(ip))
		si, _, err := r.run()
		mustSyscall(t, si, err, wantCall, r.ac)
		if got := r.as.AliasFaults(); got != wantFaults {
			t.Fatalf("%s: intercepted writes = %d, want %d", what, got, wantFaults)
		}
	}
	step(codeVA, 10, 0, "write before any copy exists")
	step(codeVA+stepOff, 41, 0, "run the frame")
	step(codeVA, 10, 1, "write while a copy exists")
	step(codeVA, 10, 1, "write after the engine dropped the copy")
	step(codeVA+stepOff, 41, 1, "run the frame again")
	step(codeVA, 10, 2, "write while the second copy exists")
}

func TestAliasIndexInvalidateDropsInstalledAndPoisonsPending(t *testing.T) {
	var x aliasIndex
	key := frameKey{file: 7, off: 0x3000}
	as1, as2 := &addressSpace{}, &addressSpace{}
	installed := &copyEntry{as: as1, base: 0x1000, key: key}
	pending := &copyEntry{as: as2, base: 0x9000, key: key}
	x.begin(installed)
	if !x.install(installed) {
		t.Fatal("install refused a copy that no write touched")
	}
	x.begin(pending)

	dropped := x.invalidate(key)
	if !reflect.DeepEqual(dropped, []*copyEntry{installed}) {
		t.Fatalf("invalidate returned %v, want only the installed copy", dropped)
	}
	if x.install(pending) {
		t.Error("install accepted a copy that a write poisoned")
	}
	if x.otherCopy(key, nil, 0) {
		t.Error("the index still holds a live copy after the invalidation")
	}
	if len(x.buckets) != 0 {
		t.Errorf("the index keeps %d buckets after every entry left", len(x.buckets))
	}
}

func TestAliasIndexBeginReturnsOtherWritableViewsOfTheFrame(t *testing.T) {
	var x aliasIndex
	as1, as2 := &addressSpace{}, &addressSpace{}
	const file = 5
	// as1 maps three frames at 0x10000, and as2 maps the second one at 0x70000.
	x.addView(&writeView{as: as1, va: 0x10000, file: file, off: 0x4000, size: 0x3000})
	x.addView(&writeView{as: as2, va: 0x70000, file: file, off: 0x5000, size: 0x1000})
	// The view of another file at the same offsets must not match.
	x.addView(&writeView{as: as2, va: 0x80000, file: file + 1, off: 0x5000, size: 0x1000})

	e := &copyEntry{as: as1, base: 0x50000, key: frameKey{file, 0x5000}}
	got := x.begin(e)
	want := []viewHit{{as1, 0x11000}, {as2, 0x70000}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("begin returned %v, want %v", got, want)
	}

	// The view of the block itself is not a hit.
	own := &copyEntry{as: as1, base: 0x11000, key: frameKey{file, 0x5000}}
	if got := x.begin(own); !reflect.DeepEqual(got, []viewHit{{as2, 0x70000}}) {
		t.Errorf("begin for the block at 0x11000 returned %v, want only the view of the other address space", got)
	}
}

func TestAliasIndexCopiesInReturnsLiveCopiesInOffsetOrder(t *testing.T) {
	var x aliasIndex
	as := &addressSpace{}
	const file = 3
	offs := []uint64{0x5000, 0x1000, 0x20_1000, 0x3000}
	for i, off := range offs {
		x.begin(&copyEntry{as: as, base: uint64(i+1) * 0x1000, key: frameKey{file, off}})
	}
	x.invalidate(frameKey{file, 0x3000})
	var got []uint64
	for _, e := range x.copiesIn(file, 0, 0x10_0000) {
		got = append(got, e.key.off)
	}
	if want := []uint64{0x1000, 0x5000}; !reflect.DeepEqual(got, want) {
		t.Errorf("copiesIn = %#x, want %#x", got, want)
	}
	if got := x.copiesIn(file+1, 0, 0x10_0000); len(got) != 0 {
		t.Errorf("copiesIn of another file = %v", got)
	}
}

func TestAliasIndexRemoveViewForgetsEveryBucket(t *testing.T) {
	var x aliasIndex
	v := &writeView{as: &addressSpace{}, va: 0x10000, file: 2, off: 0xf_f000, size: 0x3000}
	x.addView(v)
	if len(x.buckets) != 2 {
		t.Fatalf("a view across a bucket boundary is in %d buckets, want 2", len(x.buckets))
	}
	x.removeView(v)
	if len(x.buckets) != 0 {
		t.Errorf("%d buckets remain after the view left", len(x.buckets))
	}
}
