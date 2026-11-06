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

//go:build amd64

package arch

import (
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/cpuid"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/usermem"
)

func init() { cpuid.Initialize() }

func TestPageFaultErrorCode(t *testing.T) {
	read := hostarch.Read
	write := hostarch.Write
	exec := hostarch.Execute
	for _, tc := range []struct {
		name    string
		at      hostarch.AccessType
		present bool
		want    uint64
	}{
		{"read of an unmapped page", read, false, 0x4},
		{"write to an unmapped page", write, false, 0x6},
		{"fetch from an unmapped page", exec, false, 0x14},
		{"read of a mapped page", read, true, 0x5},
		{"write to a read-only page", write, true, 0x7},
		{"fetch from a page without execute", exec, true, 0x15},
	} {
		if got := pageFaultErrorCode(tc.at, tc.present); got != tc.want {
			t.Errorf("%s: pageFaultErrorCode() = %#x, want %#x", tc.name, got, tc.want)
		}
	}
}

// deliverSignal delivers sig with the code on ctx and returns the signal
// context of the frame.
func deliverSignal(t *testing.T, ctx *Context64, sig linux.Signal, code int32) SignalContext64 {
	t.Helper()
	buf := make([]byte, 1<<14)
	st := &Stack{Arch: ctx, IO: &usermem.BytesIO{Bytes: buf}, Bottom: hostarch.Addr(len(buf))}
	act := &linux.SigAction{Handler: 0x1000, Flags: linux.SA_RESTORER, Restorer: 0x2000}
	info := &linux.SignalInfo{Signo: int32(sig), Code: code}
	if err := ctx.SignalSetup(st, act, info, &linux.SignalStack{}, 0, cpuid.HostFeatureSet()); err != nil {
		t.Fatalf("SignalSetup: %v", err)
	}
	var uc UContext64
	uc.UnmarshalBytes(buf[ctx.Regs.Rdx:])
	return uc.MContext
}

func TestSignalFrameReportsTheFault(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sig        linux.Signal
		at         hostarch.AccessType
		code       int32
		wantErr    uint64
		wantTrapno uint64
	}{
		{"SIGSEGV on a read", linux.SIGSEGV, hostarch.Read, 1, 0x4, 14},
		{"SIGSEGV on a write to a read-only page", linux.SIGSEGV, hostarch.Write, segvAccerr, 0x7, 14},
		{"SIGSEGV on a fetch", linux.SIGSEGV, hostarch.Execute, 1, 0x14, 14},
		{"SIGBUS on a write", linux.SIGBUS, hostarch.Write, 2, 0x6, 14},
		{"SIGSEGV without a recorded access", linux.SIGSEGV, hostarch.AccessType{}, 1, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := New(AMD64)
			ctx.SetFaultAccess(tc.at)
			sc := deliverSignal(t, ctx, tc.sig, tc.code)
			if sc.Trapno != tc.wantTrapno || sc.Err != tc.wantErr {
				t.Errorf("frame has trapno=%d err=%#x, want trapno=%d err=%#x", sc.Trapno, sc.Err, tc.wantTrapno, tc.wantErr)
			}
		})
	}
}

func TestSignalFrameForgetsTheFault(t *testing.T) {
	ctx := New(AMD64)
	ctx.SetFaultAccess(hostarch.Write)
	if sc := deliverSignal(t, ctx, linux.SIGUSR1, linux.SI_USER); sc.Trapno != 0 || sc.Err != 0 {
		t.Errorf("SIGUSR1 frame has trapno=%d err=%#x, want zero", sc.Trapno, sc.Err)
	}
	ctx.SetFaultAccess(hostarch.Write)
	deliverSignal(t, ctx, linux.SIGSEGV, 1)
	if sc := deliverSignal(t, ctx, linux.SIGSEGV, linux.SI_USER); sc.Trapno != 0 || sc.Err != 0 {
		t.Errorf("a later SIGSEGV frame has trapno=%d err=%#x, want zero", sc.Trapno, sc.Err)
	}
}
