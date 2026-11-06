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

package systrap

import (
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
)

// fault is one SIGSEGV that the inferrer sees.
type fault struct {
	ip, addr uint64
	code     int32
	sigError uint64
	reported hostarch.AccessType
	want     hostarch.AccessType
}

func runFaults(t *testing.T, f *faultAccessInferrer, faults []fault) {
	t.Helper()
	for i, ft := range faults {
		info := &linux.SignalInfo{Signo: int32(linux.SIGSEGV), Code: ft.code}
		info.SetAddr(ft.addr)
		sigError := ft.sigError
		if got := f.infer(ft.reported, &sigError, ft.ip, info); got != ft.want {
			t.Errorf("fault %d (ip=%#x addr=%#x): infer() = %v, want %v", i, ft.ip, ft.addr, got, ft.want)
		}
		if sigError != 0 {
			t.Errorf("fault %d: infer() left the raw value %#x, want 0", i, sigError)
		}
	}
}

func TestFaultAccessInferrer(t *testing.T) {
	const (
		ip   = 0x401000
		addr = 0x7f0000001000
	)
	for _, tc := range []struct {
		name   string
		faults []fault
	}{
		{"a fetch has the fault address at the instruction pointer", []fault{
			{ip: addr, addr: addr, code: segvMaperr, want: hostarch.Execute},
		}},
		{"the first fault at an address is a read", []fault{
			{ip: ip, addr: addr, code: segvMaperr, want: hostarch.Read},
		}},
		{"the second fault in a row at the same place is a write", []fault{
			{ip: ip, addr: addr, code: segvMaperr, want: hostarch.Read},
			{ip: ip, addr: addr, code: segvAccerr, want: hostarch.Write},
		}},
		{"the third fault in a row starts a new read", []fault{
			{ip: ip, addr: addr, code: segvMaperr, want: hostarch.Read},
			{ip: ip, addr: addr, code: segvAccerr, want: hostarch.Write},
			{ip: ip, addr: addr, code: segvMaperr, want: hostarch.Read},
		}},
		{"a fault at another address is a new read", []fault{
			{ip: ip, addr: addr, code: segvMaperr, want: hostarch.Read},
			{ip: ip, addr: addr + 8, code: segvMaperr, want: hostarch.Read},
			{ip: ip + 4, addr: addr + 8, code: segvMaperr, want: hostarch.Read},
		}},
		{"a fetch ends the pending read", []fault{
			{ip: ip, addr: addr, code: segvMaperr, want: hostarch.Read},
			{ip: addr, addr: addr, code: segvMaperr, want: hostarch.Execute},
			{ip: ip, addr: addr, code: segvMaperr, want: hostarch.Read},
		}},
		{"a general protection fault keeps the reported access", []fault{
			{ip: ip, addr: 0, code: 0x80, want: hostarch.NoAccess},
			{ip: ip, addr: 0, code: 0x80, reported: hostarch.Read, want: hostarch.Read},
		}},
		{"a host that reports the error code is trusted", []fault{
			{ip: ip, addr: addr, code: segvMaperr, sigError: 0x6, reported: hostarch.Write, want: hostarch.Write},
			{ip: ip, addr: addr, code: segvMaperr, sigError: 0x4, reported: hostarch.Read, want: hostarch.Read},
			{ip: addr, addr: addr, code: segvMaperr, sigError: 0x4, reported: hostarch.Read, want: hostarch.Read},
		}},
		{"a reported fault does not make a pending read", []fault{
			{ip: ip, addr: addr, code: segvMaperr, sigError: 0x4, reported: hostarch.Read, want: hostarch.Read},
			{ip: ip, addr: addr, code: segvMaperr, want: hostarch.Read},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var f faultAccessInferrer
			runFaults(t, &f, tc.faults)
		})
	}
}

func TestFaultAccessInferrerResetAfterSyscall(t *testing.T) {
	var f faultAccessInferrer
	const ip, addr = 0x401000, 0x7f0000001000
	runFaults(t, &f, []fault{{ip: ip, addr: addr, code: segvMaperr, want: hostarch.Read}})
	f.reset()
	runFaults(t, &f, []fault{{ip: ip, addr: addr, code: segvMaperr, want: hostarch.Read}})
}
