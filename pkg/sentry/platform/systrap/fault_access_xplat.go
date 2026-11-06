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
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
)

// faultAccessInferrer finds the access of a fault when the host kernel reports
// none.
//
// Linux gives a SIGSEGV from a page fault the error code (amd64) or the ESR
// value (arm64) in the signal frame. A host kernel that is a Sentry without
// this record, such as upstream runsc on arm64 and amd64, gives zero. A page
// fault always has a non-zero error code or ESR value on Linux, so the zero
// value identifies such a host and no other host takes this path.
//
// The inferrer follows the policy of a kernel without the information: an
// instruction fetch has the fault address equal to the instruction pointer.
// Every other fault is a read first. The Sentry maps the page for a read. A
// write to it faults again at the same instruction and address, so the second
// fault in a row is a write.
type faultAccessInferrer struct {
	// pending is true when the last fault was inferred as a read and no
	// syscall ran after it.
	pending bool
	// ip is the instruction pointer of the pending read.
	ip uint64
	// addr is the fault address of the pending read.
	addr uint64
}

// infer returns the access of a SIGSEGV. reported is the access that the
// signal frame gave. sigError points to the raw value of the frame (the amd64
// error code or the arm64 ESR value). ip is the instruction pointer of the
// thread and info is the signal. infer clears the raw value, so that a stub
// that writes it only for some signals cannot leak it into the next signal.
func (f *faultAccessInferrer) infer(reported hostarch.AccessType, sigError *uint64, ip uint64, info *linux.SignalInfo) hostarch.AccessType {
	raw := *sigError
	*sigError = 0
	// Only a SIGSEGV from a page fault has the code SEGV_MAPERR or SEGV_ACCERR.
	// Another fault, such as a general protection fault, has SI_KERNEL.
	if raw != 0 || (info.Code != segvMaperr && info.Code != segvAccerr) {
		f.pending = false
		return reported
	}
	addr := info.Addr()
	if ip == addr {
		f.pending = false
		return hostarch.Execute
	}
	if f.pending && f.ip == ip && f.addr == addr {
		f.pending = false
		return hostarch.Write
	}
	f.pending, f.ip, f.addr = true, ip, addr
	return hostarch.Read
}

// reset forgets the pending read. A syscall of the thread can change the
// mapping, so the next fault at the same instruction and address is a new read.
func (f *faultAccessInferrer) reset() {
	f.pending = false
}

const (
	// segvMaperr is the si_code of a fault on an unmapped page.
	segvMaperr = 1
	// segvAccerr is the si_code of a fault on a mapped page with the wrong
	// permission.
	segvAccerr = 2
)
