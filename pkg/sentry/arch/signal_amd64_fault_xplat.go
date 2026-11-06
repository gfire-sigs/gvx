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
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
)

const (
	// x86TrapPageFault is the trap number of a page fault.
	x86TrapPageFault = 14

	// segvAccerr is the si_code of a fault on a mapped page with the wrong
	// permission.
	segvAccerr = 2
)

// SetFaultAccess records the access of a user fault that the Sentry could not
// resolve and turns into a signal. The next signal frame of SIGSEGV or SIGBUS
// reports it in the trap number and the error code of the signal context, as
// Linux does. A nested Sentry reads both fields to learn if the fault is a
// read, a write, or an instruction fetch.
func (c *Context64) SetFaultAccess(at hostarch.AccessType) {
	c.faultAccess = at
}

// setFaultInSignalContext fills the trap number and the error code of sc from
// the recorded fault. It does nothing when no fault is recorded or when the
// signal does not come from a fault. It clears the recorded access.
func (c *Context64) setFaultInSignalContext(sc *SignalContext64, info *linux.SignalInfo) {
	at := c.faultAccess
	c.faultAccess = hostarch.AccessType{}
	if !at.Any() || (info.Signo != int32(linux.SIGSEGV) && info.Signo != int32(linux.SIGBUS)) {
		return
	}
	sc.Trapno = x86TrapPageFault
	// Only SIGSEGV with SEGV_ACCERR has a mapped page. A SIGBUS fault, such as
	// a read past the end of a file, finds no page.
	sc.Err = pageFaultErrorCode(at, info.Signo == int32(linux.SIGSEGV) && info.Code == segvAccerr)
}

// pageFaultErrorCode returns the error code of a page fault from user mode.
// present is true when the page is mapped and the access violates its
// permission. Compare Linux arch/x86/mm/fault.c.
func pageFaultErrorCode(at hostarch.AccessType, present bool) uint64 {
	code := uint64(linux.X86_PF_USER)
	if present {
		code |= linux.X86_PF_PROT
	}
	switch {
	case at.Execute:
		code |= linux.X86_PF_INSTR
	case at.Write:
		code |= linux.X86_PF_WRITE
	}
	return code
}
