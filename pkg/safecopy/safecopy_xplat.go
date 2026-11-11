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

//go:build !linux

// Package safecopy copies data across memory regions and translates fault
// errors into EFAULT.
package safecopy

import (
	"fmt"
	"runtime"

	"z.gfire.dev/gvx/pkg/errors"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// SegvError records the fault address of a SIGSEGV trap.
type SegvError struct {
	// Addr holds the faulting memory address.
	Addr uintptr
}

// Error implements error.Error.
func (e SegvError) Error() string {
	return fmt.Sprintf("SIGSEGV at %#x", e.Addr)
}

// BusError records the fault address of a SIGBUS trap.
type BusError struct {
	// Addr holds the faulting memory address.
	Addr uintptr
}

// Error implements error.Error.
func (e BusError) Error() string {
	return fmt.Sprintf("SIGBUS at %#x", e.Addr)
}

// AlignmentError records an unaligned memory address and its alignment rule.
type AlignmentError struct {
	// Addr holds the unaligned address.
	Addr uintptr

	// Alignment holds the required byte boundary.
	Alignment uintptr
}

// Error implements error.Error.
func (e AlignmentError) Error() string {
	return fmt.Sprintf("address %#x is not aligned to a %d-byte boundary", e.Addr, e.Alignment)
}

// FindEndAddress returns the first address after the function that contains
// begin.
func FindEndAddress(begin uintptr) uintptr {
	f := runtime.FuncForPC(begin)
	if f != nil {
		for p := begin; ; p++ {
			g := runtime.FuncForPC(p)
			if f != g {
				return p
			}
		}
	}
	return begin
}

// init registers the EFAULT unwrapper without replacing signal handlers.
func init() {
	linuxerr.AddErrorUnwrapper(func(e error) (*errors.Error, bool) {
		switch e.(type) {
		case SegvError, BusError, AlignmentError:
			return linuxerr.EFAULT, true
		default:
			return nil, false
		}
	})
}
