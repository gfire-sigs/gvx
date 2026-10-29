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

//go:build darwin

package hvf

import (
	"errors"
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// This file loads Hypervisor.framework at run time and wraps the VM-level
// entry points. The architecture-specific vCPU calls live in hv_darwin_*.go.
// Loading at run time keeps the binary startable on hosts without the
// framework and avoids a link-time dependency in every gvx binary.

const (
	hvMemoryRead  uint64 = 1 << 0
	hvMemoryWrite uint64 = 1 << 1
	hvMemoryExec  uint64 = 1 << 2

	rtldLazy = 0x1

	hypervisorFrameworkPath = "/System/Library/Frameworks/Hypervisor.framework/Hypervisor"
)

// Hypervisor.framework return codes (hv_error.h).
const (
	hvSuccess      uint32 = 0
	hvErrGeneral   uint32 = 0xfae94001
	hvErrBusy      uint32 = 0xfae94002
	hvErrBadArg    uint32 = 0xfae94003
	hvErrNoRes     uint32 = 0xfae94005
	hvErrNoDevice  uint32 = 0xfae94006
	hvErrDenied    uint32 = 0xfae94007
	hvErrFault     uint32 = 0xfae94008
	hvErrUnsupport uint32 = 0xfae9400f
)

//go:linkname darwinSyscall6 syscall.syscall6
func darwinSyscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

func dlopenTrampoline()
func addrOfDlopen() uintptr

func dlsymTrampoline()
func addrOfDlsym() uintptr

// hvError reports a failed Hypervisor.framework call.
type hvError struct {
	fn   string
	code uint32
}

func (e *hvError) Error() string {
	return fmt.Sprintf("hvf: %s failed: %s (0x%08x)", e.fn, hvCodeName(e.code), e.code)
}

func hvCodeName(code uint32) string {
	switch code {
	case hvErrGeneral:
		return "HV_ERROR (a missing com.apple.security.hypervisor entitlement also reports this code)"
	case hvErrBusy:
		return "HV_BUSY"
	case hvErrBadArg:
		return "HV_BAD_ARGUMENT"
	case hvErrNoRes:
		return "HV_NO_RESOURCES"
	case hvErrNoDevice:
		return "HV_NO_DEVICE"
	case hvErrDenied:
		return "HV_DENIED"
	case hvErrFault:
		return "HV_FAULT"
	case hvErrUnsupport:
		return "HV_UNSUPPORTED"
	default:
		return "unknown return code"
	}
}

// hvCode returns the framework return code stored in err, or false when err
// does not wrap an hvError.
func hvCode(err error) (uint32, bool) {
	var he *hvError
	if errors.As(err, &he) {
		return he.code, true
	}
	return 0, false
}

// hvResult converts the raw result register of a framework call into an error.
// The framework returns a 32-bit hv_return_t: the upper half of the register
// is undefined.
func hvResult(fn string, r1 uintptr) error {
	if code := uint32(r1); code != hvSuccess {
		return &hvError{fn: fn, code: code}
	}
	return nil
}

// hvSymbols holds the resolved framework entry points.
type hvSymbols struct {
	vmCreate  uintptr
	vmDestroy uintptr
	vmMap     uintptr
	vmUnmap   uintptr
	hvArchSymbols
}

var (
	symOnce sync.Once
	symTab  hvSymbols
	symErr  error
)

// loadSymbols opens the framework once and returns the resolved table.
func loadSymbols() (*hvSymbols, error) {
	symOnce.Do(func() {
		path, err := unix.BytePtrFromString(hypervisorFrameworkPath)
		if err != nil {
			symErr = fmt.Errorf("hvf: framework path: %w", err)
			return
		}
		handle, _, _ := darwinSyscall6(addrOfDlopen(), uintptr(unsafe.Pointer(path)), rtldLazy, 0, 0, 0, 0)
		if handle == 0 {
			symErr = errors.New("hvf: cannot open Hypervisor.framework")
			return
		}
		resolve := func(name string) (uintptr, error) {
			cname, err := unix.BytePtrFromString(name)
			if err != nil {
				return 0, fmt.Errorf("hvf: symbol name %q: %w", name, err)
			}
			sym, _, _ := darwinSyscall6(addrOfDlsym(), handle, uintptr(unsafe.Pointer(cname)), 0, 0, 0, 0)
			if sym == 0 {
				return 0, fmt.Errorf("hvf: Hypervisor.framework does not export %s", name)
			}
			return sym, nil
		}
		for _, entry := range []struct {
			name string
			dst  *uintptr
		}{
			{"hv_vm_create", &symTab.vmCreate},
			{"hv_vm_destroy", &symTab.vmDestroy},
			{"hv_vm_map", &symTab.vmMap},
			{"hv_vm_unmap", &symTab.vmUnmap},
		} {
			if *entry.dst, symErr = resolve(entry.name); symErr != nil {
				return
			}
		}
		symErr = symTab.resolveArch(resolve)
	})
	if symErr != nil {
		return nil, symErr
	}
	return &symTab, nil
}

// FrameworkSymbolsLoaded reports whether Hypervisor.framework and every entry
// point of this backend resolved in the current process.
func FrameworkSymbolsLoaded() bool {
	_, err := loadSymbols()
	return err == nil
}

// hvVMCreate creates the process-wide VM with the default configuration.
func hvVMCreate() error {
	s, err := loadSymbols()
	if err != nil {
		return err
	}
	r1, _, _ := darwinSyscall6(s.vmCreate, 0, 0, 0, 0, 0, 0)
	return hvResult("hv_vm_create", r1)
}

// hvVMDestroy destroys the process-wide VM. It fails with HV_BUSY while any
// vCPU exists.
func hvVMDestroy() error {
	s, err := loadSymbols()
	if err != nil {
		return err
	}
	r1, _, _ := darwinSyscall6(s.vmDestroy, 0, 0, 0, 0, 0, 0)
	return hvResult("hv_vm_destroy", r1)
}

// hvVMMap maps host memory into the guest physical address space. The host
// address and the size must be multiples of the 16KB host page.
func hvVMMap(host uintptr, ipa uint64, size uintptr, flags uint64) error {
	s, err := loadSymbols()
	if err != nil {
		return err
	}
	r1, _, _ := darwinSyscall6(s.vmMap, host, uintptr(ipa), size, uintptr(flags), 0, 0)
	return hvResult("hv_vm_map", r1)
}

// hvVMUnmap removes a guest physical mapping created by hvVMMap.
func hvVMUnmap(ipa uint64, size uintptr) error {
	s, err := loadSymbols()
	if err != nil {
		return err
	}
	r1, _, _ := darwinSyscall6(s.vmUnmap, uintptr(ipa), size, 0, 0, 0, 0)
	return hvResult("hv_vm_unmap", r1)
}

//go:cgo_import_dynamic libc_dlopen dlopen "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_dlsym dlsym "/usr/lib/libSystem.B.dylib"
