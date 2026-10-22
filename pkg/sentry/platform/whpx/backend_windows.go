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

package whpx

import (
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	modWinHvPlatform = windows.NewLazySystemDLL("WinHvPlatform.dll")

	procGetCapability          = modWinHvPlatform.NewProc("WHvGetCapability")
	procCreatePartition        = modWinHvPlatform.NewProc("WHvCreatePartition")
	procSetupPartition         = modWinHvPlatform.NewProc("WHvSetupPartition")
	procDeletePartition        = modWinHvPlatform.NewProc("WHvDeletePartition")
	procGetPartitionProperty   = modWinHvPlatform.NewProc("WHvGetPartitionProperty")
	procSetPartitionProperty   = modWinHvPlatform.NewProc("WHvSetPartitionProperty")
	procMapGpaRange            = modWinHvPlatform.NewProc("WHvMapGpaRange")
	procUnmapGpaRange          = modWinHvPlatform.NewProc("WHvUnmapGpaRange")
	procCreateVirtualProcessor = modWinHvPlatform.NewProc("WHvCreateVirtualProcessor")
	procDeleteVirtualProcessor = modWinHvPlatform.NewProc("WHvDeleteVirtualProcessor")
	procRunVirtualProcessor    = modWinHvPlatform.NewProc("WHvRunVirtualProcessor")
	procCancelRunVP            = modWinHvPlatform.NewProc("WHvCancelRunVirtualProcessor")
	procGetVPRegisters         = modWinHvPlatform.NewProc("WHvGetVirtualProcessorRegisters")
	procSetVPRegisters         = modWinHvPlatform.NewProc("WHvSetVirtualProcessorRegisters")
)

// hresultError is a failed WinHvPlatform call.
type hresultError struct {
	op string
	hr uint32
}

func (e *hresultError) Error() string {
	return fmt.Sprintf("%s failed with HRESULT %#08x", e.op, e.hr)
}

// call invokes a WinHvPlatform function that returns an HRESULT. The
// directive keeps the objects alive that callers pass as converted pointers.
//
//go:uintptrescapes
func call(proc *windows.LazyProc, op string, args ...uintptr) error {
	if err := proc.Find(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	hr, _, _ := proc.Call(args...)
	if hresultFailed(hr) {
		return &hresultError{op: op, hr: uint32(hr)}
	}
	return nil
}

// ptrFromUintptr converts an address that Windows returned into a pointer.
// The memory is outside the Go heap, so the conversion is safe.
func ptrFromUintptr(addr uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&addr))
}

// whvRegInternalActivityState is WHvRegisterInternalActivityState. The stub
// writes zero to it after every HLT exit, so that the processor leaves the
// halted state.
const whvRegInternalActivityState = 0x80000005

// hvStatusAccessDenied is HV_STATUS_ACCESS_DENIED as WinHvPlatform returns it.
const hvStatusAccessDenied = 0xc0350006

// winBackend implements backend with WinHvPlatform.dll.
type winBackend struct {
	partition uintptr

	// activityDenied is set after the hypervisor refused a write to
	// WHvRegisterInternalActivityState. A hosted Windows runner (nested
	// virtualization) refuses it, and then WHP resumes the processor after an
	// HLT intercept without the write. The backend omits the register from every
	// later call.
	activityDenied atomic.Bool
}

// withoutActivityState returns the batch without WHvRegisterInternalActivityState.
func withoutActivityState(names []uint32, vals []byte) ([]uint32, []byte) {
	outNames := make([]uint32, 0, len(names))
	outVals := make([]byte, 0, len(vals))
	for i, name := range names {
		if name == whvRegInternalActivityState {
			continue
		}
		outNames = append(outNames, name)
		outVals = append(outVals, vals[i*regValueSize:(i+1)*regValueSize]...)
	}
	return outNames, outVals
}

func isAccessDenied(err error) bool {
	var he *hresultError
	return errors.As(err, &he) && he.hr == hvStatusAccessDenied
}

// newBackend loads WinHvPlatform.dll.
func newBackend() (backend, error) {
	if err := modWinHvPlatform.Load(); err != nil {
		return nil, fmt.Errorf("%w: load WinHvPlatform.dll: %v", ErrUnsupported, err)
	}
	return &winBackend{}, nil
}

// getCapability reads a capability into buf.
func getCapability(code uint32, buf unsafe.Pointer, size uint32) error {
	var written uint32
	return call(procGetCapability, "WHvGetCapability",
		uintptr(code), uintptr(buf), uintptr(size), uintptr(unsafe.Pointer(&written)))
}

func (b *winBackend) features() (hostFeatures, error) {
	var f hostFeatures
	var present uint32
	if err := getCapability(capCodeHypervisorPresent, unsafe.Pointer(&present), 4); err != nil {
		return f, err
	}
	f.hypervisorPresent = present != 0
	if !f.hypervisorPresent {
		return f, nil
	}
	var feats uint64
	if err := getCapability(capCodeFeatures, unsafe.Pointer(&feats), 8); err != nil {
		return f, err
	}
	f.arm64Support = feats&featArm64Support != 0
	if runtime.GOARCH == "arm64" {
		build, ubr, err := windowsVersion()
		if err != nil {
			return f, err
		}
		f.windowsBuild, f.windowsUBR = build, ubr
	}
	return f, nil
}

// windowsVersion returns the build number and the update build revision.
func windowsVersion() (build, ubr uint32, err error) {
	build = windows.RtlGetVersion().BuildNumber
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return 0, 0, fmt.Errorf("open CurrentVersion registry key: %w", err)
	}
	defer key.Close()
	v, _, err := key.GetIntegerValue("UBR")
	if err != nil {
		return 0, 0, fmt.Errorf("read UBR: %w", err)
	}
	return build, uint32(v), nil
}

func (b *winBackend) createPartition(vpCount uint32) (info partitionInfo, err error) {
	var h uintptr
	if err := call(procCreatePartition, "WHvCreatePartition", uintptr(unsafe.Pointer(&h))); err != nil {
		return info, err
	}
	b.partition = h
	defer func() {
		if err != nil {
			err = errors.Join(err, b.closePartition())
		}
	}()
	if err := call(procSetPartitionProperty, "WHvSetPartitionProperty(ProcessorCount)",
		h, uintptr(propCodeProcessorCount), uintptr(unsafe.Pointer(&vpCount)), 4); err != nil {
		return info, err
	}
	if runtime.GOARCH == "arm64" {
		var lpiBits uint32
		if err := getCapability(capCodeGicLpiIntIdBits, unsafe.Pointer(&lpiBits), 4); err != nil {
			return info, fmt.Errorf("query GIC LPI identifier bits: %w", err)
		}
		ic := a64ICParameters{
			EmulationMode:  1, // WHvArm64IcEmulationModeGicV3.
			Distributor:    a64GicDistributor,
			ITSTranslater:  a64GicITS,
			LPIBits:        lpiBits,
			TimerPPI:       27,
			PerformancePPI: 23,
		}
		if err := call(procSetPartitionProperty, "WHvSetPartitionProperty(Arm64IcParameters)",
			h, uintptr(propCodeArm64IcParameters), uintptr(unsafe.Pointer(&ic)), unsafe.Sizeof(ic)); err != nil {
			return info, err
		}
		// The stub exits with HVC. The hypervisor reports it to the caller
		// only when the partition enables hypercall exits.
		exits := extExitHypercall
		if err := call(procSetPartitionProperty, "WHvSetPartitionProperty(ExtendedVmExits)",
			h, uintptr(propCodeExtendedVmExits), uintptr(unsafe.Pointer(&exits)), 8); err != nil {
			return info, err
		}
	}
	if err := call(procSetupPartition, "WHvSetupPartition", h); err != nil {
		return info, err
	}
	info.vpCount = vpCount
	if runtime.GOARCH == "amd64" {
		var xs uint64
		var written uint32
		if err := call(procGetPartitionProperty, "WHvGetPartitionProperty(ProcessorXsaveFeatures)",
			h, uintptr(propCodeXsaveFeatures), uintptr(unsafe.Pointer(&xs)), 8, uintptr(unsafe.Pointer(&written))); err != nil {
			return info, err
		}
		info.xsave = xs&xsaveFeatXsaveSupport != 0
	}
	return info, nil
}

func (b *winBackend) closePartition() error {
	if b.partition == 0 {
		return nil
	}
	h := b.partition
	b.partition = 0
	return call(procDeletePartition, "WHvDeletePartition", h)
}

func (b *winBackend) allocHost(size uintptr) ([]byte, error) {
	addr, err := windows.VirtualAlloc(0, size, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("VirtualAlloc(%d): %w", size, err)
	}
	return unsafe.Slice((*byte)(ptrFromUintptr(addr)), int(size)), nil
}

func (b *winBackend) freeHost(mem []byte) error {
	if len(mem) == 0 {
		return nil
	}
	if err := windows.VirtualFree(uintptr(unsafe.Pointer(&mem[0])), 0, windows.MEM_RELEASE); err != nil {
		return fmt.Errorf("VirtualFree: %w", err)
	}
	return nil
}

func (b *winBackend) mapGPA(host unsafe.Pointer, gpa, size uint64, flags uint32) error {
	return call(procMapGpaRange, "WHvMapGpaRange",
		b.partition, uintptr(host), uintptr(gpa), uintptr(size), uintptr(flags))
}

func (b *winBackend) unmapGPA(gpa, size uint64) error {
	return call(procUnmapGpaRange, "WHvUnmapGpaRange", b.partition, uintptr(gpa), uintptr(size))
}

func (b *winBackend) createVP(index uint32) error {
	return call(procCreateVirtualProcessor, "WHvCreateVirtualProcessor", b.partition, uintptr(index), 0)
}

func (b *winBackend) deleteVP(index uint32) error {
	return call(procDeleteVirtualProcessor, "WHvDeleteVirtualProcessor", b.partition, uintptr(index))
}

func (b *winBackend) run(index uint32, exit []byte) error {
	size := exitCtxSizeX64
	if runtime.GOARCH == "arm64" {
		size = exitCtxSizeA64
	}
	return call(procRunVirtualProcessor, "WHvRunVirtualProcessor",
		b.partition, uintptr(index), uintptr(unsafe.Pointer(&exit[0])), uintptr(size))
}

func (b *winBackend) cancel(index uint32) error {
	return call(procCancelRunVP, "WHvCancelRunVirtualProcessor", b.partition, uintptr(index), 0)
}

func (b *winBackend) getRegs(index uint32, rb *regBatch) error {
	names, vals := rb.view()
	if len(names) == 0 {
		return nil
	}
	return call(procGetVPRegisters, "WHvGetVirtualProcessorRegisters",
		b.partition, uintptr(index), uintptr(unsafe.Pointer(&names[0])), uintptr(len(names)), uintptr(unsafe.Pointer(&vals[0])))
}

func (b *winBackend) setRegs(index uint32, rb *regBatch) error {
	names, vals := rb.view()
	if b.activityDenied.Load() {
		names, vals = withoutActivityState(names, vals)
	}
	if len(names) == 0 {
		return nil
	}
	err := call(procSetVPRegisters, "WHvSetVirtualProcessorRegisters",
		b.partition, uintptr(index), uintptr(unsafe.Pointer(&names[0])), uintptr(len(names)), uintptr(unsafe.Pointer(&vals[0])))
	if err != nil && isAccessDenied(err) && slices.Contains(names, whvRegInternalActivityState) {
		b.activityDenied.Store(true)
		names, vals = withoutActivityState(names, vals)
		if len(names) == 0 {
			return nil
		}
		err = call(procSetVPRegisters, "WHvSetVirtualProcessorRegisters",
			b.partition, uintptr(index), uintptr(unsafe.Pointer(&names[0])), uintptr(len(names)), uintptr(unsafe.Pointer(&vals[0])))
	}
	if err == nil || len(names) == 1 {
		return err
	}
	// The batch call reports one status for all registers. Setting them one by
	// one names every register that the hypervisor refuses. The processor is
	// already in an unknown state, so the extra calls cost nothing.
	var refused []string
	for i := range names {
		if one := call(procSetVPRegisters, "WHvSetVirtualProcessorRegisters",
			b.partition, uintptr(index), uintptr(unsafe.Pointer(&names[i])), 1, uintptr(unsafe.Pointer(&vals[i*regValueSize]))); one != nil {
			refused = append(refused, fmt.Sprintf("%#x", names[i]))
		}
	}
	if len(refused) > 0 {
		return fmt.Errorf("%w (registers refused one by one: %s)", err, strings.Join(refused, " "))
	}
	return err
}
