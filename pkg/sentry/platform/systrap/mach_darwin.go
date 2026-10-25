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

//go:build darwin && arm64

package systrap

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// machPort is a Mach port name in the Sentry's port namespace.
type machPort uint32

// kernReturn is a Mach kern_return_t.
type kernReturn int32

const (
	kernSuccess              kernReturn = 0
	kernInvalidAddress       kernReturn = 1
	kernProtectionFailure    kernReturn = 2
	kernNoSpace              kernReturn = 3
	kernInvalidArgument      kernReturn = 4
	kernFailure              kernReturn = 5
	kernInvalidName          kernReturn = 15
	kernTerminated           kernReturn = 49
	machSendInvalidDest      kernReturn = 0x10000003
	machRcvTimedOut          kernReturn = 0x10004003
	machSendTimedOut         kernReturn = 0x10000004
	machRcvPortDied          kernReturn = 0x10004009
	machRcvTooLarge          kernReturn = 0x10004004
	machRcvInvalidName       kernReturn = 0x10004002
	machRcvPortChanged       kernReturn = 0x1000400b
	machMsgInvalidKernArg    kernReturn = 0x1000000a
	machSendInterrupted      kernReturn = 0x10000007
	machRcvInterrupted       kernReturn = 0x10004005
	kernAborted              kernReturn = 14
	kernMemoryError          kernReturn = 10
	kernResourceShortage     kernReturn = 6
	kernNoAccess             kernReturn = 8
	kernInvalidRight         kernReturn = 17
	kernInvalidCapability    kernReturn = 20
	kernDenied               kernReturn = 53
	kernCodesignError        kernReturn = 50
	machPortNull             machPort   = 0
	machPortRightReceive                = 1
	machMsgTypeMakeSend                 = 20
	machMsgTypeMakeSendOnce             = 21
	machMsgTypeCopySend                 = 19
	machSendMsg                         = 0x1
	machRcvMsg                          = 0x2
	machSendTimeout                     = 0x10
	machRcvTimeout                      = 0x100
	machNotifyDeadName                  = 72
	machMsgComplex                      = 0x80000000
	vmFlagsFixed                        = 0x0
	vmFlagsAnywhere                     = 0x1
	vmFlagsOverwrite                    = 0x4000
	vmInheritNone                       = 2
	vmProtRead                          = 1
	vmProtWrite                         = 2
	vmProtExecute                       = 4
	excMaskResource                     = 1 << 11
	exceptionDefault                    = 1
	posixSpawnSetPgroup                 = 0x2
	posixSpawnSetSigDef                 = 0x4
	posixSpawnSetSigMask                = 0x8
	posixSpawnCloexecDefault            = 0x4000
	armThreadState64                    = 6
	armNeonState64                      = 17
	armExceptionState64                 = 7
	armThreadState64Count               = 68
	armNeonState64Count                 = 132
	armExceptionState64Count            = 4
)

// MachError reports a failed Mach call.
type MachError struct {
	Op   string
	Code kernReturn
}

// Error implements error.
func (e *MachError) Error() string {
	return fmt.Sprintf("%s: %s (kern_return_t %#x)", e.Op, e.Code, uint32(e.Code))
}

// String names the common return codes.
func (k kernReturn) String() string {
	switch k {
	case kernSuccess:
		return "success"
	case kernInvalidAddress:
		return "invalid address"
	case kernProtectionFailure:
		return "protection failure"
	case kernNoSpace:
		return "no space"
	case kernInvalidArgument:
		return "invalid argument"
	case kernFailure:
		return "failure"
	case kernResourceShortage:
		return "resource shortage"
	case kernNoAccess:
		return "no access"
	case kernInvalidName:
		return "invalid name"
	case kernInvalidRight:
		return "invalid right"
	case kernTerminated:
		return "terminated"
	case kernDenied:
		return "denied"
	case machSendInvalidDest:
		return "send invalid destination (peer is gone)"
	case machRcvTimedOut:
		return "receive timed out"
	case machRcvPortDied:
		return "receive port died"
	}
	return "unknown"
}

// IsDead reports whether err means that the remote task or port no longer exists.
func isDeadTaskError(err error) bool {
	var me *MachError
	if !errors.As(err, &me) {
		return false
	}
	switch me.Code {
	case machSendInvalidDest, kernTerminated, kernInvalidArgument, kernInvalidName, kernInvalidRight, machRcvPortDied:
		return true
	}
	return false
}

func kr(op string, r uintptr) error {
	if c := kernReturn(int32(r)); c != kernSuccess {
		return &MachError{Op: op, Code: c}
	}
	return nil
}

// machCalls holds the resolved libSystem entry points.
var machCalls struct {
	vmRemap, vmProtect, vmDeallocate, vmAllocate                            libcFunc
	portAllocate, portInsertRight, portDeallocate, portDestroy              libcFunc
	portRequestNotification, msg                                            libcFunc
	threadCreateRunning, threadGetState, threadSetState                     libcFunc
	threadSuspend, threadResume, threadTerminate, taskTerminate             libcFunc
	spawn, spawnattrInit, spawnattrDestroy, spawnattrSetFlags               libcFunc
	spawnattrSetSigDefault, spawnattrSetSigMask, spawnattrSetExceptionPorts libcFunc
	spawnattrSetPgroup                                                      libcFunc
	ulockWait, ulockWake, icacheInvalidate                                  libcFunc
	taskSetExceptionPorts                                                   libcFunc
	vmRegion, vmMachineAttribute                                            libcFunc
}

func init() {
	c := &machCalls
	c.vmRemap = mustResolve("mach_vm_remap")
	c.vmProtect = mustResolve("mach_vm_protect")
	c.vmDeallocate = mustResolve("mach_vm_deallocate")
	c.vmAllocate = mustResolve("mach_vm_allocate")
	c.portAllocate = mustResolve("mach_port_allocate")
	c.portInsertRight = mustResolve("mach_port_insert_right")
	c.portDeallocate = mustResolve("mach_port_deallocate")
	c.portDestroy = mustResolve("mach_port_destroy")
	c.portRequestNotification = mustResolve("mach_port_request_notification")
	c.msg = mustResolve("mach_msg")
	c.threadCreateRunning = mustResolve("thread_create_running")
	c.threadGetState = mustResolve("thread_get_state")
	c.threadSetState = mustResolve("thread_set_state")
	c.threadSuspend = mustResolve("thread_suspend")
	c.threadResume = mustResolve("thread_resume")
	c.threadTerminate = mustResolve("thread_terminate")
	c.taskTerminate = mustResolve("task_terminate")
	c.spawn = mustResolve("posix_spawn")
	c.spawnattrInit = mustResolve("posix_spawnattr_init")
	c.spawnattrDestroy = mustResolve("posix_spawnattr_destroy")
	c.spawnattrSetFlags = mustResolve("posix_spawnattr_setflags")
	c.spawnattrSetSigDefault = mustResolve("posix_spawnattr_setsigdefault")
	c.spawnattrSetSigMask = mustResolve("posix_spawnattr_setsigmask")
	c.spawnattrSetExceptionPorts = mustResolve("posix_spawnattr_setexceptionports_np")
	c.spawnattrSetPgroup = mustResolve("posix_spawnattr_setpgroup")
	c.ulockWait = mustResolve("__ulock_wait")
	c.ulockWake = mustResolve("__ulock_wake")
	c.icacheInvalidate = mustResolve("sys_icache_invalidate")
	c.taskSetExceptionPorts = mustResolve("task_set_exception_ports")
	c.vmRegion = mustResolve("mach_vm_region")
	c.vmMachineAttribute = mustResolve("mach_vm_machine_attribute")
}

// vmRemap maps size bytes of srcTask at srcAddr into dstTask at dstAddr and
// replaces any mapping there. The mapping shares the pages with the source.
func vmRemap(dstTask machPort, dstAddr, size uint64, srcTask machPort, srcAddr uint64) error {
	target := dstAddr
	var cur, max int32
	r := machCalls.vmRemap.call(
		uintptr(dstTask), uintptr(unsafe.Pointer(&target)), uintptr(size), 0,
		vmFlagsFixed|vmFlagsOverwrite, uintptr(srcTask), uintptr(srcAddr), 0,
		uintptr(unsafe.Pointer(&cur)), uintptr(unsafe.Pointer(&max)), vmInheritNone)
	runtime.KeepAlive(&target)
	runtime.KeepAlive(&cur)
	runtime.KeepAlive(&max)
	if err := kr("mach_vm_remap", r); err != nil {
		return err
	}
	if target != dstAddr {
		return fmt.Errorf("mach_vm_remap placed the mapping at %#x instead of %#x", target, dstAddr)
	}
	return nil
}

// vmRegionBasicInfo64 is VM_REGION_BASIC_INFO_64 and the size in 32-bit words
// of its vm_region_basic_info_data_64_t.
const (
	vmRegionBasicInfo64      = 9
	vmRegionBasicInfoWords64 = 9
)

// hostRegion is one mapping of a task.
type hostRegion struct {
	start, size uint64
}

// vmRegion returns the first mapping of task that ends above addr. It reports
// ok as false when no mapping lies at or above addr.
func vmRegion(task machPort, addr uint64) (r hostRegion, ok bool, err error) {
	var info [16]int32
	count := uint32(vmRegionBasicInfoWords64)
	var object uint32
	r.start = addr
	ret := machCalls.vmRegion.call(
		uintptr(task), uintptr(unsafe.Pointer(&r.start)), uintptr(unsafe.Pointer(&r.size)),
		vmRegionBasicInfo64, uintptr(unsafe.Pointer(&info[0])),
		uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&object)))
	runtime.KeepAlive(&r)
	runtime.KeepAlive(&info)
	runtime.KeepAlive(&count)
	runtime.KeepAlive(&object)
	if kernReturn(int32(ret)) == kernInvalidAddress {
		return hostRegion{}, false, nil
	}
	if err := kr("mach_vm_region", ret); err != nil {
		return hostRegion{}, false, err
	}
	return r, true, nil
}

// vmProtect changes the current or the maximum protection of a range.
func vmProtect(task machPort, addr, size uint64, setMax bool, prot int) error {
	m := uintptr(0)
	if setMax {
		m = 1
	}
	return kr("mach_vm_protect", machCalls.vmProtect.call(uintptr(task), uintptr(addr), uintptr(size), m, uintptr(prot)))
}

// The machine attribute call that synchronizes the caches of a range.
const (
	// mattrCache is MATTR_CACHE.
	mattrCache = 1
	// mattrValCacheSync is MATTR_VAL_CACHE_SYNC, which synchronizes the
	// instruction cache and the data cache.
	mattrValCacheSync = 9
)

// vmSyncCode asks the kernel to synchronize the instruction cache and the data
// cache for the pages that task maps in [addr, addr+size). The kernel finds the
// physical pages and does not depend on the address that the caller used to
// write the code.
func vmSyncCode(task machPort, addr, size uint64) error {
	val := int32(mattrValCacheSync)
	r := machCalls.vmMachineAttribute.call(uintptr(task), uintptr(addr), uintptr(size), mattrCache, uintptr(unsafe.Pointer(&val)))
	runtime.KeepAlive(&val)
	return kr("mach_vm_machine_attribute", r)
}

// vmDeallocate unmaps a range of a task.
func vmDeallocate(task machPort, addr, size uint64) error {
	return kr("mach_vm_deallocate", machCalls.vmDeallocate.call(uintptr(task), uintptr(addr), uintptr(size)))
}

// vmAllocate maps fresh zero pages at an address chosen by the kernel.
func vmAllocate(task machPort, size uint64) (uint64, error) {
	var addr uint64
	r := machCalls.vmAllocate.call(uintptr(task), uintptr(unsafe.Pointer(&addr)), uintptr(size), vmFlagsAnywhere)
	runtime.KeepAlive(&addr)
	return addr, kr("mach_vm_allocate", r)
}

func portAllocateReceive(task machPort) (machPort, error) {
	var name uint32
	r := machCalls.portAllocate.call(uintptr(task), machPortRightReceive, uintptr(unsafe.Pointer(&name)))
	runtime.KeepAlive(&name)
	return machPort(name), kr("mach_port_allocate", r)
}

func portInsertSendRight(task, name machPort) error {
	return kr("mach_port_insert_right", machCalls.portInsertRight.call(uintptr(task), uintptr(name), uintptr(name), machMsgTypeMakeSend))
}

func portDeallocate(task, name machPort) error {
	return kr("mach_port_deallocate", machCalls.portDeallocate.call(uintptr(task), uintptr(name)))
}

func portDestroy(task, name machPort) error {
	return kr("mach_port_destroy", machCalls.portDestroy.call(uintptr(task), uintptr(name)))
}

// portRequestDeadName asks the kernel to send a dead-name notification for
// name to notify when the port's receiver dies.
func portRequestDeadName(task, name, notify machPort) error {
	var prev uint32
	r := machCalls.portRequestNotification.call(uintptr(task), uintptr(name), machNotifyDeadName, 0,
		uintptr(notify), machMsgTypeMakeSendOnce, uintptr(unsafe.Pointer(&prev)))
	runtime.KeepAlive(&prev)
	if err := kr("mach_port_request_notification", r); err != nil {
		return err
	}
	if prev != 0 {
		// The kernel returns a previous notification right only when another request exists.
		_ = portDeallocate(selfTask(), machPort(prev))
	}
	return nil
}

// machMsgCall wraps mach_msg.
func machMsgCall(msg unsafe.Pointer, option uint32, sendSize, rcvSize uint32, rcvName machPort, timeoutMs uint32) kernReturn {
	r := machCalls.msg.call(uintptr(msg), uintptr(option), uintptr(sendSize), uintptr(rcvSize), uintptr(rcvName), uintptr(timeoutMs), 0)
	return kernReturn(int32(r))
}

// armThreadState is the ARM_THREAD_STATE64 flavor.
type armThreadState struct {
	X     [29]uint64
	FP    uint64
	LR    uint64
	SP    uint64
	PC    uint64
	CPSR  uint32
	Flags uint32
}

// getReg returns general-purpose register reg (0..31). Reg 18 returns x18,
// reg 29 returns FP, reg 30 returns LR, and reg 31 returns SP when spFor31 is
// true or 0 (XZR) otherwise.
func (ss *armThreadState) getReg(reg uint8, x18 uint64, spFor31 bool) uint64 {
	switch {
	case reg == x18Reg:
		return x18
	case reg < 29:
		return ss.X[reg]
	case reg == 29:
		return ss.FP
	case reg == 30:
		return ss.LR
	case spFor31:
		return ss.SP
	default:
		return 0
	}
}

// setReg writes v to general-purpose register reg (0..31). Reg 18 writes to
// *x18 when x18 is non-nil, reg 29 writes FP, reg 30 writes LR, and reg 31
// writes SP when spFor31 is true or discards the write (XZR) otherwise.
func (ss *armThreadState) setReg(reg uint8, v uint64, x18 *uint64, spFor31 bool) {
	switch {
	case reg == x18Reg:
		if x18 != nil {
			*x18 = v
		}
	case reg < 29:
		ss.X[reg] = v
	case reg == 29:
		ss.FP = v
	case reg == 30:
		ss.LR = v
	case spFor31:
		ss.SP = v
	}
}

// armNeonState is the ARM_NEON_STATE64 flavor.
type armNeonState struct {
	V    [32][16]byte
	FPSR uint32
	FPCR uint32
	// The C structure aligns to 16 bytes and ends with 8 bytes of padding.
	_ [8]byte
}

// armExceptionState is the ARM_EXCEPTION_STATE64 flavor.
type armExceptionState struct {
	FAR       uint64
	ESR       uint32
	Exception uint32
}

func threadCreateRunning(task machPort, st *armThreadState) (machPort, error) {
	var th uint32
	r := machCalls.threadCreateRunning.call(uintptr(task), armThreadState64, uintptr(unsafe.Pointer(st)), armThreadState64Count, uintptr(unsafe.Pointer(&th)))
	runtime.KeepAlive(st)
	runtime.KeepAlive(&th)
	return machPort(th), kr("thread_create_running", r)
}

func threadGetState(th machPort, flavor int, state unsafe.Pointer, count uint32) error {
	c := count
	r := machCalls.threadGetState.call(uintptr(th), uintptr(flavor), uintptr(state), uintptr(unsafe.Pointer(&c)))
	runtime.KeepAlive(&c)
	return kr("thread_get_state", r)
}

func threadSetState(th machPort, flavor int, state unsafe.Pointer, count uint32) error {
	return kr("thread_set_state", machCalls.threadSetState.call(uintptr(th), uintptr(flavor), uintptr(state), uintptr(count)))
}

func threadSuspend(th machPort) error {
	return kr("thread_suspend", machCalls.threadSuspend.call(uintptr(th)))
}
func threadResume(th machPort) error {
	return kr("thread_resume", machCalls.threadResume.call(uintptr(th)))
}
func threadTerminate(th machPort) error {
	return kr("thread_terminate", machCalls.threadTerminate.call(uintptr(th)))
}
func taskTerminate(task machPort) error {
	return kr("task_terminate", machCalls.taskTerminate.call(uintptr(task)))
}

// ulock operations on a word that two processes share.
const (
	ulCompareAndWaitShared = 3
	ulfWakeAll             = 0x100
)

// ulockWait parks the caller while *addr equals expected. A zero timeout
// blocks without limit. The caller re-reads the word after every return.
func ulockWait(addr *uint32, expected uint32, timeoutMicros uint32) syscall.Errno {
	_, errno := machCalls.ulockWait.call4(ulCompareAndWaitShared, uintptr(unsafe.Pointer(addr)), uintptr(expected), uintptr(timeoutMicros))
	runtime.KeepAlive(addr)
	return errno
}

// ulockWakeAll wakes every thread that waits on addr in any process.
func ulockWakeAll(addr *uint32) {
	machCalls.ulockWake.call4(ulCompareAndWaitShared|ulfWakeAll, uintptr(unsafe.Pointer(addr)), 0, 0)
	runtime.KeepAlive(addr)
}

// icacheInvalidate makes instruction fetches see data stores to [p, p+n).
func icacheInvalidate(p unsafe.Pointer, n uintptr) {
	machCalls.icacheInvalidate.call(uintptr(p), n)
}

// vmRemapFrom maps size bytes of srcTask at srcAddr into the Sentry at an
// address that the kernel picks. The mapping shares the pages with the source.
func vmRemapFrom(srcTask machPort, srcAddr, size uint64) (uint64, error) {
	var target uint64
	var cur, max int32
	r := machCalls.vmRemap.call(
		uintptr(selfTask()), uintptr(unsafe.Pointer(&target)), uintptr(size), 0,
		vmFlagsAnywhere, uintptr(srcTask), uintptr(srcAddr), 0,
		uintptr(unsafe.Pointer(&cur)), uintptr(unsafe.Pointer(&max)), vmInheritNone)
	runtime.KeepAlive(&target)
	runtime.KeepAlive(&cur)
	runtime.KeepAlive(&max)
	return target, kr("mach_vm_remap", r)
}
