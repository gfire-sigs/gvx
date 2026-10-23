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

package hostlockdown

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	jobLimitFlags = windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
	jobUILimits   = windows.JOB_OBJECT_UILIMIT_HANDLES | windows.JOB_OBJECT_UILIMIT_READCLIPBOARD | windows.JOB_OBJECT_UILIMIT_WRITECLIPBOARD

	// processSystemCallDisablePolicy is ProcessSystemCallDisablePolicy in the
	// PROCESS_MITIGATION_POLICY enumeration of winnt.h. The order is
	// DEP 0, ASLR 1, DynamicCode 2, StrictHandleCheck 3, SystemCallDisable 4.
	processSystemCallDisablePolicy = 4

	// jobObjectCPURateControlInformation is JobObjectCpuRateControlInformation.
	jobObjectCPURateControlInformation = 15
	jobCPURateControlEnable            = 0x1
	jobCPURateControlHardCap           = 0x4

	// disallowWin32kSystemCalls is bit 0 of the Flags union in
	// PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY.
	disallowWin32kSystemCalls = 1
)

var (
	modKernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	procSetInformationJobObject    = modKernel32.NewProc("SetInformationJobObject")
	procQueryInformationJobObject  = modKernel32.NewProc("QueryInformationJobObject")
	procIsProcessInJob             = modKernel32.NewProc("IsProcessInJob")
	procSetProcessMitigationPolicy = modKernel32.NewProc("SetProcessMitigationPolicy")
	procGetProcessMitigationPolicy = modKernel32.NewProc("GetProcessMitigationPolicy")
)

// jobCPURateControl mirrors JOBOBJECT_CPU_RATE_CONTROL_INFORMATION. The union
// of the C structure holds CpuRate here.
type jobCPURateControl struct {
	ControlFlags uint32
	CPURate      uint32
}

// processMitigationSystemCallDisablePolicy mirrors
// PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY.
type processMitigationSystemCallDisablePolicy struct {
	Flags uint32
}

// createContainmentJob runs steps 5 to 7. It creates an anonymous job,
// assigns the current process first, then limits the job to one active
// process and isolates USER handles and the clipboard. The caller keeps the
// returned handle open for the process lifetime. On error the handle is closed.
func createContainmentJob(cpuQuotaMillis int64) (job windows.Handle, err error) {
	job, err = windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("hostlockdown: CreateJobObject: %w", err)
	}
	defer func() {
		if err != nil {
			_ = windows.CloseHandle(job)
			job = 0
		}
	}()

	if err = windows.AssignProcessToJobObject(job, windows.CurrentProcess()); err != nil {
		return 0, fmt.Errorf("hostlockdown: AssignProcessToJobObject: %w", err)
	}

	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = jobLimitFlags
	limits.BasicLimitInformation.ActiveProcessLimit = 1
	if err = setJobInformation(job, windows.JobObjectExtendedLimitInformation, unsafe.Pointer(&limits), unsafe.Sizeof(limits)); err != nil {
		return 0, fmt.Errorf("hostlockdown: SetInformationJobObject(ExtendedLimit): %w", err)
	}

	if cpuQuotaMillis > 0 {
		if err := setJobCPURate(job, cpuQuotaMillis); err != nil {
			return 0, err
		}
	}

	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: jobUILimits}
	if err = setJobInformation(job, windows.JobObjectBasicUIRestrictions, unsafe.Pointer(&ui), unsafe.Sizeof(ui)); err != nil {
		return 0, fmt.Errorf("hostlockdown: SetInformationJobObject(BasicUIRestrictions): %w", err)
	}

	if err = verifyContainmentJob(job); err != nil {
		return 0, err
	}
	return job, nil
}

func setJobInformation(job windows.Handle, class uint32, info unsafe.Pointer, size uintptr) error {
	r1, _, callErr := procSetInformationJobObject.Call(uintptr(job), uintptr(class), uintptr(info), size)
	if r1 == 0 {
		return callErr
	}
	return nil
}

func queryJobInformation(job windows.Handle, class uint32, info unsafe.Pointer, size uintptr) error {
	r1, _, callErr := procQueryInformationJobObject.Call(uintptr(job), uintptr(class), uintptr(info), size, 0)
	if r1 == 0 {
		return callErr
	}
	return nil
}

// verifyContainmentJob reads the limits back and confirms that the current
// process belongs to the job.
func verifyContainmentJob(job windows.Handle) error {
	var inJob int32
	r1, _, callErr := procIsProcessInJob.Call(uintptr(windows.CurrentProcess()), uintptr(job), uintptr(unsafe.Pointer(&inJob)))
	if r1 == 0 {
		return fmt.Errorf("hostlockdown: IsProcessInJob: %w", callErr)
	}
	if inJob == 0 {
		return errors.New("hostlockdown: current process is not in the containment job")
	}

	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err := queryJobInformation(job, windows.JobObjectExtendedLimitInformation, unsafe.Pointer(&limits), unsafe.Sizeof(limits)); err != nil {
		return fmt.Errorf("hostlockdown: QueryInformationJobObject(ExtendedLimit): %w", err)
	}
	basic := limits.BasicLimitInformation
	if basic.LimitFlags&jobLimitFlags != jobLimitFlags || basic.ActiveProcessLimit != 1 {
		return fmt.Errorf("hostlockdown: job limits read back as flags %#x, active process limit %d", basic.LimitFlags, basic.ActiveProcessLimit)
	}

	var ui windows.JOBOBJECT_BASIC_UI_RESTRICTIONS
	if err := queryJobInformation(job, windows.JobObjectBasicUIRestrictions, unsafe.Pointer(&ui), unsafe.Sizeof(ui)); err != nil {
		return fmt.Errorf("hostlockdown: QueryInformationJobObject(BasicUIRestrictions): %w", err)
	}
	if ui.UIRestrictionsClass&jobUILimits != jobUILimits {
		return fmt.Errorf("hostlockdown: job UI limits read back as %#x", ui.UIRestrictionsClass)
	}
	return nil
}

// disableWin32kSystemCalls runs step 8 and reads the policy back.
func disableWin32kSystemCalls() error {
	if err := procSetProcessMitigationPolicy.Find(); err != nil {
		return fmt.Errorf("hostlockdown: SetProcessMitigationPolicy is unavailable: %w", err)
	}
	policy := processMitigationSystemCallDisablePolicy{Flags: disallowWin32kSystemCalls}
	r1, _, callErr := procSetProcessMitigationPolicy.Call(
		processSystemCallDisablePolicy,
		uintptr(unsafe.Pointer(&policy)),
		unsafe.Sizeof(policy),
	)
	if r1 == 0 {
		return fmt.Errorf("hostlockdown: SetProcessMitigationPolicy(ProcessSystemCallDisablePolicy): %w", callErr)
	}

	var got processMitigationSystemCallDisablePolicy
	r1, _, callErr = procGetProcessMitigationPolicy.Call(
		uintptr(windows.CurrentProcess()),
		processSystemCallDisablePolicy,
		uintptr(unsafe.Pointer(&got)),
		unsafe.Sizeof(got),
	)
	if r1 == 0 {
		return fmt.Errorf("hostlockdown: GetProcessMitigationPolicy(ProcessSystemCallDisablePolicy): %w", callErr)
	}
	if got.Flags&disallowWin32kSystemCalls == 0 {
		return fmt.Errorf("hostlockdown: win32k system call policy reads back as %#x", got.Flags)
	}
	return nil
}

func setJobCPURate(job windows.Handle, cpuQuotaMillis int64) error {
	rate := jobCPURate(cpuQuotaMillis, runtime.NumCPU())
	info := jobCPURateControl{ControlFlags: jobCPURateControlEnable | jobCPURateControlHardCap, CPURate: rate}
	if err := setJobInformation(job, jobObjectCPURateControlInformation, unsafe.Pointer(&info), unsafe.Sizeof(info)); err != nil {
		return fmt.Errorf("hostlockdown: SetInformationJobObject(CpuRateControl): %w", err)
	}
	var got jobCPURateControl
	if err := queryJobInformation(job, jobObjectCPURateControlInformation, unsafe.Pointer(&got), unsafe.Sizeof(got)); err != nil {
		return fmt.Errorf("hostlockdown: QueryInformationJobObject(CpuRateControl): %w", err)
	}
	if got.ControlFlags&info.ControlFlags != info.ControlFlags || got.CPURate != info.CPURate {
		return fmt.Errorf("hostlockdown: the job CPU cap reads back as %+v, want %+v", got, info)
	}
	return nil
}
