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

package gvx

import (
	"z.gfire.dev/gvx/pkg/abi"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
)

// The magic numbers and commands of reboot(2), from include/uapi/linux/reboot.h.
const (
	rebootMagic1  = 0xfee1dead
	rebootMagic2  = 672274793
	rebootMagic2A = 85072278
	rebootMagic2B = 369367448
	rebootMagic2C = 537993216

	rebootCmdRestart  = 0x01234567
	rebootCmdHalt     = 0xcdef0123
	rebootCmdCADOn    = 0x89abcdef
	rebootCmdCADOff   = 0x00000000
	rebootCmdPowerOff = 0x4321fedc
	rebootCmdRestart2 = 0xa1b2c3d4
)

// rebootSysno holds the number of reboot(2) in each syscall table.
var rebootSysno = map[arch.Arch]uintptr{
	arch.AMD64: 169,
	arch.ARM64: 142,
}

// The upstream table answers reboot(2) with ENOSYS. A guest init such as
// systemd then never stops after "systemctl poweroff". This init replaces the
// entry before any kernel starts.
func init() {
	for a, sysno := range rebootSysno {
		table, ok := kernel.LookupSyscallTable(abi.Linux, a)
		if !ok {
			continue
		}
		table.Table[sysno] = kernel.Syscall{
			Name:         "reboot",
			Fn:           reboot,
			SupportLevel: kernel.SupportPartial,
			Note:         "Power off and halt stop the sandbox with status 0; restart stops it as if SIGHUP killed init.",
		}
		table.Init()
	}
}

// rebootExitStatus returns the exit status of the sandbox for a reboot(2)
// command, and false for a command that does not stop the system. The guest
// root PID namespace is the whole sandbox, so a power off ends the run with
// status 0. A restart ends it as Linux ends a PID namespace on restart: init
// stops as if SIGHUP killed it.
func rebootExitStatus(cmd uint32) (linux.WaitStatus, bool) {
	switch cmd {
	case rebootCmdPowerOff, rebootCmdHalt:
		return linux.WaitStatusExit(0), true
	case rebootCmdRestart, rebootCmdRestart2:
		return linux.WaitStatusTerminationSignal(linux.SIGHUP), true
	default:
		return 0, false
	}
}

// reboot implements reboot(2) for a sandbox. A call in the root PID namespace
// stops every task of the sandbox. A call in a nested PID namespace kills the
// init of that namespace only, as Linux does.
func reboot(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	magic1, magic2, cmd := args[0].Uint(), args[1].Uint(), args[2].Uint()
	pidns := t.PIDNamespace()
	if !t.HasCapabilityIn(linux.CAP_SYS_BOOT, pidns.UserNamespace()) {
		return 0, nil, linuxerr.EPERM
	}
	if magic1 != rebootMagic1 {
		return 0, nil, linuxerr.EINVAL
	}
	switch magic2 {
	case rebootMagic2, rebootMagic2A, rebootMagic2B, rebootMagic2C:
	default:
		return 0, nil, linuxerr.EINVAL
	}
	if cmd == rebootCmdCADOn || cmd == rebootCmdCADOff {
		return 0, nil, nil
	}
	ws, ok := rebootExitStatus(cmd)
	if !ok {
		return 0, nil, linuxerr.EINVAL
	}
	if pidns != t.Kernel().RootPIDNamespace() {
		if init := pidns.TaskWithID(1); init != nil {
			_ = init.ThreadGroup().SendSignal(&linux.SignalInfo{Signo: int32(linux.SIGKILL), Code: linux.SI_KERNEL})
		}
		return 0, nil, nil
	}
	t.Kernel().TaskSet().Kill(ws)
	return 0, nil, nil
}
