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

//go:build linux

package hostfs

import (
	"math"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/seccomp"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/runsc/boot/filter/config"
)

func applyTestHostLockdown(dir string, readOnly bool) (hostlockdown.Status, error) {
	return hostlockdown.Apply(hostlockdown.Options{
		Mounts: []hostlockdown.HostMount{
			{Path: dir, ReadOnly: readOnly},
		},
		InstallSyscallFilter: func() error {
			opt := config.Options{
				Platform:       platform.StaticSeccompInfo{PlatformName: "test", Filters: seccomp.NewSyscallRules()},
				HostFilesystem: true,
				ControllerFD:   math.MaxUint32,
				ProcSelfFD:     math.MaxUint32,
				CgoEnabled:     true,
			}
			rules, denyRules := config.Rules(opt)
			rules.Add(unix.SYS_FCNTL, seccomp.Or{
				seccomp.PerArg{seccomp.AnyValue{}, seccomp.EqualTo(unix.F_SETFD), seccomp.EqualTo(unix.FD_CLOEXEC)},
				seccomp.PerArg{seccomp.AnyValue{}, seccomp.EqualTo(unix.F_DUPFD_CLOEXEC)},
			})
			rules.Add(unix.SYS_SCHED_GETAFFINITY, seccomp.MatchAll{})
			rules.Add(unix.SYS_CLONE, seccomp.PerArg{
				seccomp.EqualTo(unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES |
					unix.CLONE_SIGHAND | unix.CLONE_THREAD | unix.CLONE_SYSVSEM |
					unix.CLONE_SETTLS | unix.CLONE_PARENT_SETTID |
					unix.CLONE_CHILD_CLEARTID),
			})
			for _, flags := range []uintptr{linux.FUTEX_PRIVATE_FLAG, linux.FUTEX_PRIVATE_FLAG | linux.FUTEX_CLOCK_REALTIME} {
				rules.Add(unix.SYS_FUTEX, seccomp.PerArg{
					seccomp.AnyValue{},
					seccomp.EqualTo(linux.FUTEX_WAIT_BITSET | flags),
				})
			}
			rules.Add(unix.SYS_RENAMEAT, seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.AnyValue{},
				seccomp.NonNegativeFD{},
				seccomp.AnyValue{},
			})
			rules.Add(unix.SYS_OPENAT2, seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.AnyValue{},
				seccomp.AnyValue{},
				seccomp.EqualTo(unix.SizeofOpenHow),
			})
			rules.Add(unix.SYS_LINKAT, seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.AnyValue{},
				seccomp.NonNegativeFD{},
				seccomp.AnyValue{},
				seccomp.EqualTo(0),
			})
			for _, op := range []uintptr{
				unix.LOCK_SH,
				unix.LOCK_EX,
				unix.LOCK_SH | unix.LOCK_NB,
				unix.LOCK_EX | unix.LOCK_NB,
				unix.LOCK_UN,
			} {
				rules.Add(unix.SYS_FLOCK, seccomp.PerArg{
					seccomp.NonNegativeFD{},
					seccomp.EqualTo(op),
				})
			}
			rules.Remove(unix.SYS_CLONE3)
			rejected := seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
				unix.SYS_EXECVE:   seccomp.MatchAll{},
				unix.SYS_EXECVEAT: seccomp.MatchAll{},
				unix.SYS_CLONE:    seccomp.MatchAll{},
				unix.SYS_OPENAT:   seccomp.MatchAll{},
				unix.SYS_SOCKET:   seccomp.MatchAll{},
			})
			program := &seccomp.Program{
				RuleSets: []seccomp.RuleSet{
					{Rules: denyRules},
					{Rules: rules, Action: seccomp.Allow},
					{
						Rules:  seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{unix.SYS_CLONE3: seccomp.MatchAll{}}),
						Action: seccomp.ReturnError.Code(uint16(unix.ENOSYS)),
					},
					{Rules: rejected, Action: seccomp.ReturnError.Code(uint16(unix.EPERM))},
				},
				Options: config.SeccompOptions(opt),
			}
			return program.Install(nil)
		},
	})
}
