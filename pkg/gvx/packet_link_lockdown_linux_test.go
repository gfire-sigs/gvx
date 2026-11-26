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

package gvx

import (
	"math"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/seccomp"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/runsc/boot/filter/config"
)

// applyNetLinkTestLockdownOpts installs the exact production NetModeLink
// seccomp-bpf policy (HostNetwork: false, no SYS_SOCKET/SYS_SENDTO/SYS_RECVFROM)
// alongside hostlockdown.Apply so the test exercises real Linux confinement.
func applyNetLinkTestLockdownOpts(opts hostlockdown.Options) (hostlockdown.Status, error) {
	opts.InstallSyscallFilter = func() error {
		opt := config.Options{
			Platform:     platform.StaticSeccompInfo{PlatformName: "test", Filters: seccomp.NewSyscallRules()},
			HostFS:       config.HostFSNone,
			HostNetwork:  opts.AllowOutboundNet,
			ControllerFD: math.MaxUint32,
			ProcSelfFD:   math.MaxUint32,
			CgoEnabled:   cgoBuild,
		}
		rules, denyRules := config.Rules(opt)
		rules.Merge(embedderRules(Config{NetworkMode: NetModeLink}, false, false))
		const runtimeThread = unix.CLONE_VM |
			unix.CLONE_FS |
			unix.CLONE_FILES |
			unix.CLONE_SIGHAND |
			unix.CLONE_SYSVSEM |
			unix.CLONE_THREAD
		const libcThread = runtimeThread |
			unix.CLONE_SETTLS |
			unix.CLONE_PARENT_SETTID |
			unix.CLONE_CHILD_CLEARTID
		rules.Remove(unix.SYS_CLONE)
		rules.Set(unix.SYS_CLONE, seccomp.Or{
			seccomp.PerArg{seccomp.EqualTo(runtimeThread)},
			seccomp.PerArg{seccomp.EqualTo(runtimeThread | unix.CLONE_SETTLS)},
			seccomp.PerArg{seccomp.EqualTo(libcThread)},
			seccomp.PerArg{seccomp.EqualTo(libcThread | unix.CLONE_DETACHED)},
		})
		if cgoBuild {
			rules.Remove(unix.SYS_CLONE3)
		}
		sets := []seccomp.RuleSet{
			{Rules: denyRules},
			{Rules: rules, Action: seccomp.Allow},
		}
		if cgoBuild {
			sets = append(sets, seccomp.RuleSet{
				Rules:  seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{unix.SYS_CLONE3: seccomp.MatchAll{}}),
				Action: seccomp.ReturnError.Code(uint16(unix.ENOSYS)),
			})
		}
		sets = append(sets, seccomp.RuleSet{
			Rules:  rejectedRules(),
			Action: seccomp.ReturnError.Code(uint16(unix.EPERM)),
		})
		program := &seccomp.Program{
			RuleSets: sets,
			Options:  config.SeccompOptions(opt),
		}
		return program.Install(nil)
	}
	return hostlockdown.Apply(opts)
}
