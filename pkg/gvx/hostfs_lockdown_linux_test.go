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

func applyHostfsTestLockdown(dir string, readOnly bool) (hostlockdown.Status, error) {
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
				CgoEnabled:     cgoBuild,
			}
			rules, denyRules := config.Rules(opt)
			rules.Merge(embedderRules(Config{}, true, false))
			// Under -race, extra_filters_race.go widens SYS_CLONE to MatchAll{},
			// which bypasses rejectedRules() for hostlockdown's clone(CLONE_THREAD)
			// probe. Restrict SYS_CLONE to thread creation so the probe gets EPERM.
			rules.Remove(unix.SYS_CLONE)
			rules.Set(unix.SYS_CLONE, seccomp.PerArg{
				seccomp.EqualTo(unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES |
					unix.CLONE_SIGHAND | unix.CLONE_THREAD | unix.CLONE_SYSVSEM |
					unix.CLONE_SETTLS | unix.CLONE_PARENT_SETTID |
					unix.CLONE_CHILD_CLEARTID),
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
		},
	})
}
