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

	"golang.org/x/sys/unix"

	"z.gfire.dev/gvx/pkg/seccomp"
	"z.gfire.dev/gvx/runsc/boot/filter/config"
)

// syscallFilter returns the function that installs the seccomp program of the
// Sentry on every thread of the process. The program is the one that runsc
// builds for the Sentry: an allowlist, where every other system call kills the
// process. The options follow the config of the Sandbox. The platform adds its
// own rules, and NAT adds the host socket rules of hostinet. A bind or volume
// mount adds the rules of the host filesystem, which allow opens relative to a
// directory descriptor only.
func (s *Sandbox) syscallFilter() func() error {
	return func() error {
		opt := config.Options{
			Platform:       s.plat.SeccompInfo(),
			HostNetwork:    s.cfg.NetworkMode == NetModeNAT,
			HostFilesystem: s.cfg.hasHostDirs(),
			// gvx has no control server. No descriptor has this number.
			ControllerFD: math.MaxUint32,
		}
		rules, denyRules := config.Rules(opt)
		rules.Merge(embedderRules(s.cfg))

		seccompOpts := config.SeccompOptions(opt)
		if seccompLogOnly {
			seccompOpts.DefaultAction = seccomp.Log
		}
		program := &seccomp.Program{
			RuleSets: []seccomp.RuleSet{
				{Rules: denyRules},
				{Rules: rules, Action: seccomp.Allow},
				// The calls that hostlockdown probes, and the calls that code
				// in the embedding process may try, return EPERM. The Sentry
				// kills the process for them, but a Go program that embeds gvx
				// expects an error from os/exec or os.Open.
				{Rules: rejectedRules(), Action: seccomp.ReturnError.Code(uint16(unix.EPERM))},
			},
			Options: seccompOpts,
		}
		return program.Install(nil)
	}
}

// rejectedRules lists the calls that return EPERM when no allow rule matches.
// The list is short on purpose, because every call here keeps the process
// alive where the Sentry of runsc dies. Each call has a reason:
//   - hostlockdown probes execve, execveat, clone, openat, and socket.
//   - The Go runtime opens cgroup files once a second to adjust GOMAXPROCS and
//     treats a failure as "no limit". Code in the embedding process may call
//     os/exec, os.Open, or net.Dial, and expects an error from each.
//
// The calls open, creat, fork, vfork, clone3, and openat2 stay outside the
// list, so they kill the process. The Go standard library does not call them
// in a build without cgo.
func rejectedRules() seccomp.SyscallRules {
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_EXECVE:   seccomp.MatchAll{},
		unix.SYS_EXECVEAT: seccomp.MatchAll{},
		unix.SYS_CLONE:    seccomp.MatchAll{},
		unix.SYS_OPENAT:   seccomp.MatchAll{},
		unix.SYS_SOCKET:   seccomp.MatchAll{},
	})
}

// embedderRules lists the host calls that gvx makes beyond the Sentry of runsc.
// The Sentry in runsc runs in its own process with a gofer and the control
// server. The Sentry in gvx runs in the host process and reaches the host
// through Go packages, so these calls come from pkg/fd, os.Root, and the net
// package. Each rule is as narrow as the call allows.
func embedderRules(cfg Config) seccomp.SyscallRules {
	rules := seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		// pkg/fd marks a duplicated descriptor close-on-exec.
		unix.SYS_FCNTL: seccomp.Or{
			seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.EqualTo(unix.F_SETFD),
				seccomp.EqualTo(unix.FD_CLOEXEC),
			},
			seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.EqualTo(unix.F_DUPFD_CLOEXEC),
			},
		},
	})
	// The Go runtime reads the CPU affinity mask once a second to adjust
	// GOMAXPROCS. The call reads one mask and has no side effect.
	rules.Add(unix.SYS_SCHED_GETAFFINITY, seccomp.MatchAll{})
	if cfg.hasHostDirs() {
		// os.Root.Rename calls renameat. The host filesystem rules of runsc
		// have only renameat2.
		rules.Add(unix.SYS_RENAMEAT, seccomp.PerArg{
			seccomp.NonNegativeFD{},
			seccomp.AnyValue{},
			seccomp.NonNegativeFD{},
			seccomp.AnyValue{},
		})
	}
	switch cfg.NetworkMode {
	case NetModeNAT:
		// The net package opens sockets with protocol 0, but hostinet allows
		// only sockets with an explicit protocol.
		for _, family := range []uintptr{unix.AF_INET, unix.AF_INET6} {
			for _, typ := range []uintptr{unix.SOCK_STREAM, unix.SOCK_DGRAM} {
				rules.Add(unix.SYS_SOCKET, seccomp.PerArg{
					seccomp.EqualTo(family),
					seccomp.EqualTo(typ | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
					seccomp.EqualTo(0),
				})
			}
		}
	case NetModeWireGuard:
		// The pre-bound UDP socket of wireguard-go sends and receives
		// datagrams. Seccomp cannot read the peer address, so the filter cannot
		// pin the peer port the way the Seatbelt profile does.
		rules.Add(unix.SYS_SENDTO, seccomp.MatchAll{})
		rules.Add(unix.SYS_RECVFROM, seccomp.MatchAll{})
	}
	return rules
}
