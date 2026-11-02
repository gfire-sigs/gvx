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
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	sentrylinux "z.gfire.dev/gvx/pkg/sentry/syscalls/linux"
)

// The keyctl(2) operation and special key ID that the upstream table does not
// know, from include/uapi/linux/keyctl.h.
const (
	keyctlLink         = 8
	keySpecUserKeyring = -4
)

// keyctlSysno holds the number of keyctl(2) in each syscall table.
var keyctlSysno = map[arch.Arch]uintptr{
	arch.AMD64: 250,
	arch.ARM64: 219,
}

// systemd links the user keyring into the new session keyring of each unit
// with KeyringMode=shared, such as run-lock.mount, and fails the unit with
// status 237/KEYRING when keyctl(2) returns ENOSYS. The Sentry has no user
// keyring and cannot add a key to any keyring, so the user keyring is always
// empty. This init lets that one link succeed as a no-op.
func init() {
	for a, sysno := range keyctlSysno {
		table, ok := kernel.LookupSyscallTable(abi.Linux, a)
		if !ok {
			continue
		}
		upstream := table.Table[sysno]
		upstream.Fn = keyctl
		table.Table[sysno] = upstream
		table.Init()
	}
}

// keyctl implements keyctl(2). It answers the link of the user keyring into
// the session keyring and passes every other call to the upstream handler.
func keyctl(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	if args[0].Int() == keyctlLink && args[1].Int() == keySpecUserKeyring && args[2].Int() == linux.KEY_SPEC_SESSION_KEYRING {
		return 0, nil, nil
	}
	return sentrylinux.Keyctl(t, sysno, args)
}
