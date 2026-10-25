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

import "golang.org/x/sys/unix"

// platformCaps returns the capabilities of a Linux workspace volume. A Linux
// volume keeps names case-sensitive and does not normalize Unicode, so the
// probe never creates a file for those two flags. The seccomp allowlist of the
// host filesystem already permits renameat2, fallocate, and the descriptor
// forms of the xattr calls. A writable workspace tries each call once on
// temporary files, before the lockdown, because a few volumes refuse them.
// A read-only workspace keeps the defaults, which it never uses.
func platformCaps(host hostBackend, readOnly bool) WorkspaceCaps {
	caps := WorkspaceCaps{
		CaseSensitive:    true,
		NativeXattr:      true,
		NativeRenameSwap: true,
		NativeFallocate:  true,
	}
	if !readOnly {
		probeLinuxCalls(host, &caps)
	}
	return caps
}

// probeLinuxCalls clears each native flag whose call fails on the volume.
func probeLinuxCalls(host hostBackend, caps *WorkspaceCaps) {
	base := probeBase()
	fa, removeA, err := createProbeFile(host, base+"a")
	if err != nil {
		return
	}
	defer removeA()
	_, removeB, err := createProbeFile(host, base+"b")
	if err != nil {
		return
	}
	defer removeB()

	if err := withFileFD(fa, func(fd int) error {
		if unix.Fsetxattr(fd, "user.gvx.probe", []byte{1}, 0) != nil {
			caps.NativeXattr = false
		}
		if unix.Fallocate(fd, 0, 0, 4096) != nil {
			caps.NativeFallocate = false
		}
		return nil
	}); err != nil {
		return
	}
	dirfd := int(host.rootDir())
	if renameSwap(dirfd, base+"a", dirfd, base+"b") != nil {
		caps.NativeRenameSwap = false
	}
}
