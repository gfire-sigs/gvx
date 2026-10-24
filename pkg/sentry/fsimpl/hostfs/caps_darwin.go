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

//go:build darwin

package hostfs

import "golang.org/x/sys/unix"

// platformCaps probes the volume of the workspace root on macOS. The host
// backend reads the case rule of the volume with fpathconf. A temporary file
// in the root shows whether the volume treats the NFC and NFD forms of a name
// as one name. APFS does. A read-only workspace assumes the APFS answer.
//
// Extended attributes stay in .gvx_meta on macOS, so NativeXattr is false.
func platformCaps(host hostBackend, readOnly bool) WorkspaceCaps {
	caps := WorkspaceCaps{
		CaseSensitive:     !host.caseInsensitive(),
		UnicodeNormalized: true,
		NativeRenameSwap:  true,
		NativeFallocate:   true,
	}
	if normalizes, ok := probeNormalizes(host, readOnly); ok {
		caps.UnicodeNormalized = normalizes
	}
	if !readOnly {
		caps.NativeRenameSwap = probeRenameSwap(host)
	}
	return caps
}

// probeRenameSwap reports whether renamex_np exchanges two names on the
// volume.
func probeRenameSwap(host hostBackend) bool {
	base := probeBase()
	_, removeA, err := createProbeFile(host, base+"a")
	if err != nil {
		return false
	}
	defer removeA()
	_, removeB, err := createProbeFile(host, base+"b")
	if err != nil {
		return false
	}
	defer removeB()
	dirfd := int(host.rootDir())
	return unix.RenameatxNp(dirfd, base+"a", dirfd, base+"b", unix.RENAME_SWAP) == nil
}
