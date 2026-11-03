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

package hostfs

// probeFileIDs decides whether the volume of the workspace gives each file an
// identity that .gvx_meta can key records on, and whether the host can open a
// file by that identity. It sets caps.StableIDs and caps.ExistsByID.
//
// A volume qualifies when its files report a real identity (a birth time on
// Linux, an inode number on macOS, FILE_ID_INFO on Windows), the platform
// trusts the volume (APFS on macOS), and the identity of a file stays the same
// across a write. The write test rejects a volume that fills the birth time
// with the change time. A read-only workspace cannot create a probe file,
// so it trusts the identity of the root. A volume that fails keeps its records
// by guest path, as earlier releases did.
func probeFileIDs(host hostBackend, root hostInfo, readOnly bool, caps *WorkspaceCaps) {
	caps.StableIDs, caps.ExistsByID = false, false
	if !root.fidOK || root.fid.isZero() || !volumeIDsTrusted(host, readOnly) {
		return
	}
	if readOnly {
		caps.StableIDs = true
		return
	}
	f, remove, err := createProbeFile(host, probeBase()+"i")
	if err != nil {
		return
	}
	defer remove()
	before, err := host.fstat(f)
	if err != nil || !before.fidOK || before.fid.isZero() {
		return
	}
	if _, err := f.Write([]byte{0}); err != nil {
		return
	}
	after, err := host.fstat(f)
	if err != nil || after.fid != before.fid {
		return
	}
	caps.StableIDs = true
	if found, err := host.existsByID(before.fid); err != nil || !found {
		return
	}
	// remove closes the probe file and unlinks it. The deferred call repeats
	// the removal and fails without effect.
	remove()
	found, err := host.existsByID(before.fid)
	caps.ExistsByID = err == nil && !found
}
