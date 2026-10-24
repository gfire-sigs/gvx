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

package hostfs

const (
	// hostSeparatorIsBackslash reports whether the host treats a backslash as
	// a path separator. Windows does.
	hostSeparatorIsBackslash = true

	// hostRenameReplacesDir reports whether the host rename replaces an empty
	// destination directory. The Windows rename information structure fails
	// when the destination is a directory, so hostfs removes the empty
	// destination first.
	hostRenameReplacesDir = false
)

// platformCaps probes the volume of the workspace root on Windows. NTFS
// restricts the Windows names, and it refuses to move a directory that has an
// open descendant. The case rule depends on the volume and on the per-directory
// flag of the root, so a probe file shows it. A probe that cannot tell assumes
// the default NTFS rule, a volume that folds case. That choice only adds
// collision checks.
//
// Extended attributes and the exchange of two names stay in hostfs on Windows.
func platformCaps(host hostBackend, readOnly bool) WorkspaceCaps {
	caps := WorkspaceCaps{
		RestrictsWinNames: true,
		LocksOpenDirMove:  true,
		NativeFallocate:   true,
	}
	if folds, ok := probeFoldsCase(host, readOnly); ok {
		caps.CaseSensitive = !folds
	}
	return caps
}
