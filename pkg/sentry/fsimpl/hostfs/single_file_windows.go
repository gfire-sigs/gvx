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

import "golang.org/x/sys/windows"

// lstatBound reads the metadata of the bound file of a single-file workspace.
// OpenWorkspace resolved the stored name before the lockdown, so the call
// skips the check of the stored name that lstatIn makes. That check calls
// GetFinalPathNameByHandle, which reads the parent directory to normalize the
// name. The restricted token has no list right on the parent directory, so the
// query fails with ERROR_ACCESS_DENIED. The open needs only the right to read
// attributes on the file.
func (h *hostRoot) lstatBound(name string) (hostInfo, error) {
	handle, err := openAt(h.handle, name, windows.FILE_READ_ATTRIBUTES, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN, 0)
	if err != nil {
		return hostInfo{}, hostError("lstat", name, err)
	}
	defer closeHandle(handle)
	info, err := statHandle(handle)
	if err != nil {
		return hostInfo{}, hostError("lstat", name, err)
	}
	return info, nil
}
