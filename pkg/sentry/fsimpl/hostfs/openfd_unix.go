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

//go:build !windows

package hostfs

import (
	"fmt"
	"os"
	"strings"
)

// OpenWorkspaceFromDirFD builds a hostfs Workspace directly from an already
// open POSIX directory file descriptor (for example received over SCM_RIGHTS).
// Ownership of dirFD always transfers to OpenWorkspaceFromDirFD, which closes
// it on error.
//
// When singleFileName is empty, dirFD is mounted as a directory workspace.
// When singleFileName is non-empty, dirFD is the parent directory and
// singleFileName must name a single regular-file leaf entry inside it.
func OpenWorkspaceFromDirFD(dirFD int, label, singleFileName string, readOnly bool) (*Workspace, error) {
	if dirFD < 0 {
		return nil, fmt.Errorf("hostfs: invalid directory descriptor %d", dirFD)
	}
	if label == "" {
		label = "attached-bind"
	}
	dir := os.NewFile(uintptr(dirFD), label)
	if dir == nil {
		return nil, fmt.Errorf("hostfs: wrap directory descriptor %d", dirFD)
	}
	info, err := fstatInfo(dirFD)
	if err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("hostfs: stat attached descriptor: %w", err)
	}
	if info.kind != hostKindDir {
		_ = dir.Close()
		return nil, fmt.Errorf("hostfs: attached descriptor is not a directory")
	}

	if singleFileName != "" {
		if singleFileName == "." || singleFileName == ".." || strings.ContainsAny(singleFileName, "/\x00") {
			_ = dir.Close()
			return nil, fmt.Errorf("hostfs: invalid single-file leaf name %q", singleFileName)
		}
	}

	backend, err := newHostRootFromFile(dir)
	if err != nil {
		return nil, err
	}
	if singleFileName != "" {
		finfo, lerr := backend.lstat(singleFileName)
		if lerr != nil {
			_ = backend.close()
			return nil, fmt.Errorf("hostfs: stat single file %q: %w", singleFileName, lerr)
		}
		if finfo.kind != hostKindRegular {
			_ = backend.close()
			return nil, fmt.Errorf("hostfs: single-file target %q is not a regular file", singleFileName)
		}
	}
	return initWorkspace(label, nil, backend, singleFileName, readOnly, workspaceOptions{coalesce: defaultCoalesceWindow})
}
