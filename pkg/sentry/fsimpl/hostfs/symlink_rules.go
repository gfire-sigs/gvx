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

import (
	"fmt"
	"io/fs"
	"strings"
)

// This file holds the rules for the targets of symbolic links that the guest
// creates. Two kinds of symbolic link exist in a workspace:
//
//   - A guest symbolic link lives only in .gvx_meta. The host never receives a
//     link, so the host kernel never follows one. The Sentry VFS resolves the
//     target string in the guest mount namespace. An absolute target such as
//     "/usr/bin/python3" and a target that climbs above the workspace, such as
//     "../..", name guest paths and cannot reach a host path.
//   - A native host link, which a host process created, stays under
//     validateSymlinkTarget. lookupLocked and listDir hide each host link that
//     points outside the workspace root.

var (
	// errSymlinkEmpty reports an empty target. It wraps fs.ErrNotExist, so the
	// guest sees ENOENT as on Linux.
	errSymlinkEmpty = fmt.Errorf("hostfs: empty symbolic link target: %w", fs.ErrNotExist)

	// errSymlinkNUL reports a target that holds a NUL byte. It wraps
	// fs.ErrInvalid, so the guest sees EINVAL.
	errSymlinkNUL = fmt.Errorf("hostfs: symbolic link target holds a NUL byte: %w", fs.ErrInvalid)
)

// validateGuestSymlinkTarget checks the target of a guest symbolic link. It
// rejects the empty target and a target with a NUL byte. Every other string is
// valid, because the host never interprets it.
func validateGuestSymlinkTarget(target string) error {
	switch {
	case target == "":
		return errSymlinkEmpty
	case strings.IndexByte(target, 0) >= 0:
		return errSymlinkNUL
	}
	return nil
}
