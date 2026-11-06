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

package overlay

import (
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// dirDevice returns the device numbers of the directories of an overlay. A
// caller that sets DirDevMajor chooses the numbers, so that the root file
// system of a sandbox has the numbers of its disk in /proc/diskstats. The
// overlay then does not own the numbers, and it does not release them. Any
// other overlay takes an anonymous number from the VFS.
func (o *FilesystemOptions) dirDevice(vfsObj *vfs.VirtualFilesystem) (major, minor uint32, err error) {
	if o.DirDevMajor != linux.UNNAMED_MAJOR {
		return o.DirDevMajor, o.DirDevMinor, nil
	}
	minor, err = vfsObj.GetAnonBlockDevMinor()
	return linux.UNNAMED_MAJOR, minor, err
}
