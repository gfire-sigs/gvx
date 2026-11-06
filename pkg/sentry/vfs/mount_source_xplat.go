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

package vfs

// MountSourceProvider is implemented by file systems that sit on a block
// device. MountSource returns the device node, such as /dev/vdb. The file
// /proc/<pid>/mountinfo and /proc/<pid>/mounts show it as the mount source,
// and cAdvisor uses it to find the disk of a file system. A file system
// without the interface has the source "none".
type MountSourceProvider interface {
	MountSource() string
}

// mountSource returns the mount source of mnt for the files in /proc.
func mountSource(mnt *Mount) string {
	if p, ok := mnt.fs.impl.(MountSourceProvider); ok {
		if source := p.MountSource(); source != "" {
			return manglePath(source)
		}
	}
	return "none"
}
