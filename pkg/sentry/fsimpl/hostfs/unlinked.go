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

// This file tracks the regular files that no name reaches any more. A guest
// can keep such a file open, read it, and write it. POSIX reports a link count
// of zero for it. Linux and macOS report that through fstat on the open host
// file. Windows keeps a link count above zero while a handle stays open, so
// statxFor reads the unlinked flag of the inode on every host.

// noteUnlinked records that a guest unlink removed the last name of the file.
// The registry of open handles has detached the handles from the path already.
// Only a regular file is tracked here. special_node.go counts the links of a
// socket, a FIFO, and a device node itself.
func (i *inode) noteUnlinked() {
	if i.isRegular() {
		i.unlinked.Store(true)
	}
}

// noteReplaced records that a rename replaced a name of the file. The file is
// unlinked when that name was the last one. The cached link count is exact,
// because every guest change of a link count drops the cache.
func (i *inode) noteReplaced() {
	if i.isRegular() && i.snapshot().info.nlink <= 1 {
		i.unlinked.Store(true)
	}
}
