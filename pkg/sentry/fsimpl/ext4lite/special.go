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

package ext4lite

import (
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// openSpecial opens a FIFO, a device node, or a socket node.
//
// A FIFO uses the pipe of its inode, which the VFS pipe implementation drives.
// A device node opens through the device registry of the VFS, and it fails
// with ENXIO when no device has that number. A socket node never opens, and a
// connect to it goes through BoundEndpointAt.
//
// Preconditions: no filesystem lock is held, because opening a FIFO can block
// until another process opens the other end.
func (d *dentry) openSpecial(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
	ino := d.inode
	switch ino.kind {
	case modeFIFO:
		return ino.pipe.Open(ctx, rp.Mount(), &d.vfsd, opts.Flags, &ino.locks)
	case modeChar, modeBlock:
		kind := vfs.CharDevice
		if ino.kind == modeBlock {
			kind = vfs.BlockDevice
		}
		a := ino.attr()
		major, minor := decodeRdev(a.rdev)
		return rp.VirtualFilesystem().OpenDeviceSpecialFile(ctx, rp.Mount(), &d.vfsd, kind, major, minor, opts)
	default:
		return nil, linuxerr.ENXIO
	}
}
