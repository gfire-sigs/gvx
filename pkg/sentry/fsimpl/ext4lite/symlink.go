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

// maxSymlinkTarget is the longest symlink target, as in Linux.
const maxSymlinkTarget = 4095

// symlinkTarget returns the target of a symlink inode. The target never
// changes, so the inode reads it once. The engine keeps up to 128 bytes in the
// inode and the rest in extents.
func (i *inode) symlinkTarget() (string, error) {
	i.targetOnce.Do(func() {
		i.n.mu.RLock()
		size := i.n.size
		i.n.mu.RUnlock()
		buf := make([]byte, size)
		got, err := i.n.readAt(buf, 0)
		if err != nil && got != len(buf) {
			i.targetErr = toLinuxErr(err)
			return
		}
		i.target = string(buf[:got])
	})
	return i.target, i.targetErr
}

// SymlinkAt implements vfs.FilesystemImpl.SymlinkAt.
func (fs *filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	return fs.doCreateAt(ctx, rp, false, func(parent *dentry, name string) (*inode, error) {
		if target == "" {
			return nil, linuxerr.ENOENT
		}
		if len(target) > maxSymlinkTarget {
			return nil, linuxerr.ENAMETOOLONG
		}
		uid, gid, _ := parent.inode.newOwner(rp.Credentials())
		return fs.newChildLocked(parent, name, modeSymlink|0o777, uid, gid, 0, func(n *node) error {
			_, err := n.writeAt([]byte(target), 0)
			return err
		})
	})
}

// ReadlinkAt implements vfs.FilesystemImpl.ReadlinkAt.
func (fs *filesystem) ReadlinkAt(ctx context.Context, rp *vfs.ResolvingPath) (string, error) {
	fs.lock(ctx)
	defer fs.unlock(ctx)
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		return "", err
	}
	if !d.inode.isSymlink() {
		return "", linuxerr.EINVAL
	}
	d.inode.touchAtime(rp.Mount())
	return d.inode.symlinkTarget()
}
