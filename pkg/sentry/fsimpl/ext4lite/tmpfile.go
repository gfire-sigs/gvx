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
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// A file that open(2) creates with O_TMPFILE is an inode with no link and no
// directory entry. It is the same object as the file that a guest unlinks and
// keeps open, so the orphan list of the volume (see orphan.go) already frees it
// at the last close and after a crash. The creation only has to leave the node
// at link count zero.
//
// Linux marks such a file with I_LINKABLE unless the guest passed O_EXCL. A
// linkable file can later get a name through linkat with AT_EMPTY_PATH or
// through the magic link in /proc/self/fd. Every other file with no link
// refuses linkat with ENOENT, so inode.tmpLinkable tells the two apart. A link
// gives the inode a new dentry. The dentry of the open descriptor stays out of
// the tree and stays dead, as the dentry of a file that was never named does.

// openTmpfile implements OpenAt with O_TMPFILE. The path names the directory
// for the file. VirtualFilesystem.OpenAt checked that the flags include
// O_DIRECTORY and a writable access mode and exclude O_CREAT.
func (fs *filesystem) openTmpfile(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fs.lock(ctx)
	unlocked := false
	unlock := func() {
		if !unlocked {
			fs.unlock(ctx)
			unlocked = true
		}
	}
	defer unlock()
	parent, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		return nil, err
	}
	if !parent.inode.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	creds := rp.Credentials()
	if err := parent.inode.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return nil, err
	}
	if parent.dead {
		return nil, linuxerr.ENOENT
	}
	var ino *inode
	if err := fs.writeOp(rp.Mount(), func() error {
		uid, gid, _ := parent.inode.newOwner(creds)
		n, err := fs.v.newNode(modeRegular|uint16(opts.Mode&0o7777), uint32(uid), uint32(gid), 0, fs.now())
		if err != nil {
			return toLinuxErr(err)
		}
		ino = fs.inodeForNodeLocked(n)
		return nil
	}); err != nil {
		return nil, err
	}
	ino.tmpLinkable = opts.Flags&linux.O_EXCL == 0
	d := fs.newDentryLocked(nil, "", ino)
	d.dead = true
	unlock()
	// The dentry holds one reference for this call. The file description takes
	// its own, and a failed open frees the inode with this one.
	defer d.DecRef(ctx)
	// Nothing is mounted on the new dentry, so the call returns no reference.
	for _, r := range rp.VirtualFilesystem().InvalidateDentry(ctx, &d.vfsd) {
		r.DecRef(ctx)
	}
	// The flags describe the directory and the creation, not the file.
	opts.Flags &^= linux.O_TMPFILE | linux.O_DIRECTORY | linux.O_EXCL
	return d.open(ctx, rp, &opts, true)
}
