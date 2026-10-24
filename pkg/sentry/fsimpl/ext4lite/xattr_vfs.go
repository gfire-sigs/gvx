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
	"strings"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// checkXattrPrefix accepts the namespaces that this filesystem stores:
// user, trusted, and security. A POSIX ACL is not supported, so the system
// namespace is rejected.
func checkXattrPrefix(name string) error {
	for _, prefix := range []string{linux.XATTR_USER_PREFIX, linux.XATTR_TRUSTED_PREFIX, linux.XATTR_SECURITY_PREFIX} {
		if strings.HasPrefix(name, prefix) {
			return nil
		}
	}
	return linuxerr.EOPNOTSUPP
}

// listXattr returns the names of the attributes that the caller may see. The
// trusted namespace stays hidden from a caller without CAP_SYS_ADMIN, as in
// fs/xattr.c:simple_xattr_list().
func (i *inode) listXattr(creds *auth.Credentials, size uint64) ([]string, error) {
	all, err := i.n.listXattr()
	if err != nil {
		return nil, toLinuxErr(err)
	}
	haveCap := creds.HasRootCapability(linux.CAP_SYS_ADMIN)
	names := make([]string, 0, len(all))
	listSize := 0
	for _, name := range all {
		if checkXattrPrefix(name) != nil {
			continue
		}
		if !haveCap && strings.HasPrefix(name, linux.XATTR_TRUSTED_PREFIX) {
			continue
		}
		names = append(names, name)
		// One more byte for the null terminator.
		listSize += len(name) + 1
	}
	if size != 0 && uint64(listSize) > size {
		return nil, linuxerr.ERANGE
	}
	return names, nil
}

func (i *inode) getXattr(creds *auth.Credentials, opts *vfs.GetXattrOptions) (string, error) {
	mode, uid, gid := i.owner()
	// Linux requires read permission for the namespaces that are not security,
	// system, or trusted, and it checks before any handler rejects the name.
	if vfs.XattrReadNeedsFilePermission(opts.Name) {
		if err := vfs.GenericCheckPermissions(creds, vfs.MayRead, mode, nil, uid, gid); err != nil {
			return "", err
		}
	}
	if err := checkXattrPrefix(opts.Name); err != nil {
		return "", err
	}
	if err := vfs.CheckXattrPermissions(creds, vfs.MayRead, mode, uid, opts.Name); err != nil {
		return "", err
	}
	raw, err := i.n.getXattr(opts.Name)
	if err != nil {
		return "", toLinuxErr(err)
	}
	value := string(raw)
	// The size is a hint of the caller. A larger value gets ERANGE.
	if opts.Size != 0 && uint64(len(value)) > opts.Size {
		return "", linuxerr.ERANGE
	}
	if opts.Name == linux.XATTR_SECURITY_CAPABILITY {
		return auth.FixupVfsCapDataOnGet(creds, value)
	}
	return value, nil
}

func (i *inode) setXattr(creds *auth.Credentials, mnt *vfs.Mount, opts *vfs.SetXattrOptions) error {
	if err := checkXattrPrefix(opts.Name); err != nil {
		return err
	}
	mode, uid, gid := i.owner()
	if err := vfs.GenericCheckPermissions(creds, vfs.MayWrite, mode, nil, uid, gid); err != nil {
		return err
	}
	if err := vfs.CheckXattrPermissions(creds, vfs.MayWrite, mode, uid, opts.Name); err != nil {
		return err
	}
	if err := i.fs.beginWrite(mnt); err != nil {
		return err
	}
	defer mnt.EndWrite()
	value := opts.Value
	if opts.Name == linux.XATTR_SECURITY_CAPABILITY {
		var err error
		value, err = auth.FixupVfsCapDataOnSet(creds, value, uid, gid)
		if err != nil {
			return err
		}
	}
	create := opts.Flags&linux.XATTR_CREATE != 0
	replace := opts.Flags&linux.XATTR_REPLACE != 0
	if err := i.n.setXattr(opts.Name, []byte(value), create, replace); err != nil {
		return toLinuxErr(err)
	}
	i.touchCtime()
	return nil
}

func (i *inode) removeXattr(creds *auth.Credentials, mnt *vfs.Mount, name string) error {
	if err := checkXattrPrefix(name); err != nil {
		return err
	}
	mode, uid, gid := i.owner()
	if err := vfs.GenericCheckPermissions(creds, vfs.MayWrite, mode, nil, uid, gid); err != nil {
		return err
	}
	if err := vfs.CheckXattrPermissions(creds, vfs.MayWrite, mode, uid, name); err != nil {
		return err
	}
	if err := i.fs.beginWrite(mnt); err != nil {
		return err
	}
	defer mnt.EndWrite()
	if err := i.n.removeXattr(name); err != nil {
		return toLinuxErr(err)
	}
	i.touchCtime()
	return nil
}

// ListXattrAt implements vfs.FilesystemImpl.ListXattrAt.
func (fs *filesystem) ListXattrAt(ctx context.Context, rp *vfs.ResolvingPath, size uint64) ([]string, error) {
	fs.lock(ctx)
	defer fs.unlock(ctx)
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		return nil, err
	}
	return d.inode.listXattr(rp.Credentials(), size)
}

// GetXattrAt implements vfs.FilesystemImpl.GetXattrAt.
func (fs *filesystem) GetXattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetXattrOptions) (string, error) {
	fs.lock(ctx)
	defer fs.unlock(ctx)
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		return "", err
	}
	return d.inode.getXattr(rp.Credentials(), &opts)
}

// SetXattrAt implements vfs.FilesystemImpl.SetXattrAt.
func (fs *filesystem) SetXattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetXattrOptions) error {
	fs.lock(ctx)
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		fs.unlock(ctx)
		return err
	}
	err = d.inode.setXattr(rp.Credentials(), rp.Mount(), &opts)
	fs.unlock(ctx)
	if err != nil {
		return err
	}
	d.InotifyWithParent(ctx, linux.IN_ATTRIB, 0, vfs.InodeEvent)
	return nil
}

// RemoveXattrAt implements vfs.FilesystemImpl.RemoveXattrAt.
func (fs *filesystem) RemoveXattrAt(ctx context.Context, rp *vfs.ResolvingPath, name string) error {
	fs.lock(ctx)
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		fs.unlock(ctx)
		return err
	}
	err = d.inode.removeXattr(rp.Credentials(), rp.Mount(), name)
	fs.unlock(ctx)
	if err != nil {
		return err
	}
	d.InotifyWithParent(ctx, linux.IN_ATTRIB, 0, vfs.InodeEvent)
	return nil
}

// ListXattr implements vfs.FileDescriptionImpl.ListXattr.
func (fd *fileDescription) ListXattr(ctx context.Context, size uint64) ([]string, error) {
	return fd.dentry.inode.listXattr(auth.CredentialsFromContext(ctx), size)
}

// GetXattr implements vfs.FileDescriptionImpl.GetXattr.
func (fd *fileDescription) GetXattr(ctx context.Context, opts vfs.GetXattrOptions) (string, error) {
	return fd.dentry.inode.getXattr(auth.CredentialsFromContext(ctx), &opts)
}

// SetXattr implements vfs.FileDescriptionImpl.SetXattr.
func (fd *fileDescription) SetXattr(ctx context.Context, opts vfs.SetXattrOptions) error {
	if err := fd.dentry.inode.setXattr(auth.CredentialsFromContext(ctx), fd.vfsfd.Mount(), &opts); err != nil {
		return err
	}
	fd.dentry.InotifyWithParent(ctx, linux.IN_ATTRIB, 0, vfs.InodeEvent)
	return nil
}

// RemoveXattr implements vfs.FileDescriptionImpl.RemoveXattr.
func (fd *fileDescription) RemoveXattr(ctx context.Context, name string) error {
	if err := fd.dentry.inode.removeXattr(auth.CredentialsFromContext(ctx), fd.vfsfd.Mount(), name); err != nil {
		return err
	}
	fd.dentry.InotifyWithParent(ctx, linux.IN_ATTRIB, 0, vfs.InodeEvent)
	return nil
}
