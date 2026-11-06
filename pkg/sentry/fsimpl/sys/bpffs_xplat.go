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

package sys

import (
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/kernfs"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// Linux creates the empty directory /sys/fs/bpf at boot. User space mounts
// bpffs on it. Gvx has no BPF objects to pin, so the filesystem type "bpf"
// holds directories only. Programs that mount bpffs, such as the Calico
// init container, see the magic number and the mount entry of Linux.

const (
	// BPFName is the name of the bpffs filesystem type.
	BPFName = "bpf"

	// bpfFSMagic is BPF_FS_MAGIC in include/uapi/linux/magic.h.
	bpfFSMagic = 0xcafe4a11

	// bpfRootMode is the root mode of Linux bpffs: S_ISVTX | 0777.
	bpfRootMode = linux.FileMode(0777 | linux.ModeSticky)
)

// BPFFilesystemType implements vfs.FilesystemType for bpffs.
type BPFFilesystemType struct{}

// Name implements vfs.FilesystemType.Name.
func (BPFFilesystemType) Name() string {
	return BPFName
}

// Release implements vfs.FilesystemType.Release.
func (BPFFilesystemType) Release(context.Context) {}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem. It accepts the
// data string of Linux without any option.
func (t BPFFilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, _ string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, nil, err
	}
	fs := &bpfFilesystem{}
	fs.devMinor = devMinor
	fs.MaxCachedDentries = defaultMaxCachedDentries
	fs.VFSFilesystem().Init(vfsObj, &t, fs)

	root := fs.newBPFDir(ctx, creds, bpfRootMode)
	fs.root = &root.dir
	var rootD kernfs.Dentry
	rootD.InitRoot(&fs.Filesystem, root)
	return fs.VFSFilesystem(), rootD.VFSDentry(), nil
}

// bpfFilesystem is a bpffs instance. It shares the kernfs plumbing of sysfs.
type bpfFilesystem struct {
	filesystem
}

// MountOptions implements vfs.FilesystemImpl.MountOptions. Linux bpffs shows
// no option of this kernel.
func (*bpfFilesystem) MountOptions() string {
	return ""
}

// bpfDir is a directory of bpffs. Users create and remove directories in it.
type bpfDir struct {
	dir

	fs *bpfFilesystem
}

var _ kernfs.Inode = (*bpfDir)(nil)

func (fs *bpfFilesystem) newBPFDir(ctx context.Context, creds *auth.Credentials, mode linux.FileMode) *bpfDir {
	d := &bpfDir{fs: fs}
	d.InodeAttrs.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linux.ModeDirectory|mode)
	d.OrderedChildren.Init(kernfs.OrderedChildrenOptions{Writable: true})
	d.InitRefs()
	return d
}

// Keep implements kernfs.Inode.Keep. The directories exist only in memory,
// so the dentry cache must not evict them.
func (*bpfDir) Keep() bool {
	return true
}

// StatFS implements kernfs.Inode.StatFS.
func (*bpfDir) StatFS(context.Context, *vfs.Filesystem) (linux.Statfs, error) {
	return vfs.GenericStatFS(bpfFSMagic), nil
}

// SetStat implements kernfs.Inode.SetStat. Linux bpffs allows chmod and chown.
func (d *bpfDir) SetStat(ctx context.Context, fs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	return d.InodeAttrs.SetStat(ctx, fs, creds, opts)
}

// NewDir implements kernfs.Inode.NewDir.
func (d *bpfDir) NewDir(ctx context.Context, name string, opts vfs.MkdirOptions) (kernfs.Inode, error) {
	mode := opts.Mode.Permissions()
	child, err := d.OrderedChildren.Inserter(name, func() kernfs.Inode {
		d.IncLinks(1)
		return d.fs.newBPFDir(ctx, auth.CredentialsFromContext(ctx), mode)
	})
	if err != nil {
		return nil, err
	}
	d.TouchCMtime(ctx)
	return child, nil
}

// RmDir implements kernfs.Inode.RmDir.
func (d *bpfDir) RmDir(ctx context.Context, name string, child kernfs.Inode) error {
	if err := d.OrderedChildren.RmDir(ctx, name, child); err != nil {
		return err
	}
	d.DecLinks()
	d.TouchCMtime(ctx)
	return nil
}

// Unlink implements kernfs.Inode.Unlink. Directories only exist in bpffs, so
// unlink fails as on a Linux directory.
func (*bpfDir) Unlink(context.Context, string, kernfs.Inode) error {
	return linuxerr.EISDIR
}

// bpfMountDir is the empty /sys/fs/bpf directory of sysfs. A mount of bpffs
// covers it.
type bpfMountDir struct {
	dir
}

var _ kernfs.Inode = (*bpfMountDir)(nil)

func (fs *filesystem) newBPFMountDir(ctx context.Context, creds *auth.Credentials) kernfs.Inode {
	d := &bpfMountDir{}
	d.InodeAttrs.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linux.ModeDirectory|defaultSysDirMode)
	d.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	d.InitRefs()
	return d
}

// IsEmptyDir implements kernfs.emptyDirInode.IsEmptyDir.
func (*bpfMountDir) IsEmptyDir() bool {
	return true
}

// Sysfs directories have no new children. Linux fails the creation of an
// existing name with EEXIST before it checks the filesystem for support, so
// "mkdir -p" on an existing directory such as /sys/fs/bpf succeeds. The
// kernfs lookup cache lists only the names that a walk has seen, so look the
// name up here.
func (d *dir) existsOrPermission(ctx context.Context, name string) error {
	child, err := d.OrderedChildren.Lookup(ctx, name)
	if err != nil {
		return linuxerr.EPERM
	}
	child.DecRef(ctx)
	return linuxerr.EEXIST
}

// NewFile implements kernfs.Inode.NewFile.
func (d *dir) NewFile(ctx context.Context, name string, _ vfs.OpenOptions) (kernfs.Inode, error) {
	return nil, d.existsOrPermission(ctx, name)
}

// NewDir implements kernfs.Inode.NewDir.
func (d *dir) NewDir(ctx context.Context, name string, _ vfs.MkdirOptions) (kernfs.Inode, error) {
	return nil, d.existsOrPermission(ctx, name)
}

// NewLink implements kernfs.Inode.NewLink.
func (d *dir) NewLink(ctx context.Context, name string, _ kernfs.Inode) (kernfs.Inode, error) {
	return nil, d.existsOrPermission(ctx, name)
}

// NewSymlink implements kernfs.Inode.NewSymlink.
func (d *dir) NewSymlink(ctx context.Context, name, _ string) (kernfs.Inode, error) {
	return nil, d.existsOrPermission(ctx, name)
}

// NewNode implements kernfs.Inode.NewNode.
func (d *dir) NewNode(ctx context.Context, name string, _ vfs.MknodOptions) (kernfs.Inode, error) {
	return nil, d.existsOrPermission(ctx, name)
}
