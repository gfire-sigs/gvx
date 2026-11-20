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

package gvx

import (
	"cmp"
	"fmt"
	"path"
	"strings"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/blockdev"
	"z.gfire.dev/gvx/pkg/sentry/checkpoint"
	"z.gfire.dev/gvx/pkg/sentry/devices/memdev"
	"z.gfire.dev/gvx/pkg/sentry/devices/ttydev"
	"z.gfire.dev/gvx/pkg/sentry/devices/tundev"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/cgroup2fs"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/dev"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/devpts"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/erofs"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/ext4lite"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/fuse"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/hostfs"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/mqfs"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/overlay"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/proc"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/sys"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/tmpfs"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

func registerKernelVFS(vfsObj *vfs.VirtualFilesystem, rootNetNS *inet.Namespace) error {
	vfsObj.MustRegisterFilesystemType("erofs", erofs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	vfsObj.MustRegisterFilesystemType("overlay", overlay.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	vfsObj.MustRegisterFilesystemType("tmpfs", tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	vfsObj.MustRegisterFilesystemType("proc", proc.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	vfsObj.MustRegisterFilesystemType("sysfs", sys.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	vfsObj.MustRegisterFilesystemType(sys.BPFName, sys.BPFFilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	vfsObj.MustRegisterFilesystemType("devtmpfs", dev.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	vfsObj.MustRegisterFilesystemType("devpts", &devpts.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	vfsObj.MustRegisterFilesystemType("cgroup2", cgroup2fs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	vfsObj.MustRegisterFilesystemType(mqfs.Name, &mqfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	vfsObj.MustRegisterFilesystemType(fuse.Name, &fuse.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	vfsObj.MustRegisterFilesystemType(hostfs.Name, hostfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	vfsObj.MustRegisterFilesystemType(ext4lite.Name, ext4lite.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	if ext4lite.Name != "ext4lite" {
		vfsObj.MustRegisterFilesystemType("ext4lite", ext4lite.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	}

	if err := memdev.Register(vfsObj); err != nil {
		return fmt.Errorf("gvx: register memdev: %w", err)
	}
	if err := memdev.RegisterKmsg(vfsObj); err != nil {
		return fmt.Errorf("gvx: register /dev/kmsg: %w", err)
	}
	if err := ttydev.Register(vfsObj); err != nil {
		return fmt.Errorf("gvx: register ttydev: %w", err)
	}
	if err := fuse.Register(vfsObj); err != nil {
		return fmt.Errorf("gvx: register fuse device: %w", err)
	}
	if rootNetNS == nil || tundev.IsNetTunSupported(rootNetNS.Stack()) {
		if err := tundev.Register(vfsObj); err != nil {
			return fmt.Errorf("gvx: register tun device: %w", err)
		}
	}
	return nil
}

// buildKernelRootMountNamespace creates the mount namespace of the guest. As
// in runsc, the namespace root is a read-only, locked tmpfs, and the guest
// root file system is a second mount on top of it. pivot_root(2) refuses to
// move the namespace root mount, so runc and other container runtimes need
// the guest root to have a parent mount.
//
// The kernel gives the namespace its nsfs inode, as in runsc. Without that
// inode, /proc/[pid]/ns/mnt cannot be read, and runc refuses docker exec with
// "namespace NEWNS is not supported".
func (s *Sandbox) buildKernelRootMountNamespace(sctx gvcontext.Context, k *kernel.Kernel, creds *auth.Credentials) (*vfs.MountNamespace, error) {
	vfsObj := k.VFS()
	mntns, err := vfsObj.NewMountNamespace(sctx, creds, "rootfs", "tmpfs", &vfs.MountOptions{ReadOnly: true, Locked: true}, k)
	if err != nil {
		return nil, fmt.Errorf("gvx: create guest mount namespace: %w", err)
	}
	rootMnt, err := s.mountGuestRoot(vfs.WithMountNamespace(sctx, mntns), vfsObj, creds)
	if err != nil {
		mntns.DecRef(sctx)
		return nil, err
	}
	defer rootMnt.DecRef(sctx)

	nsRoot := mntns.Root(sctx)
	defer nsRoot.DecRef(sctx)
	if err := vfsObj.ConnectMountAt(sctx, creds, rootMnt, &vfs.PathOperation{Root: nsRoot, Start: nsRoot}); err != nil {
		mntns.DecRef(sctx)
		return nil, fmt.Errorf("gvx: mount the guest root file system: %w", err)
	}
	return mntns, nil
}

// rootUpperOptions are the options of the tmpfs that holds the writes of the
// guest to its root file system. That tmpfs has no default size limit. The
// memory guard limits it.
var rootUpperOptions = vfs.GetFilesystemOptions{InternalData: tmpfs.FilesystemOpts{DisableDefaultSizeLimit: true}}

// mountGuestRoot creates the disconnected root mount of the guest: an overlay
// of a tmpfs or ext4lite upper layer on the EROFS layers, or a plain tmpfs
// when the guest has no image.
func (s *Sandbox) mountGuestRoot(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials) (*vfs.Mount, error) {
	if len(s.layerHandles) == 0 {
		if s.rootVolume != nil {
			return nil, fmt.Errorf("%w: RootVolume requires OCI image layers", ErrInvalidConfig)
		}
		mnt, err := vfsObj.MountDisconnected(sctx, creds, "", "tmpfs", &vfs.MountOptions{GetFilesystemOptions: rootUpperOptions})
		if err != nil {
			return nil, fmt.Errorf("gvx: create tmpfs root: %w", err)
		}
		return mnt, nil
	}

	// The EROFS layers are the root disk of the guest, as the image of a
	// virtual machine is. Its reads show in /proc/diskstats as vda, and the
	// directories of the root overlay report its device numbers. When
	// RootVolume is set, writes persist in an ext4lite volume; otherwise they
	// go to the tmpfs upper layer in memory.
	rootStats := blockdev.NewStats(nil)
	disks := blockdev.Of(vfsObj)
	rootDisk, err := disks.Add(blockdev.Options{
		Stats:        rootStats,
		SectorsCount: s.layerBytes / blockdev.SectorSize,
		ReadOnly:     true,
	})
	if err != nil {
		return nil, fmt.Errorf("gvx: add the root disk: %w", err)
	}
	mounted := false
	defer func() {
		if !mounted {
			disks.Remove(rootDisk)
		}
	}()

	lowerRoots, err := s.mountEROFSLowerLayers(sctx, vfsObj, creds, rootStats)
	if err != nil {
		return nil, err
	}
	defer releaseVirtualDentries(sctx, lowerRoots)

	var upperRoot vfs.VirtualDentry
	if s.rootVolume != nil {
		var upperExisting bool
		upperRoot, upperExisting, err = s.prepareRootUpperOverlay(sctx, vfsObj, creds)
		if err != nil {
			return nil, err
		}
		s.rootUpperExisting = upperExisting
	} else {
		upperFS, upperRootDentry, err := tmpfs.FilesystemType{}.GetFilesystem(sctx, vfsObj, creds, "", rootUpperOptions)
		if err != nil {
			return nil, fmt.Errorf("gvx: create tmpfs upper layer: %w", err)
		}
		upperMnt := vfsObj.NewDisconnectedMount(upperFS, upperRootDentry, &vfs.MountOptions{})
		upperFS.DecRef(sctx)
		upperRoot = vfs.MakeVirtualDentry(upperMnt, upperRootDentry)
	}
	defer upperRoot.DecRef(sctx)

	mnt, err := vfsObj.MountDisconnected(sctx, creds, "overlay", "overlay", &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: overlay.FilesystemOptions{
				UpperRoot:   upperRoot,
				LowerRoots:  lowerRoots,
				DirDevMajor: rootDisk.Major,
				DirDevMinor: rootDisk.Minor,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("gvx: create overlay root: %w", err)
	}
	mounted = true
	return mnt, nil
}

// prepareRootUpperOverlay mounts s.rootVolume via ext4lite, prepares the upper
// and empty work directories inside it, and returns a disconnected mount
// rooted at upper along with whether upper already existed.
func (s *Sandbox) prepareRootUpperOverlay(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials) (vfs.VirtualDentry, bool, error) {
	return prepareExt4UpperOverlay(sctx, vfsObj, creds, s.rootVolume, rootVolumeUniqueID)
}

func prepareExt4UpperOverlay(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, vol *ext4lite.Volume, uniqueID string) (vfs.VirtualDentry, bool, error) {
	ext4FS, ext4RootDentry, err := ext4lite.FilesystemType{}.GetFilesystem(sctx, vfsObj, creds, "", vfs.GetFilesystemOptions{
		InternalData: ext4lite.InternalFilesystemOptions{
			Volume:   vol,
			UniqueID: uniqueID,
		},
	})
	if err != nil {
		return vfs.VirtualDentry{}, false, fmt.Errorf("gvx: mount overlay upper volume %q: %w", uniqueID, err)
	}
	ext4Mnt := vfsObj.NewDisconnectedMount(ext4FS, ext4RootDentry, &vfs.MountOptions{})
	ext4FS.DecRef(sctx)
	ext4Root := vfs.MakeVirtualDentry(ext4Mnt, ext4RootDentry)
	defer ext4Root.DecRef(sctx)

	upperPop := vfs.PathOperation{Root: ext4Root, Start: ext4Root, Path: makeFPath("/upper")}
	upperVD, err := vfsObj.GetDentryAt(sctx, creds, &upperPop, &vfs.GetDentryOptions{CheckSearchable: true})
	upperExisting := true
	if linuxerr.Equals(linuxerr.ENOENT, err) {
		upperExisting = false
		if mkErr := vfsObj.MkdirAt(sctx, creds, &upperPop, &vfs.MkdirOptions{Mode: 0o755}); mkErr != nil {
			return vfs.VirtualDentry{}, false, fmt.Errorf("gvx: create overlay upper directory: %w", mkErr)
		}
		upperVD, err = vfsObj.GetDentryAt(sctx, creds, &upperPop, &vfs.GetDentryOptions{CheckSearchable: true})
	}
	if err != nil {
		return vfs.VirtualDentry{}, false, fmt.Errorf("gvx: open overlay upper directory: %w", err)
	}
	defer upperVD.DecRef(sctx)

	if err := ensureEmptyDir(sctx, vfsObj, creds, ext4Root, "/work"); err != nil {
		return vfs.VirtualDentry{}, false, fmt.Errorf("gvx: prepare overlay work directory: %w", err)
	}

	upperDentry := upperVD.Dentry()
	upperMnt := vfsObj.NewDisconnectedMount(ext4FS, upperDentry, &vfs.MountOptions{})
	upperDentry.IncRef()
	return vfs.MakeVirtualDentry(upperMnt, upperDentry), upperExisting, nil
}

// ensureEmptyDir creates dirPath under root or clears existing contents when it
// already exists.
func ensureEmptyDir(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, dirPath string) error {
	pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(dirPath)}
	err := vfsObj.MkdirAt(sctx, creds, &pop, &vfs.MkdirOptions{Mode: 0o755})
	if err == nil {
		return nil
	}
	if !linuxerr.Equals(linuxerr.EEXIST, err) {
		return err
	}
	return clearDirContents(sctx, vfsObj, creds, root, dirPath)
}

func clearDirContents(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, dirPath string) error {
	pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(dirPath)}
	fd, err := vfsObj.OpenAt(sctx, creds, &pop, &vfs.OpenOptions{
		Flags: linux.O_RDONLY | linux.O_DIRECTORY,
	})
	if err != nil {
		return err
	}
	type childEntry struct {
		name  string
		isDir bool
	}
	var children []childEntry
	iterErr := fd.IterDirents(sctx, vfs.IterDirentsCallbackFunc(func(d vfs.Dirent) error {
		if d.Name == "." || d.Name == ".." {
			return nil
		}
		children = append(children, childEntry{
			name:  d.Name,
			isDir: d.Type == linux.DT_DIR,
		})
		return nil
	}))
	fd.DecRef(sctx)
	if iterErr != nil {
		return iterErr
	}
	for _, child := range children {
		childPath := path.Join(dirPath, child.name)
		cPop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(childPath)}
		if child.isDir {
			if err := clearDirContents(sctx, vfsObj, creds, root, childPath); err != nil {
				return err
			}
			if err := vfsObj.RmdirAt(sctx, creds, &cPop); err != nil {
				return err
			}
			continue
		}
		if err := vfsObj.UnlinkAt(sctx, creds, &cPop); err != nil {
			return err
		}
	}
	return nil
}

// mountEROFSLowerLayers mounts each EROFS layer from top to bottom and returns
// their disconnected root dentries.
func (s *Sandbox) mountEROFSLowerLayers(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, rootStats *blockdev.Stats) ([]vfs.VirtualDentry, error) {
	lowerRoots := make([]vfs.VirtualDentry, 0, len(s.layerHandles))
	for i := len(s.layerHandles) - 1; i >= 0; i-- {
		dupHH, err := s.layerHandles[i].Dup()
		if err != nil {
			releaseVirtualDentries(sctx, lowerRoots)
			return nil, fmt.Errorf("gvx: dup EROFS layer handle: %w", err)
		}
		dupFD, err := dupHH.Release()
		if err != nil {
			_ = dupHH.Close()
			releaseVirtualDentries(sctx, lowerRoots)
			return nil, fmt.Errorf("gvx: release dup EROFS layer handle: %w", err)
		}
		var digest string
		if i < len(s.layerDigests) {
			digest = s.layerDigests[i]
		}
		fs, rootDentry, err := erofs.FilesystemType{}.GetFilesystem(sctx, vfsObj, creds, "", vfs.GetFilesystemOptions{
			Data: fmt.Sprintf("ifd=%d", int(dupFD)),
			InternalData: erofs.InternalFilesystemOptions{
				UniqueID:   EROFSUniqueID("/", i, digest),
				BlockStats: rootStats,
			},
		})
		if err != nil {
			releaseVirtualDentries(sctx, lowerRoots)
			return nil, fmt.Errorf("gvx: mount EROFS layer %d: %w", i, err)
		}
		mnt := vfsObj.NewDisconnectedMount(fs, rootDentry, &vfs.MountOptions{ReadOnly: true})
		fs.DecRef(sctx)
		lowerRoots = append(lowerRoots, vfs.MakeVirtualDentry(mnt, rootDentry))
	}
	return lowerRoots, nil
}

func releaseVirtualDentries(sctx gvcontext.Context, dentries []vfs.VirtualDentry) {
	for _, vd := range dentries {
		vd.DecRef(sctx)
	}
}

type sharedExt4FS struct {
	fs   *vfs.Filesystem
	root *vfs.Dentry
}

func releaseSharedExt4FS(sctx gvcontext.Context, m map[*ext4lite.Volume]sharedExt4FS) {
	for _, entry := range m {
		entry.root.DecRef(sctx)
		entry.fs.DecRef(sctx)
	}
}

func ensureSharedExt4ReadOnly(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, vol *ext4lite.Volume, uniqueID string, shared map[*ext4lite.Volume]sharedExt4FS) (sharedExt4FS, error) {
	if entry, ok := shared[vol]; ok {
		return entry, nil
	}
	fs, rootDentry, err := ext4lite.FilesystemType{}.GetFilesystem(sctx, vfsObj, creds, "", vfs.GetFilesystemOptions{
		InternalData: ext4lite.InternalFilesystemOptions{
			Volume:   vol,
			UniqueID: uniqueID,
		},
	})
	if err != nil {
		return sharedExt4FS{}, err
	}
	entry := sharedExt4FS{fs: fs, root: rootDentry}
	shared[vol] = entry
	return entry, nil
}

func (s *Sandbox) setupKernelSubmountsAndFiles(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry) error {
	if err := createDefaultGuestDirs(sctx, vfsObj, creds, root, s.rootUpperExisting); err != nil {
		return err
	}
	mountSubfs := func(target, fsName string, opts *vfs.MountOptions) error {
		pop := vfs.PathOperation{
			Root:  root,
			Start: root,
			Path:  makeFPath(target),
		}
		if _, err := vfsObj.MountAt(sctx, creds, "", &pop, fsName, opts); err != nil {
			return fmt.Errorf("gvx: mount %s at %s: %w", fsName, target, err)
		}
		return nil
	}
	if err := mountStandardSubfilesystems(sctx, vfsObj, creds, root, mountSubfs); err != nil {
		return err
	}
	if err := populateDefaultEtcFiles(sctx, vfsObj, creds, root, s.guestResolvConf); err != nil {
		return err
	}
	if err := s.writeGuestHostFiles(sctx, vfsObj, creds, root); err != nil {
		return err
	}
	if err := s.installHostCACerts(sctx, vfsObj, creds, root); err != nil {
		return err
	}

	sharedRO := make(map[*ext4lite.Volume]sharedExt4FS)
	defer releaseSharedExt4FS(sctx, sharedRO)

	// s.mounts is ordered by increasing path depth, so a mount point below
	// another mount exists in that mount before the guest mounts there.
	for _, m := range s.mounts {
		if err := s.mountUserMount(sctx, vfsObj, creds, root, m, mountSubfs, sharedRO); err != nil {
			return err
		}
	}

	if s.cfg.ReadOnlyRoot {
		if err := vfsObj.SetMountReadOnly(root.Mount(), true); err != nil {
			return fmt.Errorf("gvx: mount the root read-only: %w", err)
		}
	}
	return nil
}

func createDefaultGuestDirs(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, preserveRootMode bool) error {
	// The tmpfs that holds the writes of the guest has the mode 01777, and the
	// overlay shows it as the mode of "/". A guest user that is not root could
	// then create files in "/". Images use the mode 0755 for "/". Preserve any
	// persisted mode when reusing an existing RootVolume upper directory.
	if !preserveRootMode {
		if err := vfsObj.SetStatAt(sctx, creds, &vfs.PathOperation{Root: root, Start: root, Path: makeFPath("/")}, &vfs.SetStatOptions{
			Stat: linux.Statx{Mask: linux.STATX_MODE, Mode: 0o755},
		}); err != nil {
			return fmt.Errorf("gvx: set the mode of the guest root: %w", err)
		}
	}
	for _, dir := range []string{"/proc", "/sys", "/dev", "/etc", "/root", "/workspace", "/bin", "/usr/bin"} {
		if err := vfsEnsureDirAll(sctx, vfsObj, creds, root, dir, 0o755); err != nil {
			return fmt.Errorf("gvx: create guest directory %s: %w", dir, err)
		}
	}
	// Programs expect a sticky, world-writable /tmp. An image that has one keeps it.
	if err := vfsEnsureDirAll(sctx, vfsObj, creds, root, "/tmp", 0o1777); err != nil {
		return fmt.Errorf("gvx: create guest directory /tmp: %w", err)
	}
	return nil
}

func mountStandardSubfilesystems(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, mountSubfs func(target, fsName string, opts *vfs.MountOptions) error) error {
	dataOpts := func(data string) *vfs.MountOptions {
		return &vfs.MountOptions{GetFilesystemOptions: vfs.GetFilesystemOptions{Data: data}}
	}
	for _, sub := range []struct {
		target string
		fsName string
	}{
		{"/proc", "proc"},
		{"/sys", "sysfs"},
		{"/dev", "devtmpfs"},
	} {
		if err := mountSubfs(sub.target, sub.fsName, dataOpts("")); err != nil {
			return err
		}
	}
	if err := vfsEnsureDirAll(sctx, vfsObj, creds, root, "/dev/pts", 0o755); err != nil {
		return fmt.Errorf("gvx: create guest directory /dev/pts: %w", err)
	}
	if err := vfsEnsureDirAll(sctx, vfsObj, creds, root, "/dev/shm", 0o1777); err != nil {
		return fmt.Errorf("gvx: create guest directory /dev/shm: %w", err)
	}
	if err := mountSubfs("/dev/pts", "devpts", dataOpts("ptmxmode=0666,mode=0620")); err != nil {
		return err
	}
	if err := mountSubfs("/dev/shm", "tmpfs", dataOpts("")); err != nil {
		return err
	}
	// Docker mounts the cgroup2 hierarchy of a private cgroup namespace at
	// /sys/fs/cgroup. systemd, runc, and dockerd read it there.
	if err := mountSubfs("/sys/fs/cgroup", "cgroup2", dataOpts("")); err != nil {
		return err
	}
	if err := vfsEnsureDirAll(sctx, vfsObj, creds, root, "/dev/mqueue", 0o1777); err != nil {
		return fmt.Errorf("gvx: create guest directory /dev/mqueue: %w", err)
	}
	return mountSubfs("/dev/mqueue", mqfs.Name, dataOpts(""))
}

// mountUserMount creates the guest mount point of m and mounts it there. The
// mount point is a directory, or an empty regular file for a file mount. A bind
// mount or a hostfs volume uses the VFS2 hostfs driver. An ext4lite volume uses
// the ext4lite driver on its open image. A tmpfs mount uses the Sentry tmpfs
// with a size limit and mode 1777.
func (s *Sandbox) mountUserMount(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, m sandboxMount, mountSubfs func(target, fsName string, opts *vfs.MountOptions) error, sharedRO map[*ext4lite.Volume]sharedExt4FS) error {
	dirMode := linux.FileMode(0o755)
	if m.Kind == MountTmpfs {
		dirMode = 0o1777
	}
	if m.hostFile {
		if err := vfsEnsureEmptyFile(sctx, vfsObj, creds, root, m.GuestPath, 0o644); err != nil {
			return fmt.Errorf("gvx: create guest file %s: %w", m.GuestPath, err)
		}
	} else if err := vfsEnsureDirAll(sctx, vfsObj, creds, root, m.GuestPath, dirMode); err != nil {
		return fmt.Errorf("gvx: create guest directory %s: %w", m.GuestPath, err)
	}
	if m.Kind == MountTmpfs {
		return mountSubfs(m.GuestPath, "tmpfs", &vfs.MountOptions{
			ReadOnly:             m.ReadOnly,
			GetFilesystemOptions: vfs.GetFilesystemOptions{Data: tmpfsMountData(m.TmpfsSizeBytes)},
		})
	}
	if m.Kind == MountOverlay {
		return s.mountOverlayUserMount(sctx, vfsObj, creds, m, mountSubfs, sharedRO)
	}
	if m.volume != nil {
		if m.ReadOnly {
			entry, err := ensureSharedExt4ReadOnly(sctx, vfsObj, creds, m.volume, m.GuestPath, sharedRO)
			if err != nil {
				return fmt.Errorf("gvx: mount read-only volume at %s: %w", m.GuestPath, err)
			}
			mnt := vfsObj.NewDisconnectedMount(entry.fs, entry.root, &vfs.MountOptions{ReadOnly: true})
			defer mnt.DecRef(sctx)
			pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(m.GuestPath)}
			if err := vfsObj.ConnectMountAt(sctx, creds, mnt, &pop); err != nil {
				return fmt.Errorf("gvx: connect read-only volume at %s: %w", m.GuestPath, err)
			}
			return nil
		}
		return mountSubfs(m.GuestPath, ext4lite.Name, &vfs.MountOptions{
			ReadOnly: false,
			GetFilesystemOptions: vfs.GetFilesystemOptions{
				InternalData: ext4lite.InternalFilesystemOptions{
					Volume:   m.volume,
					UniqueID: m.GuestPath,
				},
			},
		})
	}
	return mountSubfs(m.GuestPath, hostfs.Name, &vfs.MountOptions{
		ReadOnly: m.workspace.ReadOnly(),
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: hostfs.InternalFilesystemOptions{
				Workspace: m.workspace,
				UniqueID: checkpoint.ResourceID{
					ContainerName: cmp.Or(s.cfg.Name, "gvx-default"),
					Path:          m.GuestPath,
				},
			},
		},
	})
}

func (s *Sandbox) mountOverlayUserMount(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, m sandboxMount, mountSubfs func(target, fsName string, opts *vfs.MountOptions) error, sharedRO map[*ext4lite.Volume]sharedExt4FS) error {
	lowerEntry, err := ensureSharedExt4ReadOnly(sctx, vfsObj, creds, m.volume, overlayLowerUniqueID(m.GuestPath), sharedRO)
	if err != nil {
		return fmt.Errorf("gvx: mount overlay lower volume for %s: %w", m.GuestPath, err)
	}
	lowerMnt := vfsObj.NewDisconnectedMount(lowerEntry.fs, lowerEntry.root, &vfs.MountOptions{ReadOnly: true})
	lowerEntry.root.IncRef()
	lowerVD := vfs.MakeVirtualDentry(lowerMnt, lowerEntry.root)
	defer lowerVD.DecRef(sctx)

	var (
		upperVD       vfs.VirtualDentry
		initFromLower bool
	)
	if m.upperVolume != nil {
		var upperExisting bool
		upperVD, upperExisting, err = prepareExt4UpperOverlay(sctx, vfsObj, creds, m.upperVolume, overlayUpperUniqueID(m.GuestPath))
		if err != nil {
			return err
		}
		initFromLower = !upperExisting
	} else {
		upperFS, upperRootDentry, err := tmpfs.FilesystemType{}.GetFilesystem(sctx, vfsObj, creds, "", vfs.GetFilesystemOptions{
			Data: tmpfsMountData(m.TmpfsSizeBytes),
		})
		if err != nil {
			return fmt.Errorf("gvx: create overlay tmpfs upper for %s: %w", m.GuestPath, err)
		}
		upperMnt := vfsObj.NewDisconnectedMount(upperFS, upperRootDentry, &vfs.MountOptions{})
		upperFS.DecRef(sctx)
		upperVD = vfs.MakeVirtualDentry(upperMnt, upperRootDentry)
		initFromLower = true
	}
	defer upperVD.DecRef(sctx)

	if initFromLower {
		lowerPop := vfs.PathOperation{Root: lowerVD, Start: lowerVD, Path: makeFPath("/")}
		if st, statErr := vfsObj.StatAt(sctx, creds, &lowerPop, &vfs.StatOptions{
			Mask: linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID,
		}); statErr == nil {
			upperPop := vfs.PathOperation{Root: upperVD, Start: upperVD, Path: makeFPath("/")}
			_ = vfsObj.SetStatAt(sctx, creds, &upperPop, &vfs.SetStatOptions{
				Stat: linux.Statx{
					Mask: linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID,
					Mode: st.Mode & 0o7777,
					UID:  st.UID,
					GID:  st.GID,
				},
			})
		}
	}

	return mountSubfs(m.GuestPath, overlay.Name, &vfs.MountOptions{
		ReadOnly: m.ReadOnly,
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: overlay.FilesystemOptions{
				UpperRoot:  upperVD,
				LowerRoots: []vfs.VirtualDentry{lowerVD},
			},
		},
	})
}

// tmpfsMountData returns the mount data of a tmpfs mount. A zero size keeps
// the default limit of the Sentry tmpfs.
func tmpfsMountData(sizeBytes int64) string {
	if sizeBytes == 0 {
		return "mode=1777"
	}
	return fmt.Sprintf("size=%d,mode=1777", sizeBytes)
}

func vfsWriteFile(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, guestPath string, data []byte, mode linux.FileMode) error {
	return vfsWriteFileLinks(sctx, vfsObj, creds, root, guestPath, data, mode, false)
}

// vfsWriteFileLinks writes data to a file and creates the file when it is
// missing. When followFinalLink is true and the path names a symbolic link, it
// writes the file that the link names, as open(2) does.
func vfsWriteFileLinks(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, guestPath string, data []byte, mode linux.FileMode, followFinalLink bool) error {
	dir := path.Dir(guestPath)
	if dir != "/" && dir != "." {
		if err := vfsEnsureDirAll(sctx, vfsObj, creds, root, dir, 0o755); err != nil {
			return err
		}
	}
	pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(guestPath), FollowFinalSymlink: followFinalLink}
	fd, err := vfsObj.OpenAt(sctx, creds, &pop, &vfs.OpenOptions{
		Flags: linux.O_WRONLY | linux.O_CREAT | linux.O_TRUNC,
		Mode:  mode,
	})
	if err != nil {
		return err
	}
	defer fd.DecRef(sctx)
	if len(data) == 0 {
		return nil
	}
	n, err := fd.Write(sctx, usermem.BytesIOSequence(data), vfs.WriteOptions{})
	if err != nil {
		return err
	}
	if n != int64(len(data)) {
		return fmt.Errorf("short write: %d of %d bytes", n, len(data))
	}
	return nil
}

func ensureGuestFileIfAbsent(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, guestPath string, data []byte, mode linux.FileMode) error {
	pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(guestPath), FollowFinalSymlink: true}
	if st, err := vfsObj.StatAt(sctx, creds, &pop, &vfs.StatOptions{Mask: linux.STATX_SIZE}); err == nil && st.Size > 0 {
		return nil
	}
	return vfsWriteFile(sctx, vfsObj, creds, root, guestPath, data, mode)
}

// vfsEnsureDirAll creates dirPath and its missing parents. An existing
// component must be a directory.
func vfsEnsureDirAll(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, dirPath string, mode linux.FileMode) error {
	cleaned := path.Clean("/" + strings.TrimPrefix(dirPath, "/"))
	if cleaned == "/" {
		return nil
	}
	cur := ""
	for _, p := range strings.Split(strings.TrimPrefix(cleaned, "/"), "/") {
		cur += "/" + p
		pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(cur), FollowFinalSymlink: true}
		st, err := vfsObj.StatAt(sctx, creds, &pop, &vfs.StatOptions{Mask: linux.STATX_TYPE})
		if err == nil {
			if st.Mode&linux.S_IFMT != linux.S_IFDIR {
				return fmt.Errorf("%s: %w", cur, linuxerr.ENOTDIR)
			}
			continue
		}
		if !linuxerr.Equals(linuxerr.ENOENT, err) {
			return fmt.Errorf("stat %s: %w", cur, err)
		}
		mkPop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(cur)}
		if err := vfsObj.MkdirAt(sctx, creds, &mkPop, &vfs.MkdirOptions{Mode: mode}); err != nil {
			return fmt.Errorf("mkdir %s: %w", cur, err)
		}
	}
	return nil
}

// vfsEnsureEmptyFile creates an empty regular file at guestPath and the
// missing parent directories. An existing regular file stays as it is. Any
// other existing file type is an error, because a file mount needs a file.
func vfsEnsureEmptyFile(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, guestPath string, mode linux.FileMode) error {
	if err := vfsEnsureDirAll(sctx, vfsObj, creds, root, path.Dir(guestPath), 0o755); err != nil {
		return err
	}
	pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(guestPath)}
	st, err := vfsObj.StatAt(sctx, creds, &pop, &vfs.StatOptions{Mask: linux.STATX_TYPE})
	if err == nil {
		if st.Mode&linux.S_IFMT != linux.S_IFREG {
			return fmt.Errorf("%s: not a regular file", guestPath)
		}
		return nil
	}
	if !linuxerr.Equals(linuxerr.ENOENT, err) {
		return fmt.Errorf("stat %s: %w", guestPath, err)
	}
	fd, err := vfsObj.OpenAt(sctx, creds, &pop, &vfs.OpenOptions{
		Flags: linux.O_WRONLY | linux.O_CREAT | linux.O_EXCL,
		Mode:  mode,
	})
	if err != nil {
		return fmt.Errorf("create %s: %w", guestPath, err)
	}
	fd.DecRef(sctx)
	return nil
}

func resolveGuestExecutable(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, cmd string, envv []string) (string, error) {
	isRegularFile := func(candidate string) bool {
		pop := vfs.PathOperation{
			Root:               root,
			Start:              root,
			Path:               makeFPath(candidate),
			FollowFinalSymlink: true,
		}
		st, err := vfsObj.StatAt(sctx, creds, &pop, &vfs.StatOptions{Mask: linux.STATX_TYPE | linux.STATX_MODE})
		if err != nil {
			return false
		}
		return (st.Mode & linux.S_IFMT) == linux.S_IFREG
	}

	if strings.Contains(cmd, "/") {
		if isRegularFile(cmd) {
			return cmd, nil
		}
		return "", fmt.Errorf("gvx: executable %q not found in guest rootfs", cmd)
	}

	pathEnv := defaultPath
	for _, kv := range envv {
		if after, ok := strings.CutPrefix(kv, "PATH="); ok && after != "" {
			pathEnv = after
			break
		}
	}

	for _, dir := range strings.Split(pathEnv, ":") {
		if dir == "" {
			dir = "/"
		}
		candidate := path.Join(dir, cmd)
		if isRegularFile(candidate) {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("gvx: executable %q not found in PATH (%s)", cmd, pathEnv)
}

func makeFPath(p string) fspath.Path {
	return fspath.Parse(p)
}
