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

//go:build !windows

package hostfs

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/third_party/x_sys/unix"
)

// hostRoot performs every host file operation relative to a directory file
// descriptor pinned before sandbox lockdown. The descriptor comes from the
// os.Root that os.OpenRoot opened, so it already exists when the lockdown
// forbids new opens. Every operation then calls openat, mkdirat, unlinkat,
// renameat, linkat, or readlinkat on that descriptor.
//
// hostRoot walks paths one component at a time with O_NOFOLLOW and refuses
// symbolic links at every component. os.Root cannot do this, because it
// follows links that stay inside the root. hostfs must never alias two
// workspace paths through a host link. It must never open a host link as a
// file.
const (
	// hostSeparatorIsBackslash reports whether the host treats "\\" as a path
	// separator. On Unix hosts it is an ordinary file name character.
	hostSeparatorIsBackslash = false

	// hostRenameReplacesDir reports whether the host rename replaces an empty
	// destination directory atomically.
	hostRenameReplacesDir = true
)

type hostRoot struct {
	dir      *os.File
	caseFold bool
}

func newHostRoot(root *os.Root) (*hostRoot, error) {
	dir, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("hostfs: pin workspace directory: %w", err)
	}
	h := &hostRoot{dir: dir}
	var probeErr error
	h.caseFold, probeErr = probeCaseInsensitive(dir)
	if probeErr != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("hostfs: probe workspace volume case sensitivity: %w", probeErr)
	}
	return h, nil
}

func (h *hostRoot) close() error {
	return h.dir.Close()
}

func (h *hostRoot) caseInsensitive() bool {
	return h.caseFold
}

// rootFD returns the pinned directory descriptor. The descriptor stays valid
// until close, because h.dir holds the only reference.
func (h *hostRoot) rootFD() int {
	return int(h.dir.Fd())
}

func retryEINTR(f func() error) error {
	for {
		err := f()
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

func openatRetry(dirfd int, name string, flags int, perm uint32) (int, error) {
	var fd int
	err := retryEINTR(func() error {
		var oerr error
		fd, oerr = unix.Openat(dirfd, name, flags, perm)
		return oerr
	})
	return fd, err
}

// isLinkRefusal reports whether err means that O_NOFOLLOW refused a symbolic
// link. Linux returns ELOOP, and macOS returns ELOOP or ENOTDIR when combined
// with O_DIRECTORY, so the check asks the directory what the name is.
func isLinkRefusal(dirfd int, name string, err error) bool {
	if !errors.Is(err, unix.ELOOP) && !errors.Is(err, unix.ENOTDIR) {
		return false
	}
	var st unix.Stat_t
	if serr := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); serr != nil {
		return false
	}
	return st.Mode&unix.S_IFMT == unix.S_IFLNK
}

// walkParent opens every directory on the path to rel except the last
// component and returns the descriptor of the last directory plus that
// component. The release function closes every descriptor that walkParent
// opened. The root itself yields name ".".
func (h *hostRoot) walkParent(rel string) (dirfd int, name string, release func(), err error) {
	rootfd := h.rootFD()
	if rel == "." {
		return rootfd, ".", func() {}, nil
	}
	parts := strings.Split(rel, "/")
	cur := rootfd
	opened := make([]int, 0, len(parts))
	release = func() {
		for _, fd := range opened {
			_ = unix.Close(fd)
		}
	}
	for _, comp := range parts[:len(parts)-1] {
		fd, oerr := openatRetry(cur, comp, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if oerr != nil {
			if isLinkRefusal(cur, comp, oerr) {
				release()
				return -1, "", nil, ErrPathTraversal
			}
			release()
			return -1, "", nil, fmt.Errorf("hostfs: open directory %q: %w", comp, oerr)
		}
		opened = append(opened, fd)
		cur = fd
	}
	return cur, parts[len(parts)-1], release, nil
}

func (h *hostRoot) open(rel string, flags int, perm os.FileMode) (*os.File, error) {
	if rel == "." {
		return nil, fmt.Errorf("hostfs: open %q: %w", rel, unix.EISDIR)
	}
	parent, name, release, err := h.walkParent(rel)
	if err != nil {
		return nil, err
	}
	defer release()
	return openIn(parent, name, rel, flags, perm)
}

// hostDirHandle is an open directory descriptor. openDirAt returns one, and
// its caller closes it with closeDir.
type hostDirHandle int

func (h *hostRoot) caseVerified() bool {
	return false
}

func (h *hostRoot) rootDir() hostDirHandle {
	return hostDirHandle(h.rootFD())
}

// checkChildName rejects a name that is not one plain directory entry name,
// so that a pinned-directory call can never leave its directory.
func checkChildName(name string) error {
	if name == "" || name == "." || name == ".." || strings.IndexByte(name, '/') >= 0 {
		return ErrPathTraversal
	}
	return nil
}

func (h *hostRoot) openDirAt(dir hostDirHandle, name string) (hostDirHandle, hostInfo, error) {
	if err := checkChildName(name); err != nil {
		return -1, hostInfo{}, err
	}
	fd, err := openatRetry(int(dir), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if isLinkRefusal(int(dir), name, err) {
			return -1, hostInfo{}, ErrPathTraversal
		}
		return -1, hostInfo{}, fmt.Errorf("hostfs: open directory %q: %w", name, err)
	}
	var st unix.Stat_t
	if err := retryEINTR(func() error { return unix.Fstat(fd, &st) }); err != nil {
		_ = unix.Close(fd)
		return -1, hostInfo{}, fmt.Errorf("hostfs: fstat directory %q: %w", name, err)
	}
	return hostDirHandle(fd), statToHostInfo(&st), nil
}

func (h *hostRoot) closeDir(dir hostDirHandle) error {
	return unix.Close(int(dir))
}

func (h *hostRoot) fstatDir(dir hostDirHandle) (hostInfo, error) {
	var st unix.Stat_t
	if err := retryEINTR(func() error { return unix.Fstat(int(dir), &st) }); err != nil {
		return hostInfo{}, fmt.Errorf("hostfs: fstat directory: %w", err)
	}
	return statToHostInfo(&st), nil
}

func (h *hostRoot) lstatAt(dir hostDirHandle, name string) (hostInfo, error) {
	if err := checkChildName(name); err != nil {
		return hostInfo{}, err
	}
	var st unix.Stat_t
	if err := retryEINTR(func() error { return unix.Fstatat(int(dir), name, &st, unix.AT_SYMLINK_NOFOLLOW) }); err != nil {
		return hostInfo{}, fmt.Errorf("hostfs: lstat %q: %w", name, err)
	}
	return statToHostInfo(&st), nil
}

func (h *hostRoot) openChildAt(dir hostDirHandle, name string, flags int, perm os.FileMode) (*os.File, error) {
	if err := checkChildName(name); err != nil {
		return nil, err
	}
	return openIn(int(dir), name, name, flags, perm)
}

// openIn opens the entry name inside the directory descriptor parent. The
// path rel only labels errors.
func openIn(parent int, name, rel string, flags int, perm os.FileMode) (*os.File, error) {
	// O_NONBLOCK keeps open from blocking on a host FIFO. The descriptor
	// returns to blocking mode below once fstat proves a regular file.
	openFlags := flags&(unix.O_ACCMODE|unix.O_CREAT|unix.O_EXCL|unix.O_TRUNC) | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	fd, err := openatRetry(parent, name, openFlags, uint32(perm.Perm()))
	if err != nil {
		if errors.Is(err, unix.ELOOP) && flags&unix.O_CREAT == 0 {
			return nil, ErrPathTraversal
		}
		return nil, fmt.Errorf("hostfs: open %q: %w", rel, err)
	}
	var st unix.Stat_t
	if err := retryEINTR(func() error { return unix.Fstat(fd, &st) }); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("hostfs: fstat %q: %w", rel, err)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
	case unix.S_IFDIR:
		_ = unix.Close(fd)
		return nil, fmt.Errorf("hostfs: open %q: %w", rel, unix.EISDIR)
	default:
		_ = unix.Close(fd)
		return nil, fmt.Errorf("hostfs: open %q: %w", rel, unix.ENXIO)
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("hostfs: clear O_NONBLOCK on %q: %w", rel, err)
	}
	return os.NewFile(uintptr(fd), rel), nil
}

func (h *hostRoot) openDir(rel string) (*os.File, error) {
	parent, name, release, err := h.walkParent(rel)
	if err != nil {
		return nil, err
	}
	defer release()
	fd, err := openatRetry(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if isLinkRefusal(parent, name, err) {
			return nil, ErrPathTraversal
		}
		return nil, fmt.Errorf("hostfs: open directory %q: %w", rel, err)
	}
	return os.NewFile(uintptr(fd), rel), nil
}

func statToHostInfo(st *unix.Stat_t) hostInfo {
	info := hostInfo{
		id:     hostID{dev: uint64(st.Dev), ino: uint64(st.Ino)},
		size:   st.Size,
		blocks: st.Blocks,
		nlink:  uint32(st.Nlink),
		perm:   st.Mode & 0o7777,
		atime:  time.Unix(int64(st.Atim.Sec), int64(st.Atim.Nsec)),
		mtime:  time.Unix(int64(st.Mtim.Sec), int64(st.Mtim.Nsec)),
		ctime:  time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)),
		btime:  birthTime(st),
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		info.kind = hostKindRegular
	case unix.S_IFDIR:
		info.kind = hostKindDir
	case unix.S_IFLNK:
		info.kind = hostKindSymlink
	default:
		info.kind = hostKindOther
	}
	return info
}

func (h *hostRoot) lstat(rel string) (hostInfo, error) {
	var st unix.Stat_t
	if rel == "." {
		if err := retryEINTR(func() error { return unix.Fstat(h.rootFD(), &st) }); err != nil {
			return hostInfo{}, fmt.Errorf("hostfs: fstat workspace root: %w", err)
		}
		return statToHostInfo(&st), nil
	}
	parent, name, release, err := h.walkParent(rel)
	if err != nil {
		return hostInfo{}, err
	}
	defer release()
	if err := retryEINTR(func() error { return unix.Fstatat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW) }); err != nil {
		return hostInfo{}, fmt.Errorf("hostfs: lstat %q: %w", rel, err)
	}
	return statToHostInfo(&st), nil
}

// withFileFD runs fn with the descriptor of f and keeps f open until fn
// returns.
func withFileFD(f *os.File, fn func(fd int) error) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var fnErr error
	if err := rc.Control(func(fd uintptr) { fnErr = fn(int(fd)) }); err != nil {
		return err
	}
	return fnErr
}

func (h *hostRoot) fstat(f *os.File) (hostInfo, error) {
	var st unix.Stat_t
	if err := withFileFD(f, func(fd int) error {
		return retryEINTR(func() error { return unix.Fstat(fd, &st) })
	}); err != nil {
		return hostInfo{}, fmt.Errorf("hostfs: fstat: %w", err)
	}
	return statToHostInfo(&st), nil
}

func (h *hostRoot) mkdir(rel string) error {
	parent, name, release, err := h.walkParent(rel)
	if err != nil {
		return err
	}
	defer release()
	// Host directories stay owner-only: guest permissions are virtual and the
	// sentry process must always be able to traverse what it created.
	if err := retryEINTR(func() error { return unix.Mkdirat(parent, name, 0o700) }); err != nil {
		return fmt.Errorf("hostfs: mkdir %q: %w", rel, err)
	}
	return nil
}

func (h *hostRoot) unlink(rel string) error {
	return h.unlinkat(rel, 0)
}

func (h *hostRoot) rmdir(rel string) error {
	return h.unlinkat(rel, unix.AT_REMOVEDIR)
}

func (h *hostRoot) unlinkat(rel string, flags int) error {
	if rel == "." {
		return fmt.Errorf("hostfs: remove %q: %w", rel, unix.EBUSY)
	}
	parent, name, release, err := h.walkParent(rel)
	if err != nil {
		return err
	}
	defer release()
	if err := retryEINTR(func() error { return unix.Unlinkat(parent, name, flags) }); err != nil {
		return fmt.Errorf("hostfs: remove %q: %w", rel, err)
	}
	return nil
}

func (h *hostRoot) withTwoParents(op, prep, oldRel, newRel string, rootErr error, fn func(oldDir int, oldName string, newDir int, newName string) error) error {
	if oldRel == "." || newRel == "." {
		return fmt.Errorf("hostfs: %s %q %s %q: %w", op, oldRel, prep, newRel, rootErr)
	}
	oldParent, oldName, releaseOld, err := h.walkParent(oldRel)
	if err != nil {
		return err
	}
	defer releaseOld()
	newParent, newName, releaseNew, err := h.walkParent(newRel)
	if err != nil {
		return err
	}
	defer releaseNew()
	if err := retryEINTR(func() error { return fn(oldParent, oldName, newParent, newName) }); err != nil {
		return fmt.Errorf("hostfs: %s %q %s %q: %w", op, oldRel, prep, newRel, err)
	}
	return nil
}

func (h *hostRoot) rename(oldRel, newRel string) error {
	return h.withTwoParents("rename", "to", oldRel, newRel, unix.EBUSY, unix.Renameat)
}

func (h *hostRoot) link(oldRel, newRel string) error {
	// Flags 0 links a symbolic link itself and never its target.
	return h.withTwoParents("link", "to", oldRel, newRel, unix.EPERM, func(oldDir int, oldName string, newDir int, newName string) error {
		return unix.Linkat(oldDir, oldName, newDir, newName, 0)
	})
}

func (h *hostRoot) readlink(rel string) (string, error) {
	if rel == "." {
		return "", fmt.Errorf("hostfs: readlink %q: %w", rel, unix.EINVAL)
	}
	parent, name, release, err := h.walkParent(rel)
	if err != nil {
		return "", err
	}
	defer release()
	for size := 256; ; size *= 2 {
		buf := make([]byte, size)
		var n int
		if err := retryEINTR(func() error {
			var rerr error
			n, rerr = unix.Readlinkat(parent, name, buf)
			return rerr
		}); err != nil {
			return "", fmt.Errorf("hostfs: readlink %q: %w", rel, err)
		}
		if n < size {
			return string(buf[:n]), nil
		}
		if size >= 1<<16 {
			return "", fmt.Errorf("hostfs: readlink %q: %w", rel, unix.ENAMETOOLONG)
		}
	}
}

func (h *hostRoot) readDir(rel string) ([]hostDirEntry, error) {
	dir, err := h.openDir(rel)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = dir.Close()
	}()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("hostfs: read directory %q: %w", rel, err)
	}
	out := make([]hostDirEntry, 0, len(names))
	if err := withFileFD(dir, func(fd int) error {
		for _, name := range names {
			var st unix.Stat_t
			serr := retryEINTR(func() error { return unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW) })
			if errors.Is(serr, unix.ENOENT) {
				// The entry vanished after listing: a concurrent unlink.
				continue
			}
			if serr != nil {
				return fmt.Errorf("hostfs: lstat %q in %q: %w", name, rel, serr)
			}
			info := statToHostInfo(&st)
			out = append(out, hostDirEntry{name: name, kind: info.kind, ino: info.id.ino})
		}
		return nil
	}); err != nil {
		if strings.HasPrefix(err.Error(), "hostfs: lstat ") {
			return nil, err
		}
		return nil, fmt.Errorf("hostfs: read directory %q: %w", rel, err)
	}
	return out, nil
}

func (h *hostRoot) syncDir(rel string) error {
	dir, err := h.openDir(rel)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		return fmt.Errorf("hostfs: sync directory %q: %w", rel, syncErr)
	}
	return closeErr
}

func (h *hostRoot) chtimes(rel string, atime, mtime *time.Time) error {
	omit := unix.Timespec{Sec: 0, Nsec: unix.UTIME_OMIT}
	ts := []unix.Timespec{omit, omit}
	if atime != nil {
		ts[0] = unix.NsecToTimespec(atime.UnixNano())
	}
	if mtime != nil {
		ts[1] = unix.NsecToTimespec(mtime.UnixNano())
	}
	parent, name, release, err := h.walkParent(rel)
	if err != nil {
		return err
	}
	defer release()
	if err := retryEINTR(func() error { return unix.UtimesNanoAt(parent, name, ts, unix.AT_SYMLINK_NOFOLLOW) }); err != nil {
		return fmt.Errorf("hostfs: set times of %q: %w", rel, err)
	}
	return nil
}

// hostErrno maps a host errno found inside err to the Linux errno that guest
// code expects. Host errno numbers differ from Linux numbers on macOS, so the
// mapping goes through names.
func hostErrno(err error) (error, bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return nil, false
	}
	if errno == unix.ENOTSUP || errno == unix.EOPNOTSUPP {
		return linuxerr.EOPNOTSUPP, true
	}
	switch errno {
	case unix.ENOENT:
		return linuxerr.ENOENT, true
	case unix.EEXIST:
		return linuxerr.EEXIST, true
	case unix.ENOTDIR:
		return linuxerr.ENOTDIR, true
	case unix.EISDIR:
		return linuxerr.EISDIR, true
	case unix.ENOTEMPTY:
		return linuxerr.ENOTEMPTY, true
	case unix.EACCES:
		return linuxerr.EACCES, true
	case unix.EPERM:
		return linuxerr.EPERM, true
	case unix.EXDEV:
		return linuxerr.EXDEV, true
	case unix.EINVAL:
		return linuxerr.EINVAL, true
	case unix.ELOOP:
		return linuxerr.ELOOP, true
	case unix.ENAMETOOLONG:
		return linuxerr.ENAMETOOLONG, true
	case unix.ENOSPC:
		return linuxerr.ENOSPC, true
	case unix.EDQUOT:
		return linuxerr.ENOSPC, true
	case unix.EROFS:
		return linuxerr.EROFS, true
	case unix.EBUSY:
		return linuxerr.EBUSY, true
	case unix.EMLINK:
		return linuxerr.EMLINK, true
	case unix.EMFILE:
		return linuxerr.EMFILE, true
	case unix.ENFILE:
		return linuxerr.ENFILE, true
	case unix.EFBIG:
		return linuxerr.EFBIG, true
	case unix.ENXIO:
		return linuxerr.ENXIO, true
	case unix.ETXTBSY:
		return linuxerr.ETXTBSY, true
	case unix.EIO:
		return linuxerr.EIO, true
	case unix.ENOMEM:
		return linuxerr.ENOMEM, true
	case unix.EBADF:
		return linuxerr.EBADF, true
	}
	return nil, false
}
