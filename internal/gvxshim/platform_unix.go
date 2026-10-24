//go:build linux || darwin

package gvxshim

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

func currentOwner() (string, error) { return strconv.Itoa(os.Geteuid()), nil }

func normalizeContainerdAddress(address string) (string, error) {
	path := strings.TrimPrefix(address, "unix://")
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) || strings.Contains(path, "://") {
		return "", errUnsafeEntry
	}
	return "unix://" + filepath.Clean(path), nil
}

func platformInfoIdentity(info os.FileInfo) (fileIdentity, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, errUnsafeEntry
	}
	var id fileIdentity
	id.Volume = uint64(st.Dev)
	binary.LittleEndian.PutUint64(id.Object[:8], uint64(st.Ino))
	return id, nil
}

func platformValidateInfo(info os.FileInfo, kind entryKind, private bool) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSymlink != 0 {
		return errUnsafeEntry
	}
	valid := kind == regularEntry && info.Mode().IsRegular() || kind == directoryEntry && info.IsDir() || kind == socketEntry && info.Mode()&os.ModeSocket != 0
	if !valid {
		return errUnsafeEntry
	}
	if kind != directoryEntry && st.Nlink != 1 {
		return errUnsafeEntry
	}
	if private && (st.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0) {
		return errUnsafeEntry
	}
	return nil
}

func validateFile(f *os.File, kind entryKind, private bool) (fileIdentity, error) {
	info, err := f.Stat()
	if err != nil {
		return fileIdentity{}, err
	}
	if err := platformValidateInfo(info, kind, private); err != nil {
		return fileIdentity{}, err
	}
	return platformInfoIdentity(info)
}

func validateBundle(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 {
		return errUnsafeEntry
	}
	return platformValidateInfo(info, directoryEntry, false)
}

func platformOpenInitial(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func platformOpenRelative(dir *pinnedDir, name string, flags int, perm os.FileMode, directory bool) (*os.File, error) {
	if !validComponent(name) {
		return nil, errUnsafeEntry
	}
	flags |= unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat(int(dir.Handle.Fd()), name, flags, uint32(perm.Perm()))
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	return os.NewFile(uintptr(fd), name), nil
}

func platformMkdir(dir *pinnedDir, name string) error {
	err := unix.Mkdirat(int(dir.Handle.Fd()), name, 0700)
	if err != nil {
		return &os.PathError{Op: "mkdirat", Path: name, Err: err}
	}
	return nil
}

func platformEntryIdentity(dir *pinnedDir, name string, info os.FileInfo, kind entryKind) (fileIdentity, error) {
	id, err := platformInfoIdentity(info)
	if err != nil || kind == socketEntry {
		return id, err
	}
	f, err := platformOpenRelative(dir, name, os.O_RDONLY, 0, kind == directoryEntry)
	if err != nil {
		return fileIdentity{}, err
	}
	actual, err := validateFile(f, kind, true)
	if err = errors.Join(err, f.Close()); err != nil {
		return fileIdentity{}, err
	}
	if id != actual {
		return fileIdentity{}, errPathChanged
	}
	return id, nil
}

func platformRemove(dir *pinnedDir, entry ownedEntry) error {
	flags := 0
	if entry.Kind == directoryEntry {
		flags = unix.AT_REMOVEDIR
	}
	return unix.Unlinkat(int(dir.Handle.Fd()), entry.Name, flags)
}

func platformAddresses(id instanceIdentity, key string) (string, string, error) {
	base := filepath.Join("/tmp", "gvx-shim-"+id.Owner, key)
	task, stop := filepath.Join(base, "task"), filepath.Join(base, "stop")
	if len(task) >= 104 || len(stop) >= 104 {
		return "", "", fmt.Errorf("Unix endpoint exceeds platform path limit")
	}
	return "unix://" + task, "unix://" + stop, nil
}

func platformOpenEndpoints(ctx context.Context, p *instancePaths, mode pathMode) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tmp, err := pinSystemTemporary()
	if err != nil {
		return err
	}
	p.UnixEndpointRoot, err = pinChild(tmp, "gvx-shim-"+p.Identity.Owner, true, mode == createPaths)
	if errors.Is(err, os.ErrNotExist) && mode == inspectPaths {
		p.UnixEndpointRoot = nil
		return nil
	}
	if err != nil {
		return err
	}
	rootID := p.UnixEndpointRoot.ID
	p.Snapshot.UnixEndpointRoot = &rootID
	p.UnixEndpointDir, err = pinChild(p.UnixEndpointRoot, endpointKey(p.Identity), true, false)
	if errors.Is(err, os.ErrNotExist) {
		p.UnixEndpointDir = nil
		return nil
	}
	if err != nil {
		return err
	}
	dirID := p.UnixEndpointDir.ID
	p.Snapshot.UnixEndpointDir = &dirID
	return nil
}

func platformRevalidateEndpoints(p *instancePaths, expected pathSnapshot) error {
	tmp, err := pinSystemTemporary()
	if err != nil {
		return err
	}
	if err := verifyChild(tmp, "gvx-shim-"+p.Identity.Owner, p.UnixEndpointRoot, true); err != nil {
		return err
	}
	if p.UnixEndpointRoot == nil {
		return nil
	}
	if expected.UnixEndpointRoot == nil || *expected.UnixEndpointRoot != p.UnixEndpointRoot.ID {
		return errPathChanged
	}
	if err := verifyChild(p.UnixEndpointRoot, endpointKey(p.Identity), p.UnixEndpointDir, true); err != nil {
		if !errors.Is(err, os.ErrNotExist) || p.UnixEndpointDir == nil || expected.UnixEndpointDir == nil || *expected.UnixEndpointDir != p.UnixEndpointDir.ID {
			return err
		}
	}
	if p.UnixEndpointDir != nil && (expected.UnixEndpointDir == nil || *expected.UnixEndpointDir != p.UnixEndpointDir.ID) {
		return errPathChanged
	}
	return nil
}

func prepareEndpointDir(ctx context.Context, p *instancePaths) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.UnixEndpointRoot == nil || p.UnixEndpointDir != nil {
		return errUnsafeEntry
	}
	name := endpointKey(p.Identity)
	if err := platformMkdir(p.UnixEndpointRoot, name); err != nil {
		return err
	}
	dir, err := pinChild(p.UnixEndpointRoot, name, true, false)
	if err != nil {
		return err
	}
	p.UnixEndpointDir = dir
	id := dir.ID
	p.Snapshot.UnixEndpointDir = &id
	return nil
}

func removeEndpointDir(p *instancePaths, expected fileIdentity) error {
	if p.UnixEndpointRoot == nil {
		return errPathChanged
	}
	if p.UnixEndpointDir != nil && p.UnixEndpointDir.ID != expected {
		return errPathChanged
	}
	return removeOwned(p.UnixEndpointRoot, ownedEntry{Name: endpointKey(p.Identity), Kind: directoryEntry, Identity: expected})
}

func tryLock(l *ownedLock) error {
	err := unix.Flock(int(l.File.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return errLockBusy
	}
	return err
}

func unlock(l *ownedLock) error { return unix.Flock(int(l.File.Fd()), unix.LOCK_UN) }

func configureChild(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

type ownerListener struct{ net.Listener }

func (l *ownerListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if err := authorizePeer(conn); err != nil {
			conn.Close()
			continue
		}
		return conn, nil
	}
}

func listenLocal(ctx context.Context, paths *instancePaths, kind endpointKind) (*ownedEndpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := paths.Revalidate(paths.Snapshot); err != nil {
		return nil, err
	}
	name, address := "task", paths.TaskAddress
	if kind == stopEndpoint {
		name, address = "stop", paths.StopAddress
	} else if kind != taskEndpoint {
		return nil, errUnsafeEntry
	}
	if paths.UnixEndpointDir == nil {
		return nil, errUnsafeEntry
	}
	if _, err := paths.UnixEndpointDir.Root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return nil, err
		}
		return nil, os.ErrExist
	}
	listener, err := bindPinnedSocket(paths.UnixEndpointDir, name)
	if err != nil {
		return nil, err
	}
	ref, err := inspectEntry(paths.UnixEndpointDir, name, socketEntry)
	if err != nil {
		return nil, errors.Join(err, listener.Close())
	}
	return &ownedEndpoint{Listener: &ownerListener{Listener: listener}, Ref: endpointRef{Address: address, Socket: &ref}}, nil
}

func dialLocal(ctx context.Context, address string) (net.Conn, error) {
	if !strings.HasPrefix(address, "unix:///") {
		return nil, errUnsafeEntry
	}
	path := strings.TrimPrefix(address, "unix://")
	if filepath.Clean(path) != path || len(path) >= 104 || strings.ContainsRune(path, 0) {
		return nil, errUnsafeEntry
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	if err := authorizePeer(conn); err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	return conn, nil
}

func platformRootIdentity(root *os.Root) (fileIdentity, error) {
	info, err := root.Stat(".")
	if err != nil {
		return fileIdentity{}, err
	}
	return platformInfoIdentity(info)
}

var systemTemporary = sync.OnceValues(func() (*pinnedDir, error) {
	path, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		return nil, err
	}
	return pinInitial(path, false)
})

func pinSystemTemporary() (*pinnedDir, error) { return systemTemporary() }

func absentEndpoints(paths *instancePaths) error {
	if err := platformRevalidateEndpoints(paths, paths.Snapshot); err != nil {
		return err
	}
	if paths.UnixEndpointDir != nil {
		return errUnsafeEntry
	}
	return nil
}

func authorizeUID(peerUID, effectiveUID uint32) error {
	if peerUID != effectiveUID {
		return errUnsafeEntry
	}
	return nil
}

func boundSocketReference(dir *pinnedDir, name string) (ownedEntry, error) {
	if !validComponent(name) {
		return ownedEntry{}, errUnsafeEntry
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(int(dir.Handle.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return ownedEntry{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFSOCK || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return ownedEntry{}, errUnsafeEntry
	}
	var id fileIdentity
	id.Volume = uint64(stat.Dev)
	binary.LittleEndian.PutUint64(id.Object[:8], uint64(stat.Ino))
	return ownedEntry{Name: name, Kind: socketEntry, Identity: id}, nil
}

func removeBoundSocket(dir *pinnedDir, expected ownedEntry) error {
	dirID, err := validateFile(dir.Handle, directoryEntry, true)
	if err != nil {
		return err
	}
	if dirID != dir.ID {
		return errPathChanged
	}
	actual, err := boundSocketReference(dir, expected.Name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if actual != expected {
		return errPathChanged
	}
	return platformRemove(dir, expected)
}
