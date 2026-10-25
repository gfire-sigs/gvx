package gvxshim

import (
	"errors"
	"net"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

func authorizePeer(conn net.Conn) error {
	return authorizePeerWith(conn, func(fd int) (uint32, error) {
		cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			return 0, err
		}
		return cred.Uid, nil
	})
}

func bindPinnedSocket(dir *pinnedDir, name string) (net.Listener, error) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	file := os.NewFile(uintptr(fd), name)
	// Use libSystem: Darwin no longer supports these raw syscall entry points.
	runtime.LockOSThread()
	setErr := unix.PthreadFchdir(int(dir.Handle.Fd()))
	if setErr != nil {
		runtime.UnlockOSThread()
		return nil, errors.Join(setErr, file.Close())
	}
	bindErr := unix.Bind(fd, &unix.SockaddrUnix{Name: name})
	var ref ownedEntry
	var refErr error
	if bindErr == nil {
		ref, refErr = boundSocketReference(dir, name)
	}
	resetErr := unix.PthreadFchdir(-1)
	if resetErr == nil {
		runtime.UnlockOSThread()
	}
	// A failed reset keeps this goroutine on its thread until process exit.
	if bindErr != nil || refErr != nil {
		return nil, errors.Join(bindErr, refErr, resetErr, file.Close())
	}
	if resetErr != nil {
		return nil, errors.Join(resetErr, file.Close(), removeBoundSocket(dir, ref))
	}
	return finishPinnedSocket(dir, name, fd, file, ref, unix.AT_SYMLINK_NOFOLLOW)
}
