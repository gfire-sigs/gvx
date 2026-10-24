package gvxshim

import (
	"errors"
	"net"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

func authorizePeer(conn net.Conn) error {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return errUnsafeEntry
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var peerErr error
	err = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			peerErr = err
			return
		}
		peerErr = authorizeUID(cred.Uid, uint32(os.Geteuid()))
	})
	return errors.Join(err, peerErr)
}

func bindPinnedSocket(dir *pinnedDir, name string) (_ net.Listener, err error) {
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
	defer func() {
		if err != nil {
			err = errors.Join(err, removeBoundSocket(dir, ref))
		}
	}()
	if resetErr != nil {
		return nil, errors.Join(resetErr, file.Close())
	}
	if err := unix.Fchmodat(int(dir.Handle.Fd()), name, 0600, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if err := unix.Listen(fd, 32); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	listener, err := net.FileListener(file)
	if err = errors.Join(err, file.Close()); err != nil {
		if listener != nil {
			err = errors.Join(err, listener.Close())
		}
		return nil, err
	}
	return listener, nil
}
