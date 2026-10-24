package gvxshim

import (
	"errors"
	"fmt"
	"net"
	"os"
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
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			peerErr = err
			return
		}
		peerErr = authorizeUID(cred.Uid, uint32(os.Geteuid()))
	})
	return errors.Join(err, peerErr)
}

func bindPinnedSocket(dir *pinnedDir, name string) (_ net.Listener, err error) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: fmt.Sprintf("/proc/self/fd/%d/%s", dir.Handle.Fd(), name)}); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	ref, err := boundSocketReference(dir, name)
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, removeBoundSocket(dir, ref))
		}
	}()
	if err := unix.Fchmodat(int(dir.Handle.Fd()), name, 0600, 0); err != nil {
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
