package gvxshim

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func authorizePeer(conn net.Conn) error {
	return authorizePeerWith(conn, func(fd int) (uint32, error) {
		cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			return 0, err
		}
		return cred.Uid, nil
	})
}

func bindPinnedSocket(dir *pinnedDir, name string) (net.Listener, error) {
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
	return finishPinnedSocket(dir, name, fd, file, ref, 0)
}
