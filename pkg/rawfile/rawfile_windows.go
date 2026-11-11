//go:build windows

package rawfile

import (
	"errors"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/internal/xsys/unix"
)

// SizeofIovec is the size of a unix.Iovec in bytes.
const SizeofIovec = unsafe.Sizeof(unix.Iovec{})

// MaxIovs is UIO_MAXIOV, the maximum number of iovecs in a single array.
const MaxIovs = 1024

// IovecFromBytes returns a unix.Iovec representing bs.
func IovecFromBytes(bs []byte) unix.Iovec {
	var iov unix.Iovec
	if len(bs) > 0 {
		iov.Base = &bs[0]
		iov.SetLen(len(bs))
	}
	return iov
}

func bytesFromIovec(iov unix.Iovec) []byte {
	if iov.Len == 0 {
		return nil
	}
	ptr := unsafe.Pointer(iov.Base)
	return unsafe.Slice((*byte)(ptr), int(iov.Len))
}

// AppendIovecFromBytes appends an iovec representing bs up to max entries.
func AppendIovecFromBytes(iovs []unix.Iovec, bs []byte, max int) []unix.Iovec {
	if len(bs) == 0 {
		return iovs
	}
	if len(iovs) < max {
		return append(iovs, IovecFromBytes(bs))
	}
	iovs[len(iovs)-1] = IovecFromBytes(append(bytesFromIovec(iovs[len(iovs)-1]), bs...))
	return iovs
}

// MMsgHdr represents the mmsg_hdr structure.
type MMsgHdr struct {
	Msg unix.Msghdr
	Len uint32
	_   [4]byte
}

// SizeofMMsgHdr is the size of MMsgHdr in bytes.
const SizeofMMsgHdr = unsafe.Sizeof(MMsgHdr{})

// GetMTU returns the MTU of a network interface device.
func GetMTU(_ string) (uint32, error) {
	return 1500, nil
}

// translateError converts a Windows host error into a Linux-compatible unix.Errno.
func translateError(err error) unix.Errno {
	if err == nil {
		return 0
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch windows.Errno(errno) {
		case 0:
			return 0
		case windows.ERROR_BROKEN_PIPE, windows.ERROR_NO_DATA, windows.ERROR_PIPE_NOT_CONNECTED, windows.WSAESHUTDOWN:
			return unix.EPIPE
		case windows.ERROR_INVALID_HANDLE, windows.WSAEBADF:
			return unix.EBADF
		case windows.WSAEWOULDBLOCK, windows.ERROR_IO_PENDING, windows.ERROR_IO_INCOMPLETE, windows.ERROR_PIPE_BUSY:
			return unix.EAGAIN
		case windows.WSAEINTR, windows.ERROR_OPERATION_ABORTED:
			return unix.EINTR
		case windows.ERROR_ACCESS_DENIED, windows.WSAEACCES, windows.ERROR_SHARING_VIOLATION, windows.ERROR_LOCK_VIOLATION:
			return unix.EACCES
		case windows.ERROR_WRITE_PROTECT:
			return unix.EROFS
		case windows.ERROR_FILE_NOT_FOUND, windows.ERROR_PATH_NOT_FOUND:
			return unix.ENOENT
		case windows.ERROR_FILE_EXISTS, windows.ERROR_ALREADY_EXISTS:
			return unix.EEXIST
		case windows.ERROR_INVALID_PARAMETER, windows.WSAEINVAL:
			return unix.EINVAL
		case windows.ERROR_INVALID_ADDRESS, windows.WSAEFAULT:
			return unix.EFAULT
		case windows.ERROR_NOT_ENOUGH_MEMORY, windows.ERROR_OUTOFMEMORY, windows.WSAENOBUFS:
			return unix.ENOMEM
		case windows.ERROR_DISK_FULL:
			return unix.ENOSPC
		case windows.ERROR_TOO_MANY_OPEN_FILES, windows.WSAEMFILE:
			return unix.EMFILE
		case windows.ERROR_NOT_SUPPORTED, windows.WSAEOPNOTSUPP:
			return unix.ENOTSUP
		case windows.ERROR_CALL_NOT_IMPLEMENTED, windows.ERROR_INVALID_FUNCTION:
			return unix.ENOSYS
		case windows.WSAECONNRESET, windows.ERROR_NETNAME_DELETED, windows.WSAENETRESET:
			return unix.ECONNRESET
		case windows.WSAECONNABORTED:
			return unix.ECONNABORTED
		case windows.WSAECONNREFUSED:
			return unix.ECONNREFUSED
		case windows.WSAENOTCONN:
			return unix.ENOTCONN
		case windows.WSAENOTSOCK:
			return unix.ENOTSOCK
		case windows.WSAEMSGSIZE, windows.ERROR_MORE_DATA:
			return unix.EMSGSIZE
		case windows.WSAETIMEDOUT:
			return unix.ETIMEDOUT
		case windows.WSAEINPROGRESS:
			return unix.EINPROGRESS
		case windows.WSAEALREADY:
			return unix.EALREADY
		case windows.WSAENETDOWN:
			return unix.ENETDOWN
		case windows.WSAENETUNREACH:
			return unix.ENETUNREACH
		}
	}
	switch {
	case errors.Is(err, os.ErrClosed):
		return unix.EBADF
	case errors.Is(err, os.ErrPermission):
		return unix.EACCES
	case errors.Is(err, os.ErrNotExist):
		return unix.ENOENT
	case errors.Is(err, os.ErrExist):
		return unix.EEXIST
	case errors.Is(err, os.ErrInvalid):
		return unix.EINVAL
	case errors.Is(err, os.ErrDeadlineExceeded):
		return unix.ETIMEDOUT
	default:
		return unix.EIO
	}
}

// NonBlockingWrite writes buf to fd.
func NonBlockingWrite(fd int, buf []byte) unix.Errno {
	_, err := unix.Write(fd, buf)
	if err != nil {
		return translateError(err)
	}
	return 0
}

// NonBlockingWriteIovec writes iovec slices to fd.
func NonBlockingWriteIovec(fd int, iovec []unix.Iovec) unix.Errno {
	for _, iov := range iovec {
		if errno := NonBlockingWrite(fd, bytesFromIovec(iov)); errno != 0 {
			return errno
		}
	}
	return 0
}

// NonBlockingSendMMsg returns ENOSYS on Windows.
func NonBlockingSendMMsg(_ int, _ []MMsgHdr) (int, unix.Errno) {
	return 0, unix.ENOSYS
}

// PollEvent represents the pollfd structure.
type PollEvent struct {
	FD      int32
	Events  int16
	Revents int16
}

// BlockingPoll returns ENOSYS on Windows.
func BlockingPoll(_ *PollEvent, _ int, _ *unix.Timespec) (int, unix.Errno) {
	return 0, unix.ENOSYS
}

// BlockingRead reads from fd.
func BlockingRead(fd int, b []byte) (int, unix.Errno) {
	n, err := unix.Read(fd, b)
	if err != nil {
		return -1, translateError(err)
	}
	return n, 0
}

// BlockingPollUntilStopped returns ENOSYS on Windows.
func BlockingPollUntilStopped(_ int, _ int, _ int16) (bool, unix.Errno) {
	return true, unix.ENOSYS
}

// BlockingReadvUntilStopped returns ENOSYS on Windows.
func BlockingReadvUntilStopped(_ int, _ int, _ []unix.Iovec) (int, unix.Errno) {
	return -1, unix.ENOSYS
}

// BlockingRecvMMsgUntilStopped returns ENOSYS on Windows.
func BlockingRecvMMsgUntilStopped(_ int, _ int, _ []MMsgHdr) (int, unix.Errno) {
	return -1, unix.ENOSYS
}
