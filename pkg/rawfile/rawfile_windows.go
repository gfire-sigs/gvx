//go:build windows

package rawfile

import (
	"unsafe"

	"z.gfire.dev/gvx/third_party/x_sys/unix"
)

// SizeofIovec is the size of a unix.Iovec in bytes.
const SizeofIovec = unsafe.Sizeof(unix.Iovec{})

// MaxIovs is UIO_MAXIOV, the maximum number of iovecs in a single array.
const MaxIovs = 1024

// IovecFromBytes returns a unix.Iovec representing bs.
func IovecFromBytes(bs []byte) unix.Iovec {
	iov := unix.Iovec{
		Base: &bs[0],
	}
	iov.SetLen(len(bs))
	return iov
}

func bytesFromIovec(iov unix.Iovec) []byte {
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

// NonBlockingWrite writes buf to fd.
func NonBlockingWrite(fd int, buf []byte) unix.Errno {
	_, err := unix.Write(fd, buf)
	if err != nil {
		return unix.EIO
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
		return 0, unix.EIO
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
