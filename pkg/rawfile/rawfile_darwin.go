//go:build darwin

package rawfile

import (
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
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

// GetMTU determines the MTU of a network interface device.
func GetMTU(name string) (uint32, error) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	var ifreq struct {
		name [16]byte
		mtu  int32
		_    [20]byte
	}
	copy(ifreq.name[:], name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCGIFMTU, uintptr(unsafe.Pointer(&ifreq)))
	if errno != 0 {
		return 0, errno
	}
	return uint32(ifreq.mtu), nil
}

// NonBlockingWrite writes buf to fd without blocking.
func NonBlockingWrite(fd int, buf []byte) unix.Errno {
	var ptr unsafe.Pointer
	if len(buf) > 0 {
		ptr = unsafe.Pointer(&buf[0])
	}
	_, _, e := unix.RawSyscall(unix.SYS_WRITE, uintptr(fd), uintptr(ptr), uintptr(len(buf)))
	return e
}

// NonBlockingWriteIovec writes iovec to fd in a single writev call.
func NonBlockingWriteIovec(fd int, iovec []unix.Iovec) unix.Errno {
	_, _, e := unix.RawSyscall(unix.SYS_WRITEV, uintptr(fd), uintptr(unsafe.Pointer(&iovec[0])), uintptr(len(iovec)))
	return e
}

// NonBlockingSendMMsg sends multiple messages sequentially on macOS.
func NonBlockingSendMMsg(fd int, msgHdrs []MMsgHdr) (int, unix.Errno) {
	sent := 0
	for i := range msgHdrs {
		n, _, e := unix.RawSyscall(unix.SYS_SENDMSG, uintptr(fd), uintptr(unsafe.Pointer(&msgHdrs[i].Msg)), unix.MSG_DONTWAIT)
		if e != 0 {
			if sent > 0 {
				return sent, 0
			}
			return 0, e
		}
		msgHdrs[i].Len = uint32(n)
		sent++
	}
	return sent, 0
}

// PollEvent represents the pollfd structure passed to poll(2).
type PollEvent struct {
	FD      int32
	Events  int16
	Revents int16
}

// BlockingPoll polls the given PollEvent array using poll(2).
func BlockingPoll(fds *PollEvent, nfds int, timeout *unix.Timespec) (int, unix.Errno) {
	timeoutMillis := -1
	if timeout != nil {
		timeoutMillis = int(timeout.Sec*1000 + timeout.Nsec/1_000_000)
	}
	n, _, e := unix.Syscall(unix.SYS_POLL, uintptr(unsafe.Pointer(fds)), uintptr(nfds), uintptr(timeoutMillis))
	return int(n), e
}

// BlockingRead reads from a non-blocking fd, polling until readable.
func BlockingRead(fd int, b []byte) (int, unix.Errno) {
	for {
		n, _, e := unix.RawSyscall(unix.SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
		if e == 0 {
			return int(n), 0
		}
		event := PollEvent{
			FD:     int32(fd),
			Events: unix.POLLIN,
		}
		_, e = BlockingPoll(&event, 1, nil)
		if e != 0 && e != unix.EINTR {
			return 0, e
		}
	}
}

// BlockingPollUntilStopped polls for events on fd or until stop is signalled on efd.
func BlockingPollUntilStopped(efd int, fd int, events int16) (bool, unix.Errno) {
	pevents := [...]PollEvent{
		{
			FD:     int32(efd),
			Events: unix.POLLIN,
		},
		{
			FD:     int32(fd),
			Events: events,
		},
	}
	_, errno := BlockingPoll(&pevents[0], len(pevents), nil)
	if errno != 0 {
		return pevents[0].Revents&unix.POLLIN != 0, errno
	}
	if pevents[1].Revents&unix.POLLHUP != 0 || pevents[1].Revents&unix.POLLERR != 0 {
		errno = unix.ECONNRESET
	}
	return pevents[0].Revents&unix.POLLIN != 0, errno
}

// BlockingReadvUntilStopped reads into iovecs or unblocks when efd becomes readable.
func BlockingReadvUntilStopped(efd int, fd int, iovecs []unix.Iovec) (int, unix.Errno) {
	for {
		n, _, e := unix.RawSyscall(unix.SYS_READV, uintptr(fd), uintptr(unsafe.Pointer(&iovecs[0])), uintptr(len(iovecs)))
		if e == 0 {
			return int(n), 0
		}
		if e != unix.EWOULDBLOCK && e != unix.EAGAIN {
			return 0, e
		}
		stopped, e := BlockingPollUntilStopped(efd, fd, unix.POLLIN)
		if stopped {
			return -1, e
		}
		if e != 0 && e != unix.EINTR {
			return 0, e
		}
	}
}

// BlockingRecvMMsgUntilStopped receives messages into msgHdrs or unblocks when efd becomes readable.
func BlockingRecvMMsgUntilStopped(efd int, fd int, msgHdrs []MMsgHdr) (int, unix.Errno) {
	for {
		n, _, e := unix.RawSyscall(unix.SYS_RECVMSG, uintptr(fd), uintptr(unsafe.Pointer(&msgHdrs[0].Msg)), unix.MSG_DONTWAIT)
		if e == 0 {
			msgHdrs[0].Len = uint32(n)
			return 1, 0
		}
		if e != unix.EWOULDBLOCK && e != unix.EAGAIN {
			return 0, e
		}
		stopped, e := BlockingPollUntilStopped(efd, fd, unix.POLLIN)
		if stopped {
			return -1, e
		}
		if e != 0 && e != unix.EINTR {
			return 0, e
		}
	}
}
