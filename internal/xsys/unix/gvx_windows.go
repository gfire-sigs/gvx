//go:build windows

package unix

import (
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Errno = syscall.Errno
type Signal = syscall.Signal

type Sockaddr interface {
	sockaddr() (ptr unsafe.Pointer, len _Socklen, err error)
}

type SockaddrInet4 struct {
	Port int
	Addr [4]byte
	raw  RawSockaddrInet4
}

func (sa *SockaddrInet4) sockaddr() (unsafe.Pointer, _Socklen, error) {
	return unsafe.Pointer(&sa.raw), SizeofSockaddrInet4, nil
}

type SockaddrInet6 struct {
	Port   int
	ZoneId uint32
	Addr   [16]byte
	raw    RawSockaddrInet6
}

func (sa *SockaddrInet6) sockaddr() (unsafe.Pointer, _Socklen, error) {
	return unsafe.Pointer(&sa.raw), SizeofSockaddrInet6, nil
}

type SockaddrUnix struct {
	Name string
	raw  RawSockaddrUnix
}

func (sa *SockaddrUnix) sockaddr() (unsafe.Pointer, _Socklen, error) {
	return unsafe.Pointer(&sa.raw), SizeofSockaddrUnix, nil
}

type SockaddrLinklayer struct {
	Protocol uint16
	Ifindex  int
	Hatype   uint16
	Pkttype  uint8
	Halen    uint8
	Addr     [8]byte
	raw      RawSockaddrLinklayer
}

func (sa *SockaddrLinklayer) sockaddr() (unsafe.Pointer, _Socklen, error) {
	return unsafe.Pointer(&sa.raw), SizeofSockaddrLinklayer, nil
}

type SockaddrNetlink struct {
	Family uint16
	Pad    uint16
	Pid    uint32
	Groups uint32
	raw    RawSockaddrNetlink
}

func (sa *SockaddrNetlink) sockaddr() (unsafe.Pointer, _Socklen, error) {
	return unsafe.Pointer(&sa.raw), SizeofSockaddrNetlink, nil
}

func (iov *Iovec) SetLen(length int) {
	iov.Len = uint64(length)
}

func (msghdr *Msghdr) SetControllen(length int) {
	msghdr.Controllen = uint64(length)
}

func (msghdr *Msghdr) SetIovlen(length int) {
	msghdr.Iovlen = uint64(length)
}

func (cmsg *Cmsghdr) SetLen(length int) {
	cmsg.Len = uint64(length)
}

func cmsgAlignOf(salen int) int {
	salign := SizeofPtr
	return (salen + salign - 1) & ^(salign - 1)
}

func CmsgLen(datalen int) int {
	return cmsgAlignOf(SizeofCmsghdr) + datalen
}

func CmsgSpace(datalen int) int {
	return cmsgAlignOf(SizeofCmsghdr) + cmsgAlignOf(datalen)
}

func (h *Cmsghdr) data(offset uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(h)) + uintptr(cmsgAlignOf(SizeofCmsghdr)) + offset)
}

type SocketControlMessage struct {
	Header Cmsghdr
	Data   []byte
}

func ParseSocketControlMessage(b []byte) ([]SocketControlMessage, error) {
	var msgs []SocketControlMessage
	i := 0
	for i+CmsgLen(0) <= len(b) {
		h, dbuf, err := socketControlMessageHeaderAndData(b[i:])
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, SocketControlMessage{Header: *h, Data: dbuf})
		i += cmsgAlignOf(int(h.Len))
	}
	return msgs, nil
}

func socketControlMessageHeaderAndData(b []byte) (*Cmsghdr, []byte, error) {
	h := (*Cmsghdr)(unsafe.Pointer(&b[0]))
	if h.Len < SizeofCmsghdr || uint64(h.Len) > uint64(len(b)) {
		return nil, nil, EINVAL
	}
	return h, b[cmsgAlignOf(SizeofCmsghdr):h.Len], nil
}

func UnixRights(fds ...int) []byte {
	datalen := len(fds) * 4
	b := make([]byte, CmsgSpace(datalen))
	h := (*Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = SOL_SOCKET
	h.Type = SCM_RIGHTS
	h.SetLen(CmsgLen(datalen))
	for i, fd := range fds {
		*(*int32)(h.data(4 * uintptr(i))) = int32(fd)
	}
	return b
}

func ParseUnixRights(m *SocketControlMessage) ([]int, error) {
	if m.Header.Level != SOL_SOCKET || m.Header.Type != SCM_RIGHTS {
		return nil, EINVAL
	}
	fds := make([]int, len(m.Data)>>2)
	for i, j := 0, 0; i < len(m.Data); i += 4 {
		fds[j] = int(*(*int32)(unsafe.Pointer(&m.Data[i])))
		j++
	}
	return fds, nil
}

func (ts *Timespec) Unix() (sec int64, nsec int64) {
	return int64(ts.Sec), int64(ts.Nsec)
}

func (tv *Timeval) Unix() (sec int64, nsec int64) {
	return int64(tv.Sec), int64(tv.Usec) * 1000
}

func (ts *Timespec) Nano() int64 {
	return int64(ts.Sec)*1e9 + int64(ts.Nsec)
}

func (tv *Timeval) Nano() int64 {
	return int64(tv.Sec)*1e9 + int64(tv.Usec)*1000
}

func TimespecToNsec(ts Timespec) int64 { return ts.Nano() }

func NsecToTimespec(nsec int64) Timespec {
	sec := nsec / 1e9
	nsec = nsec % 1e9
	if nsec < 0 {
		nsec += 1e9
		sec--
	}
	return Timespec{Sec: sec, Nsec: nsec}
}

func TimevalToNsec(tv Timeval) int64 { return tv.Nano() }

func NsecToTimeval(nsec int64) Timeval {
	nsec += 999
	usec := nsec % 1e9 / 1e3
	sec := nsec / 1e9
	if usec < 0 {
		usec += 1e6
		sec--
	}
	return Timeval{Sec: sec, Usec: usec}
}

func BytePtrFromString(s string) (*byte, error) {
	return syscall.BytePtrFromString(s)
}

func ByteSliceFromString(s string) ([]byte, error) {
	return syscall.ByteSliceFromString(s)
}

func ByteSliceToString(s []byte) string {
	for i, b := range s {
		if b == 0 {
			return string(s[:i])
		}
	}
	return string(s)
}

func Syscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return Syscall6(trap, a1, a2, a3, 0, 0, 0)
}

func RawSyscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return Syscall6(trap, a1, a2, a3, 0, 0, 0)
}

func RawSyscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return Syscall6(trap, a1, a2, a3, a4, a5, a6)
}

func Syscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno) {
	switch trap {
	case SYS_MMAP:
		addr, errno := winMmap(a1, a2, a3, a4, a5, a6)
		return addr, 0, errno
	case SYS_MUNMAP:
		return 0, 0, winMunmap(a1, a2)
	case SYS_MPROTECT:
		return 0, 0, winMprotect(a1, a2, a3)
	case SYS_MLOCK:
		return 0, 0, winMlock(a1, a2, true)
	case SYS_MUNLOCK:
		return 0, 0, winMlock(a1, a2, false)
	case SYS_MADVISE:
		return 0, 0, winMadvise(a1, a2, int(a3))
	case SYS_MINCORE:
		return 0, 0, winMincore(a1, a2, a3)
	default:
		return 0, 0, ENOSYS
	}
}

func ErrnoName(e syscall.Errno) string {
	return e.Error()
}

func SignalName(s syscall.Signal) string {
	return s.String()
}

func SignalNum(name string) syscall.Signal {
	return 0
}

func Getpid() int      { return os.Getpid() }
func Getppid() int     { return os.Getppid() }
func Getuid() int      { return 0 }
func Geteuid() int     { return 0 }
func Getgid() int      { return 0 }
func Getegid() int     { return 0 }
func Gettid() int      { return os.Getpid() }
func Getpagesize() int { return os.Getpagesize() }

func Open(path string, mode int, perm uint32) (int, error) {
	return -1, ENOSYS
}

func Openat(_ int, _ string, _ int, _ uint32) (int, error) {
	return -1, ENOSYS
}

func Close(fd int) error {
	return syscall.Close(syscall.Handle(uintptr(fd)))
}

func Read(fd int, p []byte) (int, error) {
	return syscall.Read(syscall.Handle(uintptr(fd)), p)
}

func Write(fd int, p []byte) (int, error) {
	return syscall.Write(syscall.Handle(uintptr(fd)), p)
}

func Pread(fd int, p []byte, offset int64) (int, error) {
	var o syscall.Overlapped
	o.Offset = uint32(offset)
	o.OffsetHigh = uint32(uint64(offset) >> 32)
	var done uint32
	err := syscall.ReadFile(syscall.Handle(uintptr(fd)), p, &done, &o)
	return int(done), err
}

func Pwrite(fd int, p []byte, offset int64) (int, error) {
	var o syscall.Overlapped
	o.Offset = uint32(offset)
	o.OffsetHigh = uint32(uint64(offset) >> 32)
	var done uint32
	err := syscall.WriteFile(syscall.Handle(uintptr(fd)), p, &done, &o)
	return int(done), err
}

func Seek(fd int, offset int64, whence int) (int64, error) {
	return syscall.Seek(syscall.Handle(uintptr(fd)), offset, whence)
}

func Dup(fd int) (int, error) {
	proc, err := syscall.GetCurrentProcess()
	if err != nil {
		return -1, err
	}
	var dup syscall.Handle
	if err := syscall.DuplicateHandle(proc, syscall.Handle(uintptr(fd)), proc, &dup, 0, false, syscall.DUPLICATE_SAME_ACCESS); err != nil {
		return -1, err
	}
	return int(uintptr(dup)), nil
}

func Dup2(oldfd, newfd int) error        { return ENOSYS }
func Dup3(oldfd, newfd, flags int) error { return ENOSYS }

// fileStandardInfo mirrors FILE_STANDARD_INFO from winbase.h.
type fileStandardInfo struct {
	AllocationSize int64
	EndOfFile      int64
	NumberOfLinks  uint32
	DeletePending  uint8
	Directory      uint8
}

// Fstat reports the size and the allocated blocks of a handle.
// Blocks counts the clusters that NTFS allocated, not the logical size, so
// sparse and punched files report their real disk use.
func Fstat(fd int, stat *Stat_t) error {
	var info fileStandardInfo
	err := windows.GetFileInformationByHandleEx(windows.Handle(uintptr(fd)), windows.FileStandardInfo, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	if err != nil {
		return winErrno(err)
	}
	if stat != nil {
		stat.Size = info.EndOfFile
		stat.Blocks = (info.AllocationSize + 511) / 512
	}
	return nil
}
func Fstatat(dirfd int, path string, stat *Stat_t, flags int) error          { return ENOSYS }
func Stat(path string, stat *Stat_t) error                                   { return ENOSYS }
func Lstat(path string, stat *Stat_t) error                                  { return ENOSYS }
func Statx(dirfd int, path string, flags int, mask int, stat *Statx_t) error { return ENOSYS }
func Fstatfs(fd int, buf *Statfs_t) error                                    { return ENOSYS }
func Statfs(path string, buf *Statfs_t) error                                { return ENOSYS }

// Ftruncate sets the file size without moving the file pointer.
func Ftruncate(fd int, length int64) error {
	return winError(windows.Ftruncate(windows.Handle(uintptr(fd)), length))
}
func Truncate(path string, length int64) error                                  { return os.Truncate(path, length) }
func Fsync(fd int) error                                                        { return syscall.FlushFileBuffers(syscall.Handle(uintptr(fd))) }
func Fdatasync(fd int) error                                                    { return syscall.FlushFileBuffers(syscall.Handle(uintptr(fd))) }
func Fchmod(fd int, mode uint32) error                                          { return ENOTSUP }
func Fchmodat(dirfd int, path string, mode uint32, flags int) error             { return ENOTSUP }
func Fchown(fd int, uid int, gid int) error                                     { return ENOTSUP }
func Fchownat(dirfd int, path string, uid int, gid int, flags int) error        { return ENOTSUP }
func Chmod(path string, mode uint32) error                                      { return os.Chmod(path, os.FileMode(mode)) }
func Chown(path string, uid int, gid int) error                                 { return ENOTSUP }
func Lchown(path string, uid int, gid int) error                                { return ENOTSUP }
func Unlink(path string) error                                                  { return os.Remove(path) }
func Unlinkat(dirfd int, path string, flags int) error                          { return ENOSYS }
func Mkdir(path string, mode uint32) error                                      { return os.Mkdir(path, os.FileMode(mode)) }
func Mkdirat(dirfd int, path string, mode uint32) error                         { return ENOSYS }
func Rmdir(path string) error                                                   { return os.Remove(path) }
func Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) error { return ENOSYS }
func Renameat2(olddirfd int, oldpath string, newdirfd int, newpath string, flags uint) error {
	return ENOSYS
}
func Symlinkat(oldpath string, newdirfd int, newpath string) error { return ENOSYS }
func Readlinkat(dirfd int, path string, buf []byte) (int, error)   { return 0, ENOSYS }
func Readlink(path string, buf []byte) (int, error)                { return 0, ENOSYS }
func Linkat(olddirfd int, oldpath string, newdirfd int, newpath string, flags int) error {
	return ENOSYS
}
func Mknodat(dirfd int, path string, mode uint32, dev int) error          { return ENOSYS }
func UtimesNanoAt(dirfd int, path string, ts []Timespec, flags int) error { return ENOSYS }
func Getdents(fd int, buf []byte) (int, error)                            { return 0, ENOSYS }

func Fgetxattr(fd int, attr string, dest []byte) (int, error)          { return 0, ENOTSUP }
func Fsetxattr(fd int, attr string, data []byte, flags int) error      { return ENOTSUP }
func Fremovexattr(fd int, attr string) error                           { return ENOTSUP }
func Flistxattr(fd int, dest []byte) (int, error)                      { return 0, ENOTSUP }
func Lgetxattr(link string, attr string, dest []byte) (int, error)     { return 0, ENOTSUP }
func Lsetxattr(link string, attr string, data []byte, flags int) error { return ENOTSUP }
func Lremovexattr(link string, attr string) error                      { return ENOTSUP }
func Llistxattr(link string, dest []byte) (int, error)                 { return 0, ENOTSUP }

func Socket(domain, typ, proto int) (int, error)                          { return -1, ENOSYS }
func Socketpair(domain, typ, proto int) ([2]int, error)                   { return [2]int{-1, -1}, ENOSYS }
func Bind(fd int, sa Sockaddr) error                                      { return ENOSYS }
func Listen(s int, n int) error                                           { return ENOSYS }
func Accept(fd int) (int, Sockaddr, error)                                { return -1, nil, ENOSYS }
func Accept4(fd int, flags int) (int, Sockaddr, error)                    { return -1, nil, ENOSYS }
func Connect(fd int, sa Sockaddr) error                                   { return ENOSYS }
func Getsockname(fd int) (Sockaddr, error)                                { return nil, ENOSYS }
func Getpeername(fd int) (Sockaddr, error)                                { return nil, ENOSYS }
func GetsockoptInt(fd, level, opt int) (int, error)                       { return 0, ENOSYS }
func SetsockoptInt(fd, level, opt int, value int) error                   { return ENOSYS }
func GetsockoptUcred(fd, level, opt int) (*Ucred, error)                  { return nil, ENOSYS }
func GetsockoptLinger(fd, level, opt int) (*Linger, error)                { return nil, ENOSYS }
func SetsockoptLinger(fd, level, opt int, l *Linger) error                { return ENOSYS }
func GetsockoptTimeval(fd, level, opt int) (*Timeval, error)              { return nil, ENOSYS }
func SetsockoptTimeval(fd, level, opt int, tv *Timeval) error             { return ENOSYS }
func GetsockoptInet4Addr(fd, level, opt int) ([4]byte, error)             { return [4]byte{}, ENOSYS }
func SetsockoptInet4Addr(fd, level, opt int, value [4]byte) error         { return ENOSYS }
func SetsockoptIPMreq(fd, level, opt int, mreq *IPMreq) error             { return ENOSYS }
func SetsockoptIPv6Mreq(fd, level, opt int, mreq *IPv6Mreq) error         { return ENOSYS }
func Shutdown(fd int, how int) error                                      { return ENOSYS }
func Sendmsg(fd int, p, oob []byte, to Sockaddr, flags int) error         { return ENOSYS }
func SendmsgN(fd int, p, oob []byte, to Sockaddr, flags int) (int, error) { return 0, ENOSYS }
func Recvmsg(fd int, p, oob []byte, flags int) (int, int, int, Sockaddr, error) {
	return 0, 0, 0, nil, ENOSYS
}
func Sendto(fd int, p []byte, flags int, to Sockaddr) error       { return ENOSYS }
func Recvfrom(fd int, p []byte, flags int) (int, Sockaddr, error) { return 0, nil, ENOSYS }

func IoctlGetInt(fd int, req uint) (int, error)              { return 0, ENOSYS }
func IoctlSetInt(fd int, req uint, value int) error          { return ENOSYS }
func IoctlGetWinsize(fd int, req uint) (*Winsize, error)     { return nil, ENOSYS }
func IoctlSetWinsize(fd int, req uint, value *Winsize) error { return ENOSYS }
func IoctlGetTermios(fd int, req uint) (*Termios, error)     { return nil, ENOSYS }
func IoctlSetTermios(fd int, req uint, value *Termios) error { return ENOSYS }

// FcntlInt supports the descriptor commands that have Win32 equivalents:
// F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD and F_SETFD with FD_CLOEXEC.
// File status flags and locks have no handle-level equivalent, so other commands return EINVAL.
func FcntlInt(fd uintptr, cmd int, arg int) (int, error) {
	handle := windows.Handle(fd)
	switch cmd {
	case F_DUPFD, F_DUPFD_CLOEXEC:
		if arg != 0 {
			// A handle value cannot honour a minimum descriptor number.
			return -1, EINVAL
		}
		process := windows.CurrentProcess()
		var dup windows.Handle
		inherit := cmd == F_DUPFD
		if err := windows.DuplicateHandle(process, handle, process, &dup, 0, inherit, windows.DUPLICATE_SAME_ACCESS); err != nil {
			return -1, winErrno(err)
		}
		return int(dup), nil
	case F_GETFD:
		var flags uint32
		if r1, _, callErr := procGetHandleInformationUx.Call(uintptr(handle), uintptr(unsafe.Pointer(&flags))); r1 == 0 {
			return -1, winErrno(callErr)
		}
		if flags&windows.HANDLE_FLAG_INHERIT == 0 {
			return FD_CLOEXEC, nil
		}
		return 0, nil
	case F_SETFD:
		inherit := uint32(windows.HANDLE_FLAG_INHERIT)
		if arg&FD_CLOEXEC != 0 {
			inherit = 0
		}
		if err := windows.SetHandleInformation(handle, windows.HANDLE_FLAG_INHERIT, inherit); err != nil {
			return -1, winErrno(err)
		}
		return 0, nil
	}
	return -1, EINVAL
}
func FcntlFlock(fd uintptr, cmd int, lk *Flock_t) error { return ENOSYS }
func Flock(fd int, how int) error                       { return ENOSYS }
func SetNonblock(fd int, nonblocking bool) error        { return ENOSYS }

// CloseOnExec stops child processes from inheriting the handle.
// The signature has no error result, so a failure leaves the handle inheritable.
func CloseOnExec(fd int) {
	_ = windows.SetHandleInformation(windows.Handle(uintptr(fd)), windows.HANDLE_FLAG_INHERIT, 0)
}

func Pipe(p []int) error             { return ENOSYS }
func Pipe2(p []int, flags int) error { return ENOSYS }

func Poll(fds []PollFd, timeout int) (int, error)                           { return 0, ENOSYS }
func Ppoll(fds []PollFd, timeout *Timespec, sigmask *Sigset_t) (int, error) { return 0, ENOSYS }

func EpollCreate1(flag int) (int, error)                             { return -1, ENOSYS }
func EpollCtl(epfd int, op int, fd int, event *EpollEvent) error     { return ENOSYS }
func EpollWait(epfd int, events []EpollEvent, msec int) (int, error) { return 0, ENOSYS }

func Getrlimit(resource int, rlim *Rlimit) error                                     { return ENOSYS }
func Setrlimit(resource int, rlim *Rlimit) error                                     { return ENOSYS }
func Getrusage(who int, rusage *Rusage) error                                        { return ENOSYS }
func Uname(buf *Utsname) error                                                       { return ENOSYS }
func Sysinfo(info *Sysinfo_t) error                                                  { return ENOSYS }
func ClockGettime(clockid int32, time *Timespec) error                               { return ENOSYS }
func Kill(pid int, sig syscall.Signal) error                                         { return ENOSYS }
func Tgkill(tgid int, tid int, sig syscall.Signal) error                             { return ENOSYS }
func Prctl(option int, arg2 uintptr, arg3 uintptr, arg4 uintptr, arg5 uintptr) error { return ENOSYS }
func Prlimit(pid int, resource int, newlimit *Rlimit, old *Rlimit) error             { return ENOSYS }
func SchedGetaffinity(pid int, set *CPUSet) error                                    { return ENOSYS }

type CPUSet [16]uint64

func (s *CPUSet) Zero() {
	*s = CPUSet{}
}

func (s *CPUSet) Set(cpu int) {
	if cpu >= 0 && cpu < 1024 {
		s[cpu/64] |= 1 << (uint(cpu) % 64)
	}
}

func (s *CPUSet) IsSet(cpu int) bool {
	if cpu >= 0 && cpu < 1024 {
		return s[cpu/64]&(1<<(uint(cpu)%64)) != 0
	}
	return false
}

func (s *CPUSet) Count() int {
	n := 0
	for _, w := range s {
		for w != 0 {
			w &= w - 1
			n++
		}
	}
	return n
}

func Major(dev uint64) uint32 {
	return uint32((dev&0x00000000000fff00)>>8) | uint32((dev&0xfffff00000000000)>>32)
}

func Minor(dev uint64) uint32 {
	return uint32((dev&0x00000000000000ff)>>0) | uint32((dev&0x00000ffffff00000)>>12)
}

func Mkdev(major, minor uint32) uint64 {
	dev := (uint64(major) & 0x00000fff) << 8
	dev |= (uint64(major) & 0xfffff000) << 32
	dev |= (uint64(minor) & 0x000000ff) << 0
	dev |= (uint64(minor) & 0xffffff00) << 12
	return dev
}
