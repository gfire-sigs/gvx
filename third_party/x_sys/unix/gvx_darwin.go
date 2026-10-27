//go:build darwin

package unix

import (
	"syscall"
	"unsafe"
)

type darwinRawStat_t struct {
	Dev     int32
	Mode    uint16
	Nlink   uint16
	Ino     uint64
	Uid     uint32
	Gid     uint32
	Rdev    int32
	Atim    Timespec
	Mtim    Timespec
	Ctim    Timespec
	Btim    Timespec
	Size    int64
	Blocks  int64
	Blksize int32
	Flags   uint32
	Gen     uint32
	Lspare  int32
	Qspare  [2]int64
}

func copyDarwinRawStat(dst *Stat_t, src *darwinRawStat_t) {
	if dst == nil || src == nil {
		return
	}
	*dst = Stat_t{
		Dev:     uint64(uint32(src.Dev)),
		Mode:    uint32(src.Mode),
		Nlink:   uint64(src.Nlink),
		Ino:     src.Ino,
		Uid:     src.Uid,
		Gid:     src.Gid,
		Rdev:    uint64(uint32(src.Rdev)),
		Atim:    src.Atim,
		Mtim:    src.Mtim,
		Ctim:    src.Ctim,
		Btim:    src.Btim,
		Size:    src.Size,
		Blocks:  src.Blocks,
		Blksize: int64(src.Blksize),
		Flags:   src.Flags,
		Gen:     src.Gen,
		Lspare:  src.Lspare,
		Qspare:  src.Qspare,
	}
}

const (
	O_LARGEFILE           = 0
	O_DIRECT              = 0
	O_PATH                = 0x200000
	SOCK_CLOEXEC          = 0
	SOCK_NONBLOCK         = 0
	SYS_PRCTL             = 0
	SYS_PREAD64           = SYS_PREAD
	SYS_PWRITE64          = SYS_PWRITE
	SYS_PREADV2           = 516
	SYS_PWRITEV2          = 517
	SYS_UTIMENSAT         = 0
	SYS_RENAMEAT2         = SYS_RENAMEAT
	SYS_NEWFSTATAT        = SYS_FSTATAT64
	SYS_IO_URING_SETUP    = 425
	SYS_IO_URING_ENTER    = 426
	SYS_IO_URING_REGISTER = 427
	SYS_EVENTFD2          = 290
	SYS_PPOLL             = SYS_POLL
	SYS_MEMBARRIER        = 324
	SYS_MREMAP            = 25
	SYS_CLOCK_GETTIME     = 228
	SYS_FALLBACK          = 0
	ENOTUNIQ              = Errno(0x1000)
	EREMOTEIO             = Errno(121)

	STATX_TYPE        = 0x1
	STATX_MODE        = 0x2
	STATX_NLINK       = 0x4
	STATX_UID         = 0x8
	STATX_GID         = 0x10
	STATX_ATIME       = 0x20
	STATX_MTIME       = 0x40
	STATX_CTIME       = 0x80
	STATX_INO         = 0x100
	STATX_SIZE        = 0x200
	STATX_BLOCKS      = 0x400
	STATX_BASIC_STATS = 0x7ff
	STATX_BTIME       = 0x800
	STATX_MNT_ID      = 0x1000
	STATX_ALL         = 0xfff

	AT_EMPTY_PATH         = 0x1000
	AT_STATX_SYNC_TYPE    = 0x6000
	AT_STATX_SYNC_AS_STAT = 0x0000
	AT_STATX_FORCE_SYNC   = 0x2000
	AT_STATX_DONT_SYNC    = 0x4000
	UTIME_NOW             = -1
	UTIME_OMIT            = -2

	POLLRDHUP = 0x2000

	EPOLLIN      = 0x1
	EPOLLPRI     = 0x2
	EPOLLOUT     = 0x4
	EPOLLERR     = 0x8
	EPOLLHUP     = 0x10
	EPOLLRDHUP   = 0x2000
	EPOLLET      = -1 << 31
	EPOLLONESHOT = 1 << 30

	EPOLL_CTL_ADD = 1
	EPOLL_CTL_DEL = 2
	EPOLL_CTL_MOD = 3
	EPOLL_CLOEXEC = 0x80000

	SO_DOMAIN       = 39
	SO_PASSCRED     = 16
	SCM_CREDENTIALS = 0x2
	SizeofUcred     = 12

	AF_NETLINK = 16
	AF_PACKET  = 17

	MADV_HUGEPAGE       = 14
	MADV_NOHUGEPAGE     = 15
	MADV_POPULATE_READ  = 22
	MADV_POPULATE_WRITE = 23
	MADV_DONTFORK       = 10
	MADV_REMOVE         = 9

	FALLOC_FL_KEEP_SIZE  = 0x1
	FALLOC_FL_PUNCH_HOLE = 0x2
	MAP_FIXED_NOREPLACE  = 0x100000
)

type Sigset_t uint32

type StatxTimestamp struct {
	Sec  int64
	Nsec uint32
	_    int32
}

type Statx_t struct {
	Mask             uint32
	Blksize          uint32
	Attributes       uint64
	Nlink            uint32
	Uid              uint32
	Gid              uint32
	Mode             uint16
	_                uint16
	Ino              uint64
	Size             uint64
	Blocks           uint64
	Attributes_mask  uint64
	Atime            StatxTimestamp
	Btime            StatxTimestamp
	Ctime            StatxTimestamp
	Mtime            StatxTimestamp
	Rdev_major       uint32
	Rdev_minor       uint32
	Dev_major        uint32
	Dev_minor        uint32
	Mnt_id           uint64
	Dio_mem_align    uint32
	Dio_offset_align uint32
	_                [12]uint64
}

type EpollEvent struct {
	Events uint32
	Fd     int32
	Pad    int32
}

func Statx(_ int, _ string, _ int, _ int, _ *Statx_t) error {
	return ENOSYS
}

func EpollCreate1(_ int) (int, error) {
	return -1, ENOSYS
}

func EpollCtl(_ int, _ int, _ int, _ *EpollEvent) error {
	return ENOSYS
}

func EpollWait(_ int, _ []EpollEvent, _ int) (int, error) {
	return 0, ENOSYS
}

func Getdents(fd int, buf []byte) (int, error) {
	return Getdirentries(fd, buf, nil)
}

func Ppoll(fds []PollFd, timeout *Timespec, _ *Sigset_t) (int, error) {
	timeoutMillis := -1
	if timeout != nil {
		timeoutMillis = int(timeout.Sec*1000 + timeout.Nsec/1_000_000)
	}
	return Poll(fds, timeoutMillis)
}

func Fdatasync(fd int) error {
	return Fsync(fd)
}

// fpunchhole mirrors struct fpunchhole from <sys/fcntl.h>.
type fpunchhole struct {
	Flags    uint32
	Reserved uint32
	Offset   int64
	Length   int64
}

// Fallocate extends a file or punches a hole, as far as Darwin allows.
// Mode 0 grows the file to off+length and never shrinks it.
// FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE uses fcntl(F_PUNCHHOLE), which APFS
// supports. The range must cover whole host pages, otherwise Fallocate reports
// ENOTSUP. File systems without support also report ENOTSUP.
func Fallocate(fd int, mode uint32, off int64, length int64) error {
	if off < 0 || length <= 0 {
		return EINVAL
	}
	switch mode {
	case 0:
		var st Stat_t
		if err := Fstat(fd, &st); err != nil {
			return err
		}
		if target := off + length; target > st.Size {
			return Ftruncate(fd, target)
		}
		return nil
	case FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE:
		// The page cache works on whole host pages, 16KB on Apple silicon. A hole
		// that covers only part of a host page also discards the unwritten data of
		// live 4KB neighbours in that page. Only whole host pages are safe, so any
		// other range reports ENOTSUP and the caller zeroes the range itself.
		hostPage := int64(Getpagesize())
		if off%hostPage != 0 || (off+length)%hostPage != 0 {
			return ENOTSUP
		}
		var st Stat_t
		if err := Fstat(fd, &st); err != nil {
			return err
		}
		if off >= st.Size {
			return nil
		}
		// F_PUNCHHOLE past the end of the file must not extend it.
		length = min(length, st.Size-off)
		// The pointer conversion stays inside the call expression. A pointer that
		// travels through the fcntl wrapper as an int could outlive a stack move.
		arg := fpunchhole{Offset: off, Length: length}
		if _, _, errno := syscall_syscall(libc_fcntl_trampoline_addr, uintptr(fd), F_PUNCHHOLE, uintptr(unsafe.Pointer(&arg))); errno != 0 {
			return errnoErr(errno)
		}
		return nil
	default:
		return ENOTSUP
	}
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
		return syscall_syscall6(libc_mmap_trampoline_addr, a1, a2, a3, a4, a5, a6)
	case SYS_MUNMAP:
		return syscall_syscall(libc_munmap_trampoline_addr, a1, a2, 0)
	case SYS_MPROTECT:
		return syscall_syscall(libc_mprotect_trampoline_addr, a1, a2, a3)
	case SYS_MADVISE:
		switch int(a3) {
		case MADV_POPULATE_READ, MADV_POPULATE_WRITE:
			// Callers read EINVAL as "prefaulting is unavailable".
			return 0, 0, EINVAL
		case MADV_HUGEPAGE, MADV_NOHUGEPAGE, MADV_DONTFORK, MADV_REMOVE:
			// These constants are Linux-only. Darwin has no transparent huge
			// page control, and the numbers collide with unrelated Darwin advice.
			return 0, 0, ENOTSUP
		}
		return syscall_syscall(libc_madvise_trampoline_addr, a1, a2, a3)
	case SYS_MLOCK:
		return syscall_syscall(libc_mlock_trampoline_addr, a1, a2, 0)
	case SYS_MUNLOCK:
		return syscall_syscall(libc_munlock_trampoline_addr, a1, a2, 0)
	case SYS_MINCORE:
		return 0, 0, darwinMincore(a1, a2, a3)
	case SYS_CLOSE:
		return syscall_syscall(libc_close_trampoline_addr, a1, 0, 0)
	case SYS_READ:
		return syscall_syscall(libc_read_trampoline_addr, a1, a2, a3)
	case SYS_WRITE:
		return syscall_syscall(libc_write_trampoline_addr, a1, a2, a3)
	case SYS_PREAD64:
		return syscall_syscall6(libc_pread_trampoline_addr, a1, a2, a3, a4, 0, 0)
	case SYS_PWRITE64:
		return syscall_syscall6(libc_pwrite_trampoline_addr, a1, a2, a3, a4, 0, 0)
	case SYS_LSEEK:
		return syscall_syscall(libc_lseek_trampoline_addr, a1, a2, a3)
	case SYS_FTRUNCATE:
		return syscall_syscall(libc_ftruncate_trampoline_addr, a1, a2, 0)
	case SYS_FSYNC, SYS_FDATASYNC:
		return syscall_syscall(libc_fsync_trampoline_addr, a1, 0, 0)
	case SYS_FCNTL:
		return syscall_syscall(libc_fcntl_trampoline_addr, a1, a2, a3)
	case SYS_IOCTL:
		return syscall_syscall(libc_ioctl_trampoline_addr, a1, a2, a3)
	case SYS_FLOCK:
		return syscall_syscall(libc_flock_trampoline_addr, a1, a2, 0)
	case SYS_DUP:
		return syscall_syscall(libc_dup_trampoline_addr, a1, 0, 0)
	case SYS_DUP2:
		return syscall_syscall(libc_dup2_trampoline_addr, a1, a2, 0)
	default:
		return 0, 0, ENOSYS
	}
}
