//go:build darwin

package unix_test

import (
	"bytes"
	"errors"
	"math"
	"os"
	"testing"
	"time"
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

func gvxTempFile(t *testing.T, size int64) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "gvx-overlay-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	if size > 0 {
		if err := f.Truncate(size); err != nil {
			t.Fatalf("Truncate: %v", err)
		}
	}
	return f
}

func gvxFileSize(t *testing.T, f *os.File) int64 {
	t.Helper()
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	return fi.Size()
}

func TestGvxFallocateExtendsButNeverShrinks(t *testing.T) {
	f := gvxTempFile(t, 0)
	fd := int(f.Fd())
	if err := unix.Fallocate(fd, 0, 4096, 4096); err != nil {
		t.Fatalf("Fallocate extend: %v", err)
	}
	if got := gvxFileSize(t, f); got != 8192 {
		t.Fatalf("size after extend = %d, want 8192", got)
	}
	if err := unix.Fallocate(fd, 0, 0, 4096); err != nil {
		t.Fatalf("Fallocate inside file: %v", err)
	}
	if got := gvxFileSize(t, f); got != 8192 {
		t.Fatalf("size after Fallocate of a lower range = %d, want 8192 (never shrinks)", got)
	}
	if err := unix.Fallocate(fd, unix.FALLOC_FL_KEEP_SIZE, 0, 4096); !errors.Is(err, unix.ENOTSUP) {
		t.Fatalf("Fallocate(FALLOC_FL_KEEP_SIZE) = %v, want ENOTSUP", err)
	}
	if err := unix.Fallocate(fd, 0, -1, 4096); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("Fallocate(negative offset) = %v, want EINVAL", err)
	}
}

func TestGvxFallocatePunchHoleZeroesMappedRange(t *testing.T) {
	const size = 64 * 1024
	f := gvxTempFile(t, size)
	fd := int(f.Fd())
	mapping, err := unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatalf("Mmap: %v", err)
	}
	defer unix.Munmap(mapping)
	for i := range mapping {
		mapping[i] = 0xAA
	}

	const mode = unix.FALLOC_FL_PUNCH_HOLE | unix.FALLOC_FL_KEEP_SIZE
	err = unix.Fallocate(fd, mode, 16384, 16384)
	if errors.Is(err, unix.ENOTSUP) {
		t.Skipf("temporary directory file system lacks F_PUNCHHOLE: %v", err)
	}
	if err != nil {
		t.Fatalf("Fallocate(PUNCH_HOLE): %v", err)
	}
	if got := gvxFileSize(t, f); got != size {
		t.Fatalf("size after punch = %d, want %d (KEEP_SIZE)", got, size)
	}
	for i, b := range mapping {
		want := byte(0xAA)
		if i >= 16384 && i < 32768 {
			want = 0
		}
		if b != want {
			t.Fatalf("mapping[%d] = %#x after punch, want %#x", i, b, want)
		}
	}

	// A range that splits a host page would discard live neighbours, so Fallocate refuses it.
	if hostPage := unix.Getpagesize(); hostPage > 4096 {
		if err := unix.Fallocate(fd, mode, 4096, 4096); !errors.Is(err, unix.ENOTSUP) {
			t.Fatalf("Fallocate(PUNCH_HOLE inside a host page) = %v, want ENOTSUP", err)
		}
	}

	// A range past the end of the file must not extend it.
	if err := unix.Fallocate(fd, mode, size, int64(unix.Getpagesize())); err != nil {
		t.Fatalf("Fallocate(PUNCH_HOLE past end): %v", err)
	}
	if got := gvxFileSize(t, f); got != size {
		t.Fatalf("size after punch past end = %d, want %d", got, size)
	}
}

func TestGvxMincoreReportsKernelResidency(t *testing.T) {
	hostPage := unix.Getpagesize()
	const linuxPage = unix.MincorePageSize
	mapping, err := unix.Mmap(-1, 0, 4*hostPage, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("Mmap: %v", err)
	}
	defer unix.Munmap(mapping)
	// Touch only the first host page.
	mapping[0] = 1

	vec := make([]byte, len(mapping)/linuxPage)
	_, _, errno := unix.Syscall(unix.SYS_MINCORE, uintptr(unsafe.Pointer(&mapping[0])), uintptr(len(mapping)), uintptr(unsafe.Pointer(&vec[0])))
	if errno != 0 {
		t.Fatalf("mincore: %v", errno)
	}
	perHost := hostPage / linuxPage
	for i := 0; i < perHost; i++ {
		if vec[i]&1 == 0 {
			t.Fatalf("vec[%d] = %#x, want resident for the touched host page", i, vec[i])
		}
	}
	// The kernel reports one answer per host page, so all entries of a host page must agree.
	for first := 0; first < len(vec); first += perHost {
		for i := first + 1; i < first+perHost; i++ {
			if vec[i] != vec[first] {
				t.Fatalf("vec[%d] = %#x but vec[%d] = %#x inside one host page, want equal", i, vec[i], first, vec[first])
			}
		}
	}

	// A page-aligned start inside a host page reports the enclosing host page.
	if hostPage > linuxPage {
		sub := make([]byte, 1)
		_, _, errno = unix.Syscall(unix.SYS_MINCORE, uintptr(unsafe.Pointer(&mapping[linuxPage])), linuxPage, uintptr(unsafe.Pointer(&sub[0])))
		if errno != 0 || sub[0]&1 == 0 {
			t.Fatalf("mincore(sub-host-page) = (%#x, %v), want resident", sub[0], errno)
		}
	}
	// Linux rejects an address that is not page-aligned.
	_, _, errno = unix.Syscall(unix.SYS_MINCORE, uintptr(unsafe.Pointer(&mapping[1])), linuxPage, uintptr(unsafe.Pointer(&vec[0])))
	if errno != unix.EINVAL {
		t.Fatalf("mincore(unaligned) = %v, want EINVAL", errno)
	}
}

func TestGvxMincoreDoesNotReportUnmappedRangeResident(t *testing.T) {
	hostPage := unix.Getpagesize()
	mapping, err := unix.Mmap(-1, 0, hostPage, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("Mmap: %v", err)
	}
	addr := uintptr(unsafe.Pointer(&mapping[0]))
	if err := unix.Munmap(mapping); err != nil {
		t.Fatalf("Munmap: %v", err)
	}
	vec := make([]byte, max(hostPage/unix.MincorePageSize, 1))
	_, _, errno := unix.Syscall(unix.SYS_MINCORE, addr, uintptr(hostPage), uintptr(unsafe.Pointer(&vec[0])))
	// Darwin reports an unmapped range as non-resident, while Linux fails with
	// ENOMEM. Either answer is honest. Reporting residency would be wrong.
	if errno != 0 && errno != unix.ENOMEM {
		t.Fatalf("mincore(unmapped) = %v, want success or ENOMEM", errno)
	}
	if errno == 0 {
		for i, b := range vec {
			if b&1 != 0 {
				t.Fatalf("vec[%d] = %#x for an unmapped page, want non-resident", i, b)
			}
		}
	}
}

// A caller sizes the result vector with one byte per MincorePageSize page. An
// entry written past that length corrupts the heap object behind the vector.
func TestGvxMincoreWritesExactlyOneEntryPerPage(t *testing.T) {
	hostPage := unix.Getpagesize()
	const pages = 8
	size := pages * max(hostPage, unix.MincorePageSize)
	mapping, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("Mmap: %v", err)
	}
	defer unix.Munmap(mapping)
	for i := 0; i < len(mapping); i += hostPage {
		mapping[i] = 1
	}

	entries := size / unix.MincorePageSize
	const guard = 4096
	const poison = 0xEE
	vec := make([]byte, entries+guard)
	for i := range vec {
		vec[i] = poison
	}
	_, _, errno := unix.Syscall(unix.SYS_MINCORE, uintptr(unsafe.Pointer(&mapping[0])), uintptr(size), uintptr(unsafe.Pointer(&vec[0])))
	if errno != 0 {
		t.Fatalf("mincore: %v", errno)
	}
	for i := range entries {
		if vec[i]&1 == 0 {
			t.Errorf("vec[%d] = %#x for a touched page, want resident", i, vec[i])
		}
	}
	for i := entries; i < len(vec); i++ {
		if vec[i] != poison {
			t.Fatalf("vec[%d] = %#x beyond the %d entries of the caller vector, want the untouched %#x", i, vec[i], entries, poison)
		}
	}
}

func TestGvxMadviseRejectsLinuxOnlyAdvice(t *testing.T) {
	hostPage := unix.Getpagesize()
	mapping, err := unix.Mmap(-1, 0, hostPage, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("Mmap: %v", err)
	}
	defer unix.Munmap(mapping)
	addr := uintptr(unsafe.Pointer(&mapping[0]))
	for _, advice := range []int{unix.MADV_HUGEPAGE, unix.MADV_NOHUGEPAGE, unix.MADV_DONTFORK, unix.MADV_REMOVE} {
		if _, _, errno := unix.Syscall(unix.SYS_MADVISE, addr, uintptr(hostPage), uintptr(advice)); errno != unix.ENOTSUP {
			t.Errorf("madvise(advice=%d) = %v, want ENOTSUP", advice, errno)
		}
	}
	for _, advice := range []int{unix.MADV_POPULATE_READ, unix.MADV_POPULATE_WRITE} {
		if _, _, errno := unix.Syscall(unix.SYS_MADVISE, addr, uintptr(hostPage), uintptr(advice)); errno != unix.EINVAL {
			t.Errorf("madvise(advice=%d) = %v, want EINVAL", advice, errno)
		}
	}
	if _, _, errno := unix.Syscall(unix.SYS_MADVISE, addr, uintptr(hostPage), uintptr(unix.MADV_FREE)); errno != 0 {
		t.Errorf("madvise(MADV_FREE) = %v, want success", errno)
	}
}

func newPipeWithToken(t *testing.T, token []byte) int {
	t.Helper()
	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	if _, err := unix.Write(fds[1], token); err != nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
		t.Fatalf("Write(pipe): %v", err)
	}
	_ = unix.Close(fds[1])
	t.Cleanup(func() {
		_ = unix.Close(fds[0])
	})
	return fds[0]
}

func assertPassedPipeReadable(t *testing.T, oob []byte, wantToken []byte) {
	t.Helper()
	cmsgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		t.Fatalf("ParseSocketControlMessage(%d bytes): %v", len(oob), err)
	}
	if len(cmsgs) != 1 {
		t.Fatalf("len(cmsgs) = %d, want 1", len(cmsgs))
	}
	passedFDs, err := unix.ParseUnixRights(&cmsgs[0])
	if err != nil {
		t.Fatalf("ParseUnixRights: %v", err)
	}
	if len(passedFDs) != 1 {
		t.Fatalf("len(passedFDs) = %d, want 1", len(passedFDs))
	}
	defer unix.Close(passedFDs[0])

	got := make([]byte, len(wantToken)+8)
	n, err := unix.Read(passedFDs[0], got)
	if err != nil {
		t.Fatalf("Read(passed fd): %v", err)
	}
	if !bytes.Equal(got[:n], wantToken) {
		t.Fatalf("passed fd bytes = %q, want %q", got[:n], wantToken)
	}
}

func TestGvxMsghdrSCMRightsAndControlTruncation(t *testing.T) {
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	defer unix.Close(sp[0])
	defer unix.Close(sp[1])

	// 1. SendmsgN + Recvmsg with full control buffer.
	token1 := []byte("scm-rights-wrapper")
	rfd1 := newPipeWithToken(t, token1)
	rights1 := unix.UnixRights(rfd1)
	payload1 := []byte("hello-xnu")
	sent, err := unix.SendmsgN(sp[0], payload1, rights1, nil, 0)
	if err != nil || sent != len(payload1) {
		t.Fatalf("SendmsgN = (%d, %v), want (%d, nil)", sent, err, len(payload1))
	}

	rxBuf := make([]byte, 64)
	rxOOB := make([]byte, unix.CmsgSpace(4))
	n, oobn, recvflags, _, err := unix.Recvmsg(sp[1], rxBuf, rxOOB, 0)
	if err != nil {
		t.Fatalf("Recvmsg: %v", err)
	}
	if !bytes.Equal(rxBuf[:n], payload1) {
		t.Fatalf("Recvmsg payload = %q, want %q", rxBuf[:n], payload1)
	}
	if recvflags != 0 {
		t.Fatalf("Recvmsg flags = %#x, want 0", recvflags)
	}
	assertPassedPipeReadable(t, rxOOB[:oobn], token1)

	// 2. Syscall6(SYS_SENDMSG) + Syscall6(SYS_RECVMSG) with full control buffer.
	token2 := []byte("scm-rights-syscall6")
	rfd2 := newPipeWithToken(t, token2)
	rights2 := unix.UnixRights(rfd2)
	payload2 := []byte("raw-msghdr")
	txIov := unix.Iovec{Base: &payload2[0]}
	txIov.SetLen(len(payload2))
	txMsg := unix.Msghdr{
		Iov:        &txIov,
		Iovlen:     1,
		Control:    &rights2[0],
		Controllen: uint64(len(rights2)),
	}
	r1, _, errno := unix.Syscall6(unix.SYS_SENDMSG, uintptr(sp[0]), uintptr(unsafe.Pointer(&txMsg)), unix.MSG_NOSIGNAL, 0, 0, 0)
	if errno != 0 || int(r1) != len(payload2) {
		t.Fatalf("Syscall6(SYS_SENDMSG) = (%d, %v), want (%d, 0)", int(r1), errno, len(payload2))
	}

	clear(rxBuf)
	clear(rxOOB)
	rxIov := unix.Iovec{Base: &rxBuf[0]}
	rxIov.SetLen(len(rxBuf))
	rxMsg := unix.Msghdr{
		Iov:        &rxIov,
		Iovlen:     1,
		Control:    &rxOOB[0],
		Controllen: uint64(len(rxOOB)),
		Flags:      -1,
	}
	r1, _, errno = unix.Syscall6(unix.SYS_RECVMSG, uintptr(sp[1]), uintptr(unsafe.Pointer(&rxMsg)), 0, 0, 0, 0)
	if errno != 0 || int(r1) != len(payload2) {
		t.Fatalf("Syscall6(SYS_RECVMSG) = (%d, %v), want (%d, 0)", int(r1), errno, len(payload2))
	}
	if rxMsg.Flags != 0 {
		t.Fatalf("rxMsg.Flags = %#x, want 0", rxMsg.Flags)
	}
	if rxMsg.Controllen == 0 || rxMsg.Controllen > uint64(len(rxOOB)) {
		t.Fatalf("rxMsg.Controllen = %#x, want within [1, %d]", rxMsg.Controllen, len(rxOOB))
	}
	assertPassedPipeReadable(t, rxOOB[:rxMsg.Controllen], token2)

	// 3. Receive SCM_RIGHTS into a 4-byte control buffer via Recvmsg and SYS_RECVMSG.
	// XNU sets MSG_CTRUNC in msg_flags and keeps Controllen within the 4-byte buffer.
	for _, viaSyscall := range []bool{false, true} {
		rfdTiny := newPipeWithToken(t, []byte("tiny"))
		rightsTiny := unix.UnixRights(rfdTiny)
		if _, err := unix.SendmsgN(sp[0], payload1, rightsTiny, nil, 0); err != nil {
			t.Fatalf("SendmsgN(tiny, viaSyscall=%v): %v", viaSyscall, err)
		}
		var tinyOOB [4]byte
		if !viaSyscall {
			n, oobn, recvflags, _, err := unix.Recvmsg(sp[1], rxBuf, tinyOOB[:], 0)
			if err != nil {
				t.Fatalf("Recvmsg(tiny): %v", err)
			}
			if n != len(payload1) {
				t.Fatalf("Recvmsg(tiny) n = %d, want %d", n, len(payload1))
			}
			if recvflags&unix.MSG_CTRUNC == 0 {
				t.Fatalf("Recvmsg(tiny) flags = %#x, want MSG_CTRUNC (%#x) set", recvflags, unix.MSG_CTRUNC)
			}
			if oobn < 0 || oobn > len(tinyOOB) {
				t.Fatalf("Recvmsg(tiny) oobn = %#x, want <= %d", oobn, len(tinyOOB))
			}
		} else {
			tinyMsg := unix.Msghdr{
				Iov:        &rxIov,
				Iovlen:     1,
				Control:    &tinyOOB[0],
				Controllen: uint64(len(tinyOOB)),
			}
			r1, _, errno := unix.Syscall6(unix.SYS_RECVMSG, uintptr(sp[1]), uintptr(unsafe.Pointer(&tinyMsg)), 0, 0, 0, 0)
			if errno != 0 || int(r1) != len(payload1) {
				t.Fatalf("SYS_RECVMSG(tiny) = (%d, %v), want (%d, 0)", int(r1), errno, len(payload1))
			}
			if tinyMsg.Flags&unix.MSG_CTRUNC == 0 {
				t.Fatalf("SYS_RECVMSG(tiny) Flags = %#x, want MSG_CTRUNC (%#x) set", tinyMsg.Flags, unix.MSG_CTRUNC)
			}
			if tinyMsg.Controllen > uint64(len(tinyOOB)) {
				t.Fatalf("SYS_RECVMSG(tiny) Controllen = %#x, want <= %d", tinyMsg.Controllen, len(tinyOOB))
			}
		}
	}

	// 4. Reject nil Msghdr and overflowing lengths with EINVAL.
	if _, _, errno := unix.Syscall6(unix.SYS_RECVMSG, uintptr(sp[1]), 0, 0, 0, 0, 0); errno != unix.EINVAL {
		t.Fatalf("SYS_RECVMSG(nil) = %v, want EINVAL", errno)
	}
	if _, _, errno := unix.Syscall6(unix.SYS_SENDMSG, uintptr(sp[0]), 0, 0, 0, 0, 0); errno != unix.EINVAL {
		t.Fatalf("SYS_SENDMSG(nil) = %v, want EINVAL", errno)
	}
	overflowIov := unix.Msghdr{Iovlen: math.MaxInt32 + 1}
	if _, _, errno := unix.Syscall6(unix.SYS_SENDMSG, uintptr(sp[0]), uintptr(unsafe.Pointer(&overflowIov)), 0, 0, 0, 0); errno != unix.EINVAL {
		t.Fatalf("SYS_SENDMSG(Iovlen overflow) = %v, want EINVAL", errno)
	}
	overflowCtrl := unix.Msghdr{Controllen: math.MaxUint32 + 1}
	if _, _, errno := unix.Syscall6(unix.SYS_RECVMSG, uintptr(sp[1]), uintptr(unsafe.Pointer(&overflowCtrl)), 0, 0, 0, 0); errno != unix.EINVAL {
		t.Fatalf("SYS_RECVMSG(Controllen overflow) = %v, want EINVAL", errno)
	}
}

func TestGvxSyscallPpollVsPollAndReadvWritev(t *testing.T) {
	if unix.SYS_PPOLL == unix.SYS_POLL {
		t.Fatalf("SYS_PPOLL (%d) must differ from SYS_POLL (%d)", unix.SYS_PPOLL, unix.SYS_POLL)
	}

	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	// SYS_POLL with timeout 0 returns 0 immediately on an empty pipe.
	pfd := unix.PollFd{Fd: int32(fds[0]), Events: unix.POLLIN}
	r1, _, errno := unix.Syscall(unix.SYS_POLL, uintptr(unsafe.Pointer(&pfd)), 1, 0)
	if errno != 0 || r1 != 0 {
		t.Fatalf("SYS_POLL(timeout=0) = (%d, %v), want (0, 0)", r1, errno)
	}

	// SYS_PPOLL with tsPtr == 0 translates to infinite wait (-1), blocking until a write arrives.
	type pollResult struct {
		n       uintptr
		revents int16
		errno   unix.Errno
	}
	resCh := make(chan pollResult, 1)
	go func() {
		ev := unix.PollFd{Fd: int32(fds[0]), Events: unix.POLLIN}
		n, _, e := unix.Syscall6(unix.SYS_PPOLL, uintptr(unsafe.Pointer(&ev)), 1, 0, 0, 0, 0)
		resCh <- pollResult{n: n, revents: ev.Revents, errno: e}
	}()
	time.AfterFunc(30*time.Millisecond, func() {
		_, _ = unix.Write(fds[1], []byte("w"))
	})
	select {
	case res := <-resCh:
		if res.errno != 0 || res.n != 1 || res.revents&unix.POLLIN == 0 {
			t.Fatalf("SYS_PPOLL(ts=nil) = (n=%d, revents=%#x, errno=%v), want (1, POLLIN, 0)", res.n, res.revents, res.errno)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SYS_PPOLL(ts=nil) did not wake after pipe write")
	}
	var drain [1]byte
	if _, err := unix.Read(fds[0], drain[:]); err != nil {
		t.Fatalf("drain pipe: %v", err)
	}

	// SYS_PPOLL with a zero Timespec returns 0 without blocking.
	zeroTS := unix.Timespec{}
	pfd = unix.PollFd{Fd: int32(fds[0]), Events: unix.POLLIN}
	r1, _, errno = unix.Syscall6(unix.SYS_PPOLL, uintptr(unsafe.Pointer(&pfd)), 1, uintptr(unsafe.Pointer(&zeroTS)), 0, 0, 0)
	if errno != 0 || r1 != 0 {
		t.Fatalf("SYS_PPOLL(ts=0) = (%d, %v), want (0, 0)", r1, errno)
	}

	// SYS_WRITEV + SYS_READV scatter/gather round-trip over the real pipe.
	seg0 := []byte("scatter-")
	seg1 := []byte("gather-")
	seg2 := []byte("xnu")
	txIovs := [3]unix.Iovec{
		{Base: &seg0[0]},
		{Base: &seg1[0]},
		{Base: &seg2[0]},
	}
	txIovs[0].SetLen(len(seg0))
	txIovs[1].SetLen(len(seg1))
	txIovs[2].SetLen(len(seg2))
	wantTotal := len(seg0) + len(seg1) + len(seg2)

	nw, _, errno := unix.Syscall(unix.SYS_WRITEV, uintptr(fds[1]), uintptr(unsafe.Pointer(&txIovs[0])), uintptr(len(txIovs)))
	if errno != 0 || int(nw) != wantTotal {
		t.Fatalf("SYS_WRITEV = (%d, %v), want (%d, 0)", int(nw), errno, wantTotal)
	}

	out0 := make([]byte, 5)
	out1 := make([]byte, 7)
	out2 := make([]byte, wantTotal-12)
	rxIovs := [3]unix.Iovec{
		{Base: &out0[0]},
		{Base: &out1[0]},
		{Base: &out2[0]},
	}
	rxIovs[0].SetLen(len(out0))
	rxIovs[1].SetLen(len(out1))
	rxIovs[2].SetLen(len(out2))

	nr, _, errno := unix.Syscall(unix.SYS_READV, uintptr(fds[0]), uintptr(unsafe.Pointer(&rxIovs[0])), uintptr(len(rxIovs)))
	if errno != 0 || int(nr) != wantTotal {
		t.Fatalf("SYS_READV = (%d, %v), want (%d, 0)", int(nr), errno, wantTotal)
	}
	gotJoined := bytes.Join([][]byte{out0, out1, out2}, nil)
	if want := "scatter-gather-xnu"; string(gotJoined) != want {
		t.Fatalf("SYS_READV joined = %q, want %q", gotJoined, want)
	}
}

func TestGvxPreadv2AndPwritev2Syscalls(t *testing.T) {
	f := gvxTempFile(t, 4096)
	fd := uintptr(f.Fd())

	seg0 := []byte("alpha-")
	seg1 := []byte("bravo-")
	seg2 := []byte("charlie")
	txIovs := [3]unix.Iovec{
		{Base: &seg0[0]},
		{Base: &seg1[0]},
		{Base: &seg2[0]},
	}
	txIovs[0].SetLen(len(seg0))
	txIovs[1].SetLen(len(seg1))
	txIovs[2].SetLen(len(seg2))
	wantTotal := len(seg0) + len(seg1) + len(seg2)

	nw, _, errno := unix.Syscall6(unix.SYS_PWRITEV2, fd, uintptr(unsafe.Pointer(&txIovs[0])), uintptr(len(txIovs)), 512, 0, 0)
	if errno != 0 || int(nw) != wantTotal {
		t.Fatalf("SYS_PWRITEV2 = (%d, %v), want (%d, 0)", int(nw), errno, wantTotal)
	}

	if _, _, errno := unix.Syscall6(unix.SYS_PWRITEV2, fd, uintptr(unsafe.Pointer(&txIovs[0])), uintptr(len(txIovs)), 512, 0, 1); errno != unix.ENOTSUP {
		t.Fatalf("SYS_PWRITEV2(flags=1) = %v, want ENOTSUP", errno)
	}

	out0 := make([]byte, 4)
	out1 := make([]byte, 8)
	out2 := make([]byte, wantTotal-12)
	rxIovs := [3]unix.Iovec{
		{Base: &out0[0]},
		{Base: &out1[0]},
		{Base: &out2[0]},
	}
	rxIovs[0].SetLen(len(out0))
	rxIovs[1].SetLen(len(out1))
	rxIovs[2].SetLen(len(out2))

	nr, _, errno := unix.Syscall6(unix.SYS_PREADV2, fd, uintptr(unsafe.Pointer(&rxIovs[0])), uintptr(len(rxIovs)), 512, 0, 0)
	if errno != 0 || int(nr) != wantTotal {
		t.Fatalf("SYS_PREADV2 = (%d, %v), want (%d, 0)", int(nr), errno, wantTotal)
	}
	if got, want := string(bytes.Join([][]byte{out0, out1, out2}, nil)), "alpha-bravo-charlie"; got != want {
		t.Fatalf("SYS_PREADV2 joined = %q, want %q", got, want)
	}
}
