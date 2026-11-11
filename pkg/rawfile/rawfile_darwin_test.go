//go:build darwin

package rawfile_test

import (
	"bytes"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/rawfile"
)

func newNonBlockingPipe(t *testing.T) (int, int) {
	t.Helper()
	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	})
	for _, fd := range fds {
		if err := unix.SetNonblock(fd, true); err != nil {
			t.Fatalf("SetNonblock(%d): %v", fd, err)
		}
	}
	return fds[0], fds[1]
}

func TestRawfileDarwinEmptySlicesDoNotPanic(t *testing.T) {
	iov := rawfile.IovecFromBytes(nil)
	if iov.Base != nil || iov.Len != 0 {
		t.Fatalf("IovecFromBytes(nil) = %+v, want zero Iovec", iov)
	}
	if got := rawfile.AppendIovecFromBytes(nil, nil, 4); len(got) != 0 {
		t.Fatalf("AppendIovecFromBytes(nil, nil, 4) len = %d, want 0", len(got))
	}

	r, w := newNonBlockingPipe(t)
	stopR, _ := newNonBlockingPipe(t)

	if errno := rawfile.NonBlockingWrite(w, nil); errno != 0 {
		t.Fatalf("NonBlockingWrite(w, nil) = %v, want 0", errno)
	}
	if errno := rawfile.NonBlockingWriteIovec(w, nil); errno != 0 {
		t.Fatalf("NonBlockingWriteIovec(w, nil) = %v, want 0", errno)
	}
	if n, errno := rawfile.BlockingRead(r, nil); n != 0 || errno != 0 {
		t.Fatalf("BlockingRead(r, nil) = (%d, %v), want (0, 0)", n, errno)
	}
	if n, errno := rawfile.BlockingReadvUntilStopped(stopR, r, nil); n != 0 || errno != 0 {
		t.Fatalf("BlockingReadvUntilStopped(stopR, r, nil) = (%d, %v), want (0, 0)", n, errno)
	}

	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	defer unix.Close(sp[0])
	defer unix.Close(sp[1])

	if sent, errno := rawfile.NonBlockingSendMMsg(sp[0], nil); sent != 0 || errno != 0 {
		t.Fatalf("NonBlockingSendMMsg(sp[0], nil) = (%d, %v), want (0, 0)", sent, errno)
	}
	if got, errno := rawfile.BlockingRecvMMsgUntilStopped(stopR, sp[1], nil); got != 0 || errno != 0 {
		t.Fatalf("BlockingRecvMMsgUntilStopped(stopR, sp[1], nil) = (%d, %v), want (0, 0)", got, errno)
	}
}

func TestRawfileDarwinBlockingReadErrorAndWakeup(t *testing.T) {
	var buf [16]byte
	done := make(chan struct{})
	var gotN int
	var gotErrno unix.Errno
	go func() {
		gotN, gotErrno = rawfile.BlockingRead(-1, buf[:])
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("BlockingRead(-1) blocked in poll instead of returning EBADF")
	}
	if gotN != -1 || gotErrno != unix.EBADF {
		t.Fatalf("BlockingRead(-1) = (%d, %v), want (-1, EBADF)", gotN, gotErrno)
	}

	r, w := newNonBlockingPipe(t)
	want := []byte("darwin-pipe")
	readDone := make(chan struct{})
	go func() {
		gotN, gotErrno = rawfile.BlockingRead(r, buf[:])
		close(readDone)
	}()
	time.AfterFunc(25*time.Millisecond, func() {
		_, _ = unix.Write(w, want)
	})
	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("BlockingRead timed out waiting for pipe writer")
	}
	if gotErrno != 0 || gotN != len(want) {
		t.Fatalf("BlockingRead = (%d, %v), want (%d, 0)", gotN, gotErrno, len(want))
	}
	if !bytes.Equal(buf[:gotN], want) {
		t.Fatalf("BlockingRead bytes = %q, want %q", buf[:gotN], want)
	}
}

func TestRawfileDarwinSendAndRecvMMsg(t *testing.T) {
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	defer unix.Close(sp[0])
	defer unix.Close(sp[1])
	for _, fd := range sp {
		if err := unix.SetNonblock(fd, true); err != nil {
			t.Fatalf("SetNonblock(%d): %v", fd, err)
		}
	}

	stopR, stopW := newNonBlockingPipe(t)

	p0 := []byte("alpha")
	p1 := []byte("bravo-charlie")
	iov0 := rawfile.IovecFromBytes(p0)
	iov1 := rawfile.IovecFromBytes(p1)
	sendHdrs := []rawfile.MMsgHdr{
		{Msg: unix.Msghdr{Iov: &iov0, Iovlen: 1}},
		{Msg: unix.Msghdr{Iov: &iov1, Iovlen: 1}},
	}
	sent, errno := rawfile.NonBlockingSendMMsg(sp[0], sendHdrs)
	if errno != 0 || sent != 2 {
		t.Fatalf("NonBlockingSendMMsg = (%d, %v), want (2, 0)", sent, errno)
	}
	if sendHdrs[0].Len != uint32(len(p0)) || sendHdrs[1].Len != uint32(len(p1)) {
		t.Fatalf("send lengths = (%d, %d), want (%d, %d)", sendHdrs[0].Len, sendHdrs[1].Len, len(p0), len(p1))
	}

	for idx, want := range [][]byte{p0, p1} {
		rxBuf := make([]byte, 64)
		rxIov := rawfile.IovecFromBytes(rxBuf)
		recvHdrs := []rawfile.MMsgHdr{{Msg: unix.Msghdr{Iov: &rxIov, Iovlen: 1}}}
		nMsgs, errno := rawfile.BlockingRecvMMsgUntilStopped(stopR, sp[1], recvHdrs)
		if errno != 0 || nMsgs != 1 {
			t.Fatalf("msg[%d] BlockingRecvMMsgUntilStopped = (%d, %v), want (1, 0)", idx, nMsgs, errno)
		}
		got := rxBuf[:recvHdrs[0].Len]
		if !bytes.Equal(got, want) {
			t.Fatalf("msg[%d] payload = %q, want %q", idx, got, want)
		}
	}

	// Verify stop notification unblocks BlockingRecvMMsgUntilStopped with -1.
	rxBuf := make([]byte, 64)
	rxIov := rawfile.IovecFromBytes(rxBuf)
	recvHdrs := []rawfile.MMsgHdr{{Msg: unix.Msghdr{Iov: &rxIov, Iovlen: 1}}}
	type recvResult struct {
		n     int
		errno unix.Errno
	}
	resCh := make(chan recvResult, 1)
	go func() {
		n, e := rawfile.BlockingRecvMMsgUntilStopped(stopR, sp[1], recvHdrs)
		resCh <- recvResult{n: n, errno: e}
	}()
	time.AfterFunc(25*time.Millisecond, func() {
		_, _ = unix.Write(stopW, []byte{1})
	})
	select {
	case res := <-resCh:
		if res.n != -1 || res.errno != 0 {
			t.Fatalf("stopped BlockingRecvMMsgUntilStopped = (%d, %v), want (-1, 0)", res.n, res.errno)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("BlockingRecvMMsgUntilStopped did not unblock on stop pipe")
	}
}
