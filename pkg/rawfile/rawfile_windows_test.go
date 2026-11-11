//go:build windows

package rawfile

import (
	"fmt"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/internal/xsys/unix"
)

func TestRawfileWindowsEmptyIovecDoesNotPanic(t *testing.T) {
	iov := IovecFromBytes(nil)
	if iov.Base != nil || iov.Len != 0 {
		t.Fatalf("IovecFromBytes(nil) = %+v, want zero Iovec", iov)
	}
	if got := bytesFromIovec(iov); got != nil {
		t.Fatalf("bytesFromIovec(zero) = %v, want nil", got)
	}
}

func TestTranslateErrorUnwrapsWindowsErrno(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want unix.Errno
	}{
		{name: "nil", err: nil, want: 0},
		{name: "broken_pipe", err: syscall.Errno(windows.ERROR_BROKEN_PIPE), want: unix.EPIPE},
		{name: "no_data_patherror", err: &os.PathError{Op: "write", Path: "pipe", Err: windows.ERROR_NO_DATA}, want: unix.EPIPE},
		{name: "invalid_handle", err: &os.PathError{Op: "read", Path: "fd", Err: windows.ERROR_INVALID_HANDLE}, want: unix.EBADF},
		{name: "wsae_wouldblock", err: fmt.Errorf("socket: %w", windows.WSAEWOULDBLOCK), want: unix.EAGAIN},
		{name: "wsae_intr", err: windows.WSAEINTR, want: unix.EINTR},
		{name: "access_denied", err: windows.ERROR_ACCESS_DENIED, want: unix.EACCES},
		{name: "os_closed", err: os.ErrClosed, want: unix.EBADF},
		{name: "unknown_errno", err: syscall.Errno(999999), want: unix.EIO},
	}
	for _, tc := range cases {
		if got := translateError(tc.err); got != tc.want {
			t.Errorf("%s: translateError(%v) = %v (%d), want %v (%d)", tc.name, tc.err, got, got, tc.want, tc.want)
		}
	}
}
