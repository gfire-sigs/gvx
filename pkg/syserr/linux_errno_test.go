// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package syserr

import (
	"bytes"
	"testing"
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/abi/linux/errno"
	"z.gfire.dev/gvx/pkg/errors"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/safecopy"
)

// linuxErrorFor returns the linuxerr error for a Linux errno, or nil when the
// linuxerr package defines none.
func linuxErrorFor(n int) (e *errors.Error) {
	defer func() {
		if recover() != nil {
			e = nil
		}
	}()
	err := linuxerr.ErrorFromUnix(unix.Errno(n))
	if err == nil {
		return nil
	}
	return err.(*errors.Error)
}

// TestFromErrorKeepsTheLinuxErrno checks that a linuxerr error keeps its Linux
// number on every host. The number is the one that the guest sees, so it must
// not pass through the errno table of the host.
func TestFromErrorKeepsTheLinuxErrno(t *testing.T) {
	checked := 0
	for n := 1; n < 134; n++ {
		e := linuxErrorFor(n)
		if e == nil {
			continue
		}
		checked++
		got := FromError(e).ToLinux()
		if got != errno.Errno(n) {
			t.Errorf("FromError(%v).ToLinux() = %d, want %d", e, got, n)
		}
	}
	if checked < 100 {
		t.Fatalf("checked only %d linuxerr errors", checked)
	}
}

// TestFromErrorNamesTheCommonErrors pins the errors that differ most between
// Linux and macOS numbering. FromHost on macOS panics for the first and returns
// ENOTSOCK for the second.
func TestFromErrorNamesTheCommonErrors(t *testing.T) {
	for _, c := range []struct {
		name string
		err  *errors.Error
		want errno.Errno
	}{
		{"EAGAIN", linuxerr.EAGAIN, errno.EAGAIN},
		{"ENOSYS", linuxerr.ENOSYS, errno.ENOSYS},
		{"ECONNREFUSED", linuxerr.ECONNREFUSED, errno.ECONNREFUSED},
		{"EADDRINUSE", linuxerr.EADDRINUSE, errno.EADDRINUSE},
		{"ETIMEDOUT", linuxerr.ETIMEDOUT, errno.ETIMEDOUT},
	} {
		if got := FromError(c.err).ToLinux(); got != c.want {
			t.Errorf("%s: ToLinux() = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestFromErrorKeepsAnErrnoThatHasNoHostName(t *testing.T) {
	// No syserr value owns errno 133 (EHWPOISON) on every host, so the lookup
	// falls back to a dynamic error that still carries the number.
	got := fromLinuxErrno(errno.Errno(maxLinuxABI - 1))
	if got.ToLinux() != errno.Errno(maxLinuxABI-1) {
		t.Fatalf("fromLinuxErrno(%d).ToLinux() = %d", maxLinuxABI-1, got.ToLinux())
	}
}

func TestFromHostSocketErrors(t *testing.T) {
	cases := []struct {
		host unix.Errno
		want errno.Errno
	}{
		{unix.EWOULDBLOCK, errno.EAGAIN},
		{unix.EINPROGRESS, errno.EINPROGRESS},
		{unix.EALREADY, errno.EALREADY},
		{unix.ENOTSOCK, errno.ENOTSOCK},
		{unix.EDESTADDRREQ, errno.EDESTADDRREQ},
		{unix.EMSGSIZE, errno.EMSGSIZE},
		{unix.EPROTOTYPE, errno.EPROTOTYPE},
		{unix.ENOPROTOOPT, errno.ENOPROTOOPT},
		{unix.EPROTONOSUPPORT, errno.EPROTONOSUPPORT},
		{unix.ESOCKTNOSUPPORT, errno.ESOCKTNOSUPPORT},
		{unix.EOPNOTSUPP, errno.EOPNOTSUPP},
		{unix.EPFNOSUPPORT, errno.EPFNOSUPPORT},
		{unix.EAFNOSUPPORT, errno.EAFNOSUPPORT},
		{unix.EADDRINUSE, errno.EADDRINUSE},
		{unix.EADDRNOTAVAIL, errno.EADDRNOTAVAIL},
		{unix.ENETDOWN, errno.ENETDOWN},
		{unix.ENETUNREACH, errno.ENETUNREACH},
		{unix.ENETRESET, errno.ENETRESET},
		{unix.ECONNABORTED, errno.ECONNABORTED},
		{unix.ECONNRESET, errno.ECONNRESET},
		{unix.ENOBUFS, errno.ENOBUFS},
		{unix.EISCONN, errno.EISCONN},
		{unix.ENOTCONN, errno.ENOTCONN},
		{unix.ESHUTDOWN, errno.ESHUTDOWN},
		{unix.ETOOMANYREFS, errno.ETOOMANYREFS},
		{unix.ETIMEDOUT, errno.ETIMEDOUT},
		{unix.ECONNREFUSED, errno.ECONNREFUSED},
		{unix.EHOSTDOWN, errno.EHOSTDOWN},
		{unix.EHOSTUNREACH, errno.EHOSTUNREACH},
		{unix.EDQUOT, errno.EDQUOT},
		{unix.ESTALE, errno.ESTALE},
	}
	for _, tc := range cases {
		err := FromHost(tc.host)
		if err == nil {
			t.Fatalf("FromHost(%v) = nil", tc.host)
		}
		if got := err.ToLinux(); got != tc.want {
			t.Errorf("FromHost(%v).ToLinux() = %v (%d), want %v (%d)", tc.host, got, got, tc.want, tc.want)
		}
		if got := FromError(tc.host).ToLinux(); got != tc.want {
			t.Errorf("FromError(%v).ToLinux() = %v (%d), want %v (%d)", tc.host, got, got, tc.want, tc.want)
		}
	}
}

// TestToErrorRoundTripsEveryLinuxErrno verifies that FromError maps every
// Error.ToError result back to its Linux errno on every host. Linux-only values
// such as EBADFD (77) and ENOKEY (126) lack Darwin and Windows host entries.
// Package initialization registers every Linux errno in [1, maxLinuxABI).
func TestToErrorRoundTripsEveryLinuxErrno(t *testing.T) {
	for n := errno.Errno(1); n < maxLinuxABI; n++ {
		if !linuxBackwardsTranslations[n].ok {
			t.Fatalf("linuxBackwardsTranslations[%d] is unregistered", n)
		}
		e := NewDynamic("test", n)
		got := func() (got *Error) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("FromError((errno %d).ToError()) panicked: %v", n, r)
				}
			}()
			return FromError(e.ToError())
		}()
		if got == nil {
			t.Errorf("FromError((errno %d).ToError()) = nil", n)
			continue
		}
		if got.ToLinux() != n {
			t.Errorf("round trip of errno %d gave %d", n, got.ToLinux())
		}
		if le := linuxErrorFor(int(n)); le != nil {
			fromLE := FromError(le)
			if fromLE == nil || fromLE.ToLinux() != n {
				t.Errorf("FromError(linuxerr %d) = %v, want %d", n, fromLE, n)
			}
			if rt := FromError(fromLE.ToError()); rt == nil || rt.ToLinux() != n {
				t.Errorf("FromError(FromError(linuxerr %d).ToError()) = %v, want %d", n, rt, n)
			}
		}
	}
}

func TestToErrorOfNotConnectedRoundTrips(t *testing.T) {
	// ENOTCONN is 107 on Linux and 57 on macOS. The macOS host table has no 107.
	if got := FromError(ErrNotConnected.ToError()); got.ToLinux() != errno.ENOTCONN {
		t.Fatalf("round trip gave %d, want %d", got.ToLinux(), errno.ENOTCONN)
	}
}

// TestInterruptedErrorConvertsToRestart checks that a blocking socket call that
// an interrupt ends still gets the restart error. The socket calls translate the
// result of Error.ToError with linuxerr.ConvertIntr. A missed translation shows
// the guest EINTR, also when the guest signal handler has SA_RESTART or when no
// signal arrived. Linux returns EINTR to the guest only for a handler without
// SA_RESTART.
func TestInterruptedErrorConvertsToRestart(t *testing.T) {
	for name, in := range map[string]error{
		"ErrInterrupted": linuxerr.ErrInterrupted,
		"EINTR":          linuxerr.EINTR,
	} {
		e := FromError(in)
		if e.ToLinux() != errno.EINTR {
			t.Fatalf("%s: FromError gave errno %d, want EINTR", name, e.ToLinux())
		}
		if got := linuxerr.ConvertIntr(e.ToError(), linuxerr.ERESTARTSYS); got != linuxerr.ERESTARTSYS {
			t.Errorf("%s: ConvertIntr(ToError()) = %v, want ERESTARTSYS", name, got)
		}
	}
	if got := linuxerr.ConvertIntr(ErrInterrupted.ToError(), linuxerr.ERESTARTSYS); got != linuxerr.ERESTARTSYS {
		t.Errorf("ConvertIntr(ErrInterrupted.ToError()) = %v, want ERESTARTSYS", got)
	}
}

// TestSafecopyErrorsUnwrapToEFAULT verifies that fault errors from safecopy
// unwrap to EFAULT and that CopyIn and CopyOut transfer bytes on every host.
func TestSafecopyErrorsUnwrapToEFAULT(t *testing.T) {
	var raw [2]uint32
	_, alignErr := safecopy.LoadUint32(unsafe.Add(unsafe.Pointer(&raw[0]), 1))
	if alignErr == nil {
		t.Fatal("LoadUint32 on unaligned pointer succeeded, want AlignmentError")
	}
	errs := []error{
		safecopy.SegvError{Addr: 0x1000},
		safecopy.BusError{Addr: 0x2000},
		alignErr,
	}
	for _, err := range errs {
		if got, ok := linuxerr.TranslateError(err); !ok || got != linuxerr.EFAULT {
			t.Errorf("linuxerr.TranslateError(%T) = (%v, %v), want (EFAULT, true)", err, got, ok)
		}
		if got := FromError(err).ToLinux(); got != errno.EFAULT {
			t.Errorf("FromError(%T).ToLinux() = %d, want EFAULT", err, got)
		}
	}

	src := []byte("safecopy-roundtrip")
	dst := make([]byte, len(src))
	n, err := safecopy.CopyIn(dst, unsafe.Pointer(&src[0]))
	if err != nil || n != len(src) || !bytes.Equal(dst, src) {
		t.Fatalf("CopyIn = (%d, %v), dst=%q, want (%d, nil), %q", n, err, dst, len(src), src)
	}
	clear(dst)
	n, err = safecopy.CopyOut(unsafe.Pointer(&dst[0]), src)
	if err != nil || n != len(src) || !bytes.Equal(dst, src) {
		t.Fatalf("CopyOut = (%d, %v), dst=%q, want (%d, nil), %q", n, err, dst, len(src), src)
	}
}
