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
	"fmt"
	"runtime"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/abi/linux/errno"
	"z.gfire.dev/gvx/pkg/errors"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// linuxErrnoErrors maps a Linux errno to the Error that newWithHost registered
// for it.
var linuxErrnoErrors [maxErrno]*Error

// registerLinuxErrno records e as the Error for a Linux errno. The first
// registration of an errno wins, as it does for host translations.
func registerLinuxErrno(linuxTranslation errno.Errno, e *Error) {
	if int(linuxTranslation) < len(linuxErrnoErrors) && linuxErrnoErrors[linuxTranslation] == nil {
		linuxErrnoErrors[linuxTranslation] = e
	}
}

// fromLinuxErrno converts a Linux errno, as an errors.Error from the linuxerr
// package carries it, to an Error.
//
// WHY: FromHost translates the errno numbers of the host. A Linux host uses the
// Linux numbers, so a lookup through FromHost is the identity there. A Windows
// or macOS host numbers its errors differently. On macOS, Linux EAGAIN (11) is
// EDEADLK and Linux ENOSYS (38) is ENOTSOCK. A lookup through FromHost then
// panics or returns the wrong error.
func fromLinuxErrno(n errno.Errno) *Error {
	if int(n) < len(linuxErrnoErrors) {
		if e := linuxErrnoErrors[n]; e != nil {
			return e
		}
	}
	return NewDynamic(fmt.Sprintf("linux errno %d", n), n)
}

// backwardsError returns the error value that Error.ToError gives for e.
//
// WHY: On Linux, unix.Errno carries the Linux number, so the value round-trips
// through FromError. On Windows and macOS, unix.Errno is a host number. FromError
// would then look up a Linux number in the host table and panic. For example,
// Linux ENOTCONN (107) has no entry in the macOS table. A linuxerr error keeps
// the Linux number on every host. ExtractErrno and FromError both accept it.
//
// EINTR gets linuxerr.ErrInterrupted, the value that blocking calls return when
// an interrupt ends them. linuxerr.ConvertIntr matches that value and
// unix.EINTR, but not linuxerr.EINTR. A different value turns a restartable
// call, such as recvmsg(2), into a call that fails with EINTR.
func backwardsError(e *Error) error {
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		return unix.Errno(e.errno)
	}
	if e.errno == errno.EINTR {
		return linuxerr.ErrInterrupted
	}
	if le := lookupLinuxerr(e.errno); le != nil {
		return le
	}
	return errors.New(e.errno, e.message)
}

// lookupLinuxerr returns the linuxerr error for a Linux errno, or nil when the
// linuxerr package has none.
func lookupLinuxerr(n errno.Errno) (le *errors.Error) {
	defer func() {
		if recover() != nil {
			le = nil
		}
	}()
	err := linuxerr.ErrorFromUnix(unix.Errno(n))
	if err == nil {
		return nil
	}
	return err.(*errors.Error)
}

// maxLinuxABI bounds the errno range [1, maxLinuxABI) of the Linux ABI.
const maxLinuxABI = 134

// init registers every Linux errno absent from the host tables.
// FromError and Error.ToError then resolve Linux-only values such as EBADFD,
// EDEADLK, ENOMEDIUM, and ENOKEY without panicking on macOS or Windows.
func init() {
	for code := errno.Errno(1); code < maxLinuxABI; code++ {
		le := lookupLinuxerr(code)
		msg := fmt.Sprintf("linux errno %d", code)
		if le != nil {
			msg = le.Error()
		}
		e := &Error{message: msg, errno: code}
		registerLinuxErrno(code, e)
		if !linuxBackwardsTranslations[code].ok {
			var be error
			switch {
			case code == errno.EINTR:
				be = linuxerr.ErrInterrupted
			case code == linuxerr.EWOULDBLOCK.Errno():
				be = linuxerr.ErrWouldBlock
			case (runtime.GOOS == "linux" || runtime.GOOS == "android") && getHostTranslation(unix.Errno(code)) != nil:
				be = unix.Errno(code)
			case le != nil:
				be = le
			default:
				be = errors.New(code, msg)
			}
			linuxBackwardsTranslations[code] = linuxBackwardsTranslation{err: be, ok: true}
		}
	}
}
