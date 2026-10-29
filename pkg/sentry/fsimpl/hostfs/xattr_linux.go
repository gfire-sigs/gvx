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

//go:build linux

package hostfs

import (
	"errors"
	"os"
	"strings"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/third_party/x_sys/unix"
)

// This file holds the native store of extended attributes for Linux hosts.
// Each call runs on a descriptor that the workspace pinned before the sandbox
// lockdown: the descriptor of an open file handle, the pinned descriptor of a
// directory, or a descriptor that one openat call returns relative to the
// pinned descriptor of the parent directory. The seccomp allowlist of the host
// file system permits fgetxattr, fsetxattr, flistxattr, and fremovexattr.

// nativeXattrRefused reports the errors that mean the host does not store the
// attribute: EPERM, which also reports a call that the lockdown filter
// refuses, and EOPNOTSUPP, which is also ENOTSUP.
func nativeXattrRefused(err error) bool {
	return errors.Is(err, unix.EPERM) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP)
}

// nativeXattrNoData reports that the host holds no attribute of that name.
func nativeXattrNoData(err error) bool {
	return errors.Is(err, unix.ENODATA)
}

// nativeXattrError converts a host error of a native call into the Linux
// errno that the guest sees.
func nativeXattrError(err error) error {
	switch {
	case errors.Is(err, unix.ENODATA):
		return linuxerr.ENODATA
	case errors.Is(err, unix.ENOSPC):
		return linuxerr.ENOSPC
	case errors.Is(err, unix.EDQUOT):
		return linuxerr.EDQUOT
	case errors.Is(err, unix.E2BIG):
		return linuxerr.E2BIG
	case errors.Is(err, unix.ERANGE):
		return linuxerr.ERANGE
	case errors.Is(err, unix.EEXIST):
		return linuxerr.EEXIST
	case errors.Is(err, unix.EROFS):
		return linuxerr.EROFS
	}
	return translateHostError(err)
}

// withXattrFD runs fn with a descriptor of the object of t. The descriptor
// stays valid until fn returns. Callers hold w.mu.
func (w *Workspace) withXattrFD(t xattrTarget, fn func(fd int) error) error {
	if t.h != nil {
		f, err := t.h.acquire()
		if err != nil {
			return err
		}
		defer t.h.release()
		return withFileFD(f, fn)
	}
	if t.rel == "" {
		return errHostUnsupported
	}
	switch t.ino.kind {
	case hostKindDir:
		pin, err := w.acquirePin(t.rel)
		if err != nil {
			return err
		}
		defer w.releasePin(pin)
		return fn(int(pin.h))
	case hostKindRegular:
		parent, name := splitParent(t.rel)
		leaf, err := w.hostLeaf(parent, name)
		if err != nil {
			return err
		}
		pin, err := w.acquirePin(parent)
		if err != nil {
			return err
		}
		defer w.releasePin(pin)
		f, err := w.host.openChildAt(pin.h, leaf, os.O_RDONLY, 0)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		return withFileFD(f, fn)
	}
	return errHostUnsupported
}

func (w *Workspace) nativeGetXattr(t xattrTarget, name string) (value []byte, err error) {
	err = w.withXattrFD(t, func(fd int) error {
		for {
			size, gerr := retryEINTRValue(func() (int, error) { return unix.Fgetxattr(fd, name, nil) })
			if gerr != nil {
				return gerr
			}
			buf := make([]byte, size)
			n, gerr := retryEINTRValue(func() (int, error) { return unix.Fgetxattr(fd, name, buf) })
			if errors.Is(gerr, unix.ERANGE) {
				// Another writer grew the value after the size query.
				continue
			}
			if gerr != nil {
				return gerr
			}
			value = buf[:n]
			return nil
		}
	})
	return value, err
}

func (w *Workspace) nativeListXattr(t xattrTarget) (names []string, err error) {
	err = w.withXattrFD(t, func(fd int) error {
		for {
			size, lerr := retryEINTRValue(func() (int, error) { return unix.Flistxattr(fd, nil) })
			if lerr != nil {
				return lerr
			}
			if size == 0 {
				return nil
			}
			buf := make([]byte, size)
			n, lerr := retryEINTRValue(func() (int, error) { return unix.Flistxattr(fd, buf) })
			if errors.Is(lerr, unix.ERANGE) {
				continue
			}
			if lerr != nil {
				return lerr
			}
			for _, name := range strings.Split(string(buf[:n]), "\x00") {
				if name != "" {
					names = append(names, name)
				}
			}
			return nil
		}
	})
	return names, err
}

func (w *Workspace) nativeSetXattr(t xattrTarget, name string, value []byte, flags uint32) error {
	return w.withXattrFD(t, func(fd int) error {
		return retryEINTR(func() error { return unix.Fsetxattr(fd, name, value, int(flags)) })
	})
}

func (w *Workspace) nativeRemoveXattr(t xattrTarget, name string) error {
	return w.withXattrFD(t, func(fd int) error {
		return retryEINTR(func() error { return unix.Fremovexattr(fd, name) })
	})
}

// retryEINTRValue is retryEINTR for a call that returns a count.
func retryEINTRValue(f func() (int, error)) (int, error) {
	for {
		n, err := f()
		if !errors.Is(err, unix.EINTR) {
			return n, err
		}
	}
}
