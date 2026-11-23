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

//go:build !windows

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

func controlConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

func controlUnixPeerOwned(conn net.Conn) bool {
	local, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := local.SyscallConn()
	if err != nil {
		return false
	}
	var uid uint32
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		uid, peerErr = controlPeerUID(int(fd))
	}); err != nil || peerErr != nil {
		return false
	}
	return uid == uint32(os.Geteuid())
}

func readCheckpointControlToken(network, address string) (string, error) {
	return readControlToken(network, address)
}

func validateUnixControlTokenPath(string, bool) error { return nil }

type pathControlTokenTarget string

func (path pathControlTokenTarget) verifyRegular() error {
	info, err := os.Lstat(string(path))
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("control token path %q is not a regular file", path)
	}
	return nil
}

func (path pathControlTokenTarget) open() (*os.File, error) {
	return openControlInput(string(path), true)
}

func (path pathControlTokenTarget) create() (*os.File, error) {
	return createControlTokenFile(string(path))
}

func (path pathControlTokenTarget) remove() error {
	return os.Remove(string(path))
}

func (path pathControlTokenTarget) removeIfSame(f *os.File) error {
	return removeCreatedControlToken(string(path), f)
}

func openPathControlTokenTarget(path string, create bool) (controlTokenTarget, func() error, error) {
	dir, err := privatePolicyControlDir(filepath.Dir(path), create)
	if err != nil {
		return nil, nil, err
	}
	return pathControlTokenTarget(filepath.Join(dir, filepath.Base(path))), nil, nil
}

func pinControlTokenFile(target controlTokenTarget, writer *os.File) (*os.File, error) {
	created, err := writer.Stat()
	if err != nil {
		return nil, err
	}
	f, err := target.open()
	if err != nil {
		return nil, err
	}
	current, err := f.Stat()
	if err == nil && !os.SameFile(created, current) {
		err = errors.New("control token changed after creation")
	}
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

func removeCreatedControlToken(path string, f *os.File) error {
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	created, err := f.Stat()
	if err != nil || !os.SameFile(current, created) {
		return err
	}
	return os.Remove(path)
}

func validateControlDirectory(path string) error {
	uid := uint32(os.Geteuid())
	for dir := path; ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		owner := info.Sys().(*syscall.Stat_t).Uid
		if dir == path {
			if !info.IsDir() || owner != uid || info.Mode().Perm() != 0o700 {
				return errors.New("must be owned by the current user with mode 0700")
			}
		} else if !info.IsDir() || (owner != 0 && owner != uid) ||
			(info.Mode().Perm()&0o022 != 0 && (owner != 0 || info.Mode()&os.ModeSticky == 0)) {
			return fmt.Errorf("unsafe ancestor directory %q", dir)
		}
		if err := validateControlDirectoryACL(dir, dir == path); err != nil {
			return fmt.Errorf("%q: %w", dir, err)
		}
		if dir == filepath.Dir(dir) {
			return nil
		}
	}
}

func validatePolicySocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0o600 {
		return errors.New("control socket must be owned by the current user with mode 0600")
	}
	return nil
}

func openControlInput(path string, token bool) (*os.File, error) {
	// O_NONBLOCK prevents an unexpected FIFO from blocking the open.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	if err := validateControlInput(f, token); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

func createControlTokenFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := validateControlInput(f, true); err != nil {
		return nil, errors.Join(err, f.Close(), os.Remove(path))
	}
	return f, nil
}

func validateControlInput(f *os.File, token bool) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	stat := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || stat.Nlink != 1 || (stat.Uid != uint32(os.Geteuid()) && (token || stat.Uid != 0)) {
		return fmt.Errorf("%q is not a trusted regular file", f.Name())
	}
	if (token && info.Mode().Perm() != 0o600) || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("unsafe permissions on %q", f.Name())
	}
	err = validateControlInputACL(int(f.Fd()), token)
	runtime.KeepAlive(f)
	return err
}
