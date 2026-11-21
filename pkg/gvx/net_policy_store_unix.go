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

//go:build (linux && !android) || (darwin && !ios)

package gvx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

func openPolicyStoreFile(path string, initialize func(*os.File) error) (result *os.File, err error) {
	uid := uint32(os.Geteuid())
	dir, err := openPolicyStoreParent(filepath.Dir(path), uid)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := unix.Close(dir); closeErr != nil {
			if result != nil {
				closeErr = errors.Join(closeErr, result.Close())
				result = nil
			}
			err = errors.Join(err, closeErr)
		}
	}()

	name := filepath.Base(path)
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if initialize != nil {
		flags |= unix.O_CREAT | unix.O_EXCL
	} else {
		var st unix.Stat_t
		if err := unix.Fstatat(dir, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return nil, err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			return nil, fmt.Errorf("%w: expected a regular file", errPolicyStoreUnsafe)
		}
	}
	fd, err := unix.Openat(dir, name, flags, 0o600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() {
		if result == nil {
			err = errors.Join(err, f.Close())
		}
	}()
	st, err := statPolicyStorePath(fd, true)
	if err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uid || st.Mode&0o7077 != 0 || st.Nlink != 1 {
		return nil, fmt.Errorf("%w: expected an owner-only regular file with one link", errPolicyStoreUnsafe)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("lock policy store: %w", err)
	}
	if initialize != nil {
		if st.Mode&0o600 != 0o600 {
			if err := f.Chmod(0o600); err != nil {
				return nil, fmt.Errorf("set policy file permissions: %w", err)
			}
		}
		if err := initialize(f); err != nil {
			return nil, err
		}
		if err := syncPolicyStoreName(dir, f); err != nil {
			return nil, fmt.Errorf("sync policy store name: %w", err)
		}
	}
	return f, nil
}

func openPolicyStoreParent(path string, uid uint32) (int, error) {
	const flags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_DIRECTORY | unix.O_CLOEXEC
	fd, err := unix.Open("/", flags, 0)
	if err != nil {
		return -1, err
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if path == "/" {
		components = nil
	}
	for i := 0; ; i++ {
		private := i == len(components)
		if err := validatePolicyStoreDirectory(fd, uid, private); err != nil {
			return -1, errors.Join(err, unix.Close(fd))
		}
		if private {
			return fd, nil
		}
		next, openErr := unix.Openat(fd, components[i], flags, 0)
		if err := errors.Join(openErr, unix.Close(fd)); err != nil {
			if openErr == nil {
				err = errors.Join(err, unix.Close(next))
			}
			return -1, fmt.Errorf("open parent component %q: %w", components[i], err)
		}
		fd = next
	}
}

func validatePolicyStoreDirectory(fd int, uid uint32, private bool) error {
	st, err := statPolicyStorePath(fd, private)
	if err != nil {
		return err
	}
	if private {
		if st.Uid != uid || st.Mode&0o7077 != 0 {
			return fmt.Errorf("%w: expected an owner-only parent directory", errPolicyStoreUnsafe)
		}
		return nil
	}
	// In a root-owned sticky directory, other users cannot replace a child
	// owned by root or the effective user. The walk verifies every child.
	rootSticky := st.Uid == 0 && st.Mode&unix.S_ISVTX != 0
	if (st.Uid != 0 && st.Uid != uid) || (st.Mode&0o022 != 0 && !rootSticky) {
		return fmt.Errorf("%w: untrusted directory ancestor", errPolicyStoreUnsafe)
	}
	return nil
}
