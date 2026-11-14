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

//go:build linux || darwin

package ext4lite

import (
	"errors"
	"os"
	"runtime"
	"time"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// platformTier is the tier that this operating system offers first.
const platformTier = tierNative

// lockFile takes the exclusive advisory lock of f without blocking. It retries
// briefly so a concurrent shared probe in ProbeVolumeInUse cannot abort
// OpenVolume, and returns errVolumeInUse when another handle holds the lock.
func lockFile(f *os.File) error {
	fd := int(f.Fd())
	defer runtime.KeepAlive(f)
	for attempt := 0; ; {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		switch {
		case err == nil:
			if attempt > 0 {
				var st unix.Stat_t
				if statErr := unix.Fstat(fd, &st); statErr == nil && st.Nlink == 0 {
					_ = unix.Flock(fd, unix.LOCK_UN)
					return os.ErrNotExist
				}
			}
			return nil
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EWOULDBLOCK):
			attempt++
			if attempt >= 5 {
				return errVolumeInUse
			}
			time.Sleep(time.Millisecond)
		default:
			return err
		}
	}
}

// lockFileShared takes a shared advisory lock on f without blocking. It returns
// errVolumeInUse when another open file description holds an exclusive lock.
func lockFileShared(f *os.File) error {
	fd := int(f.Fd())
	defer runtime.KeepAlive(f)
	for {
		err := unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EWOULDBLOCK):
			return errVolumeInUse
		default:
			return err
		}
	}
}

// unlockFile releases the lock that lockFile or lockFileShared took.
func unlockFile(f *os.File) error {
	fd := int(f.Fd())
	defer runtime.KeepAlive(f)
	return unix.Flock(fd, unix.LOCK_UN)
}

// removeVolumeFile acquires an exclusive lock on path, verifies that path still
// resolves to the locked inode, and unlinks path while holding the lock.
func removeVolumeFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()
	if err := lockFile(f); err != nil {
		return err
	}
	defer func() {
		_ = unlockFile(f)
	}()
	openInfo, err := f.Stat()
	if err != nil {
		return err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(openInfo, pathInfo) {
		return errVolumeInUse
	}
	return os.Remove(path)
}

// availBytes returns the space that an unprivileged writer can still use on
// the volume of f.
func availBytes(f *os.File) (uint64, error) {
	fd := int(f.Fd())
	defer runtime.KeepAlive(f)
	var st unix.Statfs_t
	for {
		err := unix.Fstatfs(fd, &st)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		break
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}
