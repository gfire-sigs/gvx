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

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// platformTier is the tier that this operating system offers first.
const platformTier = tierNative

// lockFile takes the exclusive advisory lock of f without blocking. It returns
// errVolumeInUse when another open file description holds the lock.
func lockFile(f *os.File) error {
	fd := int(f.Fd())
	defer runtime.KeepAlive(f)
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
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

// unlockFile releases the lock that lockFile took.
func unlockFile(f *os.File) error {
	fd := int(f.Fd())
	defer runtime.KeepAlive(f)
	return unix.Flock(fd, unix.LOCK_UN)
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
