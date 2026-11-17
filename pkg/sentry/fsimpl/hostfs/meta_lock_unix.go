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

package hostfs

import (
	"errors"
	"os"
	"runtime"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// lockMetaExclusive acquires a blocking exclusive advisory lock on f.
func lockMetaExclusive(f *os.File) error {
	fd := int(f.Fd())
	defer runtime.KeepAlive(f)
	for {
		err := unix.Flock(fd, unix.LOCK_EX)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err
	}
}

// tryLockMetaExclusive attempts to acquire a non-blocking exclusive advisory
// lock on f. It returns (false, nil) when another handle holds a conflicting lock.
func tryLockMetaExclusive(f *os.File) (bool, error) {
	fd := int(f.Fd())
	defer runtime.KeepAlive(f)
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EWOULDBLOCK):
			return false, nil
		default:
			return false, err
		}
	}
}

// lockMetaShared acquires a blocking shared advisory lock on f.
func lockMetaShared(f *os.File) error {
	fd := int(f.Fd())
	defer runtime.KeepAlive(f)
	for {
		err := unix.Flock(fd, unix.LOCK_SH)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err
	}
}

// unlockMeta releases the advisory lock held on f.
func unlockMeta(f *os.File) error {
	fd := int(f.Fd())
	defer runtime.KeepAlive(f)
	for {
		err := unix.Flock(fd, unix.LOCK_UN)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err
	}
}
