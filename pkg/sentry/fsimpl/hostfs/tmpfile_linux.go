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
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// tmpfileUnlinkAtOnce reports that a file which the guest never links loses its
// host name at once when the host has no native unnamed file. A Linux
// directory entry can go while descriptors stay open, and a crash then leaves
// nothing behind.
const tmpfileUnlinkAtOnce = true

// openAnonAt opens an unnamed file in the directory descriptor dir with the
// native O_TMPFILE flag. The seccomp rule of the host filesystem needs
// O_NOFOLLOW and a non-negative directory descriptor, and the call has both.
// The kernel frees the file at the last close, and a crash of the process
// leaves nothing behind.
func (h *hostRoot) openAnonAt(dir hostDirHandle) (*os.File, error) {
	fd, err := openatRetry(int(dir), ".", unix.O_TMPFILE|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("hostfs: create unnamed file: %w", err)
	}
	return os.NewFile(uintptr(fd), "O_TMPFILE"), nil
}

// anonUnsupported reports whether err means that the kernel or the volume has
// no O_TMPFILE. An old kernel returns EISDIR or EINVAL, and a volume without
// support returns EOPNOTSUPP.
func anonUnsupported(err error) bool {
	return errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EISDIR) || errors.Is(err, unix.EINVAL)
}
