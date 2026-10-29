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

package hostfs

import (
	"fmt"
	"os"

	"z.gfire.dev/gvx/third_party/x_sys/unix"
)

// listNames lists the host names in the directory that h names. It opens the
// directory again below h, so the listing has its own file offset and never
// disturbs a caller of the pinned descriptor. The open uses O_NOFOLLOW, as
// every other open of hostfs does, and the Linux seccomp filter requires the
// flag. The listing then runs getdents64 on that descriptor.
func (w *Workspace) listNames(h hostDirHandle, _ string) ([]string, error) {
	fd, err := openatRetry(int(h), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("hostfs: open watched directory: %w", err)
	}
	dir := os.NewFile(uintptr(fd), "watched directory")
	defer func() {
		_ = dir.Close()
	}()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("hostfs: list watched directory: %w", err)
	}
	return names, nil
}

// noGuard is the guard that Unix needs: none. A pinned descriptor follows its
// directory through a rename.
func noGuard() {}

// watchHandleGuard keeps a rename of a directory away while the watcher uses a
// pinned handle. The caller runs the returned function when it let go of the
// handle.
func (w *Workspace) watchHandleGuard() func() {
	return noGuard
}
