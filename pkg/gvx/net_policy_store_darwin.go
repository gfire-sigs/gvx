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

//go:build darwin && !ios

package gvx

import (
	"fmt"
	"os"
	"runtime"

	"z.gfire.dev/gvx/internal/darwinacl"
	"z.gfire.dev/gvx/internal/xsys/unix"
)

func statPolicyStorePath(fd int, private bool) (unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return st, err
	}
	var mount unix.Statfs_t
	if err := unix.Fstatfs(fd, &mount); err != nil {
		return st, err
	}
	if mount.Flags&(unix.MNT_LOCAL|unix.MNT_IGNORE_OWNERSHIP) != unix.MNT_LOCAL {
		return st, fmt.Errorf("%w: expected a local filesystem with ownership enabled", errPolicyStoreUnsafe)
	}
	if err := darwinacl.Validate(fd, private); err != nil {
		return st, fmt.Errorf("%w: %w", errPolicyStoreUnsafe, err)
	}
	return st, nil
}

func syncPolicyStoreFile(f *os.File) error {
	// F_FULLFSYNC also flushes the device cache. fsync alone does not.
	_, err := unix.FcntlInt(f.Fd(), unix.F_FULLFSYNC, 0)
	runtime.KeepAlive(f)
	return err
}

func syncPolicyStoreName(dir int, f *os.File) error {
	if err := unix.Fsync(dir); err != nil {
		return err
	}
	return syncPolicyStoreFile(f)
}
