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

package linux

import (
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// inotifyWatchAdmitter lets a dentry refuse a new guest watch when the host
// event bridge of its filesystem is full.
type inotifyWatchAdmitter interface {
	AdmitInotifyWatch() error
}

// inotifyAddWatchXplat implements inotify_add_watch(2) and verifies
// inotifyWatchAdmitter before registering the watch on the target dentry.
func inotifyAddWatchXplat(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	mask := args[2].Uint()

	if mask&linux.ALL_INOTIFY_BITS == 0 {
		return 0, nil, linuxerr.EINVAL
	}

	follow := followFinalSymlink
	if mask&linux.IN_DONT_FOLLOW != 0 {
		follow = nofollowFinalSymlink
	}

	ino, f, err := fdToInotify(t, fd)
	if err != nil {
		return 0, nil, err
	}
	defer f.DecRef(t)

	path, err := copyInPath(t, addr)
	if err != nil {
		return 0, nil, err
	}
	if mask&linux.IN_ONLYDIR != 0 {
		path.Dir = true
	}
	tpop, err := getTaskPathOperation(t, linux.AT_FDCWD, path, disallowEmptyPath, follow, 0)
	if err != nil {
		return 0, nil, err
	}
	defer tpop.Release(t)
	d, err := t.Kernel().VFS().GetDentryAt(t, t.Credentials(), &tpop.pop, &vfs.GetDentryOptions{})
	if err != nil {
		return 0, nil, err
	}
	defer d.DecRef(t)

	if a, ok := d.Dentry().Impl().(inotifyWatchAdmitter); ok {
		if err := a.AdmitInotifyWatch(); err != nil {
			return 0, nil, err
		}
	}

	return uintptr(ino.AddWatch(d.Dentry(), mask)), nil, nil
}
