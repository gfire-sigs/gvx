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
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// fallocateModeServer marks a file description that serves fallocate modes
// beyond mode 0, such as FALLOC_FL_PUNCH_HOLE. A file description without this
// method treats every call as mode 0, so the system call must not forward a
// mode to it. The implementation validates the mode as vfs_fallocate does and
// returns EOPNOTSUPP for a mode that its file system cannot serve.
type fallocateModeServer interface {
	ServesFallocateModes()
}

// checkFallocateMode returns the error of a fallocate call whose mode file
// cannot serve. Mode 0 always passes. The other modes need a file description
// that implements fallocateModeServer, and a range that vfs_fallocate accepts.
func checkFallocateMode(file *vfs.FileDescription, mode uint64, offset, length int64) error {
	if mode == 0 {
		return nil
	}
	if _, ok := file.Impl().(fallocateModeServer); !ok {
		return linuxerr.ENOTSUP
	}
	if offset < 0 || length <= 0 {
		return linuxerr.EINVAL
	}
	return nil
}

// fallocateXplat implements fallocate(2) and forwards non-zero modes to file
// descriptions that implement fallocateModeServer.
func fallocateXplat(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	mode := args[1].Uint64()
	offset := args[2].Int64()
	length := args[3].Int64()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	if !file.IsWritable() {
		return 0, nil, linuxerr.EBADF
	}
	if err := checkFallocateMode(file, mode, offset, length); err != nil {
		return 0, nil, err
	}
	if offset < 0 || length <= 0 {
		return 0, nil, linuxerr.EINVAL
	}

	size := offset + length
	if size < 0 {
		return 0, nil, linuxerr.EFBIG
	}
	limit := limits.FromContext(t).Get(limits.FileSize).Cur
	// Non-zero modes verify RLIMIT_FSIZE themselves when a call grows the file.
	if mode == 0 && uint64(size) >= limit {
		t.SendSignal(&linux.SignalInfo{
			Signo: int32(linux.SIGXFSZ),
			Code:  linux.SI_USER,
		})
		return 0, nil, linuxerr.EFBIG
	}

	return 0, nil, handleSetSizeError(t, file.Allocate(t, mode, uint64(offset), uint64(length)))
}
