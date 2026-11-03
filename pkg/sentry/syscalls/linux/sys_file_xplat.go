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
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// fallocateModeServer is implemented by a file description that serves the
// fallocate modes beyond mode 0, such as FALLOC_FL_PUNCH_HOLE. A file
// description that does not implement it treats every call as mode 0, so the
// system call must not forward a mode to it. The implementation validates the
// mode as vfs_fallocate does and returns EOPNOTSUPP for a mode that its file
// system cannot serve.
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
