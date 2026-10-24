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

//go:build windows

package ext4lite

import (
	"errors"
	"syscall"
)

// Windows error numbers for a full volume, a full handle quota, a quota stop,
// and the NTFS attribute list limit that ends a long run of random writes.
const (
	errorHandleDiskFull       = syscall.Errno(39)
	errorDiskFull             = syscall.Errno(112)
	errorNotEnoughQuota       = syscall.Errno(1816)
	errorFileSystemLimitation = syscall.Errno(665)
	errorDiskQuotaExceeded    = syscall.Errno(1295)
)

// isHostDiskFull reports whether err means that the host volume is full or
// that a quota stops the write.
func isHostDiskFull(err error) bool {
	for _, no := range []syscall.Errno{errorHandleDiskFull, errorDiskFull, errorNotEnoughQuota, errorFileSystemLimitation, errorDiskQuotaExceeded} {
		if errors.Is(err, no) {
			return true
		}
	}
	return false
}
