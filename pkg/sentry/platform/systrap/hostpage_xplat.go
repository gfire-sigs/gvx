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

package systrap

import (
	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/hostarch"
)

// hostPageSize is the page size of the host kernel. It is larger than
// hostarch.PageSize on an Android device with 16 KB pages, where guest pages
// stay 4 KB (docs/gvxip/gvxip-006-android-host-support.md). Every region that
// the engine maps or protects for itself, such as the stub code, the seccomp
// rules, and the shared queues, starts and ends on a host page.
var hostPageSize = uintptr(max(unix.Getpagesize(), hostarch.PageSize))

// syscallStubMessageOff is the offset of the stub message of a syscall thread
// from its sentry message. Each message has a host page, because one is read
// only in the stub and the other is writable. The amd64 stub assembly uses
// the constant syscallStubMessageOffset; amd64 hosts have 4 KB pages, so the
// two values are equal there.
var syscallStubMessageOff = max(uintptr(syscallStubMessageOffset), hostPageSize)

// syscallThreadMessageLen is the length of the shared memory of a syscall
// thread: the sentry message page and the stub message page.
var syscallThreadMessageLen = 2 * syscallStubMessageOff

// hostPageRoundUp rounds x up to a multiple of hostPageSize.
func hostPageRoundUp(x uintptr) uintptr {
	return (x + hostPageSize - 1) &^ (hostPageSize - 1)
}

// hostPageRoundDown rounds x down to a multiple of hostPageSize.
func hostPageRoundDown(x uintptr) uintptr {
	return x &^ (hostPageSize - 1)
}
