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
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/syscalls"
)

const (
	amd64Sysinfo         = 99
	amd64Syslog          = 103
	amd64InotifyAddWatch = 254
	amd64Fallocate       = 285

	arm64InotifyAddWatch = 27
	arm64Fallocate       = 47
	arm64Syslog          = 116
	arm64Sysinfo         = 179
)

func replaceSyscallFn(amd64No, arm64No uintptr, fn kernel.SyscallFn) {
	entry := AMD64.Table[amd64No]
	entry.Fn = fn
	AMD64.Table[amd64No] = entry

	entry = ARM64.Table[arm64No]
	entry.Fn = fn
	ARM64.Table[arm64No] = entry
}

// init binds the gvx syscall handlers into AMD64 and ARM64 after linux64.go
// registers the upstream tables, keeping the upstream syscall files pristine.
func init() {
	AMD64.Table[amd64Syslog] = syscalls.Supported("syslog", syslogXplat)
	ARM64.Table[arm64Syslog] = syscalls.Supported("syslog", syslogXplat)
	replaceSyscallFn(amd64Sysinfo, arm64Sysinfo, sysinfoXplat)
	replaceSyscallFn(amd64InotifyAddWatch, arm64InotifyAddWatch, inotifyAddWatchXplat)
	replaceSyscallFn(amd64Fallocate, arm64Fallocate, fallocateXplat)
	AMD64.Init()
	ARM64.Init()
}
