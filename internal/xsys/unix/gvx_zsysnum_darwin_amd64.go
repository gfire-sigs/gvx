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

//go:build darwin && amd64

package unix

// SYS_RESTART_SYSCALL is the Linux amd64 number of restart_syscall. The
// syscall-site rewriter of pkg/sentry/platform/systrap/usertrap compares the
// guest RAX with it, and the guest is a Linux program on every host. The
// package defines no other Linux number on darwin.
const SYS_RESTART_SYSCALL = 219
