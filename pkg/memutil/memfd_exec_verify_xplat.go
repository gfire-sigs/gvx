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

package memutil

import (
	"fmt"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// VerifyExecMapping maps one page of fd with PROT_EXEC and unmaps it again.
// The Linux systrap engine maps guest code from the memory file with PROT_EXEC,
// so a host that denies it cannot run a guest. The call reports that denial
// before the first guest starts.
func VerifyExecMapping(fd int) error {
	b, err := unix.Mmap(fd, 0, unix.Getpagesize(), unix.PROT_READ|unix.PROT_EXEC, unix.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("the host denies an executable mapping of the memory file (a seccomp or SELinux rule of the host): %w", err)
	}
	return unix.Munmap(b)
}
