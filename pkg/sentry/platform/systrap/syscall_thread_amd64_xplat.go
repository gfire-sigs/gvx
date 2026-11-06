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

//go:build linux && amd64

package systrap

import (
	"fmt"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/arch"
)

// setStubGSBase makes the stub thread call arch_prctl(ARCH_SET_GS). The value
// is the address of the message region of the thread.
//
// A Sentry that runs as the host of this stub patches the syscall
// instructions of the stub with jumps that use GS. It removes all patches and
// stops patching when a thread calls arch_prctl(ARCH_SET_GS). A change of GS
// with ptrace does not remove them. The stub code never uses GS. The call
// protects the stub code against the patches of such a host. A Linux kernel
// accepts the call and changes only the GS base of the thread.
func (t *syscallThread) setStubGSBase() error {
	_, err := t.thread.syscallIgnoreInterrupt(&t.thread.initRegs, unix.SYS_ARCH_PRCTL,
		arch.SyscallArgument{Value: linux.ARCH_SET_GS},
		arch.SyscallArgument{Value: t.stubAddr})
	if err != nil {
		return fmt.Errorf("arch_prctl(ARCH_SET_GS) failed: %w", err)
	}
	// detach and the next syscall write initRegs back with ptrace. A zero
	// Gs_base there would reset the GS base of the thread.
	t.thread.initRegs.Gs_base = uint64(t.stubAddr)
	return nil
}
