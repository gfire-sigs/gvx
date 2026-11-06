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
	"errors"
	"os"
	"sync/atomic"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/log"
)

// seccompNotifyBusy becomes true when the kernel refuses a seccomp listener
// with EBUSY. The kernel allows one listener in the filter chain of a task.
// A listener in the chain of the host process, for example from a parent
// sandbox, makes every later request fail in the same way.
var seccompNotifyBusy atomic.Bool

// installSeccompNotifyIfFree installs the seccomp listener of the stub thread.
// It returns a nil file and no error when the host process chain has a
// listener already. The stub thread then uses the futex loop. Any other
// error from the kernel is fatal for the stub thread.
func (t *syscallThread) installSeccompNotifyIfFree() (*os.File, error) {
	if seccompNotifyBusy.Load() {
		return nil, nil
	}
	f, err := t.installSeccompNotify()
	if errors.Is(err, unix.EBUSY) {
		if seccompNotifyBusy.CompareAndSwap(false, true) {
			log.Warningf("Another seccomp listener exists in the filter chain of the host process. " +
				"The stub threads use the slower futex loop instead of seccomp-unotify.")
		}
		return nil, nil
	}
	return f, err
}
