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

package gvx

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
)

// ErrEngineFault reports that the execution engine failed under the guest. The
// kernel then ends the guest with SIGKILL, so without this error the exit code
// 137 looks like a kill for the memory limit.
var ErrEngineFault = errors.New("gvx: the execution engine stopped the guest")

// engineFaultMarker starts the message that the kernel logs when the platform
// fails to run a task: a stub that died, an engine that lost a thread, or a
// hypervisor fault.
const engineFaultMarker = "Unexpected SwitchToApp error: "

// lastEngineFault holds the cause of the last engine fault. One process runs one
// guest at a time, because Run consumes the kernel memory file.
var lastEngineFault atomic.Pointer[string]

// engineFaultLog passes the log of the kernel to next and records the engine
// faults on the way. The kernel log goes to the discard writer unless the user
// sets GVX_DEBUG_LOG, so the cause of a fault would be lost without this tap.
type engineFaultLog struct {
	next io.Writer
}

func (w engineFaultLog) Write(p []byte) (int, error) {
	if i := bytes.Index(p, []byte(engineFaultMarker)); i >= 0 {
		cause := strings.TrimSpace(string(p[i+len(engineFaultMarker):]))
		lastEngineFault.Store(&cause)
	}
	return w.next.Write(p)
}

// takeEngineFault returns the recorded cause and clears it.
func takeEngineFault() string {
	if p := lastEngineFault.Swap(nil); p != nil {
		return *p
	}
	return ""
}

// engineFaultError wraps the cause of an engine fault in ErrEngineFault.
func engineFaultError(cause string) error {
	return fmt.Errorf("%w: %s (set GVX_DEBUG_LOG=1 for the log of the kernel)", ErrEngineFault, cause)
}
