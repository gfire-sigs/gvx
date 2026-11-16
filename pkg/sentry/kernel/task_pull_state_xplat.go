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

package kernel

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
)

type taskPullError struct {
	tid ThreadID
	err error
}

// PullFullStateChecked captures full platform register and floating-point
// state for all tasks and returns any platform errors.
//
// Precondition: The kernel must be paused.
func (ts *TaskSet) PullFullStateChecked() error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.Root == nil {
		return nil
	}
	var failures []taskPullError
	for t, tid := range ts.Root.tids {
		if mm := t.MemoryManager(); mm != nil {
			if err := t.p.PullFullState(mm.AddressSpace(), t.Arch()); err != nil {
				failures = append(failures, taskPullError{tid: tid, err: err})
			}
		}
	}
	if len(failures) == 0 {
		return nil
	}
	slices.SortFunc(failures, func(a, b taskPullError) int {
		return cmp.Compare(a.tid, b.tid)
	})
	errs := make([]error, len(failures))
	for i, f := range failures {
		errs[i] = fmt.Errorf("pull task %d state: %w", f.tid, f.err)
	}
	return errors.Join(errs...)
}

// ReceiveTaskStatesChecked captures full platform state for all tasks and
// returns any platform errors.
//
// Precondition: The kernel must be paused.
func (k *Kernel) ReceiveTaskStatesChecked() error {
	k.extMu.Lock()
	defer k.extMu.Unlock()
	return k.tasks.PullFullStateChecked()
}
