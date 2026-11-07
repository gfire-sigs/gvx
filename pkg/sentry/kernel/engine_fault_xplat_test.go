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
	"errors"
	"testing"
)

func TestEngineFaultBelongsToItsKernel(t *testing.T) {
	a, b := &Kernel{}, &Kernel{}
	if got := a.TakeEngineFault(); got != "" {
		t.Fatalf("TakeEngineFault without a fault = %q, want an empty string", got)
	}
	a.recordEngineFault(errors.New("the stub died: exit code 0xc0000005"))
	if got := b.TakeEngineFault(); got != "" {
		t.Errorf("a fault of the first kernel reached the second kernel: %q", got)
	}
	b.recordEngineFault(errors.New("the hypervisor stopped the vCPU"))
	if got, want := a.TakeEngineFault(), "the stub died: exit code 0xc0000005"; got != want {
		t.Errorf("first kernel: TakeEngineFault = %q, want %q", got, want)
	}
	if got := a.TakeEngineFault(); got != "" {
		t.Errorf("a second TakeEngineFault of the first kernel = %q, want it empty", got)
	}
	if got, want := b.TakeEngineFault(), "the hypervisor stopped the vCPU"; got != want {
		t.Errorf("second kernel: TakeEngineFault = %q, want %q: the take of the first kernel cleared it", got, want)
	}
}
