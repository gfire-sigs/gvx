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

import "testing"

func TestKernelReportedMemoryIsPerKernel(t *testing.T) {
	const small, large = 1 << 30, 3 << 30
	a, b, plain := &Kernel{}, &Kernel{}, &Kernel{}
	a.SetReportedMemory(small)
	b.SetReportedMemory(large)
	for _, tc := range []struct {
		name   string
		k      *Kernel
		want   uint64
		wantOK bool
	}{
		{"first kernel", a, small, true},
		{"second kernel", b, large, true},
		{"kernel without a value", plain, 0, false},
	} {
		if got, ok := tc.k.ReportedMemory(); got != tc.want || ok != tc.wantOK {
			t.Errorf("%s: ReportedMemory = %d, %t, want %d, %t", tc.name, got, ok, tc.want, tc.wantOK)
		}
	}
	a.SetReportedMemory(0)
	if got, ok := a.ReportedMemory(); ok {
		t.Errorf("after reset: ReportedMemory = %d, true, want no value", got)
	}
	if got, _ := b.ReportedMemory(); got != large {
		t.Errorf("reset of one kernel changed the other: %d, want %d", got, uint64(large))
	}
}
