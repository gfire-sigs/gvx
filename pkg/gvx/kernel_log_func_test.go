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
	"runtime"
	"testing"
	"weak"

	"z.gfire.dev/gvx/pkg/sentry/kernel"
)

func TestKernelLogFuncWritesToTheKernelLog(t *testing.T) {
	k := &kernel.Kernel{}
	kernelLogFunc(k)(kernel.LogWarning, "IPT: IN= OUT=lo")
	rec, ok := k.KernelLog().Lookup(0)
	if !ok || rec.Text != "IPT: IN= OUT=lo" || rec.Level != kernel.LogWarning || rec.Facility != kernel.LogFacilityKern {
		t.Errorf("record = %+v, %v", rec, ok)
	}
}

// The registry of log functions is global and the key, the network stack, is
// reachable from the kernel. A function that held the kernel strongly would
// keep every sandbox of the process alive.
func TestKernelLogFuncDoesNotKeepTheKernelAlive(t *testing.T) {
	var fn func(int, string)
	var ref weak.Pointer[kernel.Kernel]
	func() {
		k := &kernel.Kernel{}
		fn = kernelLogFunc(k)
		fn(kernel.LogInfo, "while the kernel lives")
		ref = weak.Make(k)
	}()
	for range 5 {
		runtime.GC()
	}
	if ref.Value() != nil {
		t.Fatal("the log function keeps the kernel reachable")
	}
	fn(kernel.LogInfo, "after the kernel is gone")
}
