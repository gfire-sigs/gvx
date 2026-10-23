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

//go:build windows

package gvx

import (
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/usage"
)

// TestMemoryAccountingInitializes checks the global memory accounting that the
// package initializes. A guest that reads /proc/meminfo or runs in a memory
// cgroup charges per-cgroup counters, and the Sentry panics when the map of
// those counters does not exist.
func TestMemoryAccountingInitializes(t *testing.T) {
	if err := usage.Init(); err != nil {
		t.Fatalf("usage.Init() = %v, want nil", err)
	}
	if usage.MemoryAccounting == nil || usage.MemoryAccounting.MemCgIDToMemStats == nil {
		t.Fatalf("MemoryAccounting = %+v, want per-cgroup counters", usage.MemoryAccounting)
	}
}
