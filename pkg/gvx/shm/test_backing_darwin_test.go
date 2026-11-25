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

//go:build darwin

package shm

import (
	"os"
	"testing"
)

func createTestBackingFD(t *testing.T, size int64) (int, func()) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "gvx-shm-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		t.Fatalf("Truncate: %v", err)
	}
	return int(f.Fd()), func() { _ = f.Close() }
}
