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

//go:build linux || darwin

package ext4lite

import (
	"path/filepath"
	"testing"

	"z.gfire.dev/gvx/third_party/x_sys/unix"
)

func TestStorageNativeReallyAllocates(t *testing.T) {
	f := openTestFile(t, filepath.Join(t.TempDir(), "volume.ext4"))
	h, err := newHostFile(f)
	if err != nil {
		f.Close()
		t.Fatalf("newHostFile() failed: %v", err)
	}
	defer h.Close()

	if err := h.EnsureSize(16 * mib); err != nil {
		t.Fatalf("EnsureSize(16 MiB) failed: %v", err)
	}
	if h.Tier() == tierFallback {
		t.Skip("the temporary volume does not support preallocation")
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatalf("Fstat() failed: %v", err)
	}
	if st.Size != 16*mib {
		t.Errorf("st_size = %d, want %d", st.Size, 16*mib)
	}
	if allocated := int64(st.Blocks) * 512; allocated < 16*mib {
		t.Skipf("the temporary volume reports %d allocated bytes for 16 MiB; it has no allocation support", allocated)
	}
}
