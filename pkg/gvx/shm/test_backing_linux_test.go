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

package shm

import (
	"testing"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

func createTestBackingFD(t *testing.T, size int64) (int, func()) {
	t.Helper()
	fd, err := unix.MemfdCreate("gvx-shm-test", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatalf("MemfdCreate: %v", err)
	}
	if err := unix.Ftruncate(fd, size); err != nil {
		_ = unix.Close(fd)
		t.Fatalf("Ftruncate: %v", err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, unix.F_SEAL_SHRINK); err != nil {
		_ = unix.Close(fd)
		t.Fatalf("F_ADD_SEALS(F_SEAL_SHRINK): %v", err)
	}
	return fd, func() { _ = unix.Close(fd) }
}
