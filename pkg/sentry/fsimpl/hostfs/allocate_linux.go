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

package hostfs

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// allocateNative passes the request to fallocate on the descriptor of f. The
// Linux modes 0, KEEP_SIZE, and PUNCH_HOLE with KEEP_SIZE have the same
// values in the guest and on the host, so the mode passes unchanged. The
// seccomp allowlist of the host filesystem permits fallocate.
func allocateNative(f *os.File, mode uint64, off, length int64) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return fmt.Errorf("hostfs: fallocate: %w", err)
	}
	var callErr error
	if err := rc.Control(func(fd uintptr) {
		callErr = retryEINTR(func() error { return unix.Fallocate(int(fd), uint32(mode), off, length) })
	}); err != nil {
		return fmt.Errorf("hostfs: fallocate: %w", err)
	}
	if callErr != nil {
		return fmt.Errorf("hostfs: fallocate: %w", callErr)
	}
	return nil
}
