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

package gvx

import (
	"os"
	"syscall"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

func fileAllocatedBytes(path string, info os.FileInfo) int64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st != nil {
		return int64(st.Blocks) * 512
	}
	var ust unix.Stat_t
	if err := unix.Lstat(path, &ust); err == nil {
		return int64(ust.Blocks) * 512
	}
	return info.Size()
}
