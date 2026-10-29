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

//go:build !darwin && !windows

package hostfs

import (
	"os"
	"time"

	"z.gfire.dev/gvx/third_party/x_sys/unix"
)

// probeCaseInsensitive reports false: the Linux development build runs on
// case-sensitive file systems. It exists so that the package builds on Linux.
func probeCaseInsensitive(*os.File) (bool, error) {
	return false, nil
}

func birthTime(st *unix.Stat_t) time.Time {
	return time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec))
}
