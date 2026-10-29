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

package hostfs

import (
	"os"
	"time"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// pcCaseSensitive is _PC_CASE_SENSITIVE from XNU <sys/unistd.h>. The value is
// not exported by x/sys. fpathconf returns 0 on a case-insensitive volume.
const pcCaseSensitive = 11

// probeCaseInsensitive reports whether the volume holding the workspace folds
// name case. The default APFS volume does. hostfs must then reject lookups
// whose case differs from the stored name.
func probeCaseInsensitive(dir *os.File) (bool, error) {
	var sensitive int
	if err := withFileFD(dir, func(fd int) error {
		var err error
		sensitive, err = unix.Fpathconf(fd, pcCaseSensitive)
		return err
	}); err != nil {
		return false, err
	}
	return sensitive == 0, nil
}

func birthTime(st *unix.Stat_t) time.Time {
	return time.Unix(int64(st.Btim.Sec), int64(st.Btim.Nsec))
}
