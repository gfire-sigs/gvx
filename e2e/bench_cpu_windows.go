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

package e2e

import (
	"time"

	"golang.org/x/sys/windows"
)

func filetimeToDuration(ft windows.Filetime) time.Duration {
	ticks := uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
	return time.Duration(ticks * 100)
}

// hostProcessCPUTime returns the cumulative user and kernel CPU time of the
// current host process.
func hostProcessCPUTime() (user, sys time.Duration, err error) {
	var creation, exit, kernel, userFT windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernel, &userFT); err != nil {
		return 0, 0, err
	}
	return filetimeToDuration(userFT), filetimeToDuration(kernel), nil
}
