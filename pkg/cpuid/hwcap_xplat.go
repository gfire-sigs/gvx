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

//go:build !((darwin || windows) && arm64)

package cpuid

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
)

// platformHWCap reads /proc/self/auxv on Android and returns an error on
// platforms without a registered HWCAP source.
func platformHWCap() (hwCap, error) {
	if runtime.GOOS != "android" {
		return hwCap{}, fmt.Errorf("no HWCAP source for %s", runtime.GOOS)
	}
	auxv, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return hwCap{}, fmt.Errorf("failed to read file /proc/self/auxv: %w", err)
	}
	var c hwCap
	l := len(auxv) / 16
	for i := range l {
		tag := binary.LittleEndian.Uint64(auxv[i*16:])
		val := binary.LittleEndian.Uint64(auxv[i*16+8:])
		switch tag {
		case _AT_HWCAP:
			c.hwCap1 = val
		case _AT_HWCAP2:
			c.hwCap2 = val
		}
		if c.hwCap1 != 0 && c.hwCap2 != 0 {
			break
		}
	}
	return c, nil
}
