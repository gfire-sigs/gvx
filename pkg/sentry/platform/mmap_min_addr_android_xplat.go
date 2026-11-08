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

//go:build android

package platform

import (
	"os"
	"strconv"
	"strings"

	"z.gfire.dev/gvx/pkg/hostarch"
)

// systemMMapMinAddrSource is the source file. SELinux denies an Android app
// the read of this file, so init measures the value when the read fails.
const systemMMapMinAddrSource = "/proc/sys/vm/mmap_min_addr"

// systemMMapMinAddr is the system's minimum map address.
var systemMMapMinAddr uint64

// SystemMMapMinAddr returns the minimum system address.
func SystemMMapMinAddr() hostarch.Addr {
	return hostarch.Addr(systemMMapMinAddr)
}

// MMapMinAddr is a size zero struct that implements MinUserAddress based on
// the system minimum address.
type MMapMinAddr struct{}

// MinUserAddress implements platform.MinUserAddresss.
func (*MMapMinAddr) MinUserAddress() hostarch.Addr {
	return SystemMMapMinAddr()
}

func init() {
	if b, err := os.ReadFile(systemMMapMinAddrSource); err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); err == nil {
			systemMMapMinAddr = v
			return
		}
	}
	systemMMapMinAddr = measureMMapMinAddr()
}
