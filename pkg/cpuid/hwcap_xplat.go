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
	"fmt"
	"runtime"
)

// platformHWCap is called for hosts without /proc/self/auxv. The hosts in
// this file have no HWCAP source, so the call fails.
func platformHWCap() (hwCap, error) {
	return hwCap{}, fmt.Errorf("readHwCap only supported on linux, not %s", runtime.GOOS)
}
