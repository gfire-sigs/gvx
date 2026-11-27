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

//go:build !linux || !nvproxy

package nvconf

import "errors"

// HostDriverVersion reports that Linux host NVIDIA driver probing is disabled
// unless built on Linux with the nvproxy build tag.
func HostDriverVersion() (string, error) {
	return "", errors.New("nvproxy host driver is disabled in this build")
}
