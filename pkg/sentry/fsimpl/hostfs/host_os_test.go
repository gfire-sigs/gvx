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

package hostfs

import "runtime"

// isWindowsHost reports whether the tests run on a Windows host. A test that
// forces the capabilities of another host skips the checks that need the real
// host to accept the names or the permission bits of that other host.
func isWindowsHost() bool { return runtime.GOOS == "windows" }
