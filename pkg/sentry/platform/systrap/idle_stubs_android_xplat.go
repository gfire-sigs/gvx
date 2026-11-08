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

package systrap

// androidIdleStubs is the number of idle stubs that globalPool keeps on
// Android. Android kills the oldest phantom process when an app forks more
// than 32 processes, and it counts every live stub (GVXIP-006, F4).
const androidIdleStubs = 2

// defaultIdleStubLimit returns the number of idle stubs that globalPool keeps.
// The pool is process-wide, so the bound is a constant of the build and not
// an option of one sandbox.
func defaultIdleStubLimit() int {
	return androidIdleStubs
}
