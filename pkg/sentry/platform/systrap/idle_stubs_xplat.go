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

//go:build linux && !android

package systrap

const (
	// minIdleStubs is the lowest bound of the idle stub pool.
	minIdleStubs = 8
	// maxIdleStubs is the highest bound of the idle stub pool.
	maxIdleStubs = 32
)

// defaultIdleStubLimit returns the number of idle stubs that globalPool keeps.
// A pooled stub holds up to maxSysmsgThreads+1 host threads. The bound is
// maxSysmsgThreads (the base GOMAXPROCS) clamped to the range from
// minIdleStubs to maxIdleStubs. It keeps stubs for parallel builds and it caps
// the pids.max use of idle stubs.
//
// The pool is process-wide, so the bound is a constant of the build and not
// an option of one sandbox.
func defaultIdleStubLimit() int {
	return min(max(maxSysmsgThreads, minIdleStubs), maxIdleStubs)
}
