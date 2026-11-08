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

// androidMaxSysmsgThreads bounds the sysmsg threads of one stub on Android.
// A sysmsg thread is a separate host process. Android kills the child
// processes of all apps above 32 together (GVXIP-006 F4), so each live guest
// address space costs at most 1 + androidMaxSysmsgThreads of them.
//
// At most this many threads of one guest process run guest code at once. A
// third thread runs when a running one traps into the Sentry, so threads that
// spin in user mode and wait for each other, such as an active-wait barrier
// of three or more threads, can stall.
const androidMaxSysmsgThreads = 2

// sysmsgThreadLimit returns the largest number of sysmsg threads of one stub
// for a Sentry with procs base GOMAXPROCS.
func sysmsgThreadLimit(procs int) int {
	return min(procs, androidMaxSysmsgThreads)
}
