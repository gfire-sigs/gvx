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

import "testing"

// syscallBudget is the most host system calls that one steady-state run of a
// benchCase operation may make at depth 5. A path-based host call counts one
// system call for each path component, and a pinned call counts one. See
// countingHost.syscalls.
var syscallBudget = map[string]int{
	"create small file at depth 5":    15,
	"stat warm at depth 5":            0,
	"readdir and stat of 100 entries": 101,
	"rename at depth 5":               34,
	"chmod at depth 5":                7,
	"utimens at depth 5":              13,
	"hard link at depth 5":            33,
	"symlink at depth 5":              13,
	"append 4 KiB and fsync":          5,
}

// TestOperationsStayWithinHostCallBudget bounds the host system calls of each
// operation that a guest repeats. A change that adds a host call or a path
// walk to one of these operations fails here.
func TestOperationsStayWithinHostCallBudget(t *testing.T) {
	for _, c := range benchCases() {
		budget, ok := syscallBudget[c.name]
		if !ok {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			e, ch, _ := newCountEnv(t)
			c.setup(e)
			// The first run warms the caches that a steady workload keeps.
			c.op(e, 0)
			ch.reset()
			c.op(e, 1)
			if got := ch.syscalls(); got > budget {
				t.Fatalf("%s made about %d host system calls %s, want at most %d", c.name, got, ch.dump(), budget)
			}
		})
	}
}
