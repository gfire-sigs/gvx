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

package stack

// All routing tables share one list of routes, so a lookup in a table that has
// no route would still read the whole list. The default rules name the table
// local, and a node holds one host route for each pod, so that read cost a
// lookup hundreds of steps. The stack counts the routes of each table in a
// snapshot instead. Each change of the list raises routeGen, and the next
// lookup counts again.

// routeTableCounts holds the number of routes in each table at the generation
// gen.
type routeTableCounts struct {
	gen uint64
	n   map[uint32]int
}

// routesChanged marks the counts stale. The caller holds routeMu for writing.
func (f *fibState) routesChanged() {
	f.routeGen.Add(1)
}

// tableHasRoutes reports whether the table holds a route. The caller holds
// routeMu for reading, so the list does not change during the call.
//
// +checklocksread:s.routeMu
func (s *Stack) tableHasRoutes(table uint32) bool {
	gen := s.fib.routeGen.Load()
	c := s.fib.routeTables.Load()
	if c == nil || c.gen != gen {
		c = &routeTableCounts{gen: gen, n: make(map[uint32]int)}
		for r := s.routeTable.Front(); r != nil; r = r.Next() {
			c.n[r.TableID()]++
		}
		s.fib.routeTables.Store(c)
	}
	return c.n[table] != 0
}
