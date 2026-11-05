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

package ipset

import (
	"runtime"
	"sync"
	"time"
	"weak"

	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// registries maps each network stack to its sets. A network namespace owns
// one network stack, so its sets live and die with the stack.
var registries = struct {
	mu sync.Mutex
	m  map[weak.Pointer[stack.Stack]]*Registry
}{m: make(map[weak.Pointer[stack.Stack]]*Registry)}

// ForStack returns the sets of the network stack. It makes an empty registry
// at the first call. mod gives the initial size of the table of sets.
func ForStack(stk *stack.Stack, mod *Module) *Registry {
	registries.mu.Lock()
	defer registries.mu.Unlock()
	key := weak.Make(stk)
	if r := registries.m[key]; r != nil {
		return r
	}
	maxSets := DefaultMaxSets
	if mod != nil {
		maxSets = mod.MaxSets()
	}
	clock := stk.Clock()
	epoch := clock.NowMonotonic()
	r := NewRegistry(maxSets, func() time.Duration {
		// The offset keeps the time after zero, because zero marks an
		// element with no timeout.
		return clock.NowMonotonic().Sub(epoch) + time.Second
	})
	registries.m[key] = r
	runtime.AddCleanup(stk, func(key weak.Pointer[stack.Stack]) {
		registries.mu.Lock()
		delete(registries.m, key)
		registries.mu.Unlock()
	}, key)
	return r
}

// ExistingForStack returns the sets of the network stack, or nil when the
// stack never had a set. A rule that names a set needs the sets to exist.
func ExistingForStack(stk *stack.Stack) *Registry {
	registries.mu.Lock()
	defer registries.mu.Unlock()
	return registries.m[weak.Make(stk)]
}

// modules maps each owner of the module parameters to its Module.
var modules = struct {
	mu sync.Mutex
	m  map[any]*Module
}{m: make(map[any]*Module)}

// ModuleFor returns the module parameters that belong to owner, which is the
// kernel of one sandbox. It makes the parameters at the first call.
func ModuleFor[T any](owner *T) *Module {
	modules.mu.Lock()
	defer modules.mu.Unlock()
	key := weak.Make(owner)
	if m := modules.m[key]; m != nil {
		return m
	}
	m := NewModule()
	modules.m[key] = m
	runtime.AddCleanup(owner, func(key weak.Pointer[T]) {
		modules.mu.Lock()
		delete(modules.m, key)
		modules.mu.Unlock()
	}, key)
	return m
}
