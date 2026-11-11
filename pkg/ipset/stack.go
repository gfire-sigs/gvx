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

const (
	stackRegistryKey = "ipset.registry"
	kernelModuleKey  = "ipset.module"
)

type extensionOwner interface {
	LoadOrStoreExtensionState(key string, init func() any) any
}

// ForStack returns the sets of the network stack. It makes an empty registry
// at the first call. mod gives the initial size of the table of sets.
func ForStack(stk *stack.Stack, mod *Module) *Registry {
	if stk == nil {
		maxSets := DefaultMaxSets
		if mod != nil {
			maxSets = mod.MaxSets()
		}
		return NewRegistry(maxSets, nil)
	}
	return stk.LoadOrStoreExtensionState(stackRegistryKey, func() any {
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
		r.stk = stk
		return r
	}).(*Registry)
}

// ExistingForStack returns the sets of the network stack, or nil when the
// stack never had a set. A rule that names a set needs the sets to exist.
func ExistingForStack(stk *stack.Stack) *Registry {
	if stk == nil {
		return nil
	}
	v, ok := stk.ExtensionState(stackRegistryKey)
	if !ok {
		return nil
	}
	return v.(*Registry)
}

// fallbackModules maps arbitrary non-Kernel owners in unit tests weakly to
// their Module parameters.
var fallbackModules = struct {
	mu sync.Mutex
	m  map[any]*Module
}{m: make(map[any]*Module)}

// ModuleFor returns the module parameters that belong to owner, which is the
// kernel of one sandbox. It makes the parameters at the first call.
func ModuleFor[T any](owner *T) *Module {
	if owner == nil {
		return NewModule()
	}
	if ext, ok := any(owner).(extensionOwner); ok {
		return ext.LoadOrStoreExtensionState(kernelModuleKey, func() any {
			return NewModule()
		}).(*Module)
	}
	fallbackModules.mu.Lock()
	defer fallbackModules.mu.Unlock()
	key := weak.Make(owner)
	if m := fallbackModules.m[key]; m != nil {
		return m
	}
	m := NewModule()
	fallbackModules.m[key] = m
	runtime.AddCleanup(owner, func(key weak.Pointer[T]) {
		fallbackModules.mu.Lock()
		delete(fallbackModules.m, key)
		fallbackModules.mu.Unlock()
	}, key)
	return m
}
