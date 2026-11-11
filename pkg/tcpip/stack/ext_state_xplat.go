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

import (
	"context"

	"z.gfire.dev/gvx/pkg/sync"
)

type preservedEndpoint interface {
	PreserveAcrossSaveRestore() bool
}

func isPreservedEndpoint(ep LinkEndpoint) bool {
	p, ok := ep.(preservedEndpoint)
	return ok && p.PreserveAcrossSaveRestore()
}

type stackLifecycleHook struct {
	preSave func()
	resume  func()
}

// stackExtState owns per-stack extension state so checkpoint and restore
// preserve ipset, netfilter recent tables, and bridge netfilter settings
// without cross-sandbox sharing.
//
// +stateify savable
type stackExtState struct {
	mu                 sync.RWMutex                  `state:"nosave"`
	hooks              map[uint64]stackLifecycleHook `state:"nosave"`
	nextHookID         uint64                        `state:"nosave"`
	postLoadHooks      []func()                      `state:"nosave"`
	loaded             bool                          `state:"nosave"`
	stack              *Stack
	hasBridgeNetfilter bool
	bridgeIPv4         bool
	bridgeIPv6         bool
	values             map[string]any
}

func newStackExtState(s *Stack) *stackExtState {
	return &stackExtState{stack: s, loaded: true}
}

func (e *stackExtState) afterLoad(context.Context) {
	if e.stack != nil && e.hasBridgeNetfilter {
		bridgeNetfilterSwitchesMap.Store(e.stack, bridgeNetfilterSwitches{
			ipv4: e.bridgeIPv4,
			ipv6: e.bridgeIPv6,
		})
	}
}

func (s *Stack) ensureExtState() *stackExtState {
	s.extStateMu.Lock()
	defer s.extStateMu.Unlock()
	if s.extState == nil {
		s.extState = newStackExtState(s)
	}
	return s.extState
}

// RegisterLifecycleHooks registers pre-save and post-save resume callbacks for
// an overlay link endpoint without retaining the endpoint strongly. Callers
// should capture only a weak.Pointer in preSave and resume.
func (s *Stack) RegisterLifecycleHooks(preSave, resume func()) uint64 {
	if s == nil {
		return 0
	}
	e := s.ensureExtState()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.hooks == nil {
		e.hooks = make(map[uint64]stackLifecycleHook)
	}
	e.nextHookID++
	id := e.nextHookID
	e.hooks[id] = stackLifecycleHook{preSave: preSave, resume: resume}
	return id
}

// UnregisterLifecycleHooks removes a previously registered hook pair.
func (s *Stack) UnregisterLifecycleHooks(id uint64) {
	if s == nil || id == 0 {
		return
	}
	e := s.ensureExtState()
	e.mu.Lock()
	delete(e.hooks, id)
	e.mu.Unlock()
}

// ScheduleAfterStackLoad runs fn immediately when s has already completed
// StateLoad, or queues fn until Stack.afterLoad finishes populating protocol
// and port tables.
func (s *Stack) ScheduleAfterStackLoad(fn func()) {
	if s == nil || fn == nil {
		return
	}
	e := s.ensureExtState()
	e.mu.Lock()
	if e.loaded {
		e.mu.Unlock()
		fn()
		return
	}
	e.postLoadHooks = append(e.postLoadHooks, fn)
	e.mu.Unlock()
}

func (s *Stack) runPreSaveHooks() {
	if s == nil {
		return
	}
	e := s.ensureExtState()
	e.mu.RLock()
	fns := make([]func(), 0, len(e.hooks))
	for _, h := range e.hooks {
		if h.preSave != nil {
			fns = append(fns, h.preSave)
		}
	}
	e.mu.RUnlock()
	for _, fn := range fns {
		fn()
	}
}

func (s *Stack) runResumeHooks() {
	if s == nil {
		return
	}
	e := s.ensureExtState()
	e.mu.RLock()
	fns := make([]func(), 0, len(e.hooks))
	for _, h := range e.hooks {
		if h.resume != nil {
			fns = append(fns, h.resume)
		}
	}
	e.mu.RUnlock()
	for _, fn := range fns {
		fn()
	}
}

func (s *Stack) finishExtLoad() {
	if s == nil {
		return
	}
	e := s.ensureExtState()
	e.mu.Lock()
	e.loaded = true
	fns := e.postLoadHooks
	e.postLoadHooks = nil
	e.mu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

// ExtensionState returns the extension value stored under key for s.
func (s *Stack) ExtensionState(key string) (any, bool) {
	if s == nil {
		return nil, false
	}
	e := s.ensureExtState()
	e.mu.RLock()
	v, ok := e.values[key]
	e.mu.RUnlock()
	return v, ok
}

// SetExtensionState stores val under key in the per-stack extension map.
func (s *Stack) SetExtensionState(key string, val any) {
	if s == nil {
		return
	}
	e := s.ensureExtState()
	e.mu.Lock()
	if e.values == nil {
		e.values = make(map[string]any)
	}
	e.values[key] = val
	e.mu.Unlock()
}

// LoadOrStoreExtensionState returns the existing value for key on s, or
// invokes init under the extension lock to populate and return the new value.
func (s *Stack) LoadOrStoreExtensionState(key string, init func() any) any {
	if s == nil {
		return init()
	}
	e := s.ensureExtState()
	e.mu.RLock()
	if v, ok := e.values[key]; ok {
		e.mu.RUnlock()
		return v
	}
	e.mu.RUnlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	if v, ok := e.values[key]; ok {
		return v
	}
	if e.values == nil {
		e.values = make(map[string]any)
	}
	v := init()
	e.values[key] = v
	return v
}
