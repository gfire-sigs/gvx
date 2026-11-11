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

package kernel

import (
	"context"
	"weak"

	"z.gfire.dev/gvx/pkg/sync"
)

const kernelExtStateKey = "gvx.kernelExt"

// kernelExtState owns savable per-Kernel state inside
// Kernel.additionalCheckpointState so checkpoint and restore preserve reported
// memory, kernel log rings, and per-Kernel module or sysctl tables without
// editing kernel.go.
//
// +stateify savable
type kernelExtState struct {
	mu                sync.RWMutex `state:"nosave"`
	kernel            *Kernel
	hasReportedMemory bool
	reportedMemory    uint64
	logEntry          *kernelLogEntry
	values            map[string]any
}

func (e *kernelExtState) afterLoad(context.Context) {
	if e.kernel == nil {
		return
	}
	if e.hasReportedMemory {
		reportedTotals.Store(e.kernel, e.reportedMemory)
	}
	if e.logEntry != nil {
		if e.logEntry.log != nil {
			e.logEntry.log.now = kernelUptimeFunc(weak.Make(e.kernel))
		}
		kernelLogs.Store(e.kernel, e.logEntry)
	}
}

// +checklocksexclude:k.checkpointMu
// +checklocksexclude:k.CheckpointWait.mu
func (k *Kernel) ensureExtState() *kernelExtState {
	k.checkpointMu.Lock()
	defer k.checkpointMu.Unlock()
	if k.additionalCheckpointState == nil {
		k.additionalCheckpointState = make(map[any]any)
	}
	if existing, ok := k.additionalCheckpointState[kernelExtStateKey].(*kernelExtState); ok && existing != nil {
		return existing
	}
	e := &kernelExtState{kernel: k}
	k.additionalCheckpointState[kernelExtStateKey] = e
	return e
}

// ExtensionState returns the extension value stored under key for k.
//
// +checklocksexclude:k.checkpointMu
// +checklocksexclude:k.CheckpointWait.mu
func (k *Kernel) ExtensionState(key string) (any, bool) {
	if k == nil {
		return nil, false
	}
	e := k.ensureExtState()
	e.mu.RLock()
	v, ok := e.values[key]
	e.mu.RUnlock()
	return v, ok
}

// SetExtensionState stores val under key in the per-Kernel extension map.
//
// +checklocksexclude:k.checkpointMu
// +checklocksexclude:k.CheckpointWait.mu
func (k *Kernel) SetExtensionState(key string, val any) {
	if k == nil {
		return
	}
	e := k.ensureExtState()
	e.mu.Lock()
	if e.values == nil {
		e.values = make(map[string]any)
	}
	e.values[key] = val
	e.mu.Unlock()
}

// LoadOrStoreExtensionState returns the existing value for key on k, or
// invokes init under the extension lock to populate and return the new value.
//
// +checklocksexclude:k.checkpointMu
// +checklocksexclude:k.CheckpointWait.mu
func (k *Kernel) LoadOrStoreExtensionState(key string, init func() any) any {
	if k == nil {
		return init()
	}
	e := k.ensureExtState()
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
