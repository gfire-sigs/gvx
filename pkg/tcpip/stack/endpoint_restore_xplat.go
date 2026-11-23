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
	"z.gfire.dev/gvx/pkg/tcpip"
)

// CheckpointRestoreKey identifies a staged network load in the state context.
// Its value implements CheckpointActivationStager.
type CheckpointRestoreKey struct{}

// CheckpointActivationStager queues rule setup until after validation and
// before any packet can reach the restored stack.
type CheckpointActivationStager interface {
	StageCheckpointActivation(object any, activate func())
	AuthorizeCheckpointActivation(object any)
}

// DeferCheckpointActivation queues a network restore callback with its load.
// Without staging it runs the callback immediately.
func DeferCheckpointActivation(ctx context.Context, object any, activate func()) {
	if stage, ok := ctx.Value(CheckpointRestoreKey{}).(CheckpointActivationStager); ok {
		stage.StageCheckpointActivation(object, activate)
		return
	}
	activate()
}

// AuthorizeCheckpointActivation admits a decoded object that was validated as
// part of this load. An object can be reached from more than one rule.
func AuthorizeCheckpointActivation(ctx context.Context, object any) {
	if stage, ok := ctx.Value(CheckpointRestoreKey{}).(CheckpointActivationStager); ok {
		stage.AuthorizeCheckpointActivation(object)
	}
}

// IsolatedEndpointRestore reports whether endpoint loading uses local barriers.
func IsolatedEndpointRestore(ctx context.Context) bool {
	_, isolated := ctx.Value(CheckpointRestoreKey{}).(CheckpointActivationStager)
	return isolated
}

// EndpointRestoreOrder orders asynchronous restoration within one stack.
// Endpoints reserve addresses in connected, listening, connecting, bound order.
// Async tracks completion of the asynchronous restores before protocol startup.
type EndpointRestoreOrder struct {
	Connected  sync.WaitGroup
	Listening  sync.WaitGroup
	Connecting sync.WaitGroup
	Async      sync.WaitGroup
}

func (s *Stack) countStagedEndpoints(endpoints []RestoredEndpoint) {
	order := s.EndpointRestoreOrder()
	if order == nil {
		return
	}
	for _, ep := range endpoints {
		if tcp, ok := ep.(interface{ CountForStagedRestore(*EndpointRestoreOrder) }); ok {
			tcp.CountForStagedRestore(order)
		}
	}
}

// EndpointRestoreOrder returns the stack's local barriers after decode, or nil
// when it was loaded without staging.
func (s *Stack) EndpointRestoreOrder() *EndpointRestoreOrder {
	if runtime := s.runtimeState(); runtime != nil && runtime.stagedRestore {
		return &runtime.restoreOrder
	}
	return nil
}

// PrepareStagedRestore marks a validated stack so it never waits on the
// process-wide endpoint restore barriers, even if it has no saved endpoints.
func (s *Stack) PrepareStagedRestore() {
	s.ensureRuntimeState().stagedRestore = true
}

func (s *Stack) waitForEndpointRestore() {
	if order := s.EndpointRestoreOrder(); order != nil {
		order.Async.Wait()
	} else {
		tcpip.AsyncLoading.Wait()
	}
}
