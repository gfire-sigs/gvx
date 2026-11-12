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

package tcp

import "z.gfire.dev/gvx/pkg/tcpip"

// FreezeSave stops incoming segment queueing before any endpoint resets
// connections during checkpoint.
//
// +checklocksexclude:e.segmentQueue.mu
func (e *Endpoint) FreezeSave() {
	e.segmentQueue.freeze()
}

// PrepareSave terminates connected endpoints whose route does not support
// save/restore before Stack.beforeSave serializes the transport demuxer and
// port table.
//
// +checklocksexclude:e.segmentQueue.mu
// +checklocksexclude:e.pendingProcessingMu
func (e *Endpoint) PrepareSave() {
	e.segmentQueue.freeze()

	e.mu.Lock()
	epState := e.EndpointState()
	if (epState.connected() || epState.handshake()) &&
		!e.stack.GetAllowConnectedOnSave() &&
		!e.route.HasSaveRestoreCapability() &&
		e.stack.GetRemoveConf() &&
		!e.stack.AllowLiveTCPMigration() {
		e.terminateAtRestore = false
		logDisconnect()
		e.resetConnectionLocked(&tcpip.ErrConnectionAborted{})
		e.mu.Unlock()
		e.purgeSegmentQueue()
		e.Close()
		return
	}
	closed := epState.closed()
	e.mu.Unlock()
	if closed {
		e.purgeSegmentQueue()
	}
}

// FinishRestore purges queued segments on endpoints that transitioned to a
// closed or error state during restore.
//
// +checklocksexclude:e.segmentQueue.mu
func (e *Endpoint) FinishRestore() {
	e.mu.Lock()
	closed := e.EndpointState().closed()
	e.mu.Unlock()
	if closed {
		e.purgeSegmentQueue()
	}
}

// +checklocksexclude:e.segmentQueue.mu
func (e *Endpoint) purgeSegmentQueue() {
	for {
		s := e.segmentQueue.dequeue()
		if s == nil {
			break
		}
		s.DecRef()
	}
}
