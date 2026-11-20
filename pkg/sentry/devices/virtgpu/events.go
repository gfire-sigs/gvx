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

package virtgpu

import (
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
)

// eventSink receives renderer events for d. The client calls it on its reader
// goroutine; every method takes d.mu or fenceMu, never both at once, and never
// calls a Renderer method (I-6b.4).
type eventSink struct {
	d *Device
}

var _ gpuproto.EventSink = eventSink{}

// FenceDone implements gpuproto.EventSink.FenceDone.
func (s eventSink) FenceDone(ctxID, ringIdx uint32, fenceID uint64) {
	s.d.mu.Lock()
	c := s.d.contexts[ctxID]
	s.d.mu.Unlock()
	if c != nil {
		c.retire(ringIdx, fenceID)
	}
}

// ContextLost implements gpuproto.EventSink.ContextLost.
func (s eventSink) ContextLost(ctxID uint32) {
	s.d.mu.Lock()
	c := s.d.contexts[ctxID]
	s.d.mu.Unlock()
	if c != nil {
		c.lost.Store(true)
		c.failFences()
	}
}

// RendererLost implements gpuproto.EventSink.RendererLost.
func (s eventSink) RendererLost(err error) {
	s.d.lost.Store(true)

	s.d.mu.Lock()
	ctxs := make([]*fileContext, 0, len(s.d.contexts))
	for _, c := range s.d.contexts {
		ctxs = append(ctxs, c)
	}
	s.d.mu.Unlock()

	for _, c := range ctxs {
		c.lost.Store(true)
		c.failFences()
	}
	log.Warningf("virtgpu: renderer lost: %v", err)
}
