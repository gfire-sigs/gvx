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

package veth

// Restore re-arms the shared packet backlog channel and delivery goroutine on
// a restored veth pair when the pair is still open.
//
// +checklocksexclude:e.veth.mu
func (e *Endpoint) Restore() {
	if e == nil || e.veth == nil {
		return
	}
	v := e.veth
	v.mu.Lock()
	if v.closed || v.backlogQueue != nil {
		v.mu.Unlock()
		return
	}
	q := make(chan vethPacket, DefaultBacklogSize)
	v.backlogQueue = q
	v.mu.Unlock()
	go func() {
		for t := range q {
			t.e.InjectInbound(t.protocol, t.pkt)
			t.pkt.DecRef()
		}
	}()
}
