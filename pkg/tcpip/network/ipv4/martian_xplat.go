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

package ipv4

import (
	"sync"

	"z.gfire.dev/gvx/pkg/tcpip"
)

const martianLoopbackExtKey = "ipv4/route_localnet"

// martianLoopbackState tracks per-NIC route_localnet settings inside the
// owning stack's extension state so endpoint and ipv4_state_autogen.go stay
// free of gvx-only fields while preserving checkpoint/restore isolation.
//
// +stateify savable
type martianLoopbackState struct {
	mu      sync.RWMutex `state:"nosave"`
	enabled map[tcpip.NICID]bool
}

func (e *endpoint) martianState(create bool) *martianLoopbackState {
	if e == nil || e.protocol == nil || e.protocol.stack == nil || e.nic == nil {
		return nil
	}
	if !create {
		raw, ok := e.protocol.stack.ExtensionState(martianLoopbackExtKey)
		if !ok {
			return nil
		}
		st, _ := raw.(*martianLoopbackState)
		return st
	}
	raw := e.protocol.stack.LoadOrStoreExtensionState(martianLoopbackExtKey, func() any {
		return &martianLoopbackState{
			enabled: make(map[tcpip.NICID]bool),
		}
	})
	st, _ := raw.(*martianLoopbackState)
	return st
}

// SetAllowMartianLoopback sets the route_localnet value of the endpoint. When it
// is true, the endpoint accepts packets with a loopback source or destination
// address, as Linux does for one device with conf/<dev>/route_localnet. The
// protocol option AllowExternalLoopbackTraffic enables the same for every
// endpoint, as conf/all/route_localnet does.
func (e *endpoint) SetAllowMartianLoopback(allow bool) {
	st := e.martianState(allow)
	if st == nil {
		return
	}
	id := e.nic.ID()
	st.mu.Lock()
	if allow {
		if st.enabled == nil {
			st.enabled = make(map[tcpip.NICID]bool)
		}
		st.enabled[id] = true
	} else {
		delete(st.enabled, id)
	}
	st.mu.Unlock()
}

// AllowMartianLoopback returns the value that SetAllowMartianLoopback set.
func (e *endpoint) AllowMartianLoopback() bool {
	st := e.martianState(false)
	if st == nil {
		return false
	}
	id := e.nic.ID()
	st.mu.RLock()
	allowed := st.enabled[id]
	st.mu.RUnlock()
	return allowed
}

func (e *endpoint) clearMartianLoopback() {
	st := e.martianState(false)
	if st == nil {
		return
	}
	id := e.nic.ID()
	st.mu.Lock()
	delete(st.enabled, id)
	st.mu.Unlock()
}
