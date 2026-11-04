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

import (
	"time"

	"z.gfire.dev/gvx/pkg/tcpip"
)

// setKeepaliveDefaults sets the keepalive parameters that new endpoints start
// with. Each field must be above zero.
func (p *protocol) setKeepaliveDefaults(v tcpip.TCPKeepaliveDefaultsOption) tcpip.Error {
	if v.Idle <= 0 || v.Interval <= 0 || v.Count <= 0 {
		return &tcpip.ErrInvalidOptionValue{}
	}
	p.mu.Lock()
	p.keepaliveDefaults = v
	p.mu.Unlock()
	return nil
}

// getKeepaliveDefaults returns the keepalive parameters of new endpoints. The
// field is zero until a write sets it, and after a restore from a saved state,
// because state saving skips it. A zero field gives the built-in defaults.
func (p *protocol) getKeepaliveDefaults() tcpip.TCPKeepaliveDefaultsOption {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.keepaliveDefaults == (tcpip.TCPKeepaliveDefaultsOption{}) {
		return tcpip.TCPKeepaliveDefaultsOption{
			Idle:     DefaultKeepaliveIdle,
			Interval: DefaultKeepaliveInterval,
			Count:    DefaultKeepaliveCount,
		}
	}
	return p.keepaliveDefaults
}

// keepaliveParameters returns the keepalive parameters of a new endpoint.
func (p *protocol) keepaliveParameters() (idle, interval time.Duration, count int) {
	v := p.getKeepaliveDefaults()
	return v.Idle, v.Interval, v.Count
}
