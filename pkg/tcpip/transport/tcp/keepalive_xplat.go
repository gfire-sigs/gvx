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

const keepaliveDefaultsExtKey = "tcp/keepalive_defaults"

// setKeepaliveDefaults sets the keepalive parameters that new endpoints start
// with. Each field must be above zero.
func (p *protocol) setKeepaliveDefaults(v tcpip.TCPKeepaliveDefaultsOption) tcpip.Error {
	if v.Idle <= 0 || v.Interval <= 0 || v.Count <= 0 {
		return &tcpip.ErrInvalidOptionValue{}
	}
	if p.stack != nil {
		cp := v
		p.stack.SetExtensionState(keepaliveDefaultsExtKey, &cp)
	}
	return nil
}

// getKeepaliveDefaults returns the keepalive parameters of new endpoints. When
// unset, it returns the built-in defaults.
func (p *protocol) getKeepaliveDefaults() tcpip.TCPKeepaliveDefaultsOption {
	if p.stack != nil {
		if raw, ok := p.stack.ExtensionState(keepaliveDefaultsExtKey); ok {
			if v, ok := raw.(*tcpip.TCPKeepaliveDefaultsOption); ok && v != nil && *v != (tcpip.TCPKeepaliveDefaultsOption{}) {
				return *v
			}
		}
	}
	return tcpip.TCPKeepaliveDefaultsOption{
		Idle:     DefaultKeepaliveIdle,
		Interval: DefaultKeepaliveInterval,
		Count:    DefaultKeepaliveCount,
	}
}

// keepaliveParameters returns the keepalive parameters of a new endpoint.
func (p *protocol) keepaliveParameters() (idle, interval time.Duration, count int) {
	v := p.getKeepaliveDefaults()
	return v.Idle, v.Interval, v.Count
}
