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

// SetAllowMartianLoopback sets the route_localnet value of the endpoint. When it
// is true, the endpoint accepts packets with a loopback source or destination
// address, as Linux does for one device with conf/<dev>/route_localnet. The
// protocol option AllowExternalLoopbackTraffic enables the same for every
// endpoint, as conf/all/route_localnet does.
func (e *endpoint) SetAllowMartianLoopback(allow bool) {
	e.allowMartianLoopback.Store(allow)
}

// AllowMartianLoopback returns the value that SetAllowMartianLoopback set.
func (e *endpoint) AllowMartianLoopback() bool {
	return e.allowMartianLoopback.Load()
}
