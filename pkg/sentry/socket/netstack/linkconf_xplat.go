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

package netstack

import (
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
)

// martianLoopbackEndpoint is the per-endpoint route_localnet of the IPv4
// endpoint. See pkg/tcpip/network/ipv4/martian_xplat.go.
type martianLoopbackEndpoint interface {
	SetAllowMartianLoopback(bool)
	AllowMartianLoopback() bool
}

func (s *Stack) martianEndpoint(id int32) (martianLoopbackEndpoint, error) {
	ep, err := s.Stack.GetNetworkEndpoint(tcpip.NICID(id), ipv4.ProtocolNumber)
	if err != nil {
		return nil, syserr.TranslateNetstackError(err).ToError()
	}
	m, ok := ep.(martianLoopbackEndpoint)
	if !ok {
		return nil, syserr.ErrNotSupported.ToError()
	}
	return m, nil
}

// LinkRouteLocalnet returns the route_localnet value of one link.
func (s *Stack) LinkRouteLocalnet(id int32) (bool, error) {
	m, err := s.martianEndpoint(id)
	if err != nil {
		return false, err
	}
	return m.AllowMartianLoopback(), nil
}

// SetLinkRouteLocalnet sets the route_localnet value of one link. The value
// changes the martian filter of that link only.
func (s *Stack) SetLinkRouteLocalnet(id int32, enable bool) error {
	m, err := s.martianEndpoint(id)
	if err != nil {
		return err
	}
	m.SetAllowMartianLoopback(enable)
	return nil
}
