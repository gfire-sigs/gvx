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

package gvx

import (
	"fmt"
	"net"
	"strconv"

	"z.gfire.dev/gvx/pkg/netbackend"
	"z.gfire.dev/gvx/pkg/sentry/socket/netfilter"
)

// stackOptions returns the guest network stack features that the Config
// selects.
func (s *Sandbox) stackOptions() netbackend.StackOptions {
	opts := netbackend.StackOptions{
		RawSockets:        s.cfg.NetRaw,
		PacketSocketWrite: s.cfg.AllowPacketSocketWrite,
	}
	if s.cfg.NetRaw {
		opts.IPTables = netfilter.DefaultLinuxTables
	}
	return opts
}

// initNetstack builds the Netstack for the configured mode and pre-binds
// every host socket that must outlive the lockdown.
func (s *Sandbox) initNetstack() error {
	switch s.cfg.NetworkMode {
	case NetModeNone:
		st, err := netbackend.NewLoopbackStack(s.stackOptions())
		if err != nil {
			return err
		}
		s.netStack = st
		return nil

	case NetModeNAT:
		return s.initNATStack()

	case NetModeWireGuard:
		return s.initWireGuardStack()

	default:
		return fmt.Errorf("gvx: unsupported network mode %q", s.cfg.NetworkMode)
	}
}

// wireGuardPeerPort returns the UDP port of a "host:port" peer endpoint. An
// empty endpoint returns port 0.
func wireGuardPeerPort(endpoint string) (uint16, error) {
	if endpoint == "" {
		return 0, nil
	}
	_, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return 0, fmt.Errorf("%w: WireGuard peer endpoint %q: %w", ErrInvalidConfig, endpoint, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("%w: WireGuard peer endpoint %q needs a numeric UDP port in 1..65535", ErrInvalidConfig, endpoint)
	}
	return uint16(port), nil
}
