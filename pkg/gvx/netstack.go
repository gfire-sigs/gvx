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
	"os"
	"strconv"

	"z.gfire.dev/gvx/pkg/netbackend"
)

// initNetstack builds the Netstack for the configured mode and pre-binds
// every host socket that must outlive the lockdown.
func (s *Sandbox) initNetstack() error {
	switch s.cfg.NetworkMode {
	case NetModeNone:
		st, err := netbackend.NewLoopbackStack()
		if err != nil {
			return err
		}
		s.netStack = st
		return nil

	case NetModeNAT:
		st, fwd, err := netbackend.NewNATStack(netbackend.NATConfig{
			IsolateLAN:        s.cfg.IsolateLAN,
			StreamInterceptor: s.cfg.StreamInterceptor,
		})
		if err != nil {
			return err
		}
		s.netStack = st
		s.natForwarder = fwd

		s.forwards = s.effectivePortForwards()
		if len(s.forwards) > 0 {
			pf := netbackend.NewPortForwarder()
			rules := make([]netbackend.PortForwardRule, 0, len(s.forwards))
			for _, pfSpec := range s.forwards {
				hostIP := pfSpec.BindAddress
				if hostIP == "" {
					hostIP = "127.0.0.1"
				}
				rules = append(rules, netbackend.PortForwardRule{
					Proto:     pfSpec.Protocol,
					HostIP:    hostIP,
					HostPort:  pfSpec.HostPort,
					GuestIP:   netbackend.DefaultGuestIPv4,
					GuestPort: pfSpec.GuestPort,
				})
			}
			if err := pf.PreBind(rules); err != nil {
				_ = pf.Close()
				return err
			}
			s.portForwarder = pf
		}
		return nil

	case NetModeWireGuard:
		wgCfg := s.cfg.WireGuardConfig
		if wgCfg == nil {
			rawINI, err := os.ReadFile(s.cfg.WireGuardConfigPath)
			if err != nil {
				return fmt.Errorf("gvx: read WireGuard config %q: %w", s.cfg.WireGuardConfigPath, err)
			}
			parsed, err := netbackend.ParseWireGuardINI(string(rawINI))
			if err != nil {
				return err
			}
			wgCfg = &parsed
		}
		peerPort, err := wireGuardPeerPort(wgCfg.PeerEndpoint)
		if err != nil {
			return err
		}
		if peerPort == 0 && !s.cfg.DisableHostLockdown {
			return fmt.Errorf("%w: network mode %q with host lockdown needs a peer Endpoint to pin the outbound UDP port; set the Endpoint or DisableHostLockdown", ErrInvalidConfig, NetModeWireGuard)
		}
		wgEP, err := netbackend.NewWireGuardEndpoint(*wgCfg)
		if err != nil {
			return err
		}
		if err := wgEP.PreBindUDP(); err != nil {
			_ = wgEP.Close()
			return err
		}
		st, err := wgEP.Start()
		if err != nil {
			_ = wgEP.Close()
			return err
		}
		s.wgEndpoint = wgEP
		s.wgPeerPort = peerPort
		s.netStack = st
		return nil

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
