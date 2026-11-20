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

package hostlockdown

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// DialContext dials an outbound host network connection. On Windows after Apply
// with Options.AllowOutboundNet enabled, TCP and UDP dials execute on the
// Low-integrity socket broker so sandbox threads keep NULL_SID restriction.
func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return dialHostContext(ctx, network, address)
}

// AcceptListener accepts one inbound connection from a pre-bound listener. On
// Windows, AcceptEx allocates a new acceptor socket handle, so locked-down NAT
// sandboxes run the accept on the Low-integrity socket broker.
func AcceptListener(ln net.Listener) (net.Conn, error) {
	return acceptHostListener(ln)
}

// ListenLoopback binds a TCP listener on a host loopback address (127.0.0.1 or
// ::1). After Apply, it requires Options.AllowOutboundNet and
// Options.AllowLoopbackBind.
func ListenLoopback(network, address string) (net.Listener, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("hostlockdown: ListenLoopback rejects network %q", network)
	}
	if err := validateLoopbackBind(address); err != nil {
		return nil, err
	}
	if IsLockedDown() && !loopbackBindAllowed.Load() {
		return nil, errors.New("hostlockdown: loopback bind is disabled")
	}
	return listenHostLoopback(network, address)
}

// ListenPacketLoopback binds a UDP packet socket on a host loopback address
// (127.0.0.1 or ::1). After Apply, it requires Options.AllowOutboundNet and
// Options.AllowLoopbackBind.
func ListenPacketLoopback(network, address string) (net.PacketConn, error) {
	switch network {
	case "udp", "udp4", "udp6":
	default:
		return nil, fmt.Errorf("hostlockdown: ListenPacketLoopback rejects network %q", network)
	}
	if err := validateLoopbackBind(address); err != nil {
		return nil, err
	}
	if IsLockedDown() && !loopbackBindAllowed.Load() {
		return nil, errors.New("hostlockdown: loopback bind is disabled")
	}
	return listenHostPacketLoopback(network, address)
}

func validateLoopbackBind(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("hostlockdown: invalid loopback bind address %q: %w", address, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsLoopback() {
		return fmt.Errorf("hostlockdown: bind address %q is not a loopback IP", address)
	}
	return nil
}
