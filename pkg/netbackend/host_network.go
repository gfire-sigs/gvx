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

package netbackend

import (
	"net"
	"net/netip"
)

// DatagramSocket preserves UDP address information across a socket broker.
type DatagramSocket interface {
	net.PacketConn
	ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
}

// HostNetwork supplies sockets for port forwarders. Nil functions use the host network.
// The forwarder owns each returned listener or packet socket.
type HostNetwork struct {
	Listen       func(network, address string) (net.Listener, error)
	ListenPacket func(network, address string) (net.PacketConn, error)
}

func (n HostNetwork) listen(network, address string) (net.Listener, error) {
	if n.Listen != nil {
		return n.Listen(network, address)
	}
	return net.Listen(network, address)
}
func (n HostNetwork) listenPacket(network, address string) (net.PacketConn, error) {
	if n.ListenPacket != nil {
		return n.ListenPacket(network, address)
	}
	return net.ListenPacket(network, address)
}
