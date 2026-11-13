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

package stack

import (
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
)

// This file holds the forwarding decisions of a bridge. They follow
// net/bridge/br_input.c of Linux: a frame for the bridge itself never leaves
// the bridge, a known unicast address has one egress port, and only a group
// address or an unknown unicast address goes to every port.

// needsLearningLocked reports whether the FDB must record that the source
// address of a frame lives behind port from. A new address needs an entry, and
// an address that moved to another port needs a new entry, as when a MAC
// address changes its port. A group address is never a source address.
//
// +checklocksread:b.mu
func (b *BridgeEndpoint) needsLearningLocked(src tcpip.LinkAddress, from *bridgePort) bool {
	if header.IsMulticastEthernetAddress(src) || b.isLocalAddressLocked(src) || b.ports[from.nic.id] != from {
		return false
	}
	entry, ok := b.fdbTable[BridgeFDBKey(src)]
	return !ok || entry.port != from
}

// forwardTargetsLocked returns the ports that receive a frame with destination
// address dst from port from. A frame for the bridge address or for the address
// of any port goes up to the IP layer only. A known unicast address
// has the port of its FDB entry, unless that port is from. Any other frame goes
// to every port except from.
//
// +checklocksread:b.mu
func (b *BridgeEndpoint) forwardTargetsLocked(from *bridgePort, dst tcpip.LinkAddress) []*bridgePort {
	if b.isLocalAddressLocked(dst) {
		return nil
	}
	if entry, ok := b.fdbTable[BridgeFDBKey(dst)]; ok && !header.IsMulticastEthernetAddress(dst) {
		if entry.port == from {
			return nil
		}
		return []*bridgePort{entry.port}
	}
	targets := make([]*bridgePort, 0, len(b.ports))
	for _, port := range b.ports {
		if port != from {
			targets = append(targets, port)
		}
	}
	return targets
}

// egressTargetsLocked returns the ports that receive a frame that the IP layer
// of the bridge sends to the link address dst. A known unicast address has one
// port, which can be the port of the original sender of a DNAT-ed packet. Any
// other frame goes to every port.
//
// +checklocksread:b.mu
func (b *BridgeEndpoint) egressTargetsLocked(dst tcpip.LinkAddress) []*bridgePort {
	if len(dst) == header.EthernetAddressSize && !header.IsMulticastEthernetAddress(dst) {
		if entry, ok := b.fdbTable[BridgeFDBKey(dst)]; ok {
			return []*bridgePort{entry.port}
		}
	}
	targets := make([]*bridgePort, 0, len(b.ports))
	for _, port := range b.ports {
		targets = append(targets, port)
	}
	return targets
}

// IsBridgePort reports whether d is the dispatcher that a bridge gives to the
// link endpoint of one of its ports.
func IsBridgePort(d NetworkDispatcher) bool {
	_, ok := d.(*bridgePort)
	return ok
}
