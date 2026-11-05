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

package netfilter

import (
	"encoding/binary"

	"z.gfire.dev/gvx/pkg/ipset"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// Protocol numbers that the extraction of ports needs.
const (
	ipsetProtoICMP    = 1
	ipsetProtoTCP     = 6
	ipsetProtoUDP     = 17
	ipsetProtoICMPv6  = 58
	ipsetProtoSCTP    = 132
	ipsetProtoUDPLite = 136

	// The extension headers of IPv6 that ipv6_skip_exthdr of Linux skips.
	ipsetExtHopByHop = 0
	ipsetExtRouting  = 43
	ipsetExtFragment = 44
	ipsetExtAuth     = 51
	ipsetExtNone     = 59
	ipsetExtDestOpts = 60

	// The sizes of the headers that Linux reads to get the ports.
	ipsetSCTPPortsSize = 12
	ipsetICMPSize      = 8
	ipsetFragmentSize  = 8
)

// ipsetPacket builds the fields of a packet that the set types read. It
// follows ip_set_get_ip4_port, ip_set_get_ip6_port, and get_port of Linux.
// It reports false when the packet has no valid network header.
//
// The transport header of the packet buffer is empty for a fragment and
// before the stack parses the packet. In that case the function reads the
// transport header from the data of the packet.
func ipsetPacket(pkt *stack.PacketBuffer) (ipset.Packet, bool) {
	out := ipset.Packet{Len: uint32(max(pkt.Size()-len(pkt.LinkHeader().Slice()), 0))}
	netHdr := pkt.NetworkHeader().Slice()
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		if len(netHdr) < header.IPv4MinimumSize {
			return ipset.Packet{}, false
		}
		hdr := header.IPv4(netHdr)
		out.Family = ipset.FamilyIPv4
		src, dst := hdr.SourceAddress().As4(), hdr.DestinationAddress().As4()
		copy(out.Src[:], src[:])
		copy(out.Dst[:], dst[:])
		ipsetPorts4(pkt, hdr, &out)
	case header.IPv6ProtocolNumber:
		if len(netHdr) < header.IPv6MinimumSize {
			return ipset.Packet{}, false
		}
		hdr := header.IPv6(netHdr)
		out.Family = ipset.FamilyIPv6
		out.Src = ipset.Addr(hdr.SourceAddress().As16())
		out.Dst = ipset.Addr(hdr.DestinationAddress().As16())
		ipsetPorts6(pkt, netHdr, &out)
	default:
		return ipset.Packet{}, false
	}
	return out, true
}

// ipsetPorts4 fills the protocol and the ports of an IPv4 packet.
func ipsetPorts4(pkt *stack.PacketBuffer, hdr header.IPv4, out *ipset.Packet) {
	proto := hdr.Protocol()
	// Linux gives no port information for the protocol 0.
	if proto == 0 {
		return
	}
	if hdr.FragmentOffset() != 0 {
		switch proto {
		case ipsetProtoTCP, ipsetProtoSCTP, ipsetProtoUDP, ipsetProtoUDPLite, ipsetProtoICMP:
			// A fragment that does not start at offset zero has no ports.
			return
		}
		// Other protocols have no ports, so a fragment can match.
		out.Proto, out.PortsOK = proto, true
		return
	}
	ipsetFillPorts(pkt, 0, proto, out)
}

// ipsetPorts6 fills the protocol and the ports of an IPv6 packet. The network
// header of the packet buffer holds the IPv6 header and the extension headers
// that precede the transport header or a fragment header.
func ipsetPorts6(pkt *stack.PacketBuffer, netHdr []byte, out *ipset.Packet) {
	next := netHdr[6]
	off := header.IPv6MinimumSize
	// skip is the count of bytes between the start of the data of the packet
	// and the transport header.
	skip := 0
walk:
	for {
		switch next {
		case ipsetExtHopByHop, ipsetExtRouting, ipsetExtDestOpts, ipsetExtAuth:
			if off+2 > len(netHdr) {
				return
			}
			length := (int(netHdr[off+1]) + 1) * 8
			if next == ipsetExtAuth {
				length = (int(netHdr[off+1]) + 2) * 4
			}
			next = netHdr[off]
			off += length
			if off > len(netHdr) {
				return
			}
		case ipsetExtFragment:
			// The fragment header is in the data of the packet when the
			// stack stops the network header before it.
			var frag []byte
			if off+ipsetFragmentSize <= len(netHdr) {
				frag = netHdr[off : off+ipsetFragmentSize]
				off += ipsetFragmentSize
			} else if off == len(netHdr) {
				b, ok := pkt.Data().PullUp(ipsetFragmentSize)
				if !ok {
					return
				}
				frag = b[:ipsetFragmentSize]
				skip = ipsetFragmentSize
			} else {
				return
			}
			if binary.BigEndian.Uint16(frag[2:])&^7 != 0 {
				// Linux finds no ports in a fragment that does not start at
				// offset zero, whatever its protocol is.
				out.Proto = ipsetExtFragment
				return
			}
			next = frag[0]
		case ipsetExtNone:
			return
		default:
			break walk
		}
	}
	ipsetFillPorts(pkt, skip, next, out)
}

// ipsetFillPorts reads the ports of protocol proto from the transport header
// at skip bytes into the data of the packet. It is get_port of Linux.
func ipsetFillPorts(pkt *stack.PacketBuffer, skip int, proto uint8, out *ipset.Packet) {
	need := 0
	switch proto {
	case ipsetProtoTCP:
		need = header.TCPMinimumSize
	case ipsetProtoSCTP:
		need = ipsetSCTPPortsSize
	case ipsetProtoUDP, ipsetProtoUDPLite:
		need = header.UDPMinimumSize
	case ipsetProtoICMP, ipsetProtoICMPv6:
		need = ipsetICMPSize
	}
	if need == 0 {
		out.Proto, out.PortsOK = proto, true
		return
	}
	b := ipsetTransportBytes(pkt, skip, need)
	if b == nil {
		return
	}
	switch proto {
	case ipsetProtoICMP, ipsetProtoICMPv6:
		out.SrcPort = uint16(b[0])<<8 | uint16(b[1])
		out.DstPort = out.SrcPort
	default:
		out.SrcPort = binary.BigEndian.Uint16(b[0:])
		out.DstPort = binary.BigEndian.Uint16(b[2:])
	}
	out.Proto, out.PortsOK = proto, true
}

// ipsetTransportBytes returns at least need bytes of the transport header, or
// nil when the packet has fewer. The stack stores a parsed transport header
// apart from the data. Otherwise the header starts skip bytes into the data.
func ipsetTransportBytes(pkt *stack.PacketBuffer, skip, need int) []byte {
	if hdr := pkt.TransportHeader().Slice(); len(hdr) > 0 && skip == 0 {
		if len(hdr) < need {
			return nil
		}
		return hdr
	}
	b, ok := pkt.Data().PullUp(skip + need)
	if !ok {
		return nil
	}
	return b[skip:]
}
