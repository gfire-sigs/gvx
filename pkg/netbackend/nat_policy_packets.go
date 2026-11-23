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
	"encoding/binary"
	"net/netip"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// A cursor borrows the wire bytes. It copies a header only when it spans views.
type natPacketCursor struct {
	view      *buffer.View
	offset    int
	remaining int
}

func (c *natPacketCursor) skip(n int) {
	c.remaining -= n
	for c.view != nil {
		left := c.view.Size() - c.offset
		if n < left {
			c.offset += n
			return
		}
		n -= left
		c.view = c.view.Next()
		c.offset = 0
	}
}

func (c *natPacketCursor) take(n int, scratch []byte) []byte {
	if n > c.remaining || c.view == nil {
		return nil
	}
	if data := c.view.AsSlice()[c.offset:]; len(data) >= n {
		c.skip(n)
		return data[:n]
	}
	for copied := 0; copied < n; {
		count := copy(scratch[copied:n], c.view.AsSlice()[c.offset:])
		c.skip(count)
		copied += count
	}
	return scratch[:n]
}

func natPacketPolicyFlow(pkt *stack.PacketBuffer, direction NATPolicyDirection) (NATPolicyFlow, bool) {
	views, start := pkt.AsViewList()
	c := natPacketCursor{view: views.Front(), remaining: pkt.Size() + start}
	c.skip(start + len(pkt.LinkHeader().Slice()))

	flow := NATPolicyFlow{Direction: direction}
	// The host parser supplies the header after reassembly. The IPv6 wire
	// header can still describe only the first fragment at that point.
	transportHeader := pkt.TransportHeader().Slice()
	parsed := direction == NATPolicyEgress && pkt.NATInput() != nil && len(transportHeader) != 0
	var scratch [header.IPv6MinimumSize]byte
	var src, dst netip.Addr
	var transport bool
	size := c.remaining
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		h := header.IPv4(c.take(header.IPv4MinimumSize, scratch[:]))
		if !h.IsValid(size) {
			return NATPolicyFlow{}, false
		}
		src, dst = netip.AddrFrom4(h.SourceAddress().As4()), netip.AddrFrom4(h.DestinationAddress().As4())
		c.remaining = int(h.TotalLength()) - header.IPv4MinimumSize
		c.skip(int(h.HeaderLength()) - header.IPv4MinimumSize)
		flow.Protocol, transport = h.Protocol(), h.FragmentOffset() == 0
	case header.IPv6ProtocolNumber:
		h := header.IPv6(c.take(header.IPv6MinimumSize, scratch[:]))
		if !h.IsValid(size) {
			return NATPolicyFlow{}, false
		}
		src, dst = netip.AddrFrom16(h.SourceAddress().As16()), netip.AddrFrom16(h.DestinationAddress().As16())
		if parsed {
			flow.Protocol = uint8(pkt.TransportProtocolNumber)
			natPacketServicePort(&flow, transportHeader)
			break
		}
		c.remaining = int(h.PayloadLength())
		var valid bool
		flow.Protocol, transport, valid = natIPv6PacketProtocol(&c, h.NextHeader(), scratch[:])
		if !valid {
			return NATPolicyFlow{}, false
		}
	default:
		return NATPolicyFlow{}, false
	}
	if transport {
		switch tcpip.TransportProtocolNumber(flow.Protocol) {
		case header.TCPProtocolNumber:
			natPacketServicePort(&flow, c.take(header.TCPMinimumSize, scratch[:]))
		case header.UDPProtocolNumber:
			natPacketServicePort(&flow, c.take(header.UDPMinimumSize, scratch[:]))
		}
	}
	flow.Guest, flow.Remote = src, dst
	if direction == NATPolicyIngress {
		flow.Guest, flow.Remote = dst, src
	}
	return flow, true
}

func natPacketServicePort(flow *NATPolicyFlow, transport []byte) {
	switch tcpip.TransportProtocolNumber(flow.Protocol) {
	case header.TCPProtocolNumber:
		if len(transport) < header.TCPMinimumSize || header.TCP(transport).DataOffset() < header.TCPMinimumSize {
			return
		}
	case header.UDPProtocolNumber:
		if len(transport) < header.UDPMinimumSize || header.UDP(transport).Length() < header.UDPMinimumSize {
			return
		}
	default:
		return
	}
	flow.Port, flow.PortKnown = binary.BigEndian.Uint16(transport[2:4]), true
}

func natIPv6PacketProtocol(c *natPacketCursor, next uint8, scratch []byte) (protocol uint8, transport, valid bool) {
	const maxExtensionBytes = 256
	const maxExtensionCount = 8
	var walked, count int
	fragmented := false
	for natIPv6Extension(next) {
		if count == maxExtensionCount || walked >= maxExtensionBytes {
			return 0, false, false
		}
		count++
		id := header.IPv6ExtensionHeaderIdentifier(next)
		if id == header.IPv6FragmentExtHdrIdentifier {
			f := c.take(header.IPv6FragmentExtHdrLength, scratch)
			if f == nil || fragmented || f[1] != 0 || f[3]&6 != 0 {
				return 0, false, false
			}
			fragmented, next = true, f[0]
			if binary.BigEndian.Uint16(f[2:4])&^uint16(7) != 0 {
				if natIPv6Extension(next) {
					return 0, false, true
				}
				return next, false, true
			}
			walked += header.IPv6FragmentExtHdrLength
			continue
		}
		if (id == header.IPv6HopByHopOptionsExtHdrIdentifier && walked != 0) ||
			(id == header.IPv6RoutingExtHdrIdentifier && fragmented) {
			return 0, false, false
		}
		h := c.take(2, scratch)
		if h == nil {
			return 0, false, false
		}
		next = h[0]
		length := (int(h[1]) + 1) * 8
		switch id {
		case header.IPv6AuthenticationExtHdrIdentifier:
			length = (int(h[1]) + 2) * 4
			if length < 12 || length%8 != 0 {
				return 0, false, false
			}
		case header.IPv6ExperimentExtHdrIdentifier:
			if h[1] != 0 {
				return 0, false, false
			}
			length = header.IPv6ExperimentHdrLength
		}
		if length > maxExtensionBytes-walked || length-2 > c.remaining {
			return 0, false, false
		}
		walked += length
		c.skip(length - 2)
	}
	return next, true, true
}

func natIPv6Extension(next uint8) bool {
	id := header.IPv6ExtensionHeaderIdentifier(next)
	return id == header.IPv6ExperimentExtHdrIdentifier ||
		(id != header.IPv6NoNextHeaderIdentifier && header.IsExtensionHeader(next))
}
