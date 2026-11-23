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
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

const (
	maxPolicyIPv6Extensions     = 8
	maxPolicyIPv6ExtensionBytes = 256
)

// A cursor borrows packet views without PullUp or consuming a header. It copies
// only a header field that crosses a view boundary.
type policyPacketCursor struct {
	view      *buffer.View
	offset    int
	remaining int
}

func (c *policyPacketCursor) take(n int, scratch []byte) []byte {
	if n > c.remaining || c.view == nil {
		return nil
	}
	data := c.view.AsSlice()[c.offset:]
	if n <= len(data) {
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

func (c *policyPacketCursor) skip(n int) {
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

type policyIPPacket struct {
	tuple   PolicyTuple
	ipBytes int
}

func policyPacketTuple(pkt *stack.PacketBuffer) (PolicyTuple, bool) {
	tuple, _, ok := policyPacketDetails(pkt)
	return tuple, ok
}

// policyPacketDetails does not trust transport metadata. INPUT can run before
// reassembly, and raw writes can leave both header slots unset.
func policyPacketDetails(pkt *stack.PacketBuffer) (PolicyTuple, int, bool) {
	views, start := pkt.AsViewList()
	c := policyPacketCursor{view: views.Front(), remaining: pkt.Size() + start}
	c.skip(start + len(pkt.LinkHeader().Slice()))
	var ip policyIPPacket
	var ok bool
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		ok = parsePolicyIPv4(&c, &ip)
	case header.IPv6ProtocolNumber:
		ok = parsePolicyIPv6(&c, &ip)
	}
	if !ok {
		return PolicyTuple{}, 0, false
	}
	return ip.tuple, ip.ipBytes, true
}

// policyInputTuple uses the fields validated before delivery changed the
// buffer. Reassembled UDP may have been trimmed to its transport length;
// the wire-byte count still includes every byte contributed by its fragments.
func policyInputTuple(pkt *stack.PacketBuffer) PolicyTuple {
	input := &pkt.PacketPolicy().Ingress
	network := pkt.Network()
	localSource, localDestination := network.SourceAddress(), network.DestinationAddress()
	source, _ := netip.AddrFromSlice(localSource.AsSlice())
	destination, _ := netip.AddrFromSlice(localDestination.AsSlice())
	tuple := PolicyTuple{
		IPv6:                 pkt.NetworkProtocolNumber == header.IPv6ProtocolNumber,
		Protocol:             uint8(input.Protocol),
		ProtocolKnown:        input.ProtocolKnown,
		Source:               source,
		Destination:          destination,
		SourcePort:           input.SourcePort,
		DestinationPort:      input.DestinationPort,
		SourcePortKnown:      input.SourcePortKnown,
		DestinationPortKnown: input.DestinationPortKnown,
	}
	if hdr := pkt.TransportHeader().Slice(); input.Reassembled && len(hdr) >= 4 &&
		(input.Protocol == header.UDPProtocolNumber || input.Protocol == header.TCPProtocolNumber) &&
		pkt.TransportProtocolNumber == input.Protocol {
		tuple.SourcePort, tuple.DestinationPort = binary.BigEndian.Uint16(hdr[:2]), binary.BigEndian.Uint16(hdr[2:4])
		tuple.SourcePortKnown, tuple.DestinationPortKnown = true, true
	}
	return tuple
}

func parsePolicyIPv4(c *policyPacketCursor, ip *policyIPPacket) bool {
	var scratch [header.IPv4MaximumHeaderSize]byte
	available := c.remaining
	h := header.IPv4(c.take(header.IPv4MinimumSize, scratch[:]))
	if !h.IsValid(available) {
		return false
	}
	headerLen := int(h.HeaderLength())
	ip.tuple = PolicyTuple{
		Source:        netip.AddrFrom4(h.SourceAddress().As4()),
		Destination:   netip.AddrFrom4(h.DestinationAddress().As4()),
		Protocol:      h.Protocol(),
		ProtocolKnown: true,
	}
	ip.ipBytes = int(h.TotalLength())
	payloadLen := ip.ipBytes - headerLen
	offset, more := int(h.FragmentOffset()), h.More()
	flags := h.Flags()
	fragment := offset != 0 || more
	// Netstack can preserve DF on locally generated fragments. The offset
	// and MF determine whether the received bytes need reassembly.
	if flags&^uint8(header.IPv4FlagDontFragment|header.IPv4FlagMoreFragments) != 0 ||
		(fragment && !validPolicyFragment(offset, payloadLen, 65535-headerLen, more)) {
		return false
	}
	c.remaining = ip.ipBytes - header.IPv4MinimumSize
	if optionLen := headerLen - header.IPv4MinimumSize; optionLen > 0 {
		options := c.take(optionLen, scratch[:])
		if !validPolicyIPv4Options(options) {
			return false
		}
	}
	return offset != 0 || policyPacketPorts(c, &ip.tuple, more, scratch[:])
}

func validPolicyIPv4Options(options []byte) bool {
	for len(options) > 0 {
		switch options[0] {
		case 0: // End of Option List.
			return true
		case 1: // No Operation.
			options = options[1:]
		default:
			if len(options) < 2 || options[1] < 2 || int(options[1]) > len(options) {
				return false
			}
			options = options[options[1]:]
		}
	}
	return true
}

func validPolicyFragment(offset, size, maxSize int, more bool) bool {
	return size > 0 && offset+size <= maxSize && (!more || size%8 == 0)
}

func parsePolicyIPv6(c *policyPacketCursor, ip *policyIPPacket) bool {
	var scratch [header.IPv6MinimumSize]byte
	available := c.remaining
	h := header.IPv6(c.take(header.IPv6MinimumSize, scratch[:]))
	if !h.IsValid(available) {
		return false
	}
	t := &ip.tuple
	t.IPv6 = true
	t.Source = netip.AddrFrom16(h.SourceAddress().As16())
	t.Destination = netip.AddrFrom16(h.DestinationAddress().As16())
	c.remaining = int(h.PayloadLength())
	ip.ipBytes = header.IPv6MinimumSize + c.remaining
	next := header.IPv6ExtensionHeaderIdentifier(h.NextHeader())
	var walked, count int
	var fragmented, more bool
	for isPolicyIPv6Extension(next) {
		if count == maxPolicyIPv6Extensions || walked+8 > maxPolicyIPv6ExtensionBytes {
			return false
		}
		count++
		if next == header.IPv6FragmentExtHdrIdentifier {
			if fragmented {
				return false
			}
			fragment := c.take(header.IPv6FragmentExtHdrLength, scratch[:])
			if fragment == nil || fragment[1] != 0 {
				return false
			}
			field := binary.BigEndian.Uint16(fragment[2:4])
			if field&0x6 != 0 {
				return false
			}
			offset := int(field &^ 7)
			more = field&1 != 0
			if (offset != 0 || more) &&
				!validPolicyFragment(offset, c.remaining, header.IPv6MaximumPayloadSize-walked, more) {
				return false
			}
			next = header.IPv6ExtensionHeaderIdentifier(fragment[0])
			if next == header.IPv6FragmentExtHdrIdentifier || next == header.IPv6HopByHopOptionsExtHdrIdentifier ||
				next == header.IPv6RoutingExtHdrIdentifier {
				return false
			}
			if offset != 0 {
				// The remaining bytes are a fragment payload, not another header.
				if !isPolicyIPv6Extension(next) {
					t.Protocol, t.ProtocolKnown = uint8(next), true
				}
				return true
			}
			fragmented = true
			walked += header.IPv6FragmentExtHdrLength
			continue
		}
		if next == header.IPv6HopByHopOptionsExtHdrIdentifier && walked != 0 {
			return false
		}
		if next == header.IPv6RoutingExtHdrIdentifier && fragmented {
			return false
		}
		length, following, ok := policyIPv6Extension(c, next, maxPolicyIPv6ExtensionBytes-walked, scratch[:])
		if !ok {
			return false
		}
		walked += length
		next = following
	}
	t.Protocol, t.ProtocolKnown = uint8(next), true
	return policyPacketPorts(c, t, more, scratch[:])
}

func isPolicyIPv6Extension(id header.IPv6ExtensionHeaderIdentifier) bool {
	switch id {
	case header.IPv6HopByHopOptionsExtHdrIdentifier, header.IPv6RoutingExtHdrIdentifier,
		header.IPv6FragmentExtHdrIdentifier, header.IPv6DestinationOptionsExtHdrIdentifier,
		header.IPv6AuthenticationExtHdrIdentifier, header.IPv6ExperimentExtHdrIdentifier:
		return true
	default:
		return false
	}
}

func policyIPv6Extension(c *policyPacketCursor, id header.IPv6ExtensionHeaderIdentifier, limit int, scratch []byte) (int, header.IPv6ExtensionHeaderIdentifier, bool) {
	h := c.take(2, scratch)
	if h == nil {
		return 0, 0, false
	}
	next := header.IPv6ExtensionHeaderIdentifier(h[0])
	length := (1 + int(h[1])) * 8
	switch id {
	case header.IPv6AuthenticationExtHdrIdentifier:
		length = (2 + int(h[1])) * 4
		if length < 12 || length%8 != 0 {
			return 0, 0, false
		}
	case header.IPv6ExperimentExtHdrIdentifier:
		if h[1] != 0 {
			return 0, 0, false
		}
		length = header.IPv6ExperimentHdrLength
	}
	remaining := length - 2
	if length > limit || remaining > c.remaining {
		return 0, 0, false
	}
	switch id {
	case header.IPv6HopByHopOptionsExtHdrIdentifier, header.IPv6DestinationOptionsExtHdrIdentifier:
		if !validPolicyIPv6Options(c, remaining, scratch) {
			return 0, 0, false
		}
	case header.IPv6RoutingExtHdrIdentifier, header.IPv6AuthenticationExtHdrIdentifier:
		fields := c.take(2, scratch)
		// Netstack cannot advance a Routing header with remaining segments.
		if fields[1] != 0 || (id == header.IPv6AuthenticationExtHdrIdentifier && fields[0] != 0) {
			return 0, 0, false
		}
		c.skip(remaining - 2)
	default:
		c.skip(remaining)
	}
	return length, next, true
}

func validPolicyIPv6Options(c *policyPacketCursor, n int, scratch []byte) bool {
	for n > 0 {
		kind := c.take(1, scratch)[0]
		n--
		if kind == 0 { // Pad1.
			continue
		}
		if n == 0 {
			return false
		}
		length := int(c.take(1, scratch)[0])
		n--
		if length > n {
			return false
		}
		c.skip(length)
		n -= length
	}
	return true
}

func policyPacketPorts(c *policyPacketCursor, t *PolicyTuple, more bool, scratch []byte) bool {
	available := c.remaining
	switch t.Protocol {
	case uint8(header.TCPProtocolNumber):
		h := header.TCP(c.take(header.TCPMinimumSize, scratch))
		if h == nil {
			return more
		}
		length := int(h.DataOffset())
		if length < header.TCPMinimumSize {
			return false
		}
		if length > available {
			return more
		}
		t.SourcePort, t.DestinationPort = h.SourcePort(), h.DestinationPort()
	case uint8(header.UDPProtocolNumber):
		h := header.UDP(c.take(header.UDPMinimumSize, scratch))
		if h == nil {
			return more
		}
		length := int(h.Length())
		if length < header.UDPMinimumSize || (length > available && !more) {
			return false
		}
		t.SourcePort, t.DestinationPort = h.SourcePort(), h.DestinationPort()
	case uint8(header.ICMPv4ProtocolNumber):
		return t.IPv6 || available >= header.ICMPv4MinimumSize || more
	case uint8(header.ICMPv6ProtocolNumber):
		return !t.IPv6 || available >= header.ICMPv6MinimumSize || more
	default:
		return true
	}
	t.SourcePortKnown, t.DestinationPortKnown = true, true
	return true
}
