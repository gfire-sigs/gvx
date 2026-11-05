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

package ipset

// This file has the kernel interface of the sets: the match and the target of
// iptables test, add, and delete the elements that a packet makes
// (ip_set_test, ip_set_add, ip_set_del).

// Flags of the options of a kernel operation (enum ip_set_kopt). Bit n of
// the flags of a match selects the source address, port, or second address
// for dimension n, and a cleared bit selects the destination.
const (
	KInvMatch    uint32 = 1 << 0
	KDimOneSrc   uint32 = 1 << 1
	KDimTwoSrc   uint32 = 1 << 2
	KDimThreeSrc uint32 = 1 << 3
	// KReturnNomatch is IPSET_RETURN_NOMATCH of the match revision 2.
	KReturnNomatch uint32 = 1 << 7
)

// DimMax is IPSET_DIM_MAX: the largest count of dimensions of a rule.
const DimMax = 6

// Packet holds the fields of a packet that the set types read.
type Packet struct {
	// Family is FamilyIPv4 or FamilyIPv6.
	Family   uint8
	Src, Dst Addr
	// SrcPort and DstPort are in host order. For ICMP they both have the type
	// in the upper byte and the code in the lower byte. They are zero for a
	// protocol with no ports.
	SrcPort, DstPort uint16
	// Proto is the protocol of the transport header, after the extension
	// headers of IPv6.
	Proto uint8
	// PortsOK is false when the port information is not available, as in a
	// fragment that does not start at offset zero.
	PortsOK bool
	// Len is the length of the packet in bytes. A counter adds it.
	Len uint32
}

// KOpt holds the options of a kernel operation (struct ip_set_adt_opt).
type KOpt struct {
	// Dim is the count of dimensions that the rule gives. A set with more
	// dimensions never matches.
	Dim uint8
	// Flags has the KDim*Src bits.
	Flags uint32
	// CmdFlags has the Flag* bits.
	CmdFlags uint32
	// Timeout is the timeout in seconds of an element that an add creates, or
	// NoTimeout to use the default of the set.
	Timeout uint32

	// The counter conditions of a match.
	PacketsOp    uint8
	PacketsValue uint64
	BytesOp      uint8
	BytesValue   uint64

	// SkbInfo receives the packet information of the matching element when
	// the set stores it.
	SkbInfo SkbInfo
}

// timeoutOr returns the timeout of the options, or def when the options give
// none.
func (o *KOpt) timeoutOr(def uint32) uint32 {
	if o.Timeout != NoTimeout {
		return o.Timeout
	}
	return def
}

// kadt dispatches an operation of a packet to the type of the set.
func (s *Set) kadt(adt Adt, pkt *Packet, o *KOpt) int {
	switch s.spec.kind {
	case kindHash:
		return s.hashKadt(adt, pkt, o)
	case kindBitmapPort:
		return s.bitmapKadt(adt, pkt, o)
	}
	return s.listKadt(adt, pkt, o)
}

// usable reports whether the set takes the packet: the dimension of the rule
// is enough and the families agree.
func (s *Set) usable(pkt *Packet, o *KOpt) bool {
	return o.Dim >= s.spec.dimension && (pkt.Family == s.family || s.family == FamilyUnspec)
}

// Test reports for the set at the index whether the packet matches. It returns
// a positive value for a match. It is ip_set_test.
func (r *Registry) Test(id ID, pkt *Packet, o *KOpt) int {
	s := r.setByID(id)
	if s == nil || !s.usable(pkt, o) {
		return 0
	}
	ret := s.kadt(AdtTest, pkt, o)
	// --return-nomatch inverts a matching element of a type that has nomatch.
	if o.CmdFlags&FlagReturnNomatch != 0 && s.spec.features&featureNomatch != 0 &&
		(ret > 0 || ret == -errnoENOTEMPTY) {
		ret = -ret
	}
	return max(ret, 0)
}

// Add adds the element that the packet makes to the set at the index. It
// returns zero or a negative error code. It is ip_set_add.
func (r *Registry) Add(id ID, pkt *Packet, o *KOpt) int {
	s := r.setByID(id)
	if s == nil || !s.usable(pkt, o) {
		return -ErrTypeMismatch
	}
	return s.kadt(AdtAdd, pkt, o)
}

// Del removes the element that the packet makes from the set at the index. It
// returns zero or a negative error code. It is ip_set_del.
func (r *Registry) Del(id ID, pkt *Packet, o *KOpt) int {
	s := r.setByID(id)
	if s == nil || !s.usable(pkt, o) {
		return -ErrTypeMismatch
	}
	return s.kadt(AdtDel, pkt, o)
}
