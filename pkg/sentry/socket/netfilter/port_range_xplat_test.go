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
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/marshal"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

func TestNetfilterDNATAndPortMatcherContracts(t *testing.T) {
	// Verify real unmarshaled *dnatTarget satisfies the DNAT marker interface
	// consumed by pkg/netbackend without importing pkg/sentry.
	xtDNAT := linux.XTNATTargetV0{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTNATTargetV0,
		},
		NfRange: linux.NfNATIPV4MultiRangeCompat{
			RangeSize: 1,
			RangeIPV4: linux.NfNATIPV4Range{
				Flags:   linux.NF_NAT_RANGE_MAP_IPS | linux.NF_NAT_RANGE_PROTO_SPECIFIED,
				MinIP:   [4]byte{172, 17, 0, 2},
				MaxIP:   [4]byte{172, 17, 0, 2},
				MinPort: htons(80),
				MaxPort: htons(80),
			},
		},
	}
	copy(xtDNAT.Target.Name[:], DNATTargetName)
	zeroV4 := tcpip.AddrFrom4([4]byte{})
	dnatMaker := &dnatTargetMakerV4{NetworkProtocol: header.IPv4ProtocolNumber}
	tgt, serr := dnatMaker.unmarshal(marshal.Marshal(&xtDNAT), stack.IPHeaderFilter{
		Protocol:      header.TCPProtocolNumber,
		CheckProtocol: true,
		Src:           zeroV4,
		SrcMask:       zeroV4,
		Dst:           zeroV4,
		DstMask:       zeroV4,
	})
	if serr != nil {
		t.Fatalf("dnatTargetMakerV4.unmarshal: %v", serr)
	}
	type dnatMarker interface {
		IsDNATTarget() bool
	}
	dm, ok := any(tgt).(dnatMarker)
	if !ok || !dm.IsDNATTarget() {
		t.Fatalf("unmarshaled %T does not satisfy IsDNATTarget()", tgt)
	}

	// Verify real unmarshaled *TCPMatcher and *UDPMatcher satisfy DestinationPortRange.
	type dstPortRange interface {
		DestinationPortRange() (start, end uint16, inverted bool)
	}

	xtTCP := linux.XTTCP{
		DestinationPortStart: 8080,
		DestinationPortEnd:   8080,
	}
	tcpMatcher, err := (tcpMarshaler{}).unmarshal(nil, nil, marshal.Marshal(&xtTCP), stack.IPHeaderFilter{
		Protocol:      header.TCPProtocolNumber,
		CheckProtocol: true,
	})
	if err != nil {
		t.Fatalf("tcpMarshaler.unmarshal: %v", err)
	}
	pr, ok := tcpMatcher.(dstPortRange)
	if !ok {
		t.Fatalf("unmarshaled %T does not satisfy DestinationPortRange()", tcpMatcher)
	}
	if start, end, inv := pr.DestinationPortRange(); start != 8080 || end != 8080 || inv {
		t.Fatalf("TCPMatcher.DestinationPortRange() = (%d, %d, %v), want (8080, 8080, false)", start, end, inv)
	}

	xtTCPInv := linux.XTTCP{
		DestinationPortStart: 8081,
		DestinationPortEnd:   8081,
		InverseFlags:         linux.XT_TCP_INV_DSTPT,
	}
	tcpInvMatcher, err := (tcpMarshaler{}).unmarshal(nil, nil, marshal.Marshal(&xtTCPInv), stack.IPHeaderFilter{
		Protocol:      header.TCPProtocolNumber,
		CheckProtocol: true,
	})
	if err != nil {
		t.Fatalf("tcpMarshaler.unmarshal(inverted): %v", err)
	}
	prInv, ok := tcpInvMatcher.(dstPortRange)
	if !ok {
		t.Fatalf("unmarshaled %T does not satisfy DestinationPortRange()", tcpInvMatcher)
	}
	if start, end, inv := prInv.DestinationPortRange(); start != 8081 || end != 8081 || !inv {
		t.Fatalf("TCPMatcher(inverted).DestinationPortRange() = (%d, %d, %v), want (8081, 8081, true)", start, end, inv)
	}

	xtUDP := linux.XTUDP{
		DestinationPortStart: 5353,
		DestinationPortEnd:   5353,
	}
	udpMatcher, err := (udpMarshaler{}).unmarshal(nil, nil, marshal.Marshal(&xtUDP), stack.IPHeaderFilter{
		Protocol:      header.UDPProtocolNumber,
		CheckProtocol: true,
	})
	if err != nil {
		t.Fatalf("udpMarshaler.unmarshal: %v", err)
	}
	upr, ok := udpMatcher.(dstPortRange)
	if !ok {
		t.Fatalf("unmarshaled %T does not satisfy DestinationPortRange()", udpMatcher)
	}
	if start, end, inv := upr.DestinationPortRange(); start != 5353 || end != 5353 || inv {
		t.Fatalf("UDPMatcher.DestinationPortRange() = (%d, %d, %v), want (5353, 5353, false)", start, end, inv)
	}
}
