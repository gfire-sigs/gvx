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
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/marshal"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
)

// revisionMatchMaker stamps the match revision byte into the marshalled
// XTEntryMatch header when the underlying matchMaker leaves it at zero.
type revisionMatchMaker struct {
	matchMaker
}

func (rm revisionMatchMaker) marshal(m matcher) []byte {
	buf := rm.matchMaker.marshal(m)
	if len(buf) > revisionOffset {
		buf[revisionOffset] = m.revision()
	}
	return buf
}

// dnatR2TargetMaker reports SizeOfXTNATTargetV2 in XTEntryTarget.TargetSize so
// iptables rule comparisons ("iptables -C" and "iptables -D") cover all bytes.
type dnatR2TargetMaker struct {
	dnatTargetMakerR2
}

func (dnatR2TargetMaker) marshal(t target) []byte {
	dt := t.(*dnatTarget)
	nt := linux.XTNATTargetV2{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTNATTargetV2,
			Revision:   2,
		},
	}
	copy(nt.Target.Name[:], DNATTargetName)

	if dt.ChangeAddress {
		nt.Range.Flags |= linux.NF_NAT_RANGE_MAP_IPS
	}
	if dt.ChangePort {
		nt.Range.Flags |= linux.NF_NAT_RANGE_PROTO_SPECIFIED
	}
	copy(nt.Range.MinAddr[:], dt.Addr.AsSlice())
	copy(nt.Range.MaxAddr[:], dt.Addr.AsSlice())
	nt.Range.MinProto = htons(dt.Port)
	nt.Range.MaxProto = nt.Range.MinProto

	return marshal.Marshal(&nt)
}

// init runs after the other files in package netfilter because of its "zz_"
// file prefix, wrapping registered matchMakers and DNAT revision 2 targets.
func init() {
	for k, mm := range matchMakers {
		matchMakers[k] = revisionMatchMaker{matchMaker: mm}
	}
	for _, proto := range []tcpip.NetworkProtocolNumber{header.IPv4ProtocolNumber, header.IPv6ProtocolNumber} {
		tm := &dnatR2TargetMaker{dnatTargetMakerR2{NetworkProtocol: proto}}
		targetMakers[tm.id()] = tm
	}
}
