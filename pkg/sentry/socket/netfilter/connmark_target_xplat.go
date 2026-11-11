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
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// This file implements the iptables "CONNMARK" target
// (net/netfilter/xt_connmark.c). The target sets, saves, or restores the mark
// of the connection of a packet. The tool wg-quick saves the mark of a tunnel
// packet in the connection and restores it on the reply. Ref: struct
// xt_connmark_tginfo1 and xt_connmark_tginfo2 in
// include/uapi/linux/netfilter/xt_connmark.h.

// ConnmarkTargetName is the name of the CONNMARK target.
const ConnmarkTargetName = "CONNMARK"

const (
	connmarkTargetRevision1 uint8 = 1
	connmarkTargetRevision2 uint8 = 2

	// The target data starts after the 32 bytes of struct xt_entry_target. The
	// three masks come first in both revisions.
	connmarkOffCtmark = linux.SizeOfXTEntryTarget
	connmarkOffCtmask = connmarkOffCtmark + 4
	connmarkOffNfmask = connmarkOffCtmask + 4
	// Revision 1 has the mode after the masks. Revision 2 has the shift
	// direction, the shift bits, and then the mode.
	connmarkV1OffMode      = connmarkOffNfmask + 4
	connmarkV2OffShiftDir  = connmarkOffNfmask + 4
	connmarkV2OffShiftBits = connmarkV2OffShiftDir + 1
	connmarkV2OffMode      = connmarkV2OffShiftBits + 1

	// Each revision pads its data to a multiple of 8, as Linux checks.
	connmarkTargetSize = linux.SizeOfXTEntryTarget + 16
)

// Values of the mode of the CONNMARK target (XT_CONNMARK_*).
const (
	connmarkModeSet     uint8 = 0
	connmarkModeSave    uint8 = 1
	connmarkModeRestore uint8 = 2
)

// Values of the shift direction of revision 2 (D_SHIFT_*).
const (
	connmarkShiftLeft  uint8 = 0
	connmarkShiftRight uint8 = 1
)

func init() {
	for _, proto := range []tcpip.NetworkProtocolNumber{header.IPv4ProtocolNumber, header.IPv6ProtocolNumber} {
		for _, rev := range []uint8{connmarkTargetRevision1, connmarkTargetRevision2} {
			registerTargetMaker(&connmarkTargetMaker{networkProtocol: proto, rev: rev})
		}
	}
}

// connmarkTargetMaker implements targetMaker for the CONNMARK target.
type connmarkTargetMaker struct {
	networkProtocol tcpip.NetworkProtocolNumber
	rev             uint8
}

func (m *connmarkTargetMaker) id() targetID {
	return targetID{name: ConnmarkTargetName, networkProtocol: m.networkProtocol, revision: m.rev}
}

func (m *connmarkTargetMaker) marshal(tgt target) []byte {
	ct := tgt.(*connmarkTarget)
	buf := make([]byte, connmarkTargetSize)
	hdr := linux.XTEntryTarget{TargetSize: connmarkTargetSize, Revision: ct.rev}
	copy(hdr.Name[:], ConnmarkTargetName)
	hdr.MarshalUnsafe(buf)
	order := hostarch.ByteOrder
	order.PutUint32(buf[connmarkOffCtmark:], ct.ctmark)
	order.PutUint32(buf[connmarkOffCtmask:], ct.ctmask)
	order.PutUint32(buf[connmarkOffNfmask:], ct.nfmask)
	if ct.rev == connmarkTargetRevision1 {
		buf[connmarkV1OffMode] = ct.mode
		return buf
	}
	buf[connmarkV2OffShiftDir] = ct.shiftDir
	buf[connmarkV2OffShiftBits] = ct.shiftBits
	buf[connmarkV2OffMode] = ct.mode
	return buf
}

func (m *connmarkTargetMaker) unmarshal(buf []byte, _ stack.IPHeaderFilter) (target, *syserr.Error) {
	// Linux requires the exact aligned size.
	if len(buf) != connmarkTargetSize {
		nflog("CONNMARK rev%d: buf has size %d, want %d", m.rev, len(buf), connmarkTargetSize)
		return nil, syserr.ErrInvalidArgument
	}
	order := hostarch.ByteOrder
	ct := &connmarkTarget{
		rev:             m.rev,
		networkProtocol: m.networkProtocol,
		ctmark:          order.Uint32(buf[connmarkOffCtmark:]),
		ctmask:          order.Uint32(buf[connmarkOffCtmask:]),
		nfmask:          order.Uint32(buf[connmarkOffNfmask:]),
	}
	if m.rev == connmarkTargetRevision1 {
		ct.mode = buf[connmarkV1OffMode]
		return ct, nil
	}
	ct.shiftDir = buf[connmarkV2OffShiftDir]
	ct.shiftBits = buf[connmarkV2OffShiftBits]
	ct.mode = buf[connmarkV2OffMode]
	// Ref: connmark_tg_check_v2.
	if ct.shiftDir > connmarkShiftRight || ct.shiftBits >= 32 {
		nflog("CONNMARK rev2: shift direction %d, bits %d", ct.shiftDir, ct.shiftBits)
		return nil, syserr.ErrInvalidArgument
	}
	return ct, nil
}

// connmarkTarget is the "CONNMARK" target. Like Linux connmark_tg, it returns
// XT_CONTINUE (RuleContinue). A packet without a tracked connection stays
// unchanged.
//
// +stateify savable
type connmarkTarget struct {
	rev             uint8
	networkProtocol tcpip.NetworkProtocolNumber
	ctmark          uint32
	ctmask          uint32
	nfmask          uint32
	mode            uint8
	// shiftDir and shiftBits are always 0 in revision 1.
	shiftDir  uint8
	shiftBits uint8
}

func (t *connmarkTarget) id() targetID {
	return targetID{name: ConnmarkTargetName, networkProtocol: t.networkProtocol, revision: t.rev}
}

// shift moves a mark by the shift of the rule, as connmark_tg_shift does.
func (t *connmarkTarget) shift(mark uint32) uint32 {
	if t.shiftDir == connmarkShiftRight {
		return mark >> t.shiftBits
	}
	return mark << t.shiftBits
}

// Action implements stack.Target.Action.
func (t *connmarkTarget) Action(pkt *stack.PacketBuffer, _ stack.Hook, _ *stack.Route, _ stack.AddressableEndpoint) (stack.RuleVerdict, int) {
	if !pkt.IsConnTrackConfigured() {
		return stack.RuleContinue, 0
	}
	switch t.mode {
	case connmarkModeSet:
		pkt.UpdateConnMark(func(old uint32) uint32 {
			return t.shift((old &^ t.ctmask) ^ t.ctmark)
		})
	case connmarkModeSave:
		saved := t.shift(pkt.Mark & t.nfmask)
		pkt.UpdateConnMark(func(old uint32) uint32 {
			return (old &^ t.ctmask) ^ saved
		})
	case connmarkModeRestore:
		restored := t.shift(pkt.ConnMark() & t.ctmask)
		pkt.Mark = (pkt.Mark &^ t.nfmask) ^ restored
	}
	return stack.RuleContinue, 0
}
