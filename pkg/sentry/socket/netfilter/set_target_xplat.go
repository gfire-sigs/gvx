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
	"context"
	"math"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/ipset"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// SetTargetName is the name of the SET target, which adds the packet to a set,
// removes it from a set, or maps its set element to the packet mark.
const SetTargetName = "SET"

const (
	setTargetRevision1 uint8 = 1
	setTargetRevision2 uint8 = 2
	setTargetRevision3 uint8 = 3

	// The layout of the target structs, after the 32 bytes of
	// struct xt_entry_target. Each struct starts with add_set and del_set.
	setTargetOffAdd = linux.SizeOfXTEntryTarget
	setTargetOffDel = setTargetOffAdd + setInfoSize

	// Revision 2 has the flags and the timeout after del_set.
	setTargetV2OffFlags   = setTargetOffDel + setInfoSize
	setTargetV2OffTimeout = setTargetV2OffFlags + 4

	// Revision 3 has map_set before the flags and the timeout.
	setTargetV3OffMap     = setTargetOffDel + setInfoSize
	setTargetV3OffFlags   = setTargetV3OffMap + setInfoSize
	setTargetV3OffTimeout = setTargetV3OffFlags + 4

	// The sizes of the whole target of each revision, with the padding to a
	// multiple of 8 that Linux checks.
	setTargetSizeV1 = linux.SizeOfXTEntryTarget + 8
	setTargetSizeV2 = linux.SizeOfXTEntryTarget + 16
	setTargetSizeV3 = linux.SizeOfXTEntryTarget + 24

	// ipsetMaxTimeout is IPSET_MAX_TIMEOUT in seconds. A longer timeout of
	// the target does not fit the time of the kernel.
	ipsetMaxTimeout = (math.MaxUint32 >> 1) / 1000
)

func init() {
	for _, proto := range []tcpip.NetworkProtocolNumber{header.IPv4ProtocolNumber, header.IPv6ProtocolNumber} {
		for _, rev := range []uint8{setTargetRevision1, setTargetRevision2, setTargetRevision3} {
			registerTargetMaker(&setTargetMaker{networkProtocol: proto, rev: rev})
		}
	}
}

// setRefs holds the references of a rule to the sets that it names. It is the
// state that the check function of a Linux extension takes and the destroy
// function gives back.
//
// +stateify savable
type setRefs struct {
	reg *ipset.Registry
	ids []ipset.ID
	// released is true after release ran, so that a second call does nothing.
	released atomicbitops.Bool
}

func (r *setRefs) afterLoad(context.Context) {
	if r.reg == nil || r.released.Load() {
		return
	}
	for _, id := range r.ids {
		r.reg.GetRef(id)
	}
}

// acquire takes a reference to the set of each info. With optional true, an
// index of InvalidID names no set, as in the SET target. It fails with ENOENT
// for an unknown index and with ERANGE for a dimension above ipset.DimMax. On
// failure it holds no reference.
func (r *setRefs) acquire(stk *stack.Stack, infos []setInfo, optional bool) *syserr.Error {
	reg := ipset.ExistingForStack(stk)
	var taken []ipset.ID
	fail := func(err *syserr.Error) *syserr.Error {
		for _, id := range taken {
			reg.PutRef(id)
		}
		return err
	}
	for _, info := range infos {
		if optional && info.index == ipset.InvalidID {
			continue
		}
		if reg == nil || !reg.GetRef(info.index) {
			nflog("set: cannot find the set with index %d", info.index)
			return fail(syserr.ErrNoFileOrDir)
		}
		taken = append(taken, info.index)
	}
	for _, info := range infos {
		if info.dim > ipset.DimMax {
			nflog("set: dimension %d is over the limit", info.dim)
			return fail(syserr.ErrRange)
		}
	}
	r.reg, r.ids = reg, taken
	return nil
}

// release gives the references back.
func (r *setRefs) release() {
	if r.reg == nil || !r.released.CompareAndSwap(false, true) {
		return
	}
	for _, id := range r.ids {
		r.reg.PutRef(id)
	}
}

// setTargetMaker implements targetMaker for the SET target.
type setTargetMaker struct {
	networkProtocol tcpip.NetworkProtocolNumber
	rev             uint8
}

func (m *setTargetMaker) id() targetID {
	return targetID{name: SetTargetName, networkProtocol: m.networkProtocol, revision: m.rev}
}

// marshal returns the bytes that unmarshal parsed.
func (m *setTargetMaker) marshal(tgt target) []byte {
	st := tgt.(*setTarget)
	buf := append([]byte(nil), st.raw...)
	hdr := linux.XTEntryTarget{TargetSize: uint16(len(buf)), Revision: st.rev}
	copy(hdr.Name[:], SetTargetName)
	hdr.MarshalUnsafe(buf)
	return buf
}

func (m *setTargetMaker) unmarshal(buf []byte, _ stack.IPHeaderFilter) (target, *syserr.Error) {
	var want int
	switch m.rev {
	case setTargetRevision1:
		want = setTargetSizeV1
	case setTargetRevision2:
		want = setTargetSizeV2
	default:
		want = setTargetSizeV3
	}
	// Linux requires the exact aligned size.
	if len(buf) != want {
		nflog("SET rev%d: buf has size %d, want %d", m.rev, len(buf), want)
		return nil, syserr.ErrInvalidArgument
	}
	st := &setTarget{
		rev:             m.rev,
		networkProtocol: m.networkProtocol,
		raw:             append([]byte(nil), buf...),
		timeout:         ipset.NoTimeout,
		add:             parseSetInfo(buf[setTargetOffAdd:]),
		del:             parseSetInfo(buf[setTargetOffDel:]),
		mapSet:          setInfo{index: ipset.InvalidID},
	}
	order := hostarch.ByteOrder
	switch m.rev {
	case setTargetRevision2:
		st.flags = order.Uint32(buf[setTargetV2OffFlags:])
		st.timeout = order.Uint32(buf[setTargetV2OffTimeout:])
	case setTargetRevision3:
		st.mapSet = parseSetInfo(buf[setTargetV3OffMap:])
		st.flags = order.Uint32(buf[setTargetV3OffFlags:])
		st.timeout = order.Uint32(buf[setTargetV3OffTimeout:])
	}
	nflog("parsed SET rev%d: add %+v del %+v map %+v", m.rev, st.add, st.del, st.mapSet)
	return st, nil
}

// setTarget is the "SET" target. Like Linux set_target_v1 to set_target_v3,
// it returns XT_CONTINUE (RuleContinue).
//
// +stateify savable
type setTarget struct {
	rev             uint8
	networkProtocol tcpip.NetworkProtocolNumber
	// raw is the whole user target as parsed. Marshal returns it unchanged.
	raw []byte

	add, del, mapSet setInfo
	// flags are the command flags of the revisions 2 and 3. timeout is in
	// seconds, or ipset.NoTimeout.
	flags, timeout uint32

	refs setRefs
}

func (t *setTarget) id() targetID {
	return targetID{name: SetTargetName, networkProtocol: t.networkProtocol, revision: t.rev}
}

// bindStack implements stackBinder.bindStack. It is the check function of the
// target in Linux.
func (t *setTarget) bindStack(stk *stack.Stack) *syserr.Error {
	return t.refs.acquire(stk, []setInfo{t.add, t.del, t.mapSet}, true)
}

// releaseStack implements stackReleaser.releaseStack.
func (t *setTarget) releaseStack() { t.refs.release() }

// Action implements stack.Target.Action.
func (t *setTarget) Action(pkt *stack.PacketBuffer, _ stack.Hook, _ *stack.Route, _ stack.AddressableEndpoint) (stack.RuleVerdict, int) {
	reg := t.refs.reg
	if reg == nil {
		return stack.RuleContinue, 0
	}
	p, ok := ipsetPacket(pkt)
	if !ok {
		return stack.RuleContinue, 0
	}
	if t.add.index != ipset.InvalidID {
		opt := ipset.KOpt{Dim: t.add.dim, Flags: uint32(t.add.flags), CmdFlags: t.flags, Timeout: t.timeout}
		// Normalize the timeout to the range of the kernel.
		if opt.Timeout != ipset.NoTimeout {
			opt.Timeout = min(opt.Timeout, ipsetMaxTimeout)
		}
		reg.Add(t.add.index, &p, &opt)
	}
	if t.del.index != ipset.InvalidID {
		opt := ipset.KOpt{Dim: t.del.dim, Flags: uint32(t.del.flags), Timeout: ipset.NoTimeout}
		reg.Del(t.del.index, &p, &opt)
	}
	if t.rev == setTargetRevision3 && t.mapSet.index != ipset.InvalidID {
		t.mapPacket(reg, pkt, &p)
	}
	return stack.RuleContinue, 0
}

// mapPacket applies the packet information of the element of map_set to the
// packet. The packet buffer has no priority or queue, so only the mark of
// the elements applies.
func (t *setTarget) mapPacket(reg *ipset.Registry, pkt *stack.PacketBuffer, p *ipset.Packet) {
	const mapFlags = ipset.FlagMapSkbmark | ipset.FlagMapSkbprio | ipset.FlagMapSkbqueue
	opt := ipset.KOpt{
		Dim:      t.mapSet.dim,
		Flags:    uint32(t.mapSet.flags),
		CmdFlags: t.flags & mapFlags,
		Timeout:  ipset.NoTimeout,
	}
	if !setTest(reg, t.mapSet, p, &opt) {
		return
	}
	if opt.CmdFlags&ipset.FlagMapSkbmark != 0 {
		pkt.Mark = (pkt.Mark &^ opt.SkbInfo.MarkMask) ^ opt.SkbInfo.Mark
	}
}
