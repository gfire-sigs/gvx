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
	"slices"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// This file implements the iptables "NFLOG" target (net/netfilter/xt_NFLOG.c).
// A rule such as "-j NFLOG --nflog-group 100" sends a copy of the packet to
// the netlink log group of the rule. kube-router and Calico use the target to
// log dropped packets.
//
// The network stack has no NFLOG listener: no NETLINK_NETFILTER socket
// subscribes to a log group. The target therefore accepts the rule, keeps its
// bytes for iptables-save, and logs nothing. No NFLOG group receives packets.
// Ref: struct xt_nflog_info in include/uapi/linux/netfilter/xt_NFLOG.h.

// NFLogTargetName is the name of the NFLOG target.
const NFLogTargetName = "NFLOG"

const (
	// nflogTargetRevision is the only revision of the target.
	nflogTargetRevision uint8 = 0

	// nflogInfoSize is sizeof(struct xt_nflog_info): len, group, threshold,
	// flags, pad, and the 64-byte prefix.
	nflogInfoSize = 76

	// nflogTargetSize is the size of the whole target, with the padding to a
	// multiple of 8 that Linux checks.
	nflogTargetSize = linux.SizeOfXTEntryTarget + 80

	// nflogFlagsMask is XT_NFLOG_MASK. Linux rejects every other flag.
	nflogFlagsMask uint16 = 1

	// The offsets of the fields of the struct, after the 32 bytes of struct
	// xt_entry_target.
	nflogOffFlags  = linux.SizeOfXTEntryTarget + 8
	nflogOffPrefix = linux.SizeOfXTEntryTarget + 12
	nflogPrefixLen = 64
)

func init() {
	registerTargetMaker(&nflogTargetMaker{networkProtocol: header.IPv4ProtocolNumber})
	registerTargetMaker(&nflogTargetMaker{networkProtocol: header.IPv6ProtocolNumber})
}

// nflogTargetMaker implements targetMaker for the NFLOG target.
type nflogTargetMaker struct {
	networkProtocol tcpip.NetworkProtocolNumber
}

func (m *nflogTargetMaker) id() targetID {
	return targetID{name: NFLogTargetName, networkProtocol: m.networkProtocol, revision: nflogTargetRevision}
}

// marshal returns the bytes that unmarshal parsed.
func (m *nflogTargetMaker) marshal(tgt target) []byte {
	buf := slices.Clone(tgt.(*nflogTarget).raw)
	hdr := linux.XTEntryTarget{TargetSize: uint16(len(buf)), Revision: nflogTargetRevision}
	copy(hdr.Name[:], NFLogTargetName)
	hdr.MarshalUnsafe(buf)
	return buf
}

// unmarshal applies the checks of xt_check_target and nflog_tg_check.
func (m *nflogTargetMaker) unmarshal(buf []byte, _ stack.IPHeaderFilter) (target, *syserr.Error) {
	// Linux requires the exact aligned size.
	if len(buf) != nflogTargetSize {
		nflog("NFLOG: buf has size %d, want %d", len(buf), nflogTargetSize)
		return nil, syserr.ErrInvalidArgument
	}
	if flags := hostarch.ByteOrder.Uint16(buf[nflogOffFlags:]); flags&^nflogFlagsMask != 0 {
		nflog("NFLOG: invalid flags 0x%x", flags)
		return nil, syserr.ErrInvalidArgument
	}
	// The prefix must end with a NUL byte.
	if buf[nflogOffPrefix+nflogPrefixLen-1] != 0 {
		nflog("NFLOG: prefix has no terminating NUL byte")
		return nil, syserr.ErrInvalidArgument
	}
	return &nflogTarget{networkProtocol: m.networkProtocol, raw: slices.Clone(buf)}, nil
}

// nflogTarget is the NFLOG target. Like Linux nflog_tg, it returns XT_CONTINUE
// (RuleContinue), so traversal continues with the next rule.
type nflogTarget struct {
	networkProtocol tcpip.NetworkProtocolNumber
	// raw is the whole user target as parsed. Marshal returns it unchanged.
	raw []byte
}

func (t *nflogTarget) id() targetID {
	return targetID{name: NFLogTargetName, networkProtocol: t.networkProtocol, revision: nflogTargetRevision}
}

// Action implements stack.Target.Action. No NFLOG group receives packets, so
// the target has no side effect.
func (*nflogTarget) Action(*stack.PacketBuffer, stack.Hook, *stack.Route, stack.AddressableEndpoint) (stack.RuleVerdict, int) {
	return stack.RuleContinue, 0
}
