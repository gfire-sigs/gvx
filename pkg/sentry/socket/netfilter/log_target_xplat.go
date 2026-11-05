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
	"bytes"
	"fmt"
	"slices"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// This file implements the iptables "LOG" target (net/netfilter/xt_LOG.c).
// A rule such as "-j LOG --log-prefix X" writes a line about the packet to the
// kernel log. Calico and kube-router use the target for the log actions of
// their policies.
//
// /dev/kmsg of the Sentry cannot hold records yet, so the target writes the
// line to the log of the Sentry, at the level info. The line starts with the
// prefix of the rule and has the fields SRC, DST, LEN, and PROTO. When
// /dev/kmsg can hold records, this function must write the line there.
// Ref: struct ipt_log_info in include/uapi/linux/netfilter_ipv4/ipt_LOG.h.

// LogTargetName is the name of the LOG target.
const LogTargetName = "LOG"

const (
	// logTargetRevision is the only revision of the target.
	logTargetRevision uint8 = 0

	// logTargetSize is sizeof(struct ipt_log_info), which is level, logflags,
	// and the 30-byte prefix, after the 32 bytes of struct xt_entry_target.
	logTargetSize = linux.SizeOfXTEntryTarget + 32

	logOffLevel  = linux.SizeOfXTEntryTarget
	logOffPrefix = linux.SizeOfXTEntryTarget + 2
	logPrefixLen = 30
)

func init() {
	registerTargetMaker(&logTargetMaker{networkProtocol: header.IPv4ProtocolNumber})
	registerTargetMaker(&logTargetMaker{networkProtocol: header.IPv6ProtocolNumber})
}

// logTargetMaker implements targetMaker for the LOG target.
type logTargetMaker struct {
	networkProtocol tcpip.NetworkProtocolNumber
}

func (m *logTargetMaker) id() targetID {
	return targetID{name: LogTargetName, networkProtocol: m.networkProtocol, revision: logTargetRevision}
}

// marshal returns the bytes that unmarshal parsed.
func (m *logTargetMaker) marshal(tgt target) []byte {
	buf := slices.Clone(tgt.(*logTarget).raw)
	hdr := linux.XTEntryTarget{TargetSize: uint16(len(buf)), Revision: logTargetRevision}
	copy(hdr.Name[:], LogTargetName)
	hdr.MarshalUnsafe(buf)
	return buf
}

// unmarshal applies the checks of xt_check_target and log_tg_check.
func (m *logTargetMaker) unmarshal(buf []byte, _ stack.IPHeaderFilter) (target, *syserr.Error) {
	if len(buf) != logTargetSize {
		nflog("LOG: buf has size %d, want %d", len(buf), logTargetSize)
		return nil, syserr.ErrInvalidArgument
	}
	// A level is a syslog level from 0 to 7.
	if buf[logOffLevel] >= 8 {
		nflog("LOG: invalid level %d", buf[logOffLevel])
		return nil, syserr.ErrInvalidArgument
	}
	if buf[logOffPrefix+logPrefixLen-1] != 0 {
		nflog("LOG: prefix has no terminating NUL byte")
		return nil, syserr.ErrInvalidArgument
	}
	return &logTarget{networkProtocol: m.networkProtocol, raw: slices.Clone(buf)}, nil
}

// logTarget is the LOG target. Like Linux log_tg, it returns XT_CONTINUE
// (RuleContinue), so traversal continues with the next rule.
type logTarget struct {
	networkProtocol tcpip.NetworkProtocolNumber
	// raw is the whole user target as parsed. Marshal returns it unchanged.
	raw []byte
}

func (t *logTarget) id() targetID {
	return targetID{name: LogTargetName, networkProtocol: t.networkProtocol, revision: logTargetRevision}
}

// prefix returns the prefix of the rule.
func (t *logTarget) prefix() string {
	p := t.raw[logOffPrefix : logOffPrefix+logPrefixLen]
	if end := bytes.IndexByte(p, 0); end >= 0 {
		p = p[:end]
	}
	return string(p)
}

// line returns the log line of a packet.
func (t *logTarget) line(pkt *stack.PacketBuffer) string {
	src, dst, ok := packetAddresses(pkt)
	if !ok {
		return t.prefix() + "(packet without an IP header)"
	}
	var proto tcpip.TransportProtocolNumber
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		proto = header.IPv4(pkt.NetworkHeader().Slice()).TransportProtocol()
	case header.IPv6ProtocolNumber:
		proto = header.IPv6(pkt.NetworkHeader().Slice()).TransportProtocol()
	}
	return fmt.Sprintf("%sSRC=%s DST=%s LEN=%d PROTO=%d", t.prefix(), src, dst, pkt.Size(), proto)
}

// Action implements stack.Target.Action. It writes the log line and has no
// other side effect.
func (t *logTarget) Action(pkt *stack.PacketBuffer, _ stack.Hook, _ *stack.Route, _ stack.AddressableEndpoint) (stack.RuleVerdict, int) {
	log.Infof("netfilter LOG: %s", t.line(pkt))
	return stack.RuleContinue, 0
}
