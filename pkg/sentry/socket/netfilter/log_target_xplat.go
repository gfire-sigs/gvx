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
	"context"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"

	"z.gfire.dev/gvx/internal/weakmap"
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
// The line has the format of nf_log_syslog (net/netfilter/nf_log_syslog.c): the
// prefix of the rule, IN= and OUT= with the names of the interfaces, MAC= for a
// packet that came in, the fields of the IP header, and the fields of the
// transport header. The record has the level of the rule and the facility
// kernel. The line omits the optional fields that the flags of the rule
// select: the TCP sequence numbers, the TCP and IP options, and the UID and
// GID of the socket owner.
//
// A rule logs through the log function of its network stack. Linux logs only
// from the initial network namespace unless the sysctl nf_log_all_netns is set,
// so the owner of the root network namespace sets the function with
// SetStackLog, and a rule of another stack writes only to the log of the
// Sentry. Ref: struct ipt_log_info in
// include/uapi/linux/netfilter_ipv4/ipt_LOG.h.

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

// LogFunc writes one line to the kernel log at a syslog level from 0 to 7.
type LogFunc func(level int, line string)

// stackLogs maps a network stack to its log function. The map holds the stacks
// weakly, so a stack that a test drops frees its entry.
var stackLogs weakmap.Map[stack.Stack, LogFunc]

// SetStackLog sets the function that the LOG rules of stk write their lines
// to. A nil function removes it. The function applies to the rules that a later
// SetEntries request creates.
func SetStackLog(stk *stack.Stack, fn LogFunc) {
	if fn == nil {
		stackLogs.Delete(stk)
		return
	}
	stackLogs.Store(stk, fn)
}

func stackLog(stk *stack.Stack) LogFunc {
	fn, _ := stackLogs.Load(stk)
	return fn
}

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
//
// +stateify savable
type logTarget struct {
	networkProtocol tcpip.NetworkProtocolNumber
	// raw is the whole user target as parsed. Marshal returns it unchanged.
	raw []byte
	stk *stack.Stack
	// log writes the line to the kernel log. bindStack sets it before the rule
	// is published, so Action reads it without a lock. It is nil for a rule of
	// a stack without a log function.
	log LogFunc `state:"nosave"`
}

var (
	_ stackBinder           = (*logTarget)(nil)
	_ stack.InterfaceTarget = (*logTarget)(nil)
)

func (t *logTarget) afterLoad(context.Context) {
	if t.stk != nil {
		t.log = stackLog(t.stk)
	}
}

func (t *logTarget) id() targetID {
	return targetID{name: LogTargetName, networkProtocol: t.networkProtocol, revision: logTargetRevision}
}

// bindStack implements stackBinder.bindStack.
func (t *logTarget) bindStack(stk *stack.Stack) *syserr.Error {
	t.stk = stk
	t.log = stackLog(stk)
	return nil
}

// level returns the syslog level of the rule.
func (t *logTarget) level() int {
	return int(t.raw[logOffLevel])
}

// prefix returns the prefix of the rule.
func (t *logTarget) prefix() string {
	p := t.raw[logOffPrefix : logOffPrefix+logPrefixLen]
	if end := bytes.IndexByte(p, 0); end >= 0 {
		p = p[:end]
	}
	return string(p)
}

// line returns the log line of a packet. in and out are the names of the
// interfaces, or empty.
func (t *logTarget) line(pkt *stack.PacketBuffer, in, out string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%sIN=%s OUT=%s ", t.prefix(), in, out)
	if in != "" {
		b.WriteString("MAC=")
		for i, c := range pkt.LinkHeader().Slice() {
			if i > 0 {
				b.WriteByte(':')
			}
			fmt.Fprintf(&b, "%02x", c)
		}
		b.WriteByte(' ')
	}
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		dumpIPv4(&b, pkt)
	case header.IPv6ProtocolNumber:
		dumpIPv6(&b, pkt)
	default:
		b.WriteString("(packet without an IP header)")
	}
	return b.String()
}

// dumpIPv4 writes the fields of dump_ipv4_packet.
func dumpIPv4(b *strings.Builder, pkt *stack.PacketBuffer) {
	hdr := header.IPv4(pkt.NetworkHeader().Slice())
	if len(hdr) < header.IPv4MinimumSize {
		b.WriteString("(truncated IPv4 header)")
		return
	}
	tos, _ := hdr.TOS()
	fmt.Fprintf(b, "SRC=%s DST=%s LEN=%d TOS=0x%02X PREC=0x%02X TTL=%d ID=%d ",
		hdr.SourceAddress(), hdr.DestinationAddress(), hdr.TotalLength(), tos&0x1e, tos&0xe0, hdr.TTL(), hdr.ID())
	if hdr.Flags()&header.IPv4FlagDontFragment != 0 {
		b.WriteString("DF ")
	}
	if hdr.Flags()&header.IPv4FlagMoreFragments != 0 {
		b.WriteString("MF ")
	}
	frag := hdr.FragmentOffset()
	if frag != 0 {
		fmt.Fprintf(b, "FRAG:%d ", frag/8)
	}
	dumpTransport(b, pkt, hdr.TransportProtocol(), frag != 0, false)
}

// dumpIPv6 writes the fields of dump_ipv6_packet.
func dumpIPv6(b *strings.Builder, pkt *stack.PacketBuffer) {
	hdr := header.IPv6(pkt.NetworkHeader().Slice())
	if len(hdr) < header.IPv6MinimumSize {
		b.WriteString("(truncated IPv6 header)")
		return
	}
	class, label := hdr.TOS()
	fmt.Fprintf(b, "SRC=%s DST=%s LEN=%d TC=%d HOPLIMIT=%d FLOWLBL=%d ",
		fullIPv6(hdr.SourceAddress()), fullIPv6(hdr.DestinationAddress()), int(hdr.PayloadLength())+header.IPv6MinimumSize, class, hdr.HopLimit(), label)
	// The next header of the fixed header can name an extension header. The
	// network layer parsed the extension headers, and it set the protocol of
	// the transport header.
	proto := pkt.TransportProtocolNumber
	if proto == 0 {
		proto = hdr.TransportProtocol()
	}
	dumpTransport(b, pkt, proto, false, true)
}

// fullIPv6 formats an address as %pI6 of Linux does: eight groups of four
// lower-case hex digits, without the compression of "::".
func fullIPv6(a tcpip.Address) string {
	raw := a.AsSlice()
	var b strings.Builder
	for i := 0; i+1 < len(raw); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		fmt.Fprintf(&b, "%02x%02x", raw[i], raw[i+1])
	}
	return b.String()
}

// dumpTransport writes PROTO= and the fields of the transport header. A
// fragment after the first has no transport header.
func dumpTransport(b *strings.Builder, pkt *stack.PacketBuffer, proto tcpip.TransportProtocolNumber, laterFragment, ipv6 bool) {
	th := pkt.TransportHeader().Slice()
	switch proto {
	case header.TCPProtocolNumber:
		b.WriteString("PROTO=TCP ")
		if laterFragment || len(th) < header.TCPMinimumSize {
			return
		}
		tcp := header.TCP(th)
		fmt.Fprintf(b, "SPT=%d DPT=%d WINDOW=%d RES=0x%02x ", tcp.SourcePort(), tcp.DestinationPort(), tcp.WindowSize(), (th[12]&0x0f)<<2)
		flags := tcp.Flags()
		for _, f := range []struct {
			bit  header.TCPFlags
			name string
		}{
			{header.TCPFlagCwr, "CWR "}, {header.TCPFlagEce, "ECE "}, {header.TCPFlagUrg, "URG "}, {header.TCPFlagAck, "ACK "},
			{header.TCPFlagPsh, "PSH "}, {header.TCPFlagRst, "RST "}, {header.TCPFlagSyn, "SYN "}, {header.TCPFlagFin, "FIN "},
		} {
			if flags&f.bit != 0 {
				b.WriteString(f.name)
			}
		}
		fmt.Fprintf(b, "URGP=%d ", tcp.UrgentPointer())
	case header.UDPProtocolNumber:
		b.WriteString("PROTO=UDP ")
		if laterFragment || len(th) < header.UDPMinimumSize {
			return
		}
		udp := header.UDP(th)
		fmt.Fprintf(b, "SPT=%d DPT=%d LEN=%d ", udp.SourcePort(), udp.DestinationPort(), udp.Length())
	case header.ICMPv4ProtocolNumber, header.ICMPv6ProtocolNumber:
		name, echoRequest, echoReply := "ICMP", byte(header.ICMPv4Echo), byte(header.ICMPv4EchoReply)
		if ipv6 {
			name, echoRequest, echoReply = "ICMPv6", byte(header.ICMPv6EchoRequest), byte(header.ICMPv6EchoReply)
		}
		fmt.Fprintf(b, "PROTO=%s ", name)
		if laterFragment || len(th) < 4 {
			return
		}
		fmt.Fprintf(b, "TYPE=%d CODE=%d ", th[0], th[1])
		if (th[0] == echoRequest || th[0] == echoReply) && len(th) >= 8 {
			fmt.Fprintf(b, "ID=%d SEQ=%d ", binary.BigEndian.Uint16(th[4:]), binary.BigEndian.Uint16(th[6:]))
		}
	default:
		fmt.Fprintf(b, "PROTO=%d ", proto)
	}
}

// Action implements stack.Target.Action for a hook that knows no interface.
func (t *logTarget) Action(pkt *stack.PacketBuffer, hook stack.Hook, r *stack.Route, addressEP stack.AddressableEndpoint) (stack.RuleVerdict, int) {
	return t.ActionOnInterfaces(pkt, hook, r, addressEP, "", "")
}

// ActionOnInterfaces implements stack.InterfaceTarget.ActionOnInterfaces. It
// writes the log line and has no other side effect.
func (t *logTarget) ActionOnInterfaces(pkt *stack.PacketBuffer, _ stack.Hook, _ *stack.Route, _ stack.AddressableEndpoint, in, out string) (stack.RuleVerdict, int) {
	// Format the line only for a reader: the kernel log, or the debug log of
	// the Sentry. A rule of a stack without a log function and without debug
	// logging costs a packet nothing.
	logFn := t.log
	if logFn == nil && t.stk != nil {
		logFn = stackLog(t.stk)
	}
	debug := log.IsLogging(log.Debug)
	if logFn == nil && !debug {
		return stack.RuleContinue, 0
	}
	line := t.line(pkt, in, out)
	if logFn != nil {
		logFn(t.level(), line)
	}
	if debug {
		log.Debugf("netfilter LOG: %s", line)
	}
	return stack.RuleContinue, 0
}
