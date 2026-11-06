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
	"math/rand"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/faketime"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// logEntry returns the whole xt_entry_target of a LOG rule as userspace builds
// it: the header and struct ipt_log_info.
func logEntry(level uint8, prefix []byte) []byte {
	buf := make([]byte, logTargetSize)
	hdr := linux.XTEntryTarget{TargetSize: logTargetSize}
	copy(hdr.Name[:], LogTargetName)
	hdr.MarshalUnsafe(buf)
	buf[logOffLevel] = level
	copy(buf[logOffPrefix:logOffPrefix+logPrefixLen], prefix)
	return buf
}

func TestLogTargetRoundTripAndAction(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		filter, newPacket := stack.EmptyFilter4(), newIPv4Packet
		src, dst := "10.1.1.1", "10.2.2.2"
		if ipv6 {
			filter, newPacket = stack.EmptyFilter6(), newIPv6Packet
			src, dst = "fd00::1", "fd00::2"
		}
		wantSrc, wantDst := src, dst
		if ipv6 {
			wantSrc, wantDst = "fd00:0000:0000:0000:0000:0000:0000:0001", "fd00:0000:0000:0000:0000:0000:0000:0002"
		}
		entry := logEntry(4, []byte("cali-drop: "))
		tgt, err := parseTarget(filter, entry, ipv6, filterTable)
		if err != nil {
			t.Fatalf("parseTarget(ipv6=%v): %v", ipv6, err)
		}
		if got := marshalTarget(tgt); !bytes.Equal(got, entry) {
			t.Errorf("marshalTarget = %x, want %x", got, entry)
		}
		pkt := newPacket(t, src, dst)
		verdict, _ := tgt.Action(pkt, stack.Forward, nil, nil)
		if verdict != stack.RuleContinue {
			t.Errorf("verdict = %v, want RuleContinue", verdict)
		}
		line := tgt.(*logTarget).line(pkt, "eth0", "docker0")
		for _, want := range []string{"cali-drop: IN=eth0 OUT=docker0 ", "SRC=" + wantSrc, "DST=" + wantDst} {
			if !strings.Contains(line, want) {
				t.Errorf("log line %q lacks %q", line, want)
			}
		}
	}
}

// logRecord is one call of a LogFunc.
type logRecord struct {
	level int
	line  string
}

// newBoundLogTarget parses a LOG rule of the given level and prefix and binds it
// to a stack whose log function appends to the returned slice.
func newBoundLogTarget(t *testing.T, level uint8, prefix string) (*logTarget, *[]logRecord) {
	t.Helper()
	stk := stack.New(stack.Options{})
	t.Cleanup(stk.Destroy)
	var records []logRecord
	SetStackLog(stk, func(level int, line string) { records = append(records, logRecord{level, line}) })
	tgt, err := parseTarget(stack.EmptyFilter4(), logEntry(level, []byte(prefix)), false, filterTable)
	if err != nil {
		t.Fatalf("parseTarget: %v", err)
	}
	if err := bindMatcherStacks(stk, []stack.Rule{{Target: tgt}}); err != nil {
		t.Fatalf("bindMatcherStacks: %v", err)
	}
	return tgt.(*logTarget), &records
}

func TestLogTargetWritesTheLineToTheLogFunctionOfTheStackAtTheLevelOfTheRule(t *testing.T) {
	tgt, records := newBoundLogTarget(t, 2, "DROP: ")
	pkt := newIPv4Packet(t, "10.1.1.1", "10.2.2.2")
	tgt.ActionOnInterfaces(pkt, stack.Input, nil, nil, "eth0", "")
	if len(*records) != 1 {
		t.Fatalf("log function called %d times, want 1", len(*records))
	}
	got := (*records)[0]
	if got.level != 2 || !strings.HasPrefix(got.line, "DROP: IN=eth0 OUT= MAC= SRC=10.1.1.1 DST=10.2.2.2 LEN=20 ") {
		t.Errorf("record = %+v", got)
	}
}

func TestLogTargetOfAStackWithoutALogFunctionLogsNothingAndContinues(t *testing.T) {
	tgt, err := parseTarget(stack.EmptyFilter4(), logEntry(4, []byte("x")), false, filterTable)
	if err != nil {
		t.Fatal(err)
	}
	stk := stack.New(stack.Options{})
	t.Cleanup(stk.Destroy)
	if err := bindMatcherStacks(stk, []stack.Rule{{Target: tgt}}); err != nil {
		t.Fatal(err)
	}
	if v, _ := tgt.Action(newIPv4Packet(t, "10.1.1.1", "10.2.2.2"), stack.Input, nil, nil); v != stack.RuleContinue {
		t.Errorf("verdict = %v, want RuleContinue", v)
	}
}

func TestLogTargetRunsThroughTheIPTablesWithInterfaceNames(t *testing.T) {
	tgt, records := newBoundLogTarget(t, 4, "fw: ")
	table := stack.EmptyFilterTable()
	table.Rules = []stack.Rule{
		{Filter: stack.EmptyFilter4(), Target: tgt},
		{Filter: stack.EmptyFilter4(), Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
	}
	table.BuiltinChains[stack.Forward] = 0
	table.Underflows[stack.Forward] = 1
	it := stack.DefaultTables(faketime.NewManualClock(), rand.New(rand.NewSource(1)))
	it.ForceReplaceTable(stack.FilterID, table, false)
	pkt := newIPv4Packet(t, "10.1.1.1", "10.2.2.2")
	it.CheckForward(pkt, "eth0", "docker0")
	if len(*records) != 1 || !strings.HasPrefix((*records)[0].line, "fw: IN=eth0 OUT=docker0 ") {
		t.Errorf("records = %+v, want one line with IN=eth0 OUT=docker0", *records)
	}
}

// synPacket returns an IPv4 TCP packet with a SYN flag.
func synPacket(t *testing.T) *stack.PacketBuffer {
	t.Helper()
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: header.IPv4MinimumSize + header.TCPMinimumSize})
	t.Cleanup(pkt.DecRef)
	tcp := header.TCP(pkt.TransportHeader().Push(header.TCPMinimumSize))
	tcp.Encode(&header.TCPFields{SrcPort: 40000, DstPort: 443, Flags: header.TCPFlagSyn, WindowSize: 64240, DataOffset: header.TCPMinimumSize})
	ip := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
	ip.Encode(&header.IPv4Fields{
		TotalLength: header.IPv4MinimumSize + header.TCPMinimumSize,
		ID:          4660,
		Flags:       header.IPv4FlagDontFragment,
		TTL:         63,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     addr4("10.1.1.1"),
		DstAddr:     addr4("10.2.2.2"),
	})
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	return pkt
}

func TestLogTargetLineHasTheFormatOfNfLogSyslog(t *testing.T) {
	tgt, _ := newBoundLogTarget(t, 4, "IPT: ")
	got := tgt.line(synPacket(t), "eth0", "")
	want := "IPT: IN=eth0 OUT= MAC= SRC=10.1.1.1 DST=10.2.2.2 LEN=40 TOS=0x00 PREC=0x00 TTL=63 ID=4660 DF " +
		"PROTO=TCP SPT=40000 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0 "
	if got != want {
		t.Errorf("line =\n%q\nwant\n%q", got, want)
	}
}

func TestLogTargetRejects(t *testing.T) {
	tests := map[string][]byte{
		"level 8":                 logEntry(8, []byte("x")),
		"prefix without NUL byte": logEntry(4, bytes.Repeat([]byte{'a'}, logPrefixLen)),
		"too short":               logEntry(4, nil)[:logTargetSize-8],
		"too long":                append(logEntry(4, nil), make([]byte, 8)...),
	}
	for name, entry := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseTarget(stack.EmptyFilter4(), entry, false, filterTable); err == nil {
				t.Errorf("parseTarget accepted the target")
			}
		})
	}
}

// ipv6TCPPacket returns an IPv6 packet whose fixed header names a hop-by-hop
// extension header, as the network layer leaves it after it parsed the
// extension headers. The network layer sets the transport protocol to TCP.
func ipv6TCPPacket(t *testing.T) *stack.PacketBuffer {
	t.Helper()
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: header.IPv6MinimumSize + header.TCPMinimumSize})
	t.Cleanup(pkt.DecRef)
	tcp := header.TCP(pkt.TransportHeader().Push(header.TCPMinimumSize))
	tcp.Encode(&header.TCPFields{SrcPort: 1234, DstPort: 80, Flags: header.TCPFlagAck, WindowSize: 100, DataOffset: header.TCPMinimumSize})
	ip := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
	ip.Encode(&header.IPv6Fields{
		TrafficClass:      42,
		FlowLabel:         7,
		PayloadLength:     header.TCPMinimumSize + 8,
		TransportProtocol: tcpip.TransportProtocolNumber(header.IPv6HopByHopOptionsExtHdrIdentifier),
		HopLimit:          64,
		SrcAddr:           addr6("fd00::1"),
		DstAddr:           addr6("2001:db8::a:2"),
	})
	pkt.NetworkProtocolNumber = header.IPv6ProtocolNumber
	pkt.TransportProtocolNumber = header.TCPProtocolNumber
	return pkt
}

func TestLogTargetIPv6LineHasTheFormatOfNfLogSyslog(t *testing.T) {
	tgt, _ := newBoundLogTarget(t, 4, "v6: ")
	got := tgt.line(ipv6TCPPacket(t), "", "eth0")
	want := "v6: IN= OUT=eth0 " +
		"SRC=fd00:0000:0000:0000:0000:0000:0000:0001 DST=2001:0db8:0000:0000:0000:0000:000a:0002 " +
		"LEN=68 TC=42 HOPLIMIT=64 FLOWLBL=7 PROTO=TCP SPT=1234 DPT=80 WINDOW=100 RES=0x00 ACK URGP=0 "
	if got != want {
		t.Errorf("line =\n%q\nwant\n%q", got, want)
	}
}

func TestLogTargetWithoutALogFunctionAllocatesNothingPerPacket(t *testing.T) {
	tgt, err := parseTarget(stack.EmptyFilter4(), logEntry(4, []byte("x")), false, filterTable)
	if err != nil {
		t.Fatal(err)
	}
	pkt := synPacket(t)
	if allocs := testing.AllocsPerRun(100, func() { tgt.Action(pkt, stack.Input, nil, nil) }); allocs != 0 {
		t.Errorf("Action allocates %v times for a rule that nobody reads, want 0", allocs)
	}
}

func TestSetStackLogNilRemovesTheEntry(t *testing.T) {
	stk := stack.New(stack.Options{})
	t.Cleanup(stk.Destroy)
	SetStackLog(stk, func(int, string) {})
	if stackLog(stk) == nil {
		t.Fatal("the log function is not set")
	}
	SetStackLog(stk, nil)
	if stackLog(stk) != nil {
		t.Errorf("SetStackLog(stk, nil) left the log function")
	}
}
