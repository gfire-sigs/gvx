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
	"encoding/binary"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// nflogInfo is the user space view of struct xt_nflog_info.
type nflogInfo struct {
	length    uint32
	group     uint16
	threshold uint16
	flags     uint16
	prefix    string
	// rawPrefix replaces prefix when set, so that a test can fill all 64 bytes.
	rawPrefix []byte
}

// entry returns the whole xt_entry_target as userspace builds it for the
// target: the 32 byte header and the struct, padded to 112 bytes.
func (i nflogInfo) entry() []byte {
	buf := make([]byte, nflogTargetSize)
	hdr := linux.XTEntryTarget{TargetSize: nflogTargetSize}
	copy(hdr.Name[:], NFLogTargetName)
	hdr.MarshalUnsafe(buf)
	data := buf[linux.SizeOfXTEntryTarget:]
	binary.LittleEndian.PutUint32(data[0:], i.length)
	binary.LittleEndian.PutUint16(data[4:], i.group)
	binary.LittleEndian.PutUint16(data[6:], i.threshold)
	binary.LittleEndian.PutUint16(data[8:], i.flags)
	if i.rawPrefix != nil {
		copy(data[12:12+nflogPrefixLen], i.rawPrefix)
	} else {
		copy(data[12:12+nflogPrefixLen-1], i.prefix)
	}
	return buf
}

func parseNFLog(t *testing.T, filter stack.IPHeaderFilter, ipv6 bool, entry []byte) (stack.Target, *syserr.Error) {
	t.Helper()
	return parseTarget(filter, entry, ipv6, filterTable)
}

func TestNFLogParseAndMarshalRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		ipv6 bool
		info nflogInfo
	}{
		{"kube-router group", false, nflogInfo{group: 100}},
		{"prefix and threshold", false, nflogInfo{group: 1, threshold: 10, prefix: "cali-drop: "}},
		{"copy length flag", false, nflogInfo{group: 2, length: 128, flags: 1}},
		{"ipv6", true, nflogInfo{group: 100, prefix: "drop"}},
		{"longest prefix", false, nflogInfo{rawPrefix: append(bytes.Repeat([]byte{'a'}, nflogPrefixLen-1), 0)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter := stack.EmptyFilter4()
			if tc.ipv6 {
				filter = stack.EmptyFilter6()
			}
			entry := tc.info.entry()
			tgt, err := parseNFLog(t, filter, tc.ipv6, entry)
			if err != nil {
				t.Fatalf("parseTarget: %v", err)
			}
			if _, ok := tgt.(*nflogTarget); !ok {
				t.Fatalf("parseTarget returned %T, want *nflogTarget", tgt)
			}
			if got := marshalTarget(tgt); !bytes.Equal(got, entry) {
				t.Errorf("marshalTarget = %x, want %x", got, entry)
			}
		})
	}
}

func TestNFLogRejects(t *testing.T) {
	tests := []struct {
		name  string
		entry []byte
	}{
		{"unknown flag", nflogInfo{group: 1, flags: 2}.entry()},
		{"prefix without NUL byte", nflogInfo{rawPrefix: bytes.Repeat([]byte{'a'}, nflogPrefixLen)}.entry()},
		{"too short", nflogInfo{group: 1}.entry()[:nflogTargetSize-8]},
		{"too long", append(nflogInfo{group: 1}.entry(), make([]byte, 8)...)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The size of the target header stays at 112, as for a rule of
			// the wrong struct size that userspace sends.
			if _, err := parseNFLog(t, stack.EmptyFilter4(), false, tc.entry); err == nil {
				t.Errorf("parseTarget accepted the target")
			}
		})
	}
}

func TestNFLogRevisionIsReported(t *testing.T) {
	for _, proto := range []struct {
		name string
		ipv6 bool
	}{{"IPv4", false}, {"IPv6", true}} {
		filter := stack.EmptyFilter4()
		if proto.ipv6 {
			filter = stack.EmptyFilter6()
		}
		if rev, ok := targetRevision(NFLogTargetName, filter.NetworkProtocol(), 0); !ok || rev != 0 {
			t.Errorf("%s: targetRevision(NFLOG) = (%d, %v), want (0, true)", proto.name, rev, ok)
		}
	}
}

// TestNFLogContinuesTheChain sends echo requests through the INPUT chain. The
// NFLOG rule has no effect on the packet, so the rule after it decides.
func TestNFLogContinuesTheChain(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		name := "ipv4"
		if ipv6 {
			name = "ipv6"
		}
		t.Run(name, func(t *testing.T) {
			filter := icmpFilter(ipv6)
			tgt, err := parseNFLog(t, filter, ipv6, nflogInfo{group: 100, prefix: "x"}.entry())
			if err != nil {
				t.Fatalf("parseTarget: %v", err)
			}
			logRule := stack.Rule{Filter: filter, Target: tgt}

			ms := newMatchStack(t)
			ms.installRules(t, ipv6, stack.Input, logRule)
			if !ms.injectEchoRequest(t, ipv6) {
				t.Errorf("NFLOG alone dropped the request, want an echo reply")
			}

			ms = newMatchStack(t)
			ms.installRules(t, ipv6, stack.Input, logRule, dropRule(filter))
			if ms.injectEchoRequest(t, ipv6) {
				t.Errorf("the DROP rule after NFLOG did not run, got an echo reply")
			}
		})
	}
}

func TestNFLogActionReturnsContinue(t *testing.T) {
	tgt, err := parseNFLog(t, stack.EmptyFilter4(), false, nflogInfo{group: 100}.entry())
	if err != nil {
		t.Fatalf("parseTarget: %v", err)
	}
	pkt := buildICMPPacket(t, icmpPacketSpec{protocol: uint8(header.ICMPv4ProtocolNumber), typ: 8})
	mark := pkt.Mark
	if verdict, jump := tgt.Action(pkt, stack.Input, nil, nil); verdict != stack.RuleContinue || jump != 0 {
		t.Errorf("Action = (%v, %d), want (RuleContinue, 0)", verdict, jump)
	}
	if pkt.Mark != mark {
		t.Errorf("Action changed the mark of the packet")
	}
}
