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
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
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
		line := tgt.(*logTarget).line(pkt)
		for _, want := range []string{"cali-drop: ", "SRC=" + src, "DST=" + dst} {
			if !strings.Contains(line, want) {
				t.Errorf("log line %q lacks %q", line, want)
			}
		}
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
