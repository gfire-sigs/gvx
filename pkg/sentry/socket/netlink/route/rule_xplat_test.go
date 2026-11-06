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

package route

import (
	"encoding/binary"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
)

// ruleDumpRequest returns an RTM_GETRULE dump request whose body has bodyLen
// bytes, the first of which is the family.
func ruleDumpRequest(t *testing.T, family uint8, bodyLen int) *nlmsg.Message {
	t.Helper()
	buf := make([]byte, linux.NetlinkMessageHeaderSize+bodyLen)
	binary.NativeEndian.PutUint32(buf[0:], uint32(len(buf)))
	binary.NativeEndian.PutUint16(buf[4:], linux.RTM_GETRULE)
	binary.NativeEndian.PutUint16(buf[6:], linux.NLM_F_REQUEST|linux.NLM_F_DUMP)
	if bodyLen > 0 {
		buf[linux.NetlinkMessageHeaderSize] = family
	}
	msg, _, ok := nlmsg.ParseMessage(buf)
	if !ok {
		t.Fatalf("ParseMessage failed")
	}
	return msg
}

// TestRuleDumpReadsOnlyTheFamily checks that a dump request with the body of
// struct rtgenmsg, which is one byte, works, as fib_nl_dumprule needs only the
// family. busybox "ip rule" and libnl send that body.
func TestRuleDumpReadsOnlyTheFamily(t *testing.T) {
	for _, tc := range []struct {
		name    string
		bodyLen int
		wantOK  bool
	}{
		{"no body", 0, false},
		{"rtgenmsg", 1, true},
		{"rtgenmsg with padding", 4, true},
		{"ifinfomsg", 16, true},
		{"fib_rule_hdr", 12, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, ok := parseRuleMessage(ruleDumpRequest(t, linux.AF_INET6, tc.bodyLen), false)
			if ok != tc.wantOK {
				t.Fatalf("parseRuleMessage ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && h.family != linux.AF_INET6 {
				t.Errorf("family = %d, want %d", h.family, linux.AF_INET6)
			}
		})
	}
}
