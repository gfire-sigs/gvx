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
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
)

// request builds a neighbor message of the type with the body and the master
// attribute.
func request(typ uint16, body []byte, master uint32) *nlmsg.Message {
	m := nlmsg.NewMessage(linux.NetlinkMessageHeader{Type: typ, Flags: linux.NLM_F_REQUEST | linux.NLM_F_DUMP})
	m.Put(primitive.AsByteSlice(body))
	if master != 0 {
		m.PutAttr(iflaMaster, primitive.AllocateUint32(master))
	}
	return m
}

func TestParseNdmsgReadsTheShortAndTheLongFormOfAnFDBDump(t *testing.T) {
	short := ndmsg{family: afBridge, ifindex: 7}.bytes()
	long := make([]byte, ifinfoSize)
	long[0] = afBridge
	binary.NativeEndian.PutUint32(long[4:], 9)
	// ifi_flags and ifi_change would read as the state and flags of ndmsg.
	binary.NativeEndian.PutUint32(long[8:], 0xffffffff)

	tests := []struct {
		name       string
		msg        *nlmsg.Message
		ifindex    int32
		wantMaster uint32
		long       bool
	}{
		{"struct ndmsg", request(linux.RTM_GETNEIGH, short, 0), 7, 0, false},
		{"struct ndmsg with IFLA_MASTER", request(linux.RTM_GETNEIGH, short, 3), 7, 3, false},
		{"struct ifinfomsg", request(linux.RTM_GETNEIGH, long, 0), 9, 0, true},
		{"struct ifinfomsg with IFLA_MASTER", request(linux.RTM_GETNEIGH, long, 4), 9, 4, true},
	}
	for _, tc := range tests {
		nd, attrs, ok := parseNdmsg(tc.msg)
		if !ok || nd.family != afBridge || nd.ifindex != tc.ifindex {
			t.Errorf("%s: parseNdmsg = family %d, ifindex %d, ok %v; want AF_BRIDGE, %d, true", tc.name, nd.family, nd.ifindex, ok, tc.ifindex)
			continue
		}
		if tc.long && (nd.state != 0 || nd.flags != 0) {
			t.Errorf("%s: state %#x and flags %#x come from ifi_flags, want 0", tc.name, nd.state, nd.flags)
		}
		// dumpNeigh reads the bridge from the key ndaMaster.
		var master uint32
		if v, ok := attrs[ndaMaster]; ok {
			master, _ = v.Uint32()
		}
		if master != tc.wantMaster {
			t.Errorf("%s: master = %d, want %d", tc.name, master, tc.wantMaster)
		}
	}
}

func TestParseNdmsgKeepsTheStateOfARequestToChangeAnEntry(t *testing.T) {
	body := ndmsg{family: afBridge, ifindex: 5, state: nudPermanent, flags: ntfSelf}.bytes()
	nd, _, ok := parseNdmsg(request(linux.RTM_NEWNEIGH, body, 0))
	if !ok || nd.state != nudPermanent || nd.flags != ntfSelf || nd.ifindex != 5 {
		t.Fatalf("parseNdmsg = %+v, %v; want the state and the flags of the request", nd, ok)
	}
}

func TestParseNdmsgRejectsAShortBody(t *testing.T) {
	if _, _, ok := parseNdmsg(request(linux.RTM_GETNEIGH, []byte{afBridge, 0, 0, 0}, 0)); ok {
		t.Fatal("parseNdmsg accepted a body shorter than struct ndmsg")
	}
}
