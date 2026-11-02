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
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// TestDNATTargetSizeMatchesMarshalledLength verifies that the size field of
// each DNAT revision covers the whole marshalled target. "iptables -C" and
// "iptables -D" compare the target bytes up to this size. With a size that is
// too small, they do not find a DNAT rule, and dockerd leaves the rule of a
// removed container behind.
func TestDNATTargetSizeMatchesMarshalledLength(t *testing.T) {
	for rev := uint8(0); rev <= 2; rev++ {
		dt := &dnatTarget{
			DNATTarget: stack.DNATTarget{
				NetworkProtocol: header.IPv4ProtocolNumber,
				Addr:            tcpip.AddrFrom4([4]byte{172, 17, 0, 2}),
				Port:            80,
				ChangeAddress:   true,
				ChangePort:      true,
			},
			revision: rev,
		}
		buf := marshalTarget(dt)
		var hdr linux.XTEntryTarget
		hdr.UnmarshalBytes(buf)
		if int(hdr.TargetSize) != len(buf) {
			t.Errorf("revision %d: TargetSize = %d, marshalled length = %d", rev, hdr.TargetSize, len(buf))
		}
	}
}
