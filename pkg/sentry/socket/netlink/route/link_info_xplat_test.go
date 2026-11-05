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
	"sync"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// linkAttrs returns the attributes of the RTM_NEWLINK message that
// writeLinkInfo writes for i.
func linkAttrs(t *testing.T, i inet.Interface) map[uint16]nlmsg.BytesView {
	t.Helper()
	m := nlmsg.NewMessage(linux.NetlinkMessageHeader{})
	writeLinkInfo(m, 3, i, nil)
	var ifi linux.InterfaceInfoMessage
	view, ok := m.GetData(&ifi)
	if !ok {
		t.Fatal("the message has no ifinfomsg")
	}
	attrs, ok := view.Parse()
	if !ok {
		t.Fatal("the attributes do not parse")
	}
	return attrs
}

func TestLinkWithoutLinkLayerHasNoAddressAttributes(t *testing.T) {
	none := linkAttrs(t, inet.Interface{Name: "wg0", DeviceType: linux.ARPHRD_NONE})
	for _, typ := range []uint16{linux.IFLA_ADDRESS, linux.IFLA_BROADCAST} {
		if v, ok := none[typ]; ok {
			t.Errorf("a link of type ARPHRD_NONE has attribute %d = %x, want it absent, as on Linux", typ, []byte(v))
		}
	}
	lo := linkAttrs(t, inet.Interface{Name: "lo", DeviceType: linux.ARPHRD_LOOPBACK})
	if v, ok := lo[linux.IFLA_ADDRESS]; !ok || len(v) != 6 {
		t.Errorf("the loopback IFLA_ADDRESS = %x, want 6 zero bytes", []byte(v))
	}
	eth := linkAttrs(t, inet.Interface{Name: "eth0", DeviceType: linux.ARPHRD_ETHER, Addr: []byte{2, 0, 0, 0, 0, 1}})
	if v := eth[linux.IFLA_ADDRESS]; len(v) != 6 || v[5] != 1 {
		t.Errorf("the Ethernet IFLA_ADDRESS = %x, want the link address", []byte(v))
	}
}

var registerKind sync.Once

func TestOperStateOfAKindWithoutCarrierIsUnknownWhileUp(t *testing.T) {
	const kind = "test-oper-unknown"
	// The registry has no removal, and -count=2 runs the test twice in one
	// process.
	registerKind.Do(func() {
		netstack.RegisterLinkKind(kind, netstack.LinkKind{
			NamePrefix: "to",
			New: func(context.Context, *netstack.NewLinkRequest) (stack.LinkEndpoint, *syserr.Error) {
				return nil, syserr.ErrNotSupported
			},
			OperStateUnknown: true,
		})
	})
	oper := func(kind string, flags uint32) uint8 {
		attrs := linkAttrs(t, inet.Interface{Name: "x0", Kind: kind, Flags: flags})
		v := attrs[linux.IFLA_OPERSTATE]
		b, _ := v.Uint8()
		return b
	}
	if got := oper(kind, linux.IFF_UP); got != linux.IF_OPER_UNKNOWN {
		t.Errorf("operstate of the up link of the kind = %d, want IF_OPER_UNKNOWN", got)
	}
	if got := oper(kind, 0); got != linux.IF_OPER_DOWN {
		t.Errorf("operstate of the down link of the kind = %d, want IF_OPER_DOWN", got)
	}
	if got := oper("veth", linux.IFF_UP); got != linux.IF_OPER_UP {
		t.Errorf("operstate of an up veth = %d, want IF_OPER_UP", got)
	}
}
