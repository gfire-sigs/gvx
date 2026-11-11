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
	"bytes"
	"encoding/binary"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
)

// rtnlLinkStats64Fields is the number of 64-bit counters in struct
// rtnl_link_stats64 of Linux 6.8, which ends with rx_otherhost_dropped. netlink
// libraries cast the attribute to a struct of this size, so a shorter attribute
// would make them read past it.
const rtnlLinkStats64Fields = 25

func linkOperState(i inet.Interface, fallback uint8) uint8 {
	if kindState, ok := netstack.LinkOperState(i.Kind, i.Flags); ok {
		return kindState
	}
	return fallback
}

// hasLinkLayerAddr reports whether RTM_NEWLINK and RTM_DELLINK carry
// IFLA_ADDRESS and IFLA_BROADCAST for i. A link of type ARPHRD_NONE without an
// address omits both so "ip link" prints "link/none".
func hasLinkLayerAddr(i inet.Interface) bool {
	return !netstack.LinkHasNoLinkLayer(i.Kind) || len(i.Addr) > 0
}

func writeLinkInfoWithStack(m *nlmsg.Message, idx int32, i inet.Interface, stack inet.Stack) {
	m.Put(&linux.InterfaceInfoMessage{
		Family: linux.AF_UNSPEC,
		Type:   i.DeviceType,
		Index:  idx,
		Flags:  i.Flags,
	})

	m.PutAttrString(linux.IFLA_IFNAME, i.Name)
	m.PutAttr(linux.IFLA_MTU, primitive.AllocateUint32(i.MTU))

	operState := uint8(linux.IF_OPER_DOWN)
	if i.Flags&linux.IFF_UP != 0 {
		operState = linux.IF_OPER_UP
	}
	m.PutAttr(linux.IFLA_OPERSTATE, primitive.AllocateUint8(linkOperState(i, operState)))

	if hasLinkLayerAddr(i) {
		mac := make([]byte, 6)
		brd := mac
		if len(i.Addr) > 0 {
			mac = i.Addr
			brd = bytes.Repeat([]byte{0xff}, len(i.Addr))
		}
		m.PutAttr(linux.IFLA_ADDRESS, primitive.AsByteSlice(mac))
		m.PutAttr(linux.IFLA_BROADCAST, primitive.AsByteSlice(brd))
	}
	if i.Master != 0 {
		m.PutAttr(linux.IFLA_MASTER, primitive.AllocateUint32(i.Master))
	}

	if i.Kind != "" {
		var nestedAttrs nlmsg.NestedAttr
		nestedAttrs.PutAttrString(linux.IFLA_INFO_KIND, i.Kind)
		putLinkInfoData(&nestedAttrs, stack, idx, i)
		m.PutNestedAttr(linux.IFLA_LINKINFO, nestedAttrs)
	}
}

// addNewLinkMessageWithStats is AddNewLinkMessage plus the IFLA_STATS64
// attribute for the counters of the link. docker stats asks every container
// for the counters of its links and drops the whole answer, memory included,
// when a link has none.
func (p *Protocol) addNewLinkMessageWithStats(ms *nlmsg.MessageSet, stack inet.Stack, idx int32, i inet.Interface) {
	m := ms.AddMessage(linux.NetlinkMessageHeader{
		Type: linux.RTM_NEWLINK,
	})
	writeLinkInfoWithStack(m, idx, i, stack)

	var dev inet.StatDev
	if err := stack.Statistics(&dev, i.Name); err != nil {
		// The link has no counters, as for a link that vanished between the
		// listing and now.
		return
	}
	m.PutAttr(linux.IFLA_STATS64, primitive.AsByteSlice(linkStats64(dev)))
}

// linkStats64 returns struct rtnl_link_stats64 for the /proc/net/dev counters
// of a link. The struct starts with the packet and byte counters of both
// directions, and the other counters follow in a different order.
func linkStats64(dev inet.StatDev) []byte {
	const (
		devRxBytes, devRxPackets, devRxErrors, devRxDropped, devRxMulticast = 0, 1, 2, 3, 7
		devTxBytes, devTxPackets, devTxErrors, devTxDropped                 = 8, 9, 10, 11
	)
	fields := [rtnlLinkStats64Fields]uint64{
		0: dev[devRxPackets],
		1: dev[devTxPackets],
		2: dev[devRxBytes],
		3: dev[devTxBytes],
		4: dev[devRxErrors],
		5: dev[devTxErrors],
		6: dev[devRxDropped],
		7: dev[devTxDropped],
		8: dev[devRxMulticast],
	}
	b := make([]byte, 0, 8*rtnlLinkStats64Fields)
	for _, f := range fields {
		b = binary.NativeEndian.AppendUint64(b, f)
	}
	return b
}
