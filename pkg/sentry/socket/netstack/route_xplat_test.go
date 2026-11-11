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

package netstack

import (
	"bytes"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
)

func buildRouteNetlinkMessage(t *testing.T, msgType, flags uint16, rtMsg linux.RouteMessage, buildAttrs func(*nlmsg.Message)) *nlmsg.Message {
	t.Helper()
	m := nlmsg.NewMessage(linux.NetlinkMessageHeader{
		Type:  msgType,
		Flags: linux.NLM_F_REQUEST | flags,
	})
	m.Put(&rtMsg)
	if buildAttrs != nil {
		buildAttrs(m)
	}
	parsed, _, ok := nlmsg.ParseMessage(m.Finalize())
	if !ok {
		t.Fatal("nlmsg.ParseMessage failed")
	}
	return parsed
}

func TestInterfaceAddrPreservesCustomTableRoutes(t *testing.T) {
	ctx := context.Background()
	s := ethtoolStack(t, "lo", "veth")
	const nicID = 2
	const customTable = 100

	customMsg := buildRouteNetlinkMessage(t, linux.RTM_NEWROUTE, linux.NLM_F_CREATE|linux.NLM_F_EXCL, linux.RouteMessage{
		Family:   linux.AF_INET,
		DstLen:   24,
		Protocol: linux.RTPROT_BOOT,
		Scope:    linux.RT_SCOPE_LINK,
		Type:     linux.RTN_UNICAST,
	}, func(m *nlmsg.Message) {
		m.PutAttr(linux.RTA_DST, primitive.AsByteSlice([]byte{10, 20, 30, 0}))
		oif := primitive.Int32(nicID)
		m.PutAttr(linux.RTA_OIF, &oif)
		tbl := primitive.Uint32(customTable)
		m.PutAttr(linux.RTA_TABLE, &tbl)
	})
	if err := s.NewRoute(ctx, customMsg); err != nil {
		t.Fatalf("NewRoute(custom table): %v", err)
	}

	addr := inet.InterfaceAddr{
		Family:    linux.AF_INET,
		PrefixLen: 24,
		Addr:      []byte{10, 20, 30, 1},
	}
	if err := s.AddInterfaceAddr(ctx, nicID, addr); err != nil {
		t.Fatalf("AddInterfaceAddr: %v", err)
	}

	var sawMainKernel, sawCustom bool
	for _, rt := range s.RouteTable() {
		if !bytes.Equal(rt.DstAddr, []byte{10, 20, 30, 0}) || rt.DstLen != 24 {
			continue
		}
		switch rt.Table {
		case tcpip.RouteTableMain:
			if rt.Protocol == linux.RTPROT_KERNEL && rt.Scope == linux.RT_SCOPE_LINK {
				sawMainKernel = true
			}
		case customTable:
			sawCustom = true
		}
	}
	if !sawMainKernel || !sawCustom {
		t.Fatalf("RouteTable after AddInterfaceAddr: sawMainKernel=%v sawCustom=%v, want both true", sawMainKernel, sawCustom)
	}

	if err := s.RemoveInterfaceAddr(ctx, nicID, addr); err != nil {
		t.Fatalf("RemoveInterfaceAddr: %v", err)
	}

	sawMainKernel = false
	sawCustom = false
	for _, rt := range s.RouteTable() {
		if !bytes.Equal(rt.DstAddr, []byte{10, 20, 30, 0}) || rt.DstLen != 24 {
			continue
		}
		if rt.Table == tcpip.RouteTableMain {
			sawMainKernel = true
		}
		if rt.Table == customTable {
			sawCustom = true
		}
	}
	if sawMainKernel {
		t.Errorf("RemoveInterfaceAddr left main-table prefix route in RouteTable")
	}
	if !sawCustom {
		t.Errorf("RemoveInterfaceAddr deleted custom-table route in table %d", customTable)
	}
}

func TestNewRouteValidatesGatewayByTableAndRejectsBlackholeNextHop(t *testing.T) {
	ctx := context.Background()
	s := ethtoolStack(t, "lo", "veth", "bridge")
	const (
		nicA        = 2
		nicB        = 3
		customTable = 200
	)

	// Add 192.0.2.0/24 on nicA in main table and on nicB in customTable.
	mainSubnet := buildRouteNetlinkMessage(t, linux.RTM_NEWROUTE, linux.NLM_F_CREATE|linux.NLM_F_EXCL, linux.RouteMessage{
		Family:   linux.AF_INET,
		DstLen:   24,
		Protocol: linux.RTPROT_BOOT,
		Scope:    linux.RT_SCOPE_LINK,
		Type:     linux.RTN_UNICAST,
	}, func(m *nlmsg.Message) {
		m.PutAttr(linux.RTA_DST, primitive.AsByteSlice([]byte{192, 0, 2, 0}))
		oif := primitive.Int32(nicA)
		m.PutAttr(linux.RTA_OIF, &oif)
	})
	if err := s.NewRoute(ctx, mainSubnet); err != nil {
		t.Fatalf("NewRoute(main subnet): %v", err)
	}

	customSubnet := buildRouteNetlinkMessage(t, linux.RTM_NEWROUTE, linux.NLM_F_CREATE|linux.NLM_F_EXCL, linux.RouteMessage{
		Family:   linux.AF_INET,
		DstLen:   24,
		Protocol: linux.RTPROT_BOOT,
		Scope:    linux.RT_SCOPE_LINK,
		Type:     linux.RTN_UNICAST,
	}, func(m *nlmsg.Message) {
		m.PutAttr(linux.RTA_DST, primitive.AsByteSlice([]byte{192, 0, 2, 0}))
		oif := primitive.Int32(nicB)
		m.PutAttr(linux.RTA_OIF, &oif)
		tbl := primitive.Uint32(customTable)
		m.PutAttr(linux.RTA_TABLE, &tbl)
	})
	if err := s.NewRoute(ctx, customSubnet); err != nil {
		t.Fatalf("NewRoute(custom subnet): %v", err)
	}

	// A gateway route in customTable without RTA_OIF selects nicB from customTable.
	gwRoute := buildRouteNetlinkMessage(t, linux.RTM_NEWROUTE, linux.NLM_F_CREATE|linux.NLM_F_EXCL, linux.RouteMessage{
		Family:   linux.AF_INET,
		DstLen:   24,
		Protocol: linux.RTPROT_STATIC,
		Scope:    linux.RT_SCOPE_UNIVERSE,
		Type:     linux.RTN_UNICAST,
	}, func(m *nlmsg.Message) {
		m.PutAttr(linux.RTA_DST, primitive.AsByteSlice([]byte{198, 51, 100, 0}))
		m.PutAttr(linux.RTA_GATEWAY, primitive.AsByteSlice([]byte{192, 0, 2, 254}))
		tbl := primitive.Uint32(customTable)
		m.PutAttr(linux.RTA_TABLE, &tbl)
	})
	if err := s.NewRoute(ctx, gwRoute); err != nil {
		t.Fatalf("NewRoute(gateway in customTable): %v", err)
	}

	var gotNIC int32
	for _, rt := range s.RouteTable() {
		if rt.Table == customTable && bytes.Equal(rt.DstAddr, []byte{198, 51, 100, 0}) {
			gotNIC = rt.OutputInterface
		}
	}
	if gotNIC != nicB {
		t.Fatalf("gateway route OutputInterface = %d, want %d from own table", gotNIC, nicB)
	}

	delMsg := buildRouteNetlinkMessage(t, linux.RTM_DELROUTE, 0, linux.RouteMessage{
		Family: linux.AF_INET,
		DstLen: 24,
	}, func(m *nlmsg.Message) {
		m.PutAttr(linux.RTA_DST, primitive.AsByteSlice([]byte{198, 51, 100, 0}))
		tbl := primitive.Uint32(customTable)
		m.PutAttr(linux.RTA_TABLE, &tbl)
	})
	if err := s.RemoveRoute(ctx, delMsg); err != nil {
		t.Fatalf("RemoveRoute(gateway in customTable): %v", err)
	}

	// A blackhole route covering the gateway makes NewRoute reject the gateway with EINVAL.
	blackhole := buildRouteNetlinkMessage(t, linux.RTM_NEWROUTE, linux.NLM_F_CREATE|linux.NLM_F_EXCL, linux.RouteMessage{
		Family:   linux.AF_INET,
		DstLen:   24,
		Protocol: linux.RTPROT_STATIC,
		Scope:    linux.RT_SCOPE_UNIVERSE,
		Type:     linux.RTN_BLACKHOLE,
	}, func(m *nlmsg.Message) {
		m.PutAttr(linux.RTA_DST, primitive.AsByteSlice([]byte{203, 0, 113, 0}))
	})
	if err := s.NewRoute(ctx, blackhole); err != nil {
		t.Fatalf("NewRoute(blackhole): %v", err)
	}

	viaBlackhole := buildRouteNetlinkMessage(t, linux.RTM_NEWROUTE, linux.NLM_F_CREATE|linux.NLM_F_EXCL, linux.RouteMessage{
		Family:   linux.AF_INET,
		DstLen:   32,
		Protocol: linux.RTPROT_STATIC,
		Scope:    linux.RT_SCOPE_UNIVERSE,
		Type:     linux.RTN_UNICAST,
	}, func(m *nlmsg.Message) {
		m.PutAttr(linux.RTA_DST, primitive.AsByteSlice([]byte{198, 18, 0, 1}))
		m.PutAttr(linux.RTA_GATEWAY, primitive.AsByteSlice([]byte{203, 0, 113, 1}))
	})
	if got := s.NewRoute(ctx, viaBlackhole); got != syserr.ErrInvalidArgument {
		t.Fatalf("NewRoute(via blackhole gateway) = %v, want %v", got, syserr.ErrInvalidArgument)
	}
}
