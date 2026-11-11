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
	"context"
	"fmt"
	"sync/atomic"

	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/ethernet"
	"z.gfire.dev/gvx/pkg/tcpip/link/loopback"
	"z.gfire.dev/gvx/pkg/tcpip/link/packetsocket"
	"z.gfire.dev/gvx/pkg/tcpip/network/arp"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/icmp"
	"z.gfire.dev/gvx/pkg/tcpip/transport/raw"
	"z.gfire.dev/gvx/pkg/tcpip/transport/tcp"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
)

type restoredStackCreator struct {
	root   *Stack
	nextID atomic.Uint64
}

// NewStackCreator returns a savable inet.NetworkStackCreator that constructs
// isolated child network namespace stacks configured from root.
func NewStackCreator(root *Stack) inet.NetworkStackCreator {
	return &restoredStackCreator{root: root}
}

func (c *restoredStackCreator) CreateStack() (inet.Stack, error) {
	var clock tcpip.Clock
	var baseID uint64
	if c.root != nil {
		baseID = c.root.id
		if c.root.Stack != nil {
			clock = c.root.Stack.Clock()
		}
	}
	st := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
			arp.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
		RawFactory:               &raw.EndpointFactory{},
		Clock:                    clock,
		HandleLocal:              true,
		AllowPacketEndpointWrite: true,
	})
	loEP := packetsocket.New(ethernet.New(loopback.New()))
	if err := st.CreateNICWithOptions(1, loEP, stack.NICOptions{
		Name:               "lo",
		DeliverLinkPackets: true,
	}); err != nil {
		st.Destroy()
		return nil, fmt.Errorf("create loopback NIC: %s", err)
	}
	lo4 := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
			PrefixLen: 8,
		},
	}
	if err := st.AddProtocolAddress(1, lo4, stack.AddressProperties{}); err != nil {
		st.Destroy()
		return nil, fmt.Errorf("add IPv4 loopback address: %s", err)
	}
	lo6 := tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   header.IPv6Loopback,
			PrefixLen: 128,
		},
	}
	if err := st.AddProtocolAddress(1, lo6, stack.AddressProperties{}); err != nil {
		st.Destroy()
		return nil, fmt.Errorf("add IPv6 loopback address: %s", err)
	}
	loSubnet4, err := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{127, 0, 0, 0}), tcpip.MaskFromBytes([]byte{255, 0, 0, 0}))
	if err != nil {
		st.Destroy()
		return nil, err
	}
	loSubnet6, err := tcpip.NewSubnet(header.IPv6Loopback, tcpip.MaskFromBytes(bytes.Repeat([]byte{0xff}, 16)))
	if err != nil {
		st.Destroy()
		return nil, err
	}
	st.SetRouteTable([]tcpip.Route{
		{Destination: loSubnet4, NIC: 1},
		{Destination: loSubnet6, NIC: 1},
	})
	nsStack := NewStack(st, baseID+c.nextID.Add(1))
	if c.root != nil {
		_ = nsStack.InheritForwarding(c.root)
		nsStack.InheritRPFilter(c.root)
		nsStack.InitConntrackLimit(c.root)
	}
	return nsStack, nil
}

func (*restoredStackCreator) StateTypeName() string {
	return "pkg/sentry/socket/netstack.restoredStackCreator"
}

func (*restoredStackCreator) StateFields() []string {
	return []string{"root", "nextID"}
}

func (c *restoredStackCreator) StateSave(sink state.Sink) {
	id := c.nextID.Load()
	sink.Save(0, &c.root)
	sink.SaveUint64(1, &id)
}

func (c *restoredStackCreator) StateLoad(_ context.Context, src state.Source) {
	var id uint64
	src.Load(0, &c.root)
	src.LoadUint64(1, &id)
	c.nextID.Store(id)
}

// RestoreNetworkNamespaceCreator returns a NetworkStackCreator that creates
// child network namespace stacks configured from s.
func (s *Stack) RestoreNetworkNamespaceCreator() inet.NetworkStackCreator {
	return &restoredStackCreator{root: s}
}

// EnsureInterfaceEventSubscriber sets sub as the interface event subscriber
// when none is registered yet.
func (s *Stack) EnsureInterfaceEventSubscriber(sub inet.InterfaceEventSubscriber) {
	if s.eventSubscriber == nil {
		s.eventSubscriber = sub
	}
}

// RestoreChildStack wires runtime policies and shared kernel limits on a
// restored child network namespace stack from rootStack.
func (s *Stack) RestoreChildStack(rootStack inet.Stack) {
	s.bindStackPolicies()
	if root, ok := rootStack.(*Stack); ok && root != nil {
		s.InitConntrackLimit(root)
	}
}

// SetChildStackCallbacks forwards child stack lifecycle callbacks to the
// underlying tcpip.Stack.
func (s *Stack) SetChildStackCallbacks(pause, resume, restore func()) {
	if s != nil && s.Stack != nil {
		s.Stack.SetChildStackCallbacks(pause, resume, restore)
	}
}

func init() {
	state.RegisterNoHooks((*restoredStackCreator)(nil))
}
