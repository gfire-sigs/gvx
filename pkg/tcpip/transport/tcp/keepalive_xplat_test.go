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

package tcp_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/loopback"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/tcp"
	"z.gfire.dev/gvx/pkg/waiter"
)

func TestKeepaliveDefaultsSurviveSaveLoad(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	defer s.Close()

	if err := s.CreateNICWithOptions(1, loopback.New(), stack.NICOptions{Kind: "tun"}); err != nil {
		t.Fatalf("CreateNICWithOptions: %s", err)
	}
	pa := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}).WithPrefix(),
	}
	if err := s.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	want := tcpip.TCPKeepaliveDefaultsOption{
		Idle:     15 * time.Second,
		Interval: 3 * time.Second,
		Count:    4,
	}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &want); err != nil {
		t.Fatalf("SetTransportProtocolOption: %s", err)
	}

	ctx := context.Background()
	var buf bytes.Buffer
	if _, err := state.Save(ctx, &buf, &s); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	var restored *stack.Stack
	if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	defer restored.Close()
	restored.Restore()

	var got tcpip.TCPKeepaliveDefaultsOption
	if err := restored.TransportProtocolOption(tcp.ProtocolNumber, &got); err != nil {
		t.Fatalf("TransportProtocolOption after load: %s", err)
	}
	if got != want {
		t.Fatalf("restored TCPKeepaliveDefaultsOption = %+v, want %+v", got, want)
	}

	var wq waiter.Queue
	ep, err := restored.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint after load: %s", err)
	}
	defer ep.Close()

	var idle tcpip.KeepaliveIdleOption
	if err := ep.GetSockOpt(&idle); err != nil {
		t.Fatalf("GetSockOpt(KeepaliveIdleOption): %s", err)
	}
	var intvl tcpip.KeepaliveIntervalOption
	if err := ep.GetSockOpt(&intvl); err != nil {
		t.Fatalf("GetSockOpt(KeepaliveIntervalOption): %s", err)
	}
	cnt, err := ep.GetSockOptInt(tcpip.KeepaliveCountOption)
	if err != nil {
		t.Fatalf("GetSockOptInt(KeepaliveCountOption): %s", err)
	}
	if time.Duration(idle) != want.Idle || time.Duration(intvl) != want.Interval || cnt != want.Count {
		t.Fatalf("new endpoint keepalive = (idle=%v, interval=%v, count=%d), want (%v, %v, %d)",
			time.Duration(idle), time.Duration(intvl), cnt, want.Idle, want.Interval, want.Count)
	}
}
