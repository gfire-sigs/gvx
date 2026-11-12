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

package tcp

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/loopback"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/waiter"
)

func newConfiguredLoopbackStack(t *testing.T) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{NewProtocol},
	})
	if err := s.CreateNIC(1, loopback.New()); err != nil {
		s.Destroy()
		t.Fatalf("CreateNIC: %s", err)
	}
	lo4 := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}).WithPrefix(),
	}
	if err := s.AddProtocolAddress(1, lo4, stack.AddressProperties{}); err != nil {
		s.Destroy()
		t.Fatalf("AddProtocolAddress: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	return s
}

func TestEndpointBoundWildcardStateRoundTrip(t *testing.T) {
	t.Run("bound dual-stack wildcard", func(t *testing.T) {
		const reservedPort = 41009

		s := newConfiguredLoopbackStack(t)
		defer s.Destroy()

		var wq waiter.Queue
		rawEP, tcpErr := s.NewEndpoint(ProtocolNumber, ipv6.ProtocolNumber, &wq)
		if tcpErr != nil {
			t.Fatalf("NewEndpoint: %s", tcpErr)
		}
		defer rawEP.Close()

		if err := rawEP.Bind(tcpip.FullAddress{Port: reservedPort}); err != nil {
			t.Fatalf("Bind wildcard: %s", err)
		}

		orig := rawEP.(*Endpoint)
		wantNetworks := slices.Clone(orig.reservedNetworks())
		if !orig.boundWildcard || len(wantNetworks) != 2 {
			t.Fatalf("before save: boundWildcard=%v reservedNetworks=%v, want true and 2 networks", orig.boundWildcard, wantNetworks)
		}

		s.Pause()
		var buf bytes.Buffer
		ctx := context.Background()
		_, saveErr := state.Save(ctx, &buf, orig)
		s.Resume()
		if saveErr != nil {
			t.Fatalf("state.Save: %v", saveErr)
		}

		var restored Endpoint
		if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
			t.Fatalf("state.Load: %v", err)
		}
		defer restored.stack.Destroy()

		restored.stack.ResetConfig()
		cfgStack := newConfiguredLoopbackStack(t)
		restored.stack.ReplaceConfig(cfgStack)
		cfgStack.ResetConfig()
		cfgStack.Destroy()
		restored.stack.Restore()

		if !restored.boundWildcard {
			restored.Close()
			t.Fatalf("restored.boundWildcard = false, want true")
		}
		if got := restored.reservedAddr(); got != (tcpip.Address{}) {
			restored.Close()
			t.Fatalf("restored.reservedAddr() = %s, want wildcard empty address", got)
		}
		if got := restored.reservedNetworks(); !slices.Equal(got, wantNetworks) {
			restored.Close()
			t.Fatalf("restored.reservedNetworks() = %v, want %v", got, wantNetworks)
		}

		restored.Close()

		var rebindWQ waiter.Queue
		rebindEP, rebindErr := restored.stack.NewEndpoint(ProtocolNumber, ipv6.ProtocolNumber, &rebindWQ)
		if rebindErr != nil {
			t.Fatalf("NewEndpoint rebind: %s", rebindErr)
		}
		defer rebindEP.Close()
		if err := rebindEP.Bind(tcpip.FullAddress{Port: reservedPort}); err != nil {
			t.Fatalf("rebind wildcard port %d after restored Close: %s", reservedPort, err)
		}
	})

	t.Run("connected dual-stack wildcard to IPv4-mapped peer", func(t *testing.T) {
		const (
			clientPort = 41010
			serverPort = 8091
		)
		loAddr := tcpip.AddrFrom4([4]byte{127, 0, 0, 1})
		mappedPeer := tcpip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 12: 127, 15: 1})

		s := newConfiguredLoopbackStack(t)
		defer s.Destroy()
		s.SetAllowConnectedOnSave(true)

		var listenWQ waiter.Queue
		listener, tcpErr := s.NewEndpoint(ProtocolNumber, ipv4.ProtocolNumber, &listenWQ)
		if tcpErr != nil {
			t.Fatalf("NewEndpoint listener: %s", tcpErr)
		}
		defer listener.Close()
		if err := listener.Bind(tcpip.FullAddress{Addr: loAddr, Port: serverPort}); err != nil {
			t.Fatalf("Bind listener: %s", err)
		}
		if err := listener.Listen(1); err != nil {
			t.Fatalf("Listen: %s", err)
		}

		var clientWQ waiter.Queue
		rawClient, tcpErr := s.NewEndpoint(ProtocolNumber, ipv6.ProtocolNumber, &clientWQ)
		if tcpErr != nil {
			t.Fatalf("NewEndpoint client: %s", tcpErr)
		}
		defer rawClient.Close()
		if err := rawClient.Bind(tcpip.FullAddress{Port: clientPort}); err != nil {
			t.Fatalf("Bind client wildcard: %s", err)
		}

		we, ch := waiter.NewChannelEntry(waiter.WritableEvents)
		clientWQ.EventRegister(&we)
		connectErr := rawClient.Connect(tcpip.FullAddress{Addr: mappedPeer, Port: serverPort})
		if connectErr != nil {
			if _, ok := connectErr.(*tcpip.ErrConnectStarted); !ok {
				clientWQ.EventUnregister(&we)
				t.Fatalf("Connect: %s", connectErr)
			}
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
				clientWQ.EventUnregister(&we)
				t.Fatal("Connect timed out")
			}
		}
		clientWQ.EventUnregister(&we)

		orig := rawClient.(*Endpoint)
		if !orig.boundWildcard {
			t.Fatal("orig.boundWildcard = false after Connect, want true")
		}
		if !slices.Equal(orig.reservedNetworks(), []tcpip.NetworkProtocolNumber{ipv6.ProtocolNumber}) {
			t.Fatalf("orig.reservedNetworks() = %v, want [%d]", orig.reservedNetworks(), ipv6.ProtocolNumber)
		}

		s.Pause()
		var buf bytes.Buffer
		ctx := context.Background()
		_, saveErr := state.Save(ctx, &buf, orig)
		s.Resume()
		if saveErr != nil {
			t.Fatalf("state.Save: %v", saveErr)
		}

		var restored Endpoint
		if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
			t.Fatalf("state.Load: %v", err)
		}
		defer restored.stack.Destroy()

		restored.stack.ResetConfig()
		cfgStack := newConfiguredLoopbackStack(t)
		restored.stack.ReplaceConfig(cfgStack)
		cfgStack.ResetConfig()
		cfgStack.Destroy()
		restored.stack.Restore()
		defer restored.Close()

		if !restored.boundWildcard {
			t.Fatalf("restored.boundWildcard = false, want true")
		}
		if got := restored.reservedAddr(); got != (tcpip.Address{}) {
			t.Fatalf("restored.reservedAddr() = %s, want wildcard empty address", got)
		}
		if got := restored.reservedNetworks(); !slices.Equal(got, []tcpip.NetworkProtocolNumber{ipv6.ProtocolNumber}) {
			t.Fatalf("restored.reservedNetworks() = %v, want [%d]", got, ipv6.ProtocolNumber)
		}
	})
}

type nonSavableLinkEndpoint struct {
	stack.LinkEndpoint
}

func (nonSavableLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

func newNonSavableStack(t *testing.T, addr tcpip.Address) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{NewProtocol},
		HandleLocal:        true,
	})
	if err := s.CreateNIC(1, nonSavableLinkEndpoint{LinkEndpoint: loopback.New()}); err != nil {
		s.Destroy()
		t.Fatalf("CreateNIC: %s", err)
	}
	pa := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr, PrefixLen: 24},
	}
	if err := s.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
		s.Destroy()
		t.Fatalf("AddProtocolAddress: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	return s
}

func TestTerminatedConnectedEndpointRemovedFromDemuxerBeforeSave(t *testing.T) {
	const (
		clientPort = 41021
		serverPort = 8080
	)
	addr := tcpip.AddrFrom4([4]byte{10, 0, 2, 15})

	s := newNonSavableStack(t, addr)
	defer s.Destroy()

	var listenWQ waiter.Queue
	listener, tcpErr := s.NewEndpoint(ProtocolNumber, ipv4.ProtocolNumber, &listenWQ)
	if tcpErr != nil {
		t.Fatalf("NewEndpoint listener: %s", tcpErr)
	}
	defer listener.Close()
	if err := listener.Bind(tcpip.FullAddress{Port: serverPort}); err != nil {
		t.Fatalf("Bind listener: %s", err)
	}
	if err := listener.Listen(4); err != nil {
		t.Fatalf("Listen: %s", err)
	}

	acceptWE, acceptCh := waiter.NewChannelEntry(waiter.ReadableEvents)
	listenWQ.EventRegister(&acceptWE)

	var clientWQ waiter.Queue
	client, tcpErr := s.NewEndpoint(ProtocolNumber, ipv4.ProtocolNumber, &clientWQ)
	if tcpErr != nil {
		t.Fatalf("NewEndpoint client: %s", tcpErr)
	}
	defer client.Close()
	if err := client.Bind(tcpip.FullAddress{Addr: addr, Port: clientPort}); err != nil {
		t.Fatalf("Bind client: %s", err)
	}

	connWE, connCh := waiter.NewChannelEntry(waiter.WritableEvents)
	clientWQ.EventRegister(&connWE)
	connectErr := client.Connect(tcpip.FullAddress{NIC: 1, Addr: addr, Port: serverPort})
	if connectErr != nil {
		if _, ok := connectErr.(*tcpip.ErrConnectStarted); !ok {
			clientWQ.EventUnregister(&connWE)
			t.Fatalf("Connect: %s", connectErr)
		}
		select {
		case <-connCh:
		case <-time.After(5 * time.Second):
			clientWQ.EventUnregister(&connWE)
			t.Fatal("Connect timed out")
		}
	}
	clientWQ.EventUnregister(&connWE)

	accepted, _, tcpErr := listener.Accept(nil)
	for tcpErr != nil {
		if _, ok := tcpErr.(*tcpip.ErrWouldBlock); !ok {
			t.Fatalf("Accept: %s", tcpErr)
		}
		select {
		case <-acceptCh:
		case <-time.After(5 * time.Second):
			t.Fatal("Accept timed out")
		}
		accepted, _, tcpErr = listener.Accept(nil)
	}
	listenWQ.EventUnregister(&acceptWE)

	// Close the accepted endpoint so it enters FIN-WAIT and is referenced only
	// through the stack demuxer while client remains ESTABLISHED/CLOSE-WAIT.
	accepted.Close()

	s.SetRemoveConf(true)
	s.Pause()
	var buf bytes.Buffer
	ctx := context.Background()
	_, saveErr := state.Save(ctx, &buf, &s)
	s.Resume()
	if saveErr != nil {
		t.Fatalf("state.Save: %v", saveErr)
	}

	var restored *stack.Stack
	if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	cfgStack := newNonSavableStack(t, addr)
	restored.ReplaceConfig(cfgStack)
	cfgStack.ResetConfig()
	cfgStack.Destroy()
	restored.Restore()

	for _, ep := range restored.RegisteredEndpoints() {
		if tcpEP, ok := ep.(*Endpoint); ok && tcpEP.EndpointState().closed() {
			t.Fatalf("restored demuxer retained closed endpoint %+v in state %v", tcpEP.TransportEndpointInfo.ID, tcpEP.EndpointState())
		}
	}
	restored.Destroy()
}
