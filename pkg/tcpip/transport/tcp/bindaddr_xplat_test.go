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
	"io"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/loopback"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/tcp"
	"z.gfire.dev/gvx/pkg/waiter"
)

var loopbackAddr = tcpip.AddrFrom4([4]byte{127, 0, 0, 1})

const (
	clientPort = 41000
	serverPort = 8081
)

// newLoopbackStack returns a stack with one loopback NIC and a listener on
// serverPort.
func newLoopbackStack(t *testing.T) (*stack.Stack, tcpip.Endpoint) {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	if err := s.CreateNIC(1, loopback.New()); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}
	addr := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: loopbackAddr.WithPrefix()}
	if err := s.AddProtocolAddress(1, addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	var wq waiter.Queue
	l, err := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint: %s", err)
	}
	if err := l.Bind(tcpip.FullAddress{Addr: loopbackAddr, Port: serverPort}); err != nil {
		t.Fatalf("Bind(listener): %s", err)
	}
	if err := l.Listen(1); err != nil {
		t.Fatalf("Listen: %s", err)
	}
	t.Cleanup(l.Close)
	return s, l
}

// bindWithRetry binds c to addr. The release of a closed client endpoint runs in
// the background, so a port that is in use gets a bounded number of retries.
func bindWithRetry(c tcpip.Endpoint, addr tcpip.FullAddress) tcpip.Error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := c.Bind(addr)
		if _, inUse := err.(*tcpip.ErrPortInUse); err == nil || !inUse || time.Now().After(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// connectFrom connects a new client endpoint of the network protocol netProto
// that Bind gave the port clientPort on the address bindAddr to peer, lets the
// server close first, and closes the client. It returns the error of the Bind
// call.
func connectFrom(t *testing.T, s *stack.Stack, l tcpip.Endpoint, netProto tcpip.NetworkProtocolNumber, bindAddr, peer tcpip.Address) tcpip.Error {
	t.Helper()
	var wq waiter.Queue
	c, err := s.NewEndpoint(tcp.ProtocolNumber, netProto, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint: %s", err)
	}
	defer c.Close()
	if err := bindWithRetry(c, tcpip.FullAddress{Addr: bindAddr, Port: clientPort}); err != nil {
		return err
	}
	we, ch := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&we)
	defer wq.EventUnregister(&we)
	if err := c.Connect(tcpip.FullAddress{Addr: peer, Port: serverPort}); err != nil {
		if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
			t.Fatalf("Connect: %s", err)
		}
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatal("Connect did not finish")
		}
	}
	var server tcpip.Endpoint
	for i := 0; i < 500 && server == nil; i++ {
		if ep, _, err := l.Accept(nil); err == nil {
			server = ep
		} else {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if server == nil {
		t.Fatal("the listener accepted no connection")
	}
	// The server closes first, so the client never enters TIME_WAIT.
	server.Close()
	for i := 0; i < 500; i++ {
		if _, err := c.Read(io.Discard, tcpip.ReadOptions{}); err != nil {
			if _, wouldBlock := err.(*tcpip.ErrWouldBlock); !wouldBlock {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

// TestBindThenConnectReleasesPort checks that a client can bind the same port
// again after its connection closed. The cases are a wildcard address and a
// specific address of an IPv4 endpoint, and a wildcard address of a dual-stack
// IPv6 endpoint that connects to an IPv4-mapped address. The client closes
// second, so it keeps no TIME_WAIT state.
func TestBindThenConnectReleasesPort(t *testing.T) {
	mapped := tcpip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 12: 127, 15: 1})
	for _, tc := range []struct {
		name     string
		netProto tcpip.NetworkProtocolNumber
		bind     tcpip.Address
		peer     tcpip.Address
	}{
		{"IPv4 wildcard address", ipv4.ProtocolNumber, tcpip.Address{}, loopbackAddr},
		{"IPv4 specific address", ipv4.ProtocolNumber, loopbackAddr, loopbackAddr},
		{"dual-stack wildcard address to a mapped address", ipv6.ProtocolNumber, tcpip.Address{}, mapped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, l := newLoopbackStack(t)
			for i := 0; i < 3; i++ {
				if err := connectFrom(t, s, l, tc.netProto, tc.bind, tc.peer); err != nil {
					t.Fatalf("connection %d: Bind: %s", i+1, err)
				}
			}
		})
	}
}
