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

package stack_test

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/faketime"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/ethernet"
	"z.gfire.dev/gvx/pkg/tcpip/link/veth"
	"z.gfire.dev/gvx/pkg/tcpip/network/arp"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
	"z.gfire.dev/gvx/pkg/waiter"
)

// The tests of this file send raw frames into a bridge whose stack has a DNAT
// rule in the PREROUTING chain of the nat table. The frames carry UDP
// datagrams from host 0, to a virtual address, with the Ethernet address of
// another host, so the bridge forwards them and runs the iptables hooks first.

var (
	nfBridgeIP  = tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	nfHostIP    = tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
	nfPeerIP    = tcpip.AddrFrom4([4]byte{10, 0, 0, 3})
	nfVirtualIP = tcpip.AddrFrom4([4]byte{10, 0, 0, 100})
	nfRemoteIP  = tcpip.AddrFrom4([4]byte{10, 9, 0, 5})
	nfRouterIP  = tcpip.AddrFrom4([4]byte{10, 9, 0, 1})
)

const (
	nfClientPort  = 40000
	nfVirtualPort = 80
	nfTargetPort  = 8080
	nfRouterNIC   = 2
)

// nfStack is a bridge with three ports, the address 10.0.0.1 on the bridge, and
// a second link with the address 10.9.0.1 for hosts behind a route.
type nfStack struct {
	*testBridge
	remote *bridgeHost
	udp    tcpip.Endpoint
	events *waiter.Queue
}

// newNFStack builds the stack and installs the DNAT rule for the virtual
// address 10.0.0.100 port 80 that moves the datagram to dnat.
func newNFStack(t *testing.T, dnat tcpip.FullAddress) *nfStack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
		Clock:              faketime.NewManualClock(),
	})
	b := &testBridge{t: t, stack: s}
	br := stack.NewBridgeEndpoint(1500)
	if err := s.CreateNIC(bridgeNICID, br); err != nil {
		t.Fatalf("CreateNIC(bridge): %s", err)
	}
	b.mac = br.LinkAddress()
	for i := range b.hosts {
		near, far := veth.NewPair(1500, 64)
		id := tcpip.NICID(10 + i)
		if err := s.CreateNICWithOptions(id, ethernet.New(near), stack.NICOptions{Name: fmt.Sprintf("port%d", i)}); err != nil {
			t.Fatalf("CreateNIC(port %d): %s", i, err)
		}
		if err := s.SetNICCoordinator(id, bridgeNICID); err != nil {
			t.Fatalf("SetNICCoordinator(port %d): %s", i, err)
		}
		h := &bridgeHost{end: far, mac: macs[i], frames: make(chan []byte, 64)}
		far.Attach(h)
		b.hosts[i] = h
	}
	near, far := veth.NewPair(1500, 64)
	if err := s.CreateNIC(nfRouterNIC, ethernet.New(near)); err != nil {
		t.Fatalf("CreateNIC(router): %s", err)
	}
	remote := &bridgeHost{end: far, mac: "\x02\x00\x00\x00\x00\x55", frames: make(chan []byte, 64)}
	far.Attach(remote)
	for _, a := range []struct {
		nic  tcpip.NICID
		addr tcpip.Address
		pl   int
	}{{bridgeNICID, nfBridgeIP, 24}, {nfRouterNIC, nfRouterIP, 24}} {
		pa := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: a.addr, PrefixLen: a.pl}}
		if err := s.AddProtocolAddress(a.nic, pa, stack.AddressProperties{}); err != nil {
			t.Fatalf("AddProtocolAddress: %s", err)
		}
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: mustSubnet(t, nfBridgeIP, 24), NIC: bridgeNICID},
		{Destination: mustSubnet(t, nfRouterIP, 24), NIC: nfRouterNIC},
	})
	if err := s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		t.Fatalf("SetForwarding: %s", err)
	}
	for _, n := range []struct {
		nic  tcpip.NICID
		addr tcpip.Address
		mac  tcpip.LinkAddress
	}{
		{bridgeNICID, nfHostIP, macs[0]},
		{bridgeNICID, nfPeerIP, macs[2]},
		{nfRouterNIC, nfRemoteIP, remote.mac},
	} {
		if err := s.AddStaticNeighbor(n.nic, ipv4.ProtocolNumber, n.addr, n.mac); err != nil {
			t.Fatalf("AddStaticNeighbor: %s", err)
		}
	}

	table := s.IPTables().GetTable(stack.NATID, false)
	rule := stack.Rule{
		Filter: stack.EmptyFilter4(),
		Target: &stack.DNATTarget{Addr: dnat.Addr, Port: dnat.Port, NetworkProtocol: ipv4.ProtocolNumber, ChangeAddress: true, ChangePort: true},
	}
	rule.Filter.Dst = nfVirtualIP
	rule.Filter.DstMask = tcpip.AddrFrom4([4]byte{255, 255, 255, 255})
	rule.Filter.Protocol = udp.ProtocolNumber
	rule.Filter.CheckProtocol = true
	table.Rules = append([]stack.Rule{rule}, table.Rules...)
	for hook := range table.BuiltinChains {
		if table.BuiltinChains[hook] != stack.HookUnset && hook != int(stack.Prerouting) {
			table.BuiltinChains[hook]++
		}
		if table.Underflows[hook] != stack.HookUnset {
			table.Underflows[hook]++
		}
	}
	s.IPTables().ForceReplaceTable(stack.NATID, table, false)

	n := &nfStack{testBridge: b, remote: remote, events: &waiter.Queue{}}
	ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, n.events)
	if err != nil {
		t.Fatalf("NewEndpoint: %s", err)
	}
	if err := ep.Bind(tcpip.FullAddress{Port: nfTargetPort}); err != nil {
		t.Fatalf("Bind: %s", err)
	}
	n.udp = ep
	t.Cleanup(ep.Close)
	return n
}

func mustSubnet(t *testing.T, addr tcpip.Address, prefix int) tcpip.Subnet {
	t.Helper()
	sn, err := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{addr.As4()[0], addr.As4()[1], addr.As4()[2], 0}), tcpip.MaskFromBytes([]byte{255, 255, 255, 0}))
	if err != nil {
		t.Fatalf("NewSubnet: %s", err)
	}
	return sn
}

// sendDatagram sends a UDP datagram from host 0 to dst:dport. The frame goes to
// the Ethernet address of host 1, as a host that resolved the virtual address
// with ARP would send it.
func (n *nfStack) sendDatagram(dst tcpip.Address, dport uint16, payload string) {
	n.sendDatagramTo(macs[1], dst, dport, payload)
}

// sendDatagramTo is sendDatagram with the Ethernet destination ethDst.
func (n *nfStack) sendDatagramTo(ethDst tcpip.LinkAddress, dst tcpip.Address, dport uint16, payload string) {
	udpLen := header.UDPMinimumSize + len(payload)
	frame := make([]byte, header.EthernetMinimumSize+header.IPv4MinimumSize+udpLen)
	header.Ethernet(frame).Encode(&header.EthernetFields{SrcAddr: macs[0], DstAddr: ethDst, Type: header.IPv4ProtocolNumber})
	ip := header.IPv4(frame[header.EthernetMinimumSize:])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize + udpLen),
		Protocol:    uint8(header.UDPProtocolNumber),
		TTL:         64,
		SrcAddr:     nfHostIP,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	u := header.UDP(frame[header.EthernetMinimumSize+header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{SrcPort: nfClientPort, DstPort: dport, Length: uint16(udpLen)})
	copy(frame[len(frame)-len(payload):], payload)

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
	defer pkt.DecRef()
	var list stack.PacketBufferList
	list.PushBack(pkt)
	n.hosts[0].end.WritePackets(list)
}

// udpFrame holds the fields of a captured UDP frame.
type udpFrame struct {
	ethDst, ethSrc tcpip.LinkAddress
	src, dst       tcpip.Address
	sport, dport   uint16
	payload        string
}

func parseUDPFrame(t *testing.T, f []byte) udpFrame {
	t.Helper()
	eth := header.Ethernet(f)
	if eth.Type() != header.IPv4ProtocolNumber {
		t.Fatalf("frame type = %#x, want IPv4", eth.Type())
	}
	ip := header.IPv4(f[header.EthernetMinimumSize:])
	u := header.UDP(ip.Payload())
	return udpFrame{
		ethDst: eth.DestinationAddress(), ethSrc: eth.SourceAddress(),
		src: ip.SourceAddress(), dst: ip.DestinationAddress(),
		sport: u.SourcePort(), dport: u.DestinationPort(),
		payload: string(u.Payload()),
	}
}

// nextFrame returns the next frame that host h got.
func nextFrame(t *testing.T, h *bridgeHost) udpFrame {
	t.Helper()
	select {
	case f := <-h.frames:
		return parseUDPFrame(t, f)
	case <-time.After(5 * time.Second):
		t.Fatal("no frame arrived")
		return udpFrame{}
	}
}

// readDatagram returns the next datagram of the UDP endpoint and its sender.
func (n *nfStack) readDatagram() (string, tcpip.FullAddress) {
	n.t.Helper()
	we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	n.events.EventRegister(&we)
	defer n.events.EventUnregister(&we)
	for {
		var got bytes.Buffer
		res, err := n.udp.Read(&got, tcpip.ReadOptions{NeedRemoteAddr: true})
		if _, wouldBlock := err.(*tcpip.ErrWouldBlock); !wouldBlock {
			if err != nil {
				n.t.Fatalf("Read: %s", err)
			}
			return got.String(), res.RemoteAddr
		}
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			n.t.Fatal("no datagram arrived")
		}
	}
}

// TestBridgeNetfilterDNATToLocalAddress checks that a DNAT rule which moves a
// bridged datagram to an address of the bridge keeps one connection. The reply
// leaves with the virtual address as its source, and the table lists one flow
// with the original tuple.
func TestBridgeNetfilterDNATToLocalAddress(t *testing.T) {
	n := newNFStack(t, tcpip.FullAddress{Addr: nfBridgeIP, Port: nfTargetPort})
	n.learn()
	n.sendDatagram(nfVirtualIP, nfVirtualPort, "ping")

	got, from := n.readDatagram()
	if got != "ping" || from.Addr != nfHostIP || from.Port != nfClientPort {
		t.Fatalf("datagram = %q from %v, want ping from %v:%d", got, from, nfHostIP, nfClientPort)
	}
	if _, err := n.udp.Write(bytes.NewReader([]byte("pong")), tcpip.WriteOptions{To: &from}); err != nil {
		t.Fatalf("Write: %s", err)
	}
	// The bridge learned host 0 from the datagram, so only its port gets the reply.
	for {
		reply := nextFrame(t, n.hosts[0])
		if reply.payload != "pong" {
			continue
		}
		if reply.src != nfVirtualIP || reply.sport != nfVirtualPort {
			t.Errorf("reply source = %v:%d, want %v:%d", reply.src, reply.sport, nfVirtualIP, nfVirtualPort)
		}
		break
	}
	entries := n.stack.ConntrackEntries()
	if len(entries) != 1 {
		t.Fatalf("conntrack lists %d flows, want 1: %+v", len(entries), entries)
	}
	if o := entries[0].Original; o.Dst != nfVirtualIP || o.DstPort != nfVirtualPort {
		t.Errorf("original tuple destination = %v:%d, want %v:%d", o.Dst, o.DstPort, nfVirtualIP, nfVirtualPort)
	}
}

// TestBridgeNetfilterDNATToBridgeHost checks that a DNAT rule which moves a
// bridged datagram to another host of the bridge gives the frame the Ethernet
// address from the neighbor cache of the bridge and sends it to the port of that
// host only.
func TestBridgeNetfilterDNATToBridgeHost(t *testing.T) {
	n := newNFStack(t, tcpip.FullAddress{Addr: nfPeerIP, Port: nfTargetPort})
	n.learn()
	n.sendDatagram(nfVirtualIP, nfVirtualPort, "to-peer")

	f := nextFrame(t, n.hosts[2])
	if f.ethDst != macs[2] || f.dst != nfPeerIP || f.dport != nfTargetPort || f.src != nfHostIP || f.payload != "to-peer" {
		t.Errorf("frame at host 2 = %+v, want Ethernet %q, %v:%d from %v", f, macs[2], nfPeerIP, nfTargetPort, nfHostIP)
	}
	if got := n.hosts[1].received(); len(got) != 0 {
		t.Errorf("host 1 received %q, want nothing", got)
	}
}

// TestBridgeNetfilterDNATBehindRoute checks that a DNAT rule which moves a
// bridged datagram to a host behind another link sends it through that link, and
// that the table lists one flow.
func TestBridgeNetfilterDNATBehindRoute(t *testing.T) {
	n := newNFStack(t, tcpip.FullAddress{Addr: nfRemoteIP, Port: nfTargetPort})
	n.learn()
	n.sendDatagram(nfVirtualIP, nfVirtualPort, "to-remote")

	f := nextFrame(t, n.remote)
	if f.dst != nfRemoteIP || f.dport != nfTargetPort || f.payload != "to-remote" || f.ethDst != n.remote.mac {
		t.Errorf("frame behind the route = %+v, want %v:%d for %q", f, nfRemoteIP, nfTargetPort, n.remote.mac)
	}
	if entries := n.stack.ConntrackEntries(); len(entries) != 1 {
		t.Errorf("conntrack lists %d flows, want 1: %+v", len(entries), entries)
	}
}
