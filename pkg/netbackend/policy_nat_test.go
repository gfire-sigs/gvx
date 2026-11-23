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

package netbackend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/pipe"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
)

func compileNATPolicyTest(t *testing.T, ipv4Rules string, tx, rx PolicyLimit) *CompiledPolicy {
	t.Helper()
	const chains = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n"
	policy, err := CompilePolicy(PolicyConfig{
		RulesV4: chains + ipv4Rules + "COMMIT\n",
		RulesV6: chains + "COMMIT\n",
		TX:      tx,
		RX:      rx,
	})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestNATPolicyTCPAuthorizesTranslatedTargetBeforeDial(t *testing.T) {
	control := netip.MustParseAddrPort("127.0.0.1:7401")
	for _, tc := range []struct {
		name    string
		rules   string
		control netip.AddrPort
		isolate bool
	}{
		{name: "host leg denied", rules: "-A INPUT -d 127.0.0.1 -p tcp -j DROP\n"},
		{name: "management endpoint", control: control},
		{name: "LAN isolation", isolate: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := NewNATPolicy(compileNATPolicyTest(t, tc.rules, PolicyLimit{}, PolicyLimit{}), tc.control)
			t.Cleanup(policy.Close)
			var dials atomic.Int32
			guest, forwarder, err := NewNATStack(NATConfig{
				Policy:     policy,
				IsolateLAN: tc.isolate,
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					dials.Add(1)
					return nil, ErrPolicyDenied
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = forwarder.Close(); guest.Destroy() })
			ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
			defer cancel()
			conn, err := gonet.DialContextTCP(ctx, guest, tcpip.FullAddress{NIC: Eth0NICID, Addr: hostGatewayAddr, Port: control.Port()}, ipv4.ProtocolNumber)
			if err == nil {
				_ = conn.Close()
				t.Fatal("guest TCP dial reached a denied gateway target")
			}
			if ctx.Err() != nil || dials.Load() != 0 {
				t.Fatalf("denied translated target: guest err=%v, host dial attempts=%d; want immediate rejection without a host dial", err, dials.Load())
			}
		})
	}
}

func TestNATPolicyRejectsUnexpectedConnectedPeer(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	actual := listener.Addr().(*net.TCPAddr).AddrPort()
	want := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), actual.Port())
	policy := NewNATPolicy(compileNATPolicyTest(t, "", PolicyLimit{}, PolicyLimit{}), netip.AddrPort{})
	t.Cleanup(policy.Close)
	forwarder := NATForwarder{
		ctx: testContext(t),
		cfg: NATConfig{
			Policy: policy,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp4" || address != want.String() {
					t.Fatalf("provider called with %s %s; want tcp4 %s", network, address, want)
				}
				return (&net.Dialer{}).DialContext(ctx, network, actual.String())
			},
		},
	}
	guest := policyAddrTuple(uint8(header.TCPProtocolNumber), netip.MustParseAddrPort("10.0.2.15:12345"), netip.AddrPortFrom(netip.MustParseAddr(HostGatewayIPv4), want.Port()))
	conn, _, err := forwarder.dialNATTarget("tcp", want, guest)
	if conn != nil {
		_ = conn.Close()
	}
	if conn != nil || !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("dial result is (%v, %v); want rejection of changed remote endpoint", conn, err)
	}
}

func TestNATPolicyUDPChecksTranslatedReplyOnExistingSession(t *testing.T) {
	host := newUDPEndpoint(t)
	permit := compileNATPolicyTest(t, "", PolicyLimit{}, PolicyLimit{})
	denyReply := compileNATPolicyTest(t, "-A OUTPUT -s 127.0.0.1 -p udp -j DROP\n", PolicyLimit{}, PolicyLimit{})
	policy := NewNATPolicy(permit, host.addr().AddrPort())
	t.Cleanup(policy.Close)
	guest, forwarder, err := NewNATStack(NATConfig{Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forwarder.Close(); guest.Destroy() })
	gateway := tcpip.FullAddress{NIC: Eth0NICID, Addr: hostGatewayAddr, Port: uint16(host.addr().Port)}
	conn, err := gonet.DialUDP(guest, nil, &gateway, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var buf [32]byte
	readReply := func(want string) {
		t.Helper()
		if err := conn.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
			t.Fatal(err)
		}
		n, err := conn.Read(buf[:])
		if err != nil || string(buf[:n]) != want {
			t.Fatalf("guest got %q, %v; want %q", buf[:n], err, want)
		}
	}
	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	got, peer := host.recv()
	if got != "request" {
		t.Fatalf("host got %q; want request", got)
	}
	host.send("before", peer)
	readReply("before")

	if err := policy.Commit(denyReply); err != nil {
		t.Fatal(err)
	}
	host.send("denied", peer)
	if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(buf[:]); !isTimeout(err) {
		t.Fatalf("guest got %q, %v from denied host reply; want timeout", buf[:n], err)
	}
	if err := policy.Commit(permit); err != nil {
		t.Fatal(err)
	}
	host.send("after", peer)
	readReply("after")
}

type natPolicyProbeLink struct {
	stack.LinkEndpoint
	sent chan time.Time
}

func (e natPolicyProbeLink) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	for range pkts.Len() {
		e.sent <- time.Now()
	}
	return pkts.Len(), nil
}

func sendNATPolicyProbe(t *testing.T, link stack.LinkEndpoint, proto tcpip.NetworkProtocolNumber, packet []byte) {
	t.Helper()
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	defer pkt.DecRef()
	pkt.NetworkProtocolNumber = proto
	var pkts stack.PacketBufferList
	pkts.PushBack(pkt)
	if n, err := link.WritePackets(pkts); n != 1 || err != nil {
		t.Fatalf("write IP packet = %d, %v; want 1, nil", n, err)
	}
}

func natPolicyProbeIPv4(proto uint8) []byte {
	const ipBytes = header.IPv4MinimumSize + 8
	packet := make([]byte, ipBytes+6) // Pad past the IP length.
	header.IPv4(packet).Encode(&header.IPv4Fields{
		TotalLength: ipBytes, TTL: 64, Protocol: proto,
		SrcAddr: hostGatewayAddr, DstAddr: tcpip.AddrFrom4([4]byte{10, 0, 2, 15}),
	})
	if proto == uint8(header.UDPProtocolNumber) {
		header.UDP(packet[header.IPv4MinimumSize:]).Encode(&header.UDPFields{SrcPort: 1000, DstPort: 1001, Length: 8})
	}
	return packet
}

func TestNATPolicyShapesRawUDPAndICMPByIPLength(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		limit := PolicyLimit{RateBPS: 8, BurstBytes: minPolicyBurst, QueueBytes: minPolicyBurst}
		policy := NewNATPolicy(compileNATPolicyTest(t, "", PolicyLimit{}, limit), netip.AddrPort{})
		defer policy.Close()
		sent := make(chan time.Time, 2)
		state := &natPacketLinkState{paused: new(atomic.Bool)}
		link := wrapNATPolicyLink(natPolicyProbeLink{sent: sent}, policy, state)
		start := time.Now()
		sendNATPolicyProbe(t, link, header.IPv4ProtocolNumber, natPolicyProbeIPv4(uint8(header.UDPProtocolNumber)))
		if elapsed := (<-sent).Sub(start); elapsed != 28*time.Second {
			t.Fatalf("raw UDP took %v at one byte per second; want 28 IP bytes", elapsed)
		}
		sendNATPolicyProbe(t, link, header.IPv4ProtocolNumber, natPolicyProbeIPv4(uint8(header.ICMPv4ProtocolNumber)))
		if elapsed := (<-sent).Sub(start); elapsed != 56*time.Second {
			t.Fatalf("raw UDP and ICMP took %v at one byte per second; want 56 IP bytes, excluding padding", elapsed)
		}
	})
}

func TestNATPolicyFiltersRawHostPacketsWithoutHeaders(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		compiled := compileNATPolicyTest(t, "-A OUTPUT -p icmp -j DROP\n", PolicyLimit{}, PolicyLimit{})
		policy := NewNATPolicy(compiled, netip.AddrPort{})
		defer policy.Close()
		sent := make(chan time.Time, 1)
		state := &natPacketLinkState{paused: new(atomic.Bool)}
		link := wrapNATPolicyLink(natPolicyProbeLink{sent: sent}, policy, state)
		sendNATPolicyProbe(t, link, header.IPv4ProtocolNumber, natPolicyProbeIPv4(uint8(header.ICMPv4ProtocolNumber)))
		synctest.Wait()
		if len(sent) != 0 {
			t.Fatal("raw packet bypassed OUTPUT policy")
		}
	})
}

func newPolicyUDPPeer(t *testing.T, addr tcpip.FullAddress, factory stack.NetworkProtocolFactory, proto tcpip.NetworkProtocolNumber, subnet tcpip.Subnet, link stack.LinkEndpoint, hooks stack.NFTablesInterface) *stack.Stack {
	t.Helper()
	// TCP's runtime sleeper prevents synctest from advancing time.
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{factory},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
		NFTables:           hooks,
	})
	t.Cleanup(s.Destroy)
	if hooks != nil {
		s.SetNFTablesConfigured(true)
	}
	if err := s.CreateNIC(addr.NIC, link); err != nil {
		t.Fatalf("create NIC %d: %s", addr.NIC, err)
	}
	if err := s.AddProtocolAddress(addr.NIC, tcpip.ProtocolAddress{
		Protocol:          proto,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr.Addr, PrefixLen: addr.Addr.BitLen()},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("add address %s: %s", addr.Addr, err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: addr.NIC}})
	return s
}

func TestNATPolicyShapesFragmentedPacketOnlyUDPByOriginalIPLengths(t *testing.T) {
	for _, tc := range []struct {
		name, source, destination string
		factory                   stack.NetworkProtocolFactory
		subnet                    tcpip.Subnet
		headerBytes               int
	}{
		{"IPv4", "10.0.2.15", "10.0.2.2", ipv4.NewProtocol, header.IPv4EmptySubnet, header.IPv4MinimumSize},
		{"IPv6", "2001:db8::1", "2001:db8::2", ipv6.NewProtocol, header.IPv6EmptySubnet, header.IPv6MinimumSize + header.IPv6FragmentHeaderSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				limit := PolicyLimit{RateBPS: 8, BurstBytes: minPolicyBurst, QueueBytes: minPolicyBurst}
				policy := NewNATPolicy(compileNATPolicyTest(t, "", limit, PolicyLimit{}), netip.AddrPort{})
				t.Cleanup(policy.Close)
				guestLink, peerLink := pipe.New("", "", 1500)
				state := &natPacketLinkState{paused: new(atomic.Bool)}
				source, destination := netip.MustParseAddr(tc.source), netip.MustParseAddr(tc.destination)
				guestAddr, peerAddr := fullAddr(source, 12345), fullAddr(destination, 12346)
				guestAddr.NIC, peerAddr.NIC = hostNICID, hostNICID
				proto := netProto(source)
				guest := newPolicyUDPPeer(t, guestAddr, tc.factory, proto, tc.subnet, checksumOffloadEndpoint{guestLink}, nil)
				peer := newPolicyUDPPeer(t, peerAddr, tc.factory, proto, tc.subnet,
					wrapNATPolicyLink(checksumOffloadEndpoint{peerLink}, policy, state), natPolicyHooks{policy: policy})

				guestConn, err := gonet.DialUDP(guest, &guestAddr, &peerAddr, proto)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = guestConn.Close() })
				// This ordinary local socket is not a NAT or DNS endpoint.
				localConn, err := gonet.DialUDP(peer, &peerAddr, &guestAddr, proto)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = localConn.Close() })

				const payloadSize = 2000 // Two fragments at this MTU.
				wireBytes := payloadSize + header.UDPMinimumSize + 2*tc.headerBytes
				payload := strings.Repeat("p", payloadSize)
				start := time.Now()
				if _, err := guestConn.Write([]byte(payload)); err != nil {
					t.Fatal(err)
				}
				if err := localConn.SetReadDeadline(start.Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, payloadSize)
				n, err := localConn.Read(buf)
				if err != nil || string(buf[:n]) != payload {
					t.Fatalf("local UDP read: got %d bytes, err = %v, want the %d-byte datagram", n, err, payloadSize)
				}
				if elapsed := time.Since(start); elapsed != time.Duration(wireBytes)*time.Second {
					t.Fatalf("fragmented UDP reached the local endpoint at %v; want %d original IP bytes", elapsed, wireBytes)
				}
			})
		})
	}
}

type dropLaterIPv4Fragments struct {
	stack.LinkEndpoint
}

func (link dropLaterIPv4Fragments) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	for _, pkt := range pkts.AsSlice() {
		if pkt.NetworkProtocolNumber == ipv4.ProtocolNumber && header.IPv4(pkt.NetworkHeader().Slice()).FragmentOffset() != 0 {
			continue
		}
		var one stack.PacketBufferList
		one.PushBack(pkt)
		if _, err := link.LinkEndpoint.WritePackets(one); err != nil {
			return 0, err
		}
	}
	return pkts.Len(), nil
}

func TestNATPolicyChargesInputBeforeReassemblyTimeoutReply(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		limit := PolicyLimit{RateBPS: 8, BurstBytes: minPolicyBurst, QueueBytes: minPolicyBurst}
		policy := NewNATPolicy(compileNATPolicyTest(t, "", limit, PolicyLimit{}), netip.AddrPort{})
		t.Cleanup(policy.Close)

		const mtu = 1500
		guestLink, peerLink := pipe.New("", "", mtu)
		state := &natPacketLinkState{paused: new(atomic.Bool)}
		guestAddr := fullAddr(netip.MustParseAddr("10.0.2.15"), 12345)
		peerAddr := fullAddr(netip.MustParseAddr("10.0.2.2"), 12346)
		guestAddr.NIC, peerAddr.NIC = hostNICID, hostNICID
		replies := make(chan time.Time, 1)
		guest := newPolicyUDPPeer(t, guestAddr, ipv4.NewProtocol, ipv4.ProtocolNumber, header.IPv4EmptySubnet,
			dropLaterIPv4Fragments{checksumOffloadEndpoint{guestLink}}, nil)
		newPolicyUDPPeer(t, peerAddr, ipv4.NewProtocol, ipv4.ProtocolNumber, header.IPv4EmptySubnet,
			wrapNATPolicyLink(natPolicyProbeLink{LinkEndpoint: checksumOffloadEndpoint{peerLink}, sent: replies}, policy, state), natPolicyHooks{policy: policy})

		conn, err := gonet.DialUDP(guest, &guestAddr, &peerAddr, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		start := time.Now()
		if _, err := conn.Write(make([]byte, 2000)); err != nil {
			t.Fatal(err)
		}
		select {
		case reply := <-replies:
			if elapsed := reply.Sub(start); elapsed != mtu*time.Second {
				t.Fatalf("reassembly timeout reply at %v; want %d original input bytes charged first", elapsed, mtu)
			}
		case <-time.After(time.Hour):
			t.Fatal("no reassembly timeout reply for incomplete datagram")
		}
	})
}

func TestNATPolicyRelaysFragmentedUDPWithFiniteTXAndRX(t *testing.T) {
	host := newUDPEndpoint(t)
	port := host.addr().Port
	rules := fmt.Sprintf(
		"-A OUTPUT -s 10.0.2.2 -p udp -m udp --sport %d -j ACCEPT\n"+
			"-A OUTPUT -s 127.0.0.1 -p udp -m udp --sport %d -j ACCEPT\n"+
			"-A OUTPUT -p udp -j DROP\n", port, port)
	limit := PolicyLimit{RateBPS: 8_000_000, BurstBytes: minPolicyBurst, QueueBytes: minPolicyBurst}
	policy := NewNATPolicy(compileNATPolicyTest(t, rules, limit, limit), netip.AddrPort{})
	t.Cleanup(policy.Close)
	guest, forwarder, err := NewNATStack(NATConfig{Policy: policy, DNSServers: []string{"192.0.2.53"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forwarder.Close(); guest.Destroy() })
	destination := tcpip.FullAddress{NIC: Eth0NICID, Addr: hostGatewayAddr, Port: uint16(port)}
	conn, err := gonet.DialUDP(guest, nil, &destination, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	request, reply := strings.Repeat("q", 2000), strings.Repeat("r", 2000)
	buf := make([]byte, len(reply))
	for _, phase := range []string{"new relay", "established relay"} {
		if _, err := conn.Write([]byte(request)); err != nil {
			t.Fatalf("%s: write guest datagram: %v", phase, err)
		}
		got, peer := host.recv()
		if got != request {
			t.Fatalf("%s: host received %d bytes, want the %d-byte request", phase, len(got), len(request))
		}
		host.send(reply, peer)
		if err := conn.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
			t.Fatal(err)
		}
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != reply {
			t.Fatalf("%s: guest received %d bytes, err = %v, want the %d-byte reply", phase, n, err, len(reply))
		}
	}
}

func TestNATPolicyQuiesceDiscardsPreviouslyQueuedPackets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		limit := PolicyLimit{RateBPS: 8, BurstBytes: minPolicyBurst, QueueBytes: minPolicyBurst}
		policy := NewNATPolicy(compileNATPolicyTest(t, "", PolicyLimit{}, limit), netip.AddrPort{})
		defer policy.Close()
		sent := make(chan time.Time, 2)
		state := &natPacketLinkState{paused: new(atomic.Bool)}
		forwarder := NATForwarder{paused: state.paused, packetLink: state, cfg: NATConfig{Policy: policy}}
		link := wrapNATPolicyLink(natPolicyProbeLink{sent: sent}, policy, state)
		packet := natPolicyProbeIPv4(uint8(header.ICMPv4ProtocolNumber))
		sendNATPolicyProbe(t, link, header.IPv4ProtocolNumber, packet)
		forwarder.QuiesceForSave()
		if err := forwarder.ResumeAfterSave(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Minute) // The old packet would have had time to run again.
		if len(sent) != 0 {
			t.Fatal("a packet queued before quiesce was delivered after resume")
		}
		sendNATPolicyProbe(t, link, header.IPv4ProtocolNumber, packet)
		select {
		case <-sent:
		case <-time.After(time.Minute):
			t.Fatal("a fresh packet did not pass after resume")
		}
	})
}
