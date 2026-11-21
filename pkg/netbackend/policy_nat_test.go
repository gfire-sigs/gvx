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
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
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

	mark := func() error { return nil }
	if err := policy.Commit(denyReply, mark); err != nil {
		t.Fatal(err)
	}
	host.send("denied", peer)
	if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(buf[:]); !isTimeout(err) {
		t.Fatalf("guest got %q, %v from denied host reply; want timeout", buf[:n], err)
	}
	if err := policy.Commit(permit, mark); err != nil {
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

func TestNATPolicyShapesRawLinkIPBytesWithoutShapingSocketPackets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		limit := PolicyLimit{RateBPS: 8, BurstBytes: minPolicyBurst, QueueBytes: minPolicyBurst}
		policy := NewNATPolicy(compileNATPolicyTest(t, "", PolicyLimit{}, limit), netip.AddrPort{})
		defer policy.Close()
		sent := make(chan time.Time, 2)
		state := &natPacketLinkState{paused: new(atomic.Bool)}
		link := wrapNATPolicyLink(natPolicyProbeLink{sent: sent}, policy, PolicyOutput, state)
		start := time.Now()
		sendNATPolicyProbe(t, link, header.IPv4ProtocolNumber, natPolicyProbeIPv4(uint8(header.UDPProtocolNumber)))
		if elapsed := (<-sent).Sub(start); elapsed != 0 {
			t.Fatalf("socket packet took %v through the link; want no link debit", elapsed)
		}
		sendNATPolicyProbe(t, link, header.IPv4ProtocolNumber, natPolicyProbeIPv4(uint8(header.ICMPv4ProtocolNumber)))
		if elapsed := (<-sent).Sub(start); elapsed != 28*time.Second {
			t.Fatalf("raw packet took %v at one byte per second; want 28 IP bytes, excluding padding", elapsed)
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
		link := wrapNATPolicyLink(natPolicyProbeLink{sent: sent}, policy, PolicyOutput, state)
		sendNATPolicyProbe(t, link, header.IPv4ProtocolNumber, natPolicyProbeIPv4(uint8(header.ICMPv4ProtocolNumber)))
		synctest.Wait()
		if len(sent) != 0 {
			t.Fatal("raw packet bypassed OUTPUT policy")
		}
	})
}

func TestNATPolicyAmbiguousIPv6FragmentRequiresUnlimitedLink(t *testing.T) {
	packet := make([]byte, 56)
	packet[0], packet[6], packet[7] = 0x60, 44, 64 // IPv6 with a Fragment header.
	binary.BigEndian.PutUint16(packet[4:6], 16)
	packet[8], packet[23], packet[24], packet[39] = 0x20, 1, 0x20, 2
	packet[40], packet[43] = 60, 8 // Non-initial fragment of Destination Options.

	for _, tc := range []struct {
		name  string
		limit PolicyLimit
		want  int
	}{
		{name: "unlimited", want: 1},
		{name: "limited", limit: PolicyLimit{RateBPS: 8, BurstBytes: minPolicyBurst, QueueBytes: minPolicyBurst}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				policy := NewNATPolicy(compileNATPolicyTest(t, "", tc.limit, PolicyLimit{}), netip.AddrPort{})
				defer policy.Close()
				sent := make(chan time.Time, 1)
				state := &natPacketLinkState{paused: new(atomic.Bool)}
				link := wrapNATPolicyLink(natPolicyProbeLink{sent: sent}, policy, PolicyInput, state)
				sendNATPolicyProbe(t, link, header.IPv6ProtocolNumber, packet)
				time.Sleep(time.Minute) // Virtual time, sufficient to expose either path.
				if got := len(sent); got != tc.want {
					t.Fatalf("handed off %d ambiguous fragments; want %d", got, tc.want)
				}
			})
		})
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
		link := wrapNATPolicyLink(natPolicyProbeLink{sent: sent}, policy, PolicyOutput, state)
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
