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
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/header"
)

func TestNATPolicyRetiresDeniedPacketReservations(t *testing.T) {
	for _, f := range natPacketFamilies() {
		t.Run(f.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				policy := NewNATPolicy(nil, netip.MustParseAddrPort("127.0.0.1:8010"))
				defer policy.Close()
				shaper := NewBandwidthShaper(BandwidthRates{})
				defer shaper.Close()
				s, nf := newNATPacketTestStack(t, f, NATConfig{Policy: policy, Bandwidth: shaper})
				const peerPort, guestPort = 8000, 9000
				guest, err := gonet.DialUDP(s, &tcpip.FullAddress{Addr: f.guest, Port: guestPort}, nil, f.protocol)
				if err != nil {
					t.Fatal(err)
				}
				defer guest.Close()

				deniedPeer, _ := netip.AddrFromSlice(f.peer.AsSlice())
				allowedPeer := tcpip.AddrFromSlice(deniedPeer.Next().AsSlice())
				send := func(src tcpip.Address, body string) int {
					udp := natTestUDP(src, f.guest, peerPort, guestPort, body)
					ip := f.packet(src, f.guest, header.UDPProtocolNumber, udp, 0, false)
					f.send(t, nf.stack, hostNICID, ip)
					return len(ip)
				}
				read := func(want string, deadline time.Time) {
					if err := guest.SetReadDeadline(deadline); err != nil {
						t.Fatal(err)
					}
					var data [64]byte
					n, err := guest.Read(data[:])
					if err != nil || string(data[:n]) != want {
						t.Fatalf("guest read = (%q, %v), want %q", data[:n], err, want)
					}
				}

				shaper.SetRates(BandwidthRates{RXBPS: 8})
				start := time.Now()
				send(f.peer, "retire this queued packet")
				const kept = "keep"
				due := start.Add(time.Duration(send(allowedPeer, kept)) * time.Second)
				time.Sleep(time.Second) // Accrue one byte of virtual credit before replacement.
				allow := NATPolicyDirectionConfig{Default: "allow"}
				selective := NATPolicyDirectionConfig{Default: "allow", Rules: []NATPolicyRule{{
					Action: "deny",
					CIDR:   netip.PrefixFrom(deniedPeer, deniedPeer.BitLen()).String(),
				}}}
				if err := policy.Replace(compileOutboundPolicy(t, allow, selective)); err != nil {
					t.Fatalf("install selective policy: %v", err)
				}
				if err := policy.Replace(compileOutboundPolicy(t, allow, allow)); err != nil {
					t.Fatalf("restore permission for new packets: %v", err)
				}
				read(kept, due.Add(time.Nanosecond))
				if now := time.Now(); !now.Equal(due) {
					t.Fatalf("permitted packet arrived after %v, want %v", now.Sub(start), due.Sub(start))
				}

				shaper.SetRates(BandwidthRates{})
				synctest.Wait()
				const fresh = "newly allowed"
				send(f.peer, fresh)
				read(fresh, time.Now().Add(time.Second))
			})
		})
	}
}
