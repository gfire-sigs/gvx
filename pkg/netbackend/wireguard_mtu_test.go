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
	"testing"
)

// TestWireGuardEth0TakesTheMTURangeOfTheTunnel checks the range that the guest
// can set on eth0 in the wg network mode. wireguard-go carries a packet of at
// most 65503 bytes, so that value is the largest MTU.
func TestWireGuardEth0TakesTheMTURangeOfTheTunnel(t *testing.T) {
	guestKey, peerKey := newWGKeyPair(t), newWGKeyPair(t)
	w, err := NewWireGuardEndpoint(WireGuardConfig{PrivateKey: guestKey.private, PeerPublicKey: peerKey.public})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	s, err := w.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	for _, mtu := range []uint32{67, 65504, 65535} {
		if err := s.SetNICMTU(Eth0NICID, mtu); err == nil {
			t.Errorf("SetNICMTU(%d) succeeded, want an error", mtu)
		}
	}
	for _, mtu := range []uint32{68, 65503, DefaultWireGuardMTU} {
		if err := s.SetNICMTU(Eth0NICID, mtu); err != nil {
			t.Errorf("SetNICMTU(%d) = %v, want success", mtu, err)
		}
		if got := w.ChannelEndpoint().MTU(); got != mtu {
			t.Errorf("channel MTU after SetNICMTU(%d) = %d", mtu, got)
		}
	}
}
