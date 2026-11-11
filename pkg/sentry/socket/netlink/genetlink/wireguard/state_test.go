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

package wireguard

import (
	"bytes"
	stdcontext "context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

func waitForHandshake(t *testing.T, ep *linkEndpoint) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		info := ep.state(t)
		if len(info.peers) == 1 && info.peers[0].handshakeSec > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for Noise handshake on %s; peers = %+v", ep.name, ep.state(t).peers)
}

func TestStateRoundTripWipesEphemeralSessionKeysAndPreservesConfigAndDump(t *testing.T) {
	st := newLoopbackStackOf(t)

	rawA, sysErr := newLink(context.Background(), &netstack.NewLinkRequest{Stack: st, ID: 2, Name: "wg0"})
	if sysErr != nil {
		t.Fatalf("newLink(wg0) = %v", sysErr)
	}
	epA := rawA.(*linkEndpoint)
	t.Cleanup(epA.Close)
	if err := st.Stack.CreateNIC(2, epA); err != nil {
		t.Fatalf("CreateNIC(wg0): %v", err)
	}

	rawB, sysErr := newLink(context.Background(), &netstack.NewLinkRequest{Stack: st, ID: 3, Name: "wg1"})
	if sysErr != nil {
		t.Fatalf("newLink(wg1) = %v", sysErr)
	}
	epB := rawB.(*linkEndpoint)
	t.Cleanup(epB.Close)

	if err := epA.set(t, privAttr(1), markAttr(0x77)); err != nil {
		t.Fatalf("epA.set(identity): %v", err)
	}
	if err := epB.set(t, privAttr(2)); err != nil {
		t.Fatalf("epB.set(identity): %v", err)
	}
	if err := epA.LinkUp(); err != nil {
		t.Fatalf("epA.LinkUp: %v", err)
	}
	if err := epB.LinkUp(); err != nil {
		t.Fatalf("epB.LinkUp: %v", err)
	}

	portA := epA.bind.incomingPort()
	portB := epB.bind.incomingPort()
	pubA := epA.public
	pubB := epB.public

	peerSpecB := slices.Concat(
		attrBytes(peerAttrPublicKey, pubB[:]),
		attrBytes(peerAttrPresharedKey, key(9)),
		attrBytes(peerAttrEndpoint, sockaddrIn(portB, [4]byte{127, 0, 0, 1})),
		attrBytes(peerAttrKeepalive, le16(25)),
		allowedIPList(allowedIPAttr(linux.AF_INET, []byte{10, 88, 0, 2}, 32)),
	)
	peerSpecA := slices.Concat(
		attrBytes(peerAttrPublicKey, pubA[:]),
		attrBytes(peerAttrPresharedKey, key(9)),
		attrBytes(peerAttrEndpoint, sockaddrIn(portA, [4]byte{127, 0, 0, 1})),
		allowedIPList(allowedIPAttr(linux.AF_INET, []byte{10, 88, 0, 1}, 32)),
	)
	// Configure passive responder B first so A's initial keepalive handshake succeeds immediately.
	if err := epB.set(t, peerList(peerSpecA)); err != nil {
		t.Fatalf("epB.set(peer A): %v", err)
	}
	if err := epA.set(t, peerList(peerSpecB)); err != nil {
		t.Fatalf("epA.set(peer B): %v", err)
	}

	waitForHandshake(t, epA)
	epB.Close()

	preSave := epA.state(t)
	if len(preSave.peers) != 1 || preSave.peers[0].handshakeSec <= 0 {
		t.Fatalf("pre-save peer state = %+v, want active Noise handshake", preSave.peers)
	}

	st.Stack.Pause()
	var buf bytes.Buffer
	saved := []any{st.Stack, epA}
	if _, err := state.Save(stdcontext.Background(), &buf, &saved); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	// Verify that beforeSave wiped the live wireguard-go device keys and peers.
	ipcAfterSave, err := epA.dev.IpcGet()
	if err != nil {
		t.Fatalf("epA.dev.IpcGet after save: %v", err)
	}
	if strings.Contains(ipcAfterSave, "public_key=") {
		t.Fatalf("live device retained peers after beforeSave:\n%s", ipcAfterSave)
	}
	if strings.Contains(ipcAfterSave, "private_key=") {
		t.Fatalf("live device retained private key after beforeSave:\n%s", ipcAfterSave)
	}

	epA.Close()
	st.Stack.Close()
	st.Stack.Wait()

	var loaded []any
	if _, err := state.Load(stdcontext.Background(), bytes.NewReader(buf.Bytes()), &loaded); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	restoredStk := loaded[0].(*stack.Stack)
	restoredEpA := loaded[1].(*linkEndpoint)
	t.Cleanup(func() {
		restoredEpA.Close()
		restoredStk.Close()
		restoredStk.Wait()
	})

	if restoredEpA.savedConfig == nil || len(restoredEpA.savedConfig.peers) != 1 {
		t.Fatalf("restored savedConfig = %+v, want 1 saved peer", restoredEpA.savedConfig)
	}
	sp := restoredEpA.savedConfig.peers[0]
	if sp.handshakeSec != 0 || sp.handshakeNsec != 0 || sp.rxBytes != 0 || sp.txBytes != 0 {
		t.Fatalf("savedConfig retained session state: handshake=(%d,%d) rx=%d tx=%d, want all zero", sp.handshakeSec, sp.handshakeNsec, sp.rxBytes, sp.txBytes)
	}

	restoredStk.ResetConfig()
	restoredStk.ReplaceConfig(newLoopbackStack(t))
	restoredStk.Restore()

	info := restoredEpA.state(t)
	if info.privateKey != clamped(1) || restoredEpA.public != pubA || info.listenPort != portA || info.fwmark != 0x77 {
		t.Fatalf("restored device info = %+v, want port %d, fwmark 0x77, and original keys", info, portA)
	}
	if len(info.peers) != 1 {
		t.Fatalf("restored peers = %d, want 1", len(info.peers))
	}
	p := info.peers[0]
	wantEndpoint := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), portB)
	if p.publicKey != pubB || p.presharedKey != [keyLen]byte(key(9)) || p.keepalive != 25 || p.endpoint != wantEndpoint || !slices.Equal(p.allowedIPs, prefixes("10.88.0.2/32")) {
		t.Fatalf("restored peer config = %+v, want pubB, psk 9, keepalive 25, endpoint %v, allowedIPs 10.88.0.2/32", p, wantEndpoint)
	}
	if p.handshakeSec != 0 || p.handshakeNsec != 0 || p.rxBytes != 0 {
		t.Fatalf("restored peer retained active Noise session before peer B came up: handshake=(%d,%d) rx=%d", p.handshakeSec, p.handshakeNsec, p.rxBytes)
	}

	// Verify WG_CMD_GET_DEVICE netlink dump on the restored link.
	msgs := runDump(t, restoredEpA, 3776)
	if len(msgs) != 1 || len(msgs[0].peers) != 1 {
		t.Fatalf("restored dump = %d messages, want 1 message with 1 peer", len(msgs))
	}
	portView := msgs[0].device[deviceAttrListenPort]
	if gotPort, ok := portView.Uint16(); !ok || gotPort != portA {
		t.Fatalf("dump listenPort = %d (ok=%v), want %d", gotPort, ok, portA)
	}
	markView := msgs[0].device[deviceAttrFwmark]
	if gotMark, ok := markView.Uint32(); !ok || gotMark != 0x77 {
		t.Fatalf("dump fwmark = %#x (ok=%v), want 0x77", gotMark, ok)
	}
	if gotPub := msgs[0].device[deviceAttrPublicKey]; !bytes.Equal(gotPub, pubA[:]) {
		t.Fatalf("dump publicKey = %x, want %x", []byte(gotPub), pubA)
	}
	dp := msgs[0].peers[0]
	if !bytes.Equal(dp.attrs[peerAttrPublicKey], pubB[:]) || !bytes.Equal(dp.attrs[peerAttrPresharedKey], key(9)) {
		t.Fatalf("dump peer keys mismatch: %+v", dp.attrs)
	}
	if !bytes.Equal(dp.attrs[peerAttrLastHshake], make([]byte, 16)) {
		t.Fatalf("dump last handshake = %x, want 16 zero bytes", []byte(dp.attrs[peerAttrLastHshake]))
	}
	if !slices.Equal(dp.ips, prefixes("10.88.0.2/32")) {
		t.Fatalf("dump peer allowedIPs = %v, want [10.88.0.2/32]", dp.ips)
	}

	// Verify the restored link negotiates a fresh Noise session with a peer.
	restoredNS := netstack.NewStack(restoredStk, 1)
	rawB2, sysErr := newLink(context.Background(), &netstack.NewLinkRequest{Stack: restoredNS, ID: 3, Name: "wg1"})
	if sysErr != nil {
		t.Fatalf("newLink(wg1 post-restore) = %v", sysErr)
	}
	epB2 := rawB2.(*linkEndpoint)
	t.Cleanup(epB2.Close)
	if err := epB2.set(t, privAttr(2), portAttr(portB), peerList(peerSpecA)); err != nil {
		t.Fatalf("epB2.set: %v", err)
	}
	if err := epB2.LinkUp(); err != nil {
		t.Fatalf("epB2.LinkUp: %v", err)
	}
	rawPkt := make([]byte, header.IPv4MinimumSize)
	ipHdr := header.IPv4(rawPkt)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: header.IPv4MinimumSize,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		TTL:         64,
		SrcAddr:     tcpip.AddrFrom4([4]byte{10, 88, 0, 1}),
		DstAddr:     tcpip.AddrFrom4([4]byte{10, 88, 0, 2}),
	})
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(rawPkt)})
	var pkts stack.PacketBufferList
	pkts.PushBack(pkt)
	if _, err := restoredEpA.WritePackets(pkts); err != nil {
		pkt.DecRef()
		t.Fatalf("restoredEpA.WritePackets: %v", err)
	}
	pkt.DecRef()
	waitForHandshake(t, restoredEpA)
}
