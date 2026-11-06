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
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/genetlink"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
)

// newTestLink creates a link on a loopback stack. The cleanup closes it.
func newTestLink(t *testing.T) *linkEndpoint {
	t.Helper()
	return newTestLinkOn(t, newLoopbackStackOf(t))
}

// newLoopbackStackOf returns the stack of newLoopbackStack in the form that
// newLink takes.
func newLoopbackStackOf(t *testing.T) *netstack.Stack {
	t.Helper()
	return netstack.NewStack(newLoopbackStack(t), 1)
}

func newTestLinkOn(t *testing.T, st *netstack.Stack) *linkEndpoint {
	t.Helper()
	ep, sysErr := newLink(context.Background(), &netstack.NewLinkRequest{Stack: st, ID: 2, Name: "wg0"})
	if sysErr != nil {
		t.Fatalf("newLink = %v", sysErr)
	}
	t.Cleanup(ep.Close)
	return ep.(*linkEndpoint)
}

// set runs a set request with the capability of the creating namespace.
func (e *linkEndpoint) set(t *testing.T, parts ...[]byte) *syserr.Error {
	t.Helper()
	return e.applySet(setAttrs(t, parts...), true)
}

func portAttr(port uint16) []byte { return attrBytes(deviceAttrListenPort, le16(port)) }
func markAttr(mark uint32) []byte { return attrBytes(deviceAttrFwmark, le32(mark)) }
func privAttr(b byte) []byte      { return attrBytes(deviceAttrPrivateKey, key(b)) }

// peerAttrs returns the entry of one peer.
func peerAttrs(b byte, extra ...[]byte) []byte {
	return slices.Concat(append([][]byte{attrBytes(peerAttrPublicKey, key(b))}, extra...)...)
}

// state returns the snapshot that a dump of the device starts with.
func (e *linkEndpoint) state(t *testing.T) *deviceInfo {
	t.Helper()
	d, err := e.snapshot()
	if err != nil {
		t.Fatalf("snapshot = %v", err)
	}
	return d.info
}

// peerByKey returns the peer whose key bytes are all b.
func peerByKey(info *deviceInfo, b byte) *peerInfo {
	for i := range info.peers {
		if info.peers[i].publicKey[0] == b {
			return &info.peers[i]
		}
	}
	return nil
}

// clamped returns the private key that a device reports after it clamps the
// key with every byte b, as curve25519_clamp_secret does.
func clamped(b byte) [keyLen]byte {
	k := [keyLen]byte(key(b))
	k[0] &= 248
	k[31] = k[31]&127 | 64
	return k
}

func prefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestLinkStartsDownWithoutASocket(t *testing.T) {
	ep := newTestLink(t)
	if ep.up || ep.bind.session != nil {
		t.Errorf("a new link has up = %v and session = %v, want a link that is down and owns no socket", ep.up, ep.bind.session)
	}
	if got := ep.state(t).listenPort; got != 0 {
		t.Errorf("listen port of a new link = %d, want 0", got)
	}
}

func TestLinkUpOpensThePortAndDownFreesIt(t *testing.T) {
	st := newLoopbackStackOf(t)
	ep := newTestLinkOn(t, st)
	if err := ep.set(t, portAttr(0), privAttr(1)); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := ep.LinkUp(); err != nil {
		t.Fatalf("LinkUp = %v", err)
	}
	port := ep.bind.incomingPort()
	if port == 0 {
		t.Fatal("LinkUp left the port at 0, want the port that the stack picked")
	}
	if got := ep.state(t).listenPort; got != port {
		t.Errorf("listen port after LinkUp = %d, want %d", got, port)
	}
	other := newBind(st.Stack)
	other.setIncoming(port)
	var be *bindError
	if _, _, err := other.Open(0); !errors.As(err, &be) || be.err != syserr.ErrPortInUse {
		t.Fatalf("a second socket on port %d = %v, want a port in use error while the link is up", port, err)
	}

	ep.LinkDown()
	if ep.up || ep.bind.session != nil {
		t.Errorf("after LinkDown up = %v and session = %v, want a link that is down and owns no socket", ep.up, ep.bind.session)
	}
	if _, _, err := other.Open(0); err != nil {
		t.Fatalf("a second socket on port %d after LinkDown = %v, want the port free", port, err)
	}
	if got := ep.state(t).listenPort; got != port {
		t.Errorf("listen port after LinkDown = %d, want the last port %d", got, port)
	}
	other.Close()

	if err := ep.LinkUp(); err != nil || ep.bind.incomingPort() != port {
		t.Errorf("LinkUp after LinkDown = %v with port %d, want success on the same port %d", err, ep.bind.incomingPort(), port)
	}
	ep.LinkDown()
	ep.LinkDown() // A second call changes nothing.
}

func TestLinkUpFailsOnABusyPortAndStaysDown(t *testing.T) {
	st := newLoopbackStackOf(t)
	holder := newBind(st.Stack)
	_, busy, err := holder.Open(0)
	if err != nil {
		t.Fatalf("Open of the holder: %v", err)
	}
	ep := newTestLinkOn(t, st)
	// A device that is down accepts any port, as Linux does: the bind happens at up.
	if err := ep.set(t, portAttr(busy)); err != nil {
		t.Fatalf("set of a busy port on a link that is down = %v, want success", err)
	}
	terr := ep.LinkUp()
	if _, ok := terr.(*tcpip.ErrPortInUse); !ok {
		t.Fatalf("LinkUp on the busy port %d = %v, want a port in use error", busy, terr)
	}
	if ep.up || ep.bind.session != nil {
		t.Errorf("after the failed LinkUp up = %v and session = %v, want a link that is down", ep.up, ep.bind.session)
	}
	if got := ep.bind.incomingPort(); got != busy {
		t.Errorf("the port after the failed LinkUp = %d, want %d", got, busy)
	}
	holder.Close()
	if err := ep.LinkUp(); err != nil {
		t.Fatalf("LinkUp after the port became free = %v", err)
	}
	ep.LinkDown()
}

func TestSetPortOfALinkThatIsUp(t *testing.T) {
	st := newLoopbackStackOf(t)
	ep := newTestLinkOn(t, st)
	if err := ep.LinkUp(); err != nil {
		t.Fatalf("LinkUp = %v", err)
	}
	defer ep.LinkDown()
	first := ep.bind.incomingPort()

	holder := newBind(st.Stack)
	_, busy, err := holder.Open(0)
	if err != nil {
		t.Fatalf("Open of the holder: %v", err)
	}
	defer holder.Close()
	if err := ep.set(t, portAttr(busy)); err != syserr.ErrPortInUse {
		t.Fatalf("set of a busy port = %v, want EADDRINUSE", err)
	}
	if got := ep.bind.incomingPort(); got != first || ep.bind.session == nil || ep.bind.session.port != first {
		t.Errorf("after the refused set the device has port %d and session %v, want port %d with its sockets", got, ep.bind.session, first)
	}
	if err := ep.set(t, portAttr(first)); err != nil {
		t.Errorf("set to the current port = %v, want success", err)
	}

	free := newBind(st.Stack)
	_, target, err := free.Open(0)
	free.Close()
	if err != nil {
		t.Fatalf("Open of a free port: %v", err)
	}
	if err := ep.set(t, portAttr(target)); err != nil {
		t.Fatalf("set to the free port %d = %v", target, err)
	}
	if got := ep.state(t).listenPort; got != target || ep.bind.session.port != target {
		t.Errorf("listen port = %d and session port = %d, want %d", got, ep.bind.session.port, target)
	}
	// The old port is free again.
	again := newBind(st.Stack)
	again.setIncoming(first)
	if _, _, err := again.Open(0); err != nil {
		t.Errorf("the old port %d after the move = %v, want it free", first, err)
	}
	again.Close()

	if err := ep.set(t, portAttr(0)); err != nil {
		t.Fatalf("set to port 0 = %v", err)
	}
	if got := ep.bind.incomingPort(); got == 0 || got == target {
		t.Errorf("port after the set to 0 = %d, want a new random port that is not %d", got, target)
	}
}

func TestSetPortAndMarkNeedTheCapabilityOfTheCreatingNamespace(t *testing.T) {
	ep := newTestLink(t)
	for name, attr := range map[string][]byte{"port": portAttr(1234), "mark": markAttr(1)} {
		if err := ep.applySet(setAttrs(t, attr), false); err != syserr.ErrNotPermitted {
			t.Errorf("%s without the capability = %v, want EPERM", name, err)
		}
	}
	if err := ep.applySet(setAttrs(t, privAttr(1), peerList(peerAttrs(2))), false); err != nil {
		t.Errorf("a key and a peer without the capability = %v, want success", err)
	}
	if got := ep.state(t); got.listenPort != 0 || got.fwmark != 0 {
		t.Errorf("the refused requests changed the device: %+v", got)
	}
}

func TestSetKeepsTheChangesBeforeAFailureAsLinuxDoes(t *testing.T) {
	ep := newTestLink(t)
	bad := peerAttrs(2, allowedIPList(
		allowedIPAttr(linux.AF_INET, []byte{10, 0, 0, 0}, 8),
		allowedIPAttr(linux.AF_INET, []byte{10, 1, 0, 0}, 33), // EINVAL
		allowedIPAttr(linux.AF_INET, []byte{10, 2, 0, 0}, 16)),
		attrBytes(peerAttrKeepalive, le16(9)))
	err := ep.set(t, markAttr(7), privAttr(1), peerList(peerAttrs(1, attrBytes(peerAttrKeepalive, le16(5))), bad, peerAttrs(3)))
	if err != syserr.ErrInvalidArgument {
		t.Fatalf("set = %v, want EINVAL", err)
	}
	info := ep.state(t)
	if info.fwmark != 7 || info.privateKey != clamped(1) {
		t.Errorf("device = %+v, want the mark and the key that came before the failure", info)
	}
	if p := peerByKey(info, 1); p == nil || p.keepalive != 5 {
		t.Errorf("peer 1 = %+v, want the peer that came before the failure", p)
	}
	p2 := peerByKey(info, 2)
	if p2 == nil || !slices.Equal(p2.allowedIPs, prefixes("10.0.0.0/8")) || p2.keepalive != 0 {
		t.Errorf("peer 2 = %+v, want the address before the failure and no keepalive (it comes after the addresses)", p2)
	}
	if peerByKey(info, 3) != nil {
		t.Error("peer 3 exists, want it unreached")
	}
}

func TestPeerFlagsFollowSetPeer(t *testing.T) {
	ep := newTestLink(t)
	flags := func(f uint32) []byte { return attrBytes(peerAttrFlags, le32(f)) }
	ips := func(cidrs ...string) []byte {
		var entries [][]byte
		for _, c := range cidrs {
			p := netip.MustParsePrefix(c)
			entries = append(entries, allowedIPAttr(linux.AF_INET, p.Addr().AsSlice(), byte(p.Bits())))
		}
		return allowedIPList(entries...)
	}
	if err := ep.set(t, peerList(peerAttrs(1, flags(peerFlagUpdateOnly), ips("10.0.0.0/8")))); err != nil || len(ep.state(t).peers) != 0 {
		t.Fatalf("update-only of an unknown peer = %v with %d peers, want success and no peer", err, len(ep.state(t).peers))
	}
	// Linux stops at an update-only entry of an unknown peer, so a later
	// invalid attribute of that entry is not an error.
	if err := ep.set(t, peerList(peerAttrs(1, flags(peerFlagUpdateOnly), allowedIPList(allowedIPAttr(linux.AF_INET, []byte{1, 2, 3, 4}, 40))))); err != nil {
		t.Errorf("update-only of an unknown peer with an invalid address = %v, want it ignored", err)
	}
	if err := ep.set(t, peerList(peerAttrs(1, flags(peerFlagRemoveMe)))); err != nil {
		t.Errorf("remove of an unknown peer = %v, want success", err)
	}
	if err := ep.set(t, peerList(peerAttrs(1, ips("10.0.0.0/8", "192.168.0.0/16")), peerAttrs(2, ips("172.16.0.0/12")))); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Moving an address: the new owner appends it, and the old owner loses it.
	if err := ep.set(t, peerList(peerAttrs(2, ips("10.0.0.0/8")))); err != nil {
		t.Fatalf("move: %v", err)
	}
	info := ep.state(t)
	if got := peerByKey(info, 1).allowedIPs; !slices.Equal(got, prefixes("192.168.0.0/16")) {
		t.Errorf("peer 1 after the move = %v, want 192.168.0.0/16 only", got)
	}
	if got := peerByKey(info, 2).allowedIPs; !slices.Equal(got, prefixes("172.16.0.0/12", "10.0.0.0/8")) {
		t.Errorf("peer 2 after the move = %v, want its address, and then the moved one", got)
	}
	// A removal of an address that the peer does not own changes nothing.
	del := allowedIPList(allowedIPAttr(linux.AF_INET, []byte{10, 0, 0, 0}, 8, allowedIPFlagRemoveMe))
	if err := ep.set(t, peerList(peerAttrs(1, del))); err != nil {
		t.Fatalf("remove of a foreign address: %v", err)
	}
	if got := peerByKey(ep.state(t), 2).allowedIPs; !slices.Contains(got, netip.MustParsePrefix("10.0.0.0/8")) {
		t.Errorf("peer 2 lost 10.0.0.0/8 to the removal request of peer 1: %v", got)
	}
	if err := ep.set(t, peerList(peerAttrs(2, del))); err != nil {
		t.Fatalf("remove of an own address: %v", err)
	}
	if got := peerByKey(ep.state(t), 2).allowedIPs; slices.Contains(got, netip.MustParsePrefix("10.0.0.0/8")) {
		t.Errorf("peer 2 keeps 10.0.0.0/8 after its removal request: %v", got)
	}
	// REPLACE_ALLOWEDIPS drops the other addresses of the peer.
	if err := ep.set(t, peerList(peerAttrs(2, flags(peerFlagReplaceAllowedIP), ips("100.64.0.0/10")))); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if got := peerByKey(ep.state(t), 2).allowedIPs; !slices.Equal(got, prefixes("100.64.0.0/10")) {
		t.Errorf("peer 2 after the replacement = %v, want 100.64.0.0/10 only", got)
	}
	// Host bits of an address are masked, as Linux masks them.
	if err := ep.set(t, peerList(peerAttrs(1, ips("10.9.8.7/16")))); err != nil {
		t.Fatalf("host bits: %v", err)
	}
	if got := peerByKey(ep.state(t), 1).allowedIPs; !slices.Contains(got, netip.MustParsePrefix("10.9.0.0/16")) {
		t.Errorf("peer 1 = %v, want the masked prefix 10.9.0.0/16", got)
	}
	if err := ep.set(t, peerList(peerAttrs(1, flags(peerFlagRemoveMe)))); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if info := ep.state(t); peerByKey(info, 1) != nil || peerByKey(info, 2) == nil {
		t.Errorf("peers after the removal of peer 1 = %d, want only peer 2", len(info.peers))
	}
	if err := ep.set(t, attrBytes(deviceAttrFlags, le32(deviceFlagReplacePeers))); err != nil || len(ep.state(t).peers) != 0 {
		t.Errorf("replace peers = %v with %d peers left, want none", err, len(ep.state(t).peers))
	}
}

func TestPeerValuesFollowSetPeer(t *testing.T) {
	ep := newTestLink(t)
	if err := ep.set(t, peerList(peerAttrs(1,
		attrBytes(peerAttrPresharedKey, key(9)),
		attrBytes(peerAttrEndpoint, sockaddrIn(51820, [4]byte{192, 0, 2, 7})),
		attrBytes(peerAttrKeepalive, le16(25)),
		attrBytes(peerAttrProtoVersion, le32(1))))); err != nil {
		t.Fatalf("create: %v", err)
	}
	p := peerByKey(ep.state(t), 1)
	if p.presharedKey != [keyLen]byte(key(9)) || p.endpoint != netip.MustParseAddrPort("192.0.2.7:51820") || p.keepalive != 25 {
		t.Fatalf("peer = %+v", p)
	}
	// A keepalive of 0 disables it, a zero preshared key means none, and an
	// endpoint of another shape leaves the endpoint as it is.
	if err := ep.set(t, peerList(peerAttrs(1,
		attrBytes(peerAttrPresharedKey, make([]byte, keyLen)),
		attrBytes(peerAttrEndpoint, append(le16(linux.AF_UNIX), make([]byte, 14)...)),
		attrBytes(peerAttrKeepalive, le16(0))))); err != nil {
		t.Fatalf("update: %v", err)
	}
	p = peerByKey(ep.state(t), 1)
	if p.presharedKey != [keyLen]byte{} || p.keepalive != 0 || p.endpoint != netip.MustParseAddrPort("192.0.2.7:51820") {
		t.Errorf("peer after the update = %+v, want no preshared key, no keepalive, and the old endpoint", p)
	}
	if err := ep.set(t, peerList(peerAttrs(1, attrBytes(peerAttrProtoVersion, le32(2))))); err != errProtocolVersion {
		t.Errorf("protocol version 2 = %v, want EPFNOSUPPORT", err)
	}
}

func TestPeerWithTheKeyOfTheDeviceIsIgnored(t *testing.T) {
	ep := newTestLink(t)
	if err := ep.set(t, privAttr(1)); err != nil {
		t.Fatalf("set the key: %v", err)
	}
	public := ep.public[:]
	if err := ep.set(t, peerList(slices.Concat(attrBytes(peerAttrPublicKey, public), allowedIPList(allowedIPAttr(linux.AF_INET, []byte{1, 2, 3, 4}, 40))))); err != nil {
		t.Fatalf("a peer with the key of the device = %v, want it ignored without an error", err)
	}
	if n := len(ep.state(t).peers); n != 0 {
		t.Errorf("the device has %d peers, want none", n)
	}
}

func TestNewPrivateKeyRemovesThePeerWithItsPublicKey(t *testing.T) {
	ep := newTestLink(t)
	if err := ep.set(t, privAttr(1)); err != nil {
		t.Fatalf("set the key: %v", err)
	}
	pub := slices.Clone(ep.public[:])
	if err := ep.set(t, privAttr(2), peerList(slices.Concat(attrBytes(peerAttrPublicKey, pub)), peerAttrs(5))); err != nil {
		t.Fatalf("set peers: %v", err)
	}
	if n := len(ep.state(t).peers); n != 2 {
		t.Fatalf("the device has %d peers, want 2", n)
	}
	if err := ep.set(t, privAttr(1)); err != nil {
		t.Fatalf("set the key back: %v", err)
	}
	info := ep.state(t)
	if len(info.peers) != 1 || info.peers[0].publicKey[0] != 5 || ep.peers.len() != 1 {
		t.Errorf("peers after the key change = %d (list %d), want only peer 5", len(info.peers), ep.peers.len())
	}
}

func TestPeerCountHasTheLimitOfLinux(t *testing.T) {
	old := peerLimit
	peerLimit = 3
	t.Cleanup(func() { peerLimit = old })
	ep := newTestLink(t)
	if err := ep.set(t, peerList(peerAttrs(1), peerAttrs(2), peerAttrs(3))); err != nil {
		t.Fatalf("three peers: %v", err)
	}
	if err := ep.set(t, peerList(peerAttrs(4))); err != syserr.ErrNoMemory {
		t.Errorf("the fourth peer = %v, want ENOMEM", err)
	}
	if err := ep.set(t, peerList(peerAttrs(2, attrBytes(peerAttrKeepalive, le16(3))))); err != nil {
		t.Errorf("a change of an existing peer at the limit = %v, want success", err)
	}
	if err := ep.set(t, attrBytes(deviceAttrFlags, le32(deviceFlagReplacePeers)), peerList(peerAttrs(4))); err != nil {
		t.Errorf("a request that replaces every peer = %v, want success", err)
	}
}

func TestManyLinksNeedNoLimit(t *testing.T) {
	st := newLoopbackStackOf(t)
	var links []*linkEndpoint
	for i := range 300 {
		ep, sysErr := newLink(context.Background(), &netstack.NewLinkRequest{Stack: st, ID: tcpip.NICID(i + 2), Name: fmt.Sprintf("wg%d", i)})
		if sysErr != nil {
			t.Fatalf("link %d = %v, want success: Linux has no limit on the count of links", i, sysErr)
		}
		links = append(links, ep.(*linkEndpoint))
	}
	for _, l := range links {
		l.Close()
	}
}

func TestDeviceAndPeersChargeTheMemoryAccounting(t *testing.T) {
	old, oldMax := usage.MemoryAccounting, usage.MaximumTotalMemoryBytes
	usage.MemoryAccounting = &usage.MemoryLocked{RTMemoryStats: &usage.RTMemoryStats{}}
	t.Cleanup(func() { usage.MemoryAccounting, usage.MaximumTotalMemoryBytes = old, oldMax })
	acct := usage.MemoryAccounting
	st := newLoopbackStackOf(t)

	ep, sysErr := newLink(context.Background(), &netstack.NewLinkRequest{Stack: st, ID: 2, Name: "wg0"})
	if sysErr != nil {
		t.Fatalf("newLink = %v", sysErr)
	}
	link := ep.(*linkEndpoint)
	if got := acct.Total(); got != deviceBytes() {
		t.Errorf("accounting after newLink = %d, want %d", got, deviceBytes())
	}
	if err := link.set(t, peerList(peerAttrs(1), peerAttrs(2), peerAttrs(3))); err != nil {
		t.Fatalf("add peers: %v", err)
	}
	if got, want := acct.Total(), deviceBytes()+3*peerMemory; got != want {
		t.Errorf("accounting with 3 peers = %d, want %d", got, want)
	}
	if err := link.set(t, peerList(peerAttrs(2, attrBytes(peerAttrFlags, le32(peerFlagRemoveMe))))); err != nil {
		t.Fatalf("remove a peer: %v", err)
	}
	if got, want := acct.Total(), deviceBytes()+2*peerMemory; got != want {
		t.Errorf("accounting with 2 peers = %d, want %d", got, want)
	}
	if err := link.set(t, attrBytes(deviceAttrFlags, le32(deviceFlagReplacePeers))); err != nil {
		t.Fatalf("replace peers: %v", err)
	}
	if got := acct.Total(); got != deviceBytes() {
		t.Errorf("accounting with no peer = %d, want %d", got, deviceBytes())
	}

	// A peer that does not fit in the memory of the host fails with ENOMEM.
	usage.MaximumTotalMemoryBytes = acct.Total() + peerMemory
	if err := link.set(t, peerList(peerAttrs(7), peerAttrs(8))); err != syserr.ErrNoMemory {
		t.Errorf("a second peer beyond the memory = %v, want ENOMEM", err)
	}
	if n := len(link.state(t).peers); n != 1 {
		t.Errorf("the device has %d peers after the refusal, want the one that fit", n)
	}
	// So does a device.
	usage.MaximumTotalMemoryBytes = acct.Total() + 1
	if _, sysErr := newLink(context.Background(), &netstack.NewLinkRequest{Stack: st, ID: 3, Name: "wg1"}); sysErr != syserr.ErrNoMemory {
		t.Errorf("a device beyond the memory = %v, want ENOMEM", sysErr)
	}
	link.Close()
	if got := acct.Total(); got != 0 {
		t.Errorf("accounting after Close = %d, want 0", got)
	}
}

func TestCloseStopsTheDeviceAndFreesItsPortWhileItIsUp(t *testing.T) {
	st := newLoopbackStackOf(t)
	ep, sysErr := newLink(context.Background(), &netstack.NewLinkRequest{Stack: st, ID: 2, Name: "wg0"})
	if sysErr != nil {
		t.Fatalf("newLink = %v", sysErr)
	}
	link := ep.(*linkEndpoint)
	if link.MTU() != defaultMTU {
		t.Errorf("MTU = %d, want %d", link.MTU(), defaultMTU)
	}
	if err := link.set(t, privAttr(1), peerList(peerAttrs(2), peerAttrs(3))); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := link.LinkUp(); err != nil {
		t.Fatalf("LinkUp = %v", err)
	}
	port := link.bind.incomingPort()
	link.SetMTU(1380)
	if got, _ := link.tun.MTU(); got != 1380 {
		t.Errorf("tun MTU = %d after SetMTU(1380)", got)
	}
	link.Close()
	link.Close()
	// Close returns after every goroutine of the device ended.
	select {
	case <-link.dev.Wait():
	default:
		t.Error("the device is still running after Close")
	}
	other := newBind(st.Stack)
	other.setIncoming(port)
	if _, _, err := other.Open(0); err != nil {
		t.Errorf("the port %d after Close = %v, want it free", port, err)
	}
	other.Close()
	birthplaces.Lock()
	defer birthplaces.Unlock()
	if n := len(birthplaces.links[st.Stack]); n != 0 {
		t.Errorf("the registry of the birthplace keeps %d links after Close", n)
	}
}

func TestStackEndedClosesTheSocketsOfAMovedLink(t *testing.T) {
	st := newLoopbackStackOf(t)
	ep := newTestLinkOn(t, st)
	if err := ep.LinkUp(); err != nil {
		t.Fatalf("LinkUp = %v", err)
	}
	port := ep.bind.incomingPort()
	stackEnded(st.Stack)
	if ep.bind.session != nil {
		t.Error("the sockets stay open after the end of the creating stack")
	}
	other := newBind(st.Stack)
	other.setIncoming(port)
	if _, _, err := other.Open(0); err != nil {
		t.Errorf("the port %d after the end of the creating stack = %v, want it free", port, err)
	}
	other.Close()
	// The device keeps its configuration. It cannot come up again.
	if err := ep.set(t, privAttr(1)); err != nil {
		t.Errorf("set after the end of the creating stack = %v, want success", err)
	}
	ep.LinkDown()
	if _, ok := ep.LinkUp().(*tcpip.ErrNoNet); !ok {
		t.Error("LinkUp after the end of the creating stack succeeded, want ENONET")
	}
}

func TestBothCommandsNeedCapNetAdmin(t *testing.T) {
	for _, op := range family.Ops {
		if op.Flags&genetlink.OpNetAdmin == 0 {
			t.Errorf("command %d lacks OpNetAdmin: an unprivileged caller could read the private key or change the device", op.Cmd)
		}
	}
}

// decodedMessage is one message of a dump.
type decodedMessage struct {
	device map[uint16]nlmsg.BytesView
	peers  []decodedPeer
	size   int
}

type decodedPeer struct {
	attrs map[uint16]nlmsg.BytesView
	ips   []netip.Prefix
}

// runDump runs the dump of the device to its end with chunks of limit bytes.
func runDump(t *testing.T, ep *linkEndpoint, limit int) []decodedMessage {
	t.Helper()
	d, err := ep.snapshot()
	if err != nil {
		t.Fatalf("snapshot = %v", err)
	}
	d.ifindex, d.name = 7, "wg0"
	var out []decodedMessage
	for {
		ms := nlmsg.NewMessageSet(1, 2)
		ms.Multi = true
		more, err := d.DumpChunk(context.Background(), genetlink.NewChunk(family, ms, limit))
		if err != nil {
			t.Fatalf("DumpChunk = %v", err)
		}
		if len(ms.Messages) != 1 {
			t.Fatalf("a chunk holds %d messages, want 1", len(ms.Messages))
		}
		out = append(out, decodeMessage(t, ms.Messages[0]))
		if !more {
			return out
		}
	}
}

func decodeMessage(t *testing.T, m *nlmsg.Message) decodedMessage {
	t.Helper()
	buf := m.Buffer()
	dm := decodedMessage{size: len(buf)}
	if buf[linux.NetlinkMessageHeaderSize] != cmdGetDevice {
		t.Fatalf("command = %d, want WG_CMD_GET_DEVICE", buf[linux.NetlinkMessageHeaderSize])
	}
	var ok bool
	dm.device, ok = genetlink.ParseAttrs(nlmsg.AttrsView(buf[linux.NetlinkMessageHeaderSize+4:]))
	if !ok {
		t.Fatal("the attributes of a message do not parse")
	}
	list := nlmsg.AttrsView(dm.device[deviceAttrPeers])
	for !list.Empty() {
		hdr, value, rest, ok := list.ParseFirst()
		if !ok || hdr.Type != linux.NLA_F_NESTED {
			t.Fatalf("peer entry type = %#x, ok = %v, want a nested entry of type 0", hdr.Type, ok)
		}
		list = rest
		attrs, ok := genetlink.ParseAttrs(nlmsg.AttrsView(value))
		if !ok {
			t.Fatal("a peer does not parse")
		}
		p := decodedPeer{attrs: attrs}
		ips := nlmsg.AttrsView(attrs[peerAttrAllowedIPs])
		for !ips.Empty() {
			_, v, next, ok := ips.ParseFirst()
			if !ok {
				t.Fatal("an allowed IP does not parse")
			}
			ips = next
			ia, ok := genetlink.ParseAttrs(nlmsg.AttrsView(v))
			if !ok {
				t.Fatal("an allowed IP entry does not parse")
			}
			addr, _ := netip.AddrFromSlice(ia[allowedIPAttrIPAddr])
			cidrAttr := ia[allowedIPAttrCIDR]
			cidr, _ := cidrAttr.Uint8()
			p.ips = append(p.ips, netip.PrefixFrom(addr, int(cidr)))
		}
		dm.peers = append(dm.peers, p)
	}
	return dm
}

// peerKeyOf returns the public key of a decoded peer.
func peerKeyOf(p decodedPeer) [keyLen]byte { return [keyLen]byte(p.attrs[peerAttrPublicKey]) }

// bigKey returns a key that holds the number n.
func bigKey(n int) []byte {
	k := make([]byte, keyLen)
	binary.BigEndian.PutUint32(k[28:], uint32(n)+1)
	return k
}

func TestDumpOfManyPeersIsCompleteAndInOrderOfCreation(t *testing.T) {
	const peers = 10000
	ep := newTestLink(t)
	if err := ep.set(t, privAttr(3), portAttr(4242), markAttr(0x51)); err != nil {
		t.Fatalf("set: %v", err)
	}
	// 100 peers in each request, as the tool "wg" sends them. Each peer owns
	// one address, and the peer 77 owns 600, which exceed one message.
	for first := 0; first < peers; first += 100 {
		var list [][]byte
		for i := first; i < first+100; i++ {
			a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
			entries := [][]byte{allowedIPAttr(linux.AF_INET, a.AsSlice(), 32)}
			if i == 77 {
				for j := range 600 {
					b := netip.AddrFrom4([4]byte{172, 16, byte(j >> 8), byte(j)})
					entries = append(entries, allowedIPAttr(linux.AF_INET, b.AsSlice(), 32))
				}
			}
			list = append(list, slices.Concat(attrBytes(peerAttrPublicKey, bigKey(i)), allowedIPList(entries...)))
		}
		if err := ep.set(t, peerList(list...)); err != nil {
			t.Fatalf("set peers %d to %d = %v", first, first+99, err)
		}
	}
	for _, limit := range []int{3776, 8192, 32448} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			msgs := runDump(t, ep, limit)
			first := msgs[0]
			portV, markV := first.device[deviceAttrListenPort], first.device[deviceAttrFwmark]
			if got, _ := portV.Uint16(); got != 4242 {
				t.Errorf("first message: listen port = %d, want 4242", got)
			}
			if got, _ := markV.Uint32(); got != 0x51 {
				t.Errorf("first message: fwmark = %#x, want 0x51", got)
			}
			if _, ok := first.device[deviceAttrPrivateKey]; !ok {
				t.Error("first message lacks the private key")
			}
			var order []int
			addrs := map[int]int{}
			for i, m := range msgs {
				if i > 0 {
					for _, typ := range []uint16{deviceAttrIfindex, deviceAttrIfname, deviceAttrListenPort, deviceAttrFwmark, deviceAttrPrivateKey, deviceAttrPublicKey} {
						if _, ok := m.device[typ]; ok {
							t.Errorf("message %d repeats the device attribute %d, which only the first message holds", i, typ)
						}
					}
				}
				if m.size > limit && len(m.peers) > 1 {
					t.Errorf("message %d has %d bytes with %d peers, want at most %d", i, m.size, len(m.peers), limit)
				}
				for _, p := range m.peers {
					k := peerKeyOf(p)
					n := int(binary.BigEndian.Uint32(k[28:])) - 1
					if _, full := p.attrs[peerAttrPresharedKey]; full {
						order = append(order, n)
					} else if len(order) == 0 || order[len(order)-1] != n {
						t.Errorf("message %d continues peer %d, which is not the last peer", i, n)
					}
					addrs[n] += len(p.ips)
				}
			}
			if len(order) != peers {
				t.Fatalf("the dump lists %d peers, want %d", len(order), peers)
			}
			for i, n := range order {
				if n != i {
					t.Fatalf("peer %d of the dump is the peer %d, want the order of creation", i, n)
				}
			}
			if addrs[77] != 601 || addrs[78] != 1 || addrs[9999] != 1 {
				t.Errorf("addresses of peers 77, 78, and 9999 = %d, %d, %d, want 601, 1, and 1", addrs[77], addrs[78], addrs[9999])
			}
		})
	}
}

func TestDumpOfAnEmptyDeviceHasOneMessageWithoutKeys(t *testing.T) {
	ep := newTestLink(t)
	msgs := runDump(t, ep, 3776)
	if len(msgs) != 1 || len(msgs[0].peers) != 0 {
		t.Fatalf("dump = %d messages, want 1 without peers", len(msgs))
	}
	for _, typ := range []uint16{deviceAttrPrivateKey, deviceAttrPublicKey, deviceAttrPeers} {
		if _, ok := msgs[0].device[typ]; ok {
			t.Errorf("attribute %d is present, want it absent without a key and peers", typ)
		}
	}
	idx := msgs[0].device[deviceAttrIfindex]
	if got, _ := idx.Uint32(); got != 7 {
		t.Errorf("ifindex = %d, want 7", got)
	}
}

func TestDumpReportsPeersAsGetPeerDoes(t *testing.T) {
	ep := newTestLink(t)
	if err := ep.set(t, privAttr(3), peerList(peerAttrs(1,
		attrBytes(peerAttrPresharedKey, key(8)),
		attrBytes(peerAttrEndpoint, sockaddrIn(51820, [4]byte{192, 0, 2, 7})),
		attrBytes(peerAttrKeepalive, le16(25))))); err != nil {
		t.Fatalf("set: %v", err)
	}
	msgs := runDump(t, ep, 3776)
	p := msgs[0].peers[0]
	// The attributes come in the order of get_peer.
	var raw []uint16
	view := nlmsg.AttrsView(msgs[0].device[deviceAttrPeers])
	_, value, _, _ := view.ParseFirst()
	for v := nlmsg.AttrsView(value); !v.Empty(); {
		hdr, _, rest, _ := v.ParseFirst()
		raw = append(raw, hdr.Type&linux.NLA_TYPE_MASK)
		v = rest
	}
	want := []uint16{peerAttrPublicKey, peerAttrPresharedKey, peerAttrLastHshake, peerAttrKeepalive, peerAttrTxBytes, peerAttrRxBytes, peerAttrProtoVersion, peerAttrEndpoint}
	if !slices.Equal(raw, want) {
		t.Errorf("peer attributes = %v, want %v", raw, want)
	}
	if v := p.attrs[peerAttrLastHshake]; len(v) != 16 {
		t.Errorf("last handshake time has %d bytes, want 16", len(v))
	}
	proto := p.attrs[peerAttrProtoVersion]
	if got, _ := proto.Uint32(); got != 1 {
		t.Errorf("protocol version = %d, want 1", got)
	}
	pub := msgs[0].device[deviceAttrPublicKey]
	if len(pub) != keyLen || [keyLen]byte(pub) != ep.public {
		t.Errorf("public key = %x, want the key of the device", []byte(pub))
	}
}

func TestEndpointRoamsToTheSourceOfAnAuthenticatedPacket(t *testing.T) {
	// wireguard-go sets the endpoint of a peer from each authenticated packet.
	// The test follows the shape of the data path: it checks that the bind
	// gives wireguard-go the sender as the endpoint of the packet.
	b := newBind(newLoopbackStack(t))
	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()
	ep, _ := b.ParseEndpoint(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String())
	got := receiveOne(fns[0])
	if err := b.Send([][]byte{[]byte("x")}, ep); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case r := <-got:
		if r.from.Addr() != netip.MustParseAddr("127.0.0.1") || r.from.Port() != port {
			t.Errorf("the sender of the datagram is %v, want 127.0.0.1:%d", r.from, port)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no datagram arrived")
	}
}

func TestClosedDeviceRefusesRequestsAndChargesNothing(t *testing.T) {
	old := usage.MemoryAccounting
	usage.MemoryAccounting = &usage.MemoryLocked{RTMemoryStats: &usage.RTMemoryStats{}}
	t.Cleanup(func() { usage.MemoryAccounting = old })
	st := newLoopbackStackOf(t)
	ep, sysErr := newLink(context.Background(), &netstack.NewLinkRequest{Stack: st, ID: 2, Name: "wg0"})
	if sysErr != nil {
		t.Fatalf("newLink = %v", sysErr)
	}
	link := ep.(*linkEndpoint)
	link.Close()
	if got := usage.MemoryAccounting.Total(); got != 0 {
		t.Fatalf("accounting after Close = %d, want 0", got)
	}
	if err := link.set(t, peerList(peerAttrs(1))); err != syserr.ErrNoDevice {
		t.Errorf("set on a closed device = %v, want ENODEV", err)
	}
	if _, err := link.snapshot(); err != syserr.ErrNoDevice {
		t.Errorf("dump of a closed device = %v, want ENODEV", err)
	}
	if _, ok := link.LinkUp().(*tcpip.ErrUnknownDevice); !ok {
		t.Error("LinkUp on a closed device succeeded, want an unknown device error")
	}
	if got := usage.MemoryAccounting.Total(); got != 0 {
		t.Errorf("accounting after the refused requests = %d, want 0: a closed device charged memory again", got)
	}
}
