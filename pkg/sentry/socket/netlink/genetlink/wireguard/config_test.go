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
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/syserr"
)

// attrBytes returns one netlink attribute.
func attrBytes(typ uint16, value []byte) []byte {
	var n nlmsg.NestedAttr
	n.PutAttr(typ, primitive.AsByteSlice(value))
	return n
}

func le16(v uint16) []byte { return hostarch.ByteOrder.AppendUint16(nil, v) }
func le32(v uint32) []byte { return hostarch.ByteOrder.AppendUint32(nil, v) }

func key(b byte) []byte { return bytes.Repeat([]byte{b}, keyLen) }

// allowedIPAttr returns the entry of one allowed IP address.
func allowedIPAttr(family uint16, addr []byte, cidr byte, flags ...uint32) []byte {
	entry := slices.Concat(
		attrBytes(allowedIPAttrFamily, le16(family)),
		attrBytes(allowedIPAttrIPAddr, addr),
		attrBytes(allowedIPAttrCIDR, []byte{cidr}),
	)
	for _, f := range flags {
		entry = append(entry, attrBytes(allowedIPAttrFlags, le32(f))...)
	}
	return attrBytes(0|linux.NLA_F_NESTED, entry)
}

func sockaddrIn(port uint16, ip [4]byte) []byte {
	b := make([]byte, sockaddrInSize)
	hostarch.ByteOrder.PutUint16(b, linux.AF_INET)
	binary.BigEndian.PutUint16(b[2:], port)
	copy(b[4:], ip[:])
	return b
}

// setAttrs validates the attribute bytes with the policy of WG_CMD_SET_DEVICE,
// as the handler does.
func setAttrs(t *testing.T, parts ...[]byte) map[uint16]nlmsg.BytesView {
	t.Helper()
	attrs, err := parseWithPolicy(nlmsg.AttrsView(slices.Concat(parts...)), setDevicePolicy)
	if err != nil {
		t.Fatalf("parseWithPolicy = %v", err)
	}
	return attrs
}

// peerList wraps peers in the nested attribute of WGDEVICE_A_PEERS.
func peerList(peers ...[]byte) []byte {
	var entries []byte
	for _, p := range peers {
		entries = append(entries, attrBytes(0|linux.NLA_F_NESTED, p)...)
	}
	return attrBytes(deviceAttrPeers|linux.NLA_F_NESTED, entries)
}

// allowedIPList wraps entries in the nested attribute of WGPEER_A_ALLOWEDIPS.
func allowedIPList(entries ...[]byte) []byte {
	return attrBytes(peerAttrAllowedIPs|linux.NLA_F_NESTED, slices.Concat(entries...))
}

func TestEndpointRoundTrip(t *testing.T) {
	for _, s := range []string{"192.0.2.1:51820", "[2001:db8::7]:1"} {
		want := netip.MustParseAddrPort(s)
		got, ok := endpointText(encodeEndpoint(want))
		if !ok || got != want.String() {
			t.Errorf("endpointText(encodeEndpoint(%s)) = (%q, %v)", s, got, ok)
		}
	}
}

func TestEndpointTextIgnoresAnAddressOfAnotherShape(t *testing.T) {
	// set_peer accepts an endpoint only when the length fits the family.
	for name, v := range map[string][]byte{
		"IPv4 family with the size of IPv6": append(le16(linux.AF_INET), make([]byte, 26)...),
		"IPv6 family with the size of IPv4": append(le16(linux.AF_INET6), make([]byte, 14)...),
		"another family":                    append(le16(linux.AF_UNIX), make([]byte, 14)...),
		"one byte":                          {1},
	} {
		if got, ok := endpointText(v); ok {
			t.Errorf("%s: endpointText = %q, want it ignored", name, got)
		}
	}
}

func TestPolicyAcceptsTheRequestOfTheWgTool(t *testing.T) {
	peer := slices.Concat(
		attrBytes(peerAttrPublicKey, key(0xaa)),
		attrBytes(peerAttrFlags, le32(peerFlagReplaceAllowedIP|peerFlagUpdateOnly|peerFlagRemoveMe)),
		attrBytes(peerAttrPresharedKey, key(0xbb)),
		attrBytes(peerAttrEndpoint, sockaddrIn(51820, [4]byte{192, 0, 2, 7})),
		attrBytes(peerAttrKeepalive, le16(25)),
		attrBytes(peerAttrProtoVersion, le32(1)),
		allowedIPList(allowedIPAttr(linux.AF_INET, []byte{10, 0, 0, 0}, 8, allowedIPFlagRemoveMe)),
	)
	attrs := setAttrs(t,
		attrBytes(deviceAttrIfname, []byte("wg0\x00")),
		attrBytes(deviceAttrPrivateKey, key(0x11)),
		attrBytes(deviceAttrPublicKey, key(0x12)),
		attrBytes(deviceAttrListenPort, le16(51821)),
		attrBytes(deviceAttrFwmark, le32(77)),
		attrBytes(deviceAttrFlags, le32(deviceFlagReplacePeers)),
		peerList(peer),
	)
	for _, typ := range []uint16{deviceAttrIfname, deviceAttrPrivateKey, deviceAttrListenPort, deviceAttrFwmark, deviceAttrFlags, deviceAttrPeers} {
		if _, ok := attrs[typ]; !ok {
			t.Errorf("attribute %d is missing from the parsed request", typ)
		}
	}
	// An empty list of peers also passes.
	setAttrs(t, attrBytes(deviceAttrPeers|linux.NLA_F_NESTED, nil))
}

// TestPolicyRejectsInvalidRequests checks the error numbers of the policy of
// Linux: lib/nlattr.c answers ERANGE for a binary attribute of the wrong size
// and for a malformed array, and EINVAL for the other violations.
func TestPolicyRejectsInvalidRequests(t *testing.T) {
	peerWith := func(extra ...[]byte) []byte {
		return peerList(slices.Concat(append([][]byte{attrBytes(peerAttrPublicKey, key(1))}, extra...)...))
	}
	for _, tc := range []struct {
		name  string
		attrs []byte
		want  *syserr.Error
	}{
		{"unknown device flag", attrBytes(deviceAttrFlags, le32(2)), syserr.ErrInvalidArgument},
		{"short private key", attrBytes(deviceAttrPrivateKey, key(1)[:31]), errRange},
		{"long public key", attrBytes(deviceAttrPublicKey, append(key(1), 0)), errRange},
		{"short port", attrBytes(deviceAttrListenPort, []byte{1}), syserr.ErrInvalidArgument},
		{"long mark", attrBytes(deviceAttrFwmark, make([]byte, 8)), syserr.ErrInvalidArgument},
		{"name of 16 characters", attrBytes(deviceAttrIfname, append([]byte("0123456789abcdef"), 0)), syserr.ErrInvalidArgument},
		{"name with text after the NUL", attrBytes(deviceAttrIfname, append([]byte("wg0\x00"), []byte("0123456789abcdef")...)), errRange},
		{"name without NUL", attrBytes(deviceAttrIfname, []byte("wg0")), syserr.ErrInvalidArgument},
		{"empty name", attrBytes(deviceAttrIfname, nil), syserr.ErrInvalidArgument},
		{"unknown attribute", attrBytes(deviceAttrPeers+1, []byte{1}), syserr.ErrInvalidArgument},
		{"attribute of type 0", attrBytes(0, []byte{1}), syserr.ErrInvalidArgument},
		{"nested flag on a port", attrBytes(deviceAttrListenPort|linux.NLA_F_NESTED, le16(1)), syserr.ErrInvalidArgument},
		{"peers without the nested flag", attrBytes(deviceAttrPeers, nil), syserr.ErrInvalidArgument},
		{"truncated attribute", []byte{9, 0, 1}, syserr.ErrInvalidArgument},
		{"array of 3 bytes", attrBytes(deviceAttrPeers|linux.NLA_F_NESTED, []byte{1, 2, 3}), errRange},
		{"array element of 2 bytes", attrBytes(deviceAttrPeers|linux.NLA_F_NESTED, attrBytes(0, []byte{1, 2})), errRange},
		{"unknown peer flag", peerWith(attrBytes(peerAttrFlags, le32(8))), syserr.ErrInvalidArgument},
		{"short peer key", peerList(attrBytes(peerAttrPublicKey, key(1)[:3])), errRange},
		{"short preshared key", peerWith(attrBytes(peerAttrPresharedKey, key(1)[:3])), errRange},
		{"endpoint of 15 bytes", peerWith(attrBytes(peerAttrEndpoint, make([]byte, 15))), errRange},
		{"handshake time of 8 bytes", peerWith(attrBytes(peerAttrLastHshake, make([]byte, 8))), errRange},
		{"unknown peer attribute", peerWith(attrBytes(peerAttrProtoVersion+1, []byte{1})), syserr.ErrInvalidArgument},
		{"allowed IPs without the nested flag", peerWith(attrBytes(peerAttrAllowedIPs, nil)), syserr.ErrInvalidArgument},
		{"allowed IP address of 3 bytes", peerWith(allowedIPList(allowedIPAttr(linux.AF_INET, []byte{1, 2, 3}, 8))), errRange},
		{"unknown allowed IP flag", peerWith(allowedIPList(allowedIPAttr(linux.AF_INET, []byte{1, 2, 3, 4}, 8, 2))), syserr.ErrInvalidArgument},
		{"allowed IP mask of 2 bytes", peerWith(allowedIPList(attrBytes(0|linux.NLA_F_NESTED, slices.Concat(
			attrBytes(allowedIPAttrFamily, le16(linux.AF_INET)), attrBytes(allowedIPAttrIPAddr, []byte{1, 2, 3, 4}), attrBytes(allowedIPAttrCIDR, []byte{1, 2}))))), syserr.ErrInvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseWithPolicy(nlmsg.AttrsView(tc.attrs), setDevicePolicy); err != tc.want {
				t.Errorf("parseWithPolicy = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestPolicyOfGetDeviceAcceptsOnlyTheSelectors(t *testing.T) {
	ok := slices.Concat(attrBytes(deviceAttrIfindex, le32(3)), attrBytes(deviceAttrIfname, []byte("wg0\x00")))
	if _, err := parseWithPolicy(nlmsg.AttrsView(ok), getDevicePolicy); err != nil {
		t.Errorf("GET policy rejected the selectors: %v", err)
	}
	for name, attrs := range map[string][]byte{
		"private key": attrBytes(deviceAttrPrivateKey, key(1)),
		"port":        attrBytes(deviceAttrListenPort, le16(1)),
	} {
		if _, err := parseWithPolicy(nlmsg.AttrsView(attrs), getDevicePolicy); err != syserr.ErrInvalidArgument {
			t.Errorf("GET policy with a %s = %v, want EINVAL", name, err)
		}
	}
}

func TestDecodeAllowedIPFollowsSetAllowedip(t *testing.T) {
	attrs := func(family uint16, addr []byte, cidr byte) map[uint16]nlmsg.BytesView {
		a, _ := parseWithPolicy(nlmsg.AttrsView(slices.Concat(
			attrBytes(allowedIPAttrFamily, le16(family)), attrBytes(allowedIPAttrIPAddr, addr), attrBytes(allowedIPAttrCIDR, []byte{cidr}))), allowedIPPolicy)
		return a
	}
	if p, remove, err := decodeAllowedIP(attrs(linux.AF_INET, []byte{10, 1, 2, 3}, 24)); err != nil || remove || p != netip.MustParsePrefix("10.1.2.3/24") {
		t.Errorf("IPv4 = (%v, %v, %v)", p, remove, err)
	}
	for name, a := range map[string]map[uint16]nlmsg.BytesView{
		"IPv4 mask 33":          attrs(linux.AF_INET, []byte{1, 2, 3, 4}, 33),
		"IPv6 mask 129":         attrs(linux.AF_INET6, make([]byte, 16), 129),
		"IPv4 with 16 bytes":    attrs(linux.AF_INET, make([]byte, 16), 8),
		"IPv6 with 4 bytes":     attrs(linux.AF_INET6, make([]byte, 4), 8),
		"other family":          attrs(linux.AF_UNIX, make([]byte, 4), 8),
		"family attribute only": {allowedIPAttrFamily: le16(linux.AF_INET)},
	} {
		if _, _, err := decodeAllowedIP(a); err != syserr.ErrInvalidArgument {
			t.Errorf("%s: decodeAllowedIP = %v, want EINVAL", name, err)
		}
	}
}

func TestParseIpcGetReadsDeviceAndKeepsTheOrder(t *testing.T) {
	text := "private_key=" + hexKey(5) + "\nlisten_port=4242\nfwmark=9\n" +
		"public_key=" + hexKey(0x20) + "\npreshared_key=" + hexKey(0) + "\nprotocol_version=1\n" +
		"endpoint=192.0.2.1:1000\nlast_handshake_time_sec=12\nlast_handshake_time_nsec=34\n" +
		"tx_bytes=5\nrx_bytes=6\npersistent_keepalive_interval=25\nallowed_ip=10.0.0.0/8\nallowed_ip=fd00::/64\n" +
		"public_key=" + hexKey(0x10) + "\npreshared_key=" + hexKey(0) + "\nprotocol_version=1\n" +
		"endpoint=[2001:db8::1]:2000\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\n" +
		"tx_bytes=0\nrx_bytes=0\npersistent_keepalive_interval=0\n"
	d, err := parseIpcGet(text)
	if err != nil {
		t.Fatalf("parseIpcGet = %v", err)
	}
	if d.privateKey[0] != 5 || d.listenPort != 4242 || d.fwmark != 9 || len(d.peers) != 2 {
		t.Fatalf("device = %+v", d)
	}
	first, second := d.peers[0], d.peers[1]
	if second.publicKey[0] != 0x10 || second.endpoint != netip.MustParseAddrPort("[2001:db8::1]:2000") || len(second.allowedIPs) != 0 {
		t.Errorf("second peer = %+v", second)
	}
	if first.publicKey[0] != 0x20 || first.keepalive != 25 || first.handshakeSec != 12 || first.handshakeNsec != 34 ||
		first.txBytes != 5 || first.rxBytes != 6 || len(first.allowedIPs) != 2 {
		t.Errorf("first peer = %+v", first)
	}
}

func TestParseIpcGetRejectsMalformedText(t *testing.T) {
	for _, text := range []string{"listen_port", "listen_port=70000\n", "private_key=zz\n", "public_key=00\n"} {
		if _, err := parseIpcGet(text); err == nil {
			t.Errorf("parseIpcGet(%q) succeeded, want an error", text)
		}
	}
}

func TestPeerSetKeepsTheOrderOfCreation(t *testing.T) {
	var s peerSet
	s.init()
	for _, b := range []byte{0x30, 0x10, 0x20} {
		s.add([keyLen]byte(key(b)))
	}
	s.add([keyLen]byte(key(0x30))) // a second add keeps the place
	s.remove([keyLen]byte(key(0x10)))
	s.add([keyLen]byte(key(0x10))) // a new peer with a removed key goes last
	peers := []peerInfo{{publicKey: [keyLen]byte(key(0x10))}, {publicKey: [keyLen]byte(key(0x20))}, {publicKey: [keyLen]byte(key(0x30))}, {publicKey: [keyLen]byte(key(0x05))}}
	s.sortPeers(peers)
	var got []byte
	for _, p := range peers {
		got = append(got, p.publicKey[0])
	}
	if want := []byte{0x30, 0x20, 0x10, 0x05}; !bytes.Equal(got, want) {
		t.Errorf("order = %x, want %x (unknown peers last)", got, want)
	}
}
