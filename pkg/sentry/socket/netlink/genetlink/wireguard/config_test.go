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
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/genetlink"
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

// setAttrs parses the attribute bytes the way the dispatcher does.
func setAttrs(t *testing.T, parts ...[]byte) map[uint16]nlmsg.BytesView {
	t.Helper()
	attrs, ok := genetlink.ParseAttrs(nlmsg.AttrsView(slices.Concat(parts...)))
	if !ok {
		t.Fatal("ParseAttrs failed")
	}
	return attrs
}

func TestParseSetDeviceBuildsTheConfigurationText(t *testing.T) {
	peer := slices.Concat(
		attrBytes(peerAttrPublicKey, key(0xaa)),
		attrBytes(peerAttrFlags, le32(peerFlagReplaceAllowedIP|peerFlagUpdateOnly)),
		attrBytes(peerAttrPresharedKey, key(0xbb)),
		attrBytes(peerAttrEndpoint, sockaddrIn(51820, [4]byte{192, 0, 2, 7})),
		attrBytes(peerAttrKeepalive, le16(25)),
		attrBytes(peerAttrProtoVersion, le32(1)),
		attrBytes(peerAttrAllowedIPs|linux.NLA_F_NESTED, slices.Concat(
			allowedIPAttr(linux.AF_INET, []byte{10, 0, 0, 0}, 8),
			allowedIPAttr(linux.AF_INET6, netip.MustParseAddr("fd00::").AsSlice(), 64),
			allowedIPAttr(linux.AF_INET, []byte{10, 1, 0, 0}, 16, allowedIPFlagRemoveMe),
		)),
	)
	attrs := setAttrs(t,
		attrBytes(deviceAttrIfname, []byte("wg0\x00")),
		attrBytes(deviceAttrPrivateKey, key(0x11)),
		attrBytes(deviceAttrListenPort, le16(51821)),
		attrBytes(deviceAttrFwmark, le32(77)),
		attrBytes(deviceAttrFlags, le32(deviceFlagReplacePeers)),
		attrBytes(deviceAttrPeers|linux.NLA_F_NESTED, attrBytes(0|linux.NLA_F_NESTED, peer)),
	)
	plan, err := parseSetDevice(attrs, &deviceInfo{})
	if err != nil {
		t.Fatalf("parseSetDevice = %v", err)
	}
	got := plan.conf
	// The order is the order of wg_set_device in Linux.
	want := "fwmark=77\n" +
		"listen_port=51821\n" +
		"replace_peers=true\n" +
		"private_key=" + hexKey(0x11) + "\n" +
		"public_key=" + hexKey(0xaa) + "\n" +
		"update_only=true\n" +
		"preshared_key=" + hexKey(0xbb) + "\n" +
		"endpoint=192.0.2.7:51820\n" +
		"persistent_keepalive_interval=25\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=10.0.0.0/8\n" +
		"allowed_ip=fd00::/64\n" +
		"allowed_ip=-10.1.0.0/16\n"
	if got != want {
		t.Errorf("parseSetDevice =\n%s\nwant\n%s", got, want)
	}
	if !plan.changesSocket || plan.probePort != 51821 || plan.peers != 0 {
		t.Errorf("plan = %+v, want a socket change, the probe of port 51821, and 0 peers (update only of an unknown peer)", plan)
	}
}

func TestParseSetDeviceKeepsTheCurrentPort(t *testing.T) {
	attrs := setAttrs(t, attrBytes(deviceAttrListenPort, le16(51820)))
	plan, err := parseSetDevice(attrs, &deviceInfo{listenPort: 51820})
	if err != nil || plan.conf != "" || plan.probePort != 0 || !plan.changesSocket {
		t.Errorf("parseSetDevice with the current port = (%+v, %v), want no line, no probe, and a socket change", plan, err)
	}
	plan, err = parseSetDevice(attrs, &deviceInfo{listenPort: 4000})
	if err != nil || plan.conf != "listen_port=51820\n" || plan.probePort != 51820 {
		t.Errorf("parseSetDevice with a new port = (%+v, %v), want the line and a probe", plan, err)
	}
	plan, err = parseSetDevice(setAttrs(t, attrBytes(deviceAttrListenPort, le16(0))), &deviceInfo{listenPort: 4000})
	if err != nil || plan.conf != "listen_port=0\n" || plan.probePort != 0 {
		t.Errorf("parseSetDevice with port 0 = (%+v, %v), want the line and no probe", plan, err)
	}
}

func TestParseSetDeviceCountsThePeersAfterTheRequest(t *testing.T) {
	cur := &deviceInfo{peers: []peerInfo{{publicKey: [keyLen]byte(key(1))}, {publicKey: [keyLen]byte(key(2))}}}
	peers := func(entries ...[]byte) map[uint16]nlmsg.BytesView {
		var list []byte
		for _, e := range entries {
			list = append(list, attrBytes(0, e)...)
		}
		return setAttrs(t, attrBytes(deviceAttrPeers, list))
	}
	entry := func(k byte, flags uint32) []byte {
		return slices.Concat(attrBytes(peerAttrPublicKey, key(k)), attrBytes(peerAttrFlags, le32(flags)))
	}
	for _, tc := range []struct {
		name  string
		attrs map[uint16]nlmsg.BytesView
		want  int
	}{
		{"no peers in the request", setAttrs(t), 2},
		{"a new peer", peers(entry(3, 0)), 3},
		{"a known peer", peers(entry(1, 0)), 2},
		{"a removed peer", peers(entry(1, peerFlagRemoveMe)), 1},
		{"a removal of an unknown peer", peers(entry(9, peerFlagRemoveMe)), 2},
		{"update only of an unknown peer", peers(entry(9, peerFlagUpdateOnly)), 2},
		{"update only of a known peer", peers(entry(1, peerFlagUpdateOnly)), 2},
		{"replace and one peer", setAttrs(t, attrBytes(deviceAttrFlags, le32(deviceFlagReplacePeers)), attrBytes(deviceAttrPeers, attrBytes(0, entry(1, 0)))), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := parseSetDevice(tc.attrs, cur)
			if err != nil || plan.peers != tc.want {
				t.Errorf("parseSetDevice = (%+v, %v), want %d peers", plan, err, tc.want)
			}
		})
	}
}

func TestParseSetDeviceRemoveMeSkipsTheOtherAttributes(t *testing.T) {
	peer := slices.Concat(
		attrBytes(peerAttrPublicKey, key(0xaa)),
		attrBytes(peerAttrFlags, le32(peerFlagRemoveMe)),
		attrBytes(peerAttrEndpoint, []byte{1, 2, 3}), // invalid, and ignored
	)
	plan, err := parseSetDevice(setAttrs(t, attrBytes(deviceAttrPeers, attrBytes(0, peer))), &deviceInfo{})
	if err != nil {
		t.Fatalf("parseSetDevice = %v", err)
	}
	if want := "public_key=" + hexKey(0xaa) + "\nremove=true\n"; plan.conf != want {
		t.Errorf("parseSetDevice = %q, want %q", plan.conf, want)
	}
}

func TestParseSetDeviceRejectsInvalidRequests(t *testing.T) {
	peerWith := func(extra ...[]byte) map[uint16]nlmsg.BytesView {
		peer := slices.Concat(append([][]byte{attrBytes(peerAttrPublicKey, key(1))}, extra...)...)
		return setAttrs(t, attrBytes(deviceAttrPeers, attrBytes(0, peer)))
	}
	for _, tc := range []struct {
		name  string
		attrs map[uint16]nlmsg.BytesView
		want  *syserr.Error
	}{
		{"unknown device flag", setAttrs(t, attrBytes(deviceAttrFlags, le32(2))), syserr.ErrNotSupported},
		{"short private key", setAttrs(t, attrBytes(deviceAttrPrivateKey, key(1)[:31])), syserr.ErrInvalidArgument},
		{"short port", setAttrs(t, attrBytes(deviceAttrListenPort, []byte{1})), syserr.ErrInvalidArgument},
		{"peer without key", setAttrs(t, attrBytes(deviceAttrPeers, attrBytes(0, attrBytes(peerAttrKeepalive, le16(1))))), syserr.ErrInvalidArgument},
		{"unknown peer flag", peerWith(attrBytes(peerAttrFlags, le32(8))), syserr.ErrNotSupported},
		{"short preshared key", peerWith(attrBytes(peerAttrPresharedKey, key(1)[:3])), syserr.ErrInvalidArgument},
		{"endpoint of the wrong size", peerWith(attrBytes(peerAttrEndpoint, make([]byte, 20))), syserr.ErrInvalidArgument},
		{"endpoint of another family", peerWith(attrBytes(peerAttrEndpoint, append(le16(linux.AF_UNIX), make([]byte, 14)...))), syserr.ErrInvalidArgument},
		{"protocol version 2", peerWith(attrBytes(peerAttrProtoVersion, le32(2))), errProtocolVersion},
		{"IPv4 prefix of 33 bits", peerWith(attrBytes(peerAttrAllowedIPs, allowedIPAttr(linux.AF_INET, []byte{1, 2, 3, 4}, 33))), syserr.ErrInvalidArgument},
		{"IPv6 prefix of 129 bits", peerWith(attrBytes(peerAttrAllowedIPs, allowedIPAttr(linux.AF_INET6, make([]byte, 16), 129))), syserr.ErrInvalidArgument},
		{"IPv4 family with an IPv6 address", peerWith(attrBytes(peerAttrAllowedIPs, allowedIPAttr(linux.AF_INET, make([]byte, 16), 8))), syserr.ErrInvalidArgument},
		{"allowed IP without a family", peerWith(attrBytes(peerAttrAllowedIPs, attrBytes(0, attrBytes(allowedIPAttrCIDR, []byte{8})))), syserr.ErrInvalidArgument},
		{"unknown allowed IP flag", peerWith(attrBytes(peerAttrAllowedIPs, allowedIPAttr(linux.AF_INET, []byte{1, 2, 3, 4}, 8, 2))), syserr.ErrInvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if plan, err := parseSetDevice(tc.attrs, &deviceInfo{}); err != tc.want {
				t.Errorf("parseSetDevice = (%+v, %v), want %v", plan, err, tc.want)
			}
		})
	}
}

func TestEndpointRoundTrip(t *testing.T) {
	for _, s := range []string{"192.0.2.1:51820", "[2001:db8::7]:1"} {
		want := netip.MustParseAddrPort(s)
		got, err := decodeEndpoint(encodeEndpoint(want))
		if err != nil || got != want {
			t.Errorf("decodeEndpoint(encodeEndpoint(%s)) = (%v, %v)", s, got, err)
		}
	}
}

func TestParseIpcGetReadsDeviceAndSortsPeers(t *testing.T) {
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
	if first.publicKey[0] != 0x10 || first.endpoint != netip.MustParseAddrPort("[2001:db8::1]:2000") || len(first.allowedIPs) != 0 {
		t.Errorf("first peer = %+v, want the peer with the smaller key", first)
	}
	if second.publicKey[0] != 0x20 || second.keepalive != 25 || second.handshakeSec != 12 || second.handshakeNsec != 34 ||
		second.txBytes != 5 || second.rxBytes != 6 || len(second.allowedIPs) != 2 {
		t.Errorf("second peer = %+v", second)
	}
}

func TestParseIpcGetRejectsMalformedText(t *testing.T) {
	for _, text := range []string{"listen_port", "listen_port=70000\n", "private_key=zz\n", "public_key=00\n"} {
		if _, err := parseIpcGet(text); err == nil {
			t.Errorf("parseIpcGet(%q) succeeded, want an error", text)
		}
	}
}
