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
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/genetlink"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/syserr"
)

// Sizes of struct sockaddr_in and struct sockaddr_in6.
const (
	sockaddrInSize  = 16
	sockaddrIn6Size = 28
)

// peerInfo is the state of one peer as wireguard-go reports it.
type peerInfo struct {
	publicKey     [keyLen]byte
	presharedKey  [keyLen]byte
	endpoint      netip.AddrPort
	keepalive     uint16
	handshakeSec  int64
	handshakeNsec int64
	rxBytes       uint64
	txBytes       uint64
	allowedIPs    []netip.Prefix
}

// deviceInfo is the state of one device as wireguard-go reports it.
type deviceInfo struct {
	privateKey [keyLen]byte
	listenPort uint16
	fwmark     uint32
	peers      []peerInfo
}

// parseIpcGet parses the text of Device.IpcGet. It sorts the peers by public
// key, because wireguard-go keeps them in a map.
func parseIpcGet(text string) (*deviceInfo, error) {
	d := &deviceInfo{}
	var p *peerInfo
	for line := range strings.SplitSeq(text, "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("wireguard: malformed configuration line %q", line)
		}
		var err error
		switch key {
		case "private_key":
			err = decodeKey(&d.privateKey, value)
		case "listen_port":
			var v uint64
			v, err = strconv.ParseUint(value, 10, 16)
			d.listenPort = uint16(v)
		case "fwmark":
			var v uint64
			v, err = strconv.ParseUint(value, 10, 32)
			d.fwmark = uint32(v)
		case "public_key":
			d.peers = append(d.peers, peerInfo{})
			p = &d.peers[len(d.peers)-1]
			err = decodeKey(&p.publicKey, value)
		default:
			if p == nil {
				continue
			}
			err = p.set(key, value)
		}
		if err != nil {
			return nil, fmt.Errorf("wireguard: configuration line %q: %w", line, err)
		}
	}
	sort.Slice(d.peers, func(i, j int) bool { return string(d.peers[i].publicKey[:]) < string(d.peers[j].publicKey[:]) })
	return d, nil
}

// set stores one peer line of the configuration text. It ignores keys that
// the netlink interface does not report.
func (p *peerInfo) set(key, value string) error {
	var err error
	switch key {
	case "preshared_key":
		return decodeKey(&p.presharedKey, value)
	case "endpoint":
		p.endpoint, err = netip.ParseAddrPort(value)
		p.endpoint = netip.AddrPortFrom(p.endpoint.Addr().Unmap(), p.endpoint.Port())
	case "persistent_keepalive_interval":
		var v uint64
		v, err = strconv.ParseUint(value, 10, 16)
		p.keepalive = uint16(v)
	case "last_handshake_time_sec":
		p.handshakeSec, err = strconv.ParseInt(value, 10, 64)
	case "last_handshake_time_nsec":
		p.handshakeNsec, err = strconv.ParseInt(value, 10, 64)
	case "rx_bytes":
		p.rxBytes, err = strconv.ParseUint(value, 10, 64)
	case "tx_bytes":
		p.txBytes, err = strconv.ParseUint(value, 10, 64)
	case "allowed_ip":
		var prefix netip.Prefix
		prefix, err = netip.ParsePrefix(value)
		if err == nil {
			p.allowedIPs = append(p.allowedIPs, prefix)
		}
	}
	return err
}

// decodeKey decodes a hexadecimal key of 32 bytes.
func decodeKey(dst *[keyLen]byte, value string) error {
	b, err := hex.DecodeString(value)
	if err != nil {
		return err
	}
	if len(b) != keyLen {
		return fmt.Errorf("key has %d bytes, want %d", len(b), keyLen)
	}
	copy(dst[:], b)
	return nil
}

// errProtocolVersion is EPFNOSUPPORT, the answer of Linux to a peer with a
// protocol version other than 1.
var errProtocolVersion = syserr.FromError(linuxerr.EPFNOSUPPORT)

// peerOp is one peer entry of a set request.
type peerOp struct {
	key        [keyLen]byte
	remove     bool
	updateOnly bool
}

// setPlan is a validated WG_CMD_SET_DEVICE request.
type setPlan struct {
	// conf is the configuration text for wireguard-go.
	conf string

	// changesSocket is true when the request sets the listen port or the
	// mark. Linux then checks CAP_NET_ADMIN in the creating namespace.
	changesSocket bool

	// probePort is the port that the device must be able to bind, or 0 when
	// the request keeps the current port or asks for a free one.
	probePort uint16

	// peers is the count of peers after the request.
	peers int
}

// parseSetDevice validates the attributes of WG_CMD_SET_DEVICE against the
// current state and returns the plan. It validates the whole request before
// the caller applies any part of it. The errors follow
// drivers/net/wireguard/netlink.c:wg_set_device, and so does the order of the
// lines: the mark, the port, the removal of every peer, the private key, and
// the peers.
func parseSetDevice(attrs map[uint16]nlmsg.BytesView, cur *deviceInfo) (*setPlan, *syserr.Error) {
	var b strings.Builder
	plan := &setPlan{}
	var replacePeers bool
	if v, ok := attrs[deviceAttrFlags]; ok {
		flags, ok := v.Uint32()
		if !ok {
			return nil, syserr.ErrInvalidArgument
		}
		if flags&^deviceFlagReplacePeers != 0 {
			return nil, syserr.ErrNotSupported
		}
		replacePeers = flags&deviceFlagReplacePeers != 0
	}
	if v, ok := attrs[deviceAttrFwmark]; ok {
		mark, ok := v.Uint32()
		if !ok {
			return nil, syserr.ErrInvalidArgument
		}
		fmt.Fprintf(&b, "fwmark=%d\n", mark)
		plan.changesSocket = true
	}
	if v, ok := attrs[deviceAttrListenPort]; ok {
		port, ok := v.Uint16()
		if !ok {
			return nil, syserr.ErrInvalidArgument
		}
		plan.changesSocket = true
		// The same port needs no rebind. Port 0 asks for a new free port.
		if port == 0 || port != cur.listenPort {
			fmt.Fprintf(&b, "listen_port=%d\n", port)
			plan.probePort = port
		}
	}
	if replacePeers {
		b.WriteString("replace_peers=true\n")
	}
	if v, ok := attrs[deviceAttrPrivateKey]; ok {
		if len(v) != keyLen {
			return nil, syserr.ErrInvalidArgument
		}
		fmt.Fprintf(&b, "private_key=%x\n", []byte(v))
	}
	var ops []peerOp
	if v, ok := attrs[deviceAttrPeers]; ok {
		var err *syserr.Error
		if ops, err = parsePeers(&b, nlmsg.AttrsView(v)); err != nil {
			return nil, err
		}
	}
	plan.conf = b.String()
	plan.peers = countPeers(cur, replacePeers, ops)
	return plan, nil
}

// countPeers returns the count of peers after the request.
func countPeers(cur *deviceInfo, replacePeers bool, ops []peerOp) int {
	set := make(map[[keyLen]byte]struct{})
	if !replacePeers {
		for i := range cur.peers {
			set[cur.peers[i].publicKey] = struct{}{}
		}
	}
	for _, op := range ops {
		_, exists := set[op.key]
		switch {
		case op.remove:
			delete(set, op.key)
		case op.updateOnly && !exists:
		default:
			set[op.key] = struct{}{}
		}
	}
	return len(set)
}

// parsePeers appends the configuration text of each peer in the nested list
// and returns the peer entries.
func parsePeers(b *strings.Builder, list nlmsg.AttrsView) ([]peerOp, *syserr.Error) {
	var ops []peerOp
	for !list.Empty() {
		_, value, rest, ok := list.ParseFirst()
		if !ok {
			return nil, syserr.ErrInvalidArgument
		}
		list = rest
		attrs, ok := genetlink.ParseAttrs(nlmsg.AttrsView(value))
		if !ok {
			return nil, syserr.ErrInvalidArgument
		}
		op, err := parsePeer(b, attrs)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	return ops, nil
}

// parsePeer appends the configuration text of one peer. wireguard-go needs
// "update_only" right after the key and "replace_allowed_ips" before the
// first allowed IP address.
func parsePeer(b *strings.Builder, attrs map[uint16]nlmsg.BytesView) (peerOp, *syserr.Error) {
	var op peerOp
	key, ok := attrs[peerAttrPublicKey]
	if !ok || len(key) != keyLen {
		return op, syserr.ErrInvalidArgument
	}
	copy(op.key[:], key)
	var flags uint32
	if v, ok := attrs[peerAttrFlags]; ok {
		if flags, ok = v.Uint32(); !ok {
			return op, syserr.ErrInvalidArgument
		}
		if flags&^(peerFlagRemoveMe|peerFlagReplaceAllowedIP|peerFlagUpdateOnly) != 0 {
			return op, syserr.ErrNotSupported
		}
	}
	fmt.Fprintf(b, "public_key=%x\n", []byte(key))
	if flags&peerFlagRemoveMe != 0 {
		// Linux skips the other attributes of a peer that it removes.
		b.WriteString("remove=true\n")
		op.remove = true
		return op, nil
	}
	if flags&peerFlagUpdateOnly != 0 {
		b.WriteString("update_only=true\n")
		op.updateOnly = true
	}
	if v, ok := attrs[peerAttrPresharedKey]; ok {
		if len(v) != keyLen {
			return op, syserr.ErrInvalidArgument
		}
		fmt.Fprintf(b, "preshared_key=%x\n", []byte(v))
	}
	if v, ok := attrs[peerAttrEndpoint]; ok {
		ep, err := decodeEndpoint(v)
		if err != nil {
			return op, err
		}
		fmt.Fprintf(b, "endpoint=%s\n", ep)
	}
	if v, ok := attrs[peerAttrKeepalive]; ok {
		secs, ok := v.Uint16()
		if !ok {
			return op, syserr.ErrInvalidArgument
		}
		fmt.Fprintf(b, "persistent_keepalive_interval=%d\n", secs)
	}
	if v, ok := attrs[peerAttrProtoVersion]; ok {
		version, ok := v.Uint32()
		if !ok {
			return op, syserr.ErrInvalidArgument
		}
		if version != 1 {
			return op, errProtocolVersion
		}
	}
	if flags&peerFlagReplaceAllowedIP != 0 {
		b.WriteString("replace_allowed_ips=true\n")
	}
	if v, ok := attrs[peerAttrAllowedIPs]; ok {
		return op, parseAllowedIPs(b, nlmsg.AttrsView(v))
	}
	return op, nil
}

// decodeEndpoint decodes a struct sockaddr_in or struct sockaddr_in6.
func decodeEndpoint(v nlmsg.BytesView) (netip.AddrPort, *syserr.Error) {
	if len(v) < 2 {
		return netip.AddrPort{}, syserr.ErrInvalidArgument
	}
	family := hostarch.ByteOrder.Uint16(v)
	switch {
	case family == linux.AF_INET && len(v) == sockaddrInSize:
		port := binary.BigEndian.Uint16(v[2:])
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(v[4:8])), port), nil
	case family == linux.AF_INET6 && len(v) == sockaddrIn6Size:
		port := binary.BigEndian.Uint16(v[2:])
		return netip.AddrPortFrom(netip.AddrFrom16([16]byte(v[8:24])), port), nil
	}
	return netip.AddrPort{}, syserr.ErrInvalidArgument
}

// parseAllowedIPs appends one "allowed_ip" line for each entry of the list.
func parseAllowedIPs(b *strings.Builder, list nlmsg.AttrsView) *syserr.Error {
	for !list.Empty() {
		_, value, rest, ok := list.ParseFirst()
		if !ok {
			return syserr.ErrInvalidArgument
		}
		list = rest
		attrs, ok := genetlink.ParseAttrs(nlmsg.AttrsView(value))
		if !ok {
			return syserr.ErrInvalidArgument
		}
		prefix, remove, err := decodeAllowedIP(attrs)
		if err != nil {
			return err
		}
		if remove {
			fmt.Fprintf(b, "allowed_ip=-%s\n", prefix)
		} else {
			fmt.Fprintf(b, "allowed_ip=%s\n", prefix)
		}
	}
	return nil
}

// decodeAllowedIP decodes the attributes of one allowed IP address.
func decodeAllowedIP(attrs map[uint16]nlmsg.BytesView) (netip.Prefix, bool, *syserr.Error) {
	fam, ok := attrs[allowedIPAttrFamily]
	if !ok {
		return netip.Prefix{}, false, syserr.ErrInvalidArgument
	}
	family, ok := fam.Uint16()
	addr, haveAddr := attrs[allowedIPAttrIPAddr]
	cidrAttr, haveCIDR := attrs[allowedIPAttrCIDR]
	cidr, okCIDR := cidrAttr.Uint8()
	if !ok || !haveAddr || !haveCIDR || !okCIDR {
		return netip.Prefix{}, false, syserr.ErrInvalidArgument
	}
	var ip netip.Addr
	switch {
	case family == linux.AF_INET && len(addr) == 4 && cidr <= 32:
		ip = netip.AddrFrom4([4]byte(addr))
	case family == linux.AF_INET6 && len(addr) == 16 && cidr <= 128:
		ip = netip.AddrFrom16([16]byte(addr))
	default:
		return netip.Prefix{}, false, syserr.ErrInvalidArgument
	}
	var remove bool
	if v, ok := attrs[allowedIPAttrFlags]; ok {
		flags, ok := v.Uint32()
		if !ok || flags&^allowedIPFlagRemoveMe != 0 {
			return netip.Prefix{}, false, syserr.ErrInvalidArgument
		}
		remove = flags&allowedIPFlagRemoveMe != 0
	}
	return netip.PrefixFrom(ip, int(cidr)), remove, nil
}

// encodeEndpoint encodes ap as a struct sockaddr_in or struct sockaddr_in6.
func encodeEndpoint(ap netip.AddrPort) []byte {
	if ap.Addr().Is4() {
		b := make([]byte, sockaddrInSize)
		hostarch.ByteOrder.PutUint16(b, linux.AF_INET)
		binary.BigEndian.PutUint16(b[2:], ap.Port())
		a := ap.Addr().As4()
		copy(b[4:], a[:])
		return b
	}
	b := make([]byte, sockaddrIn6Size)
	hostarch.ByteOrder.PutUint16(b, linux.AF_INET6)
	binary.BigEndian.PutUint16(b[2:], ap.Port())
	a := ap.Addr().As16()
	copy(b[8:], a[:])
	return b
}

// encodeAllowedIP returns the nested attribute of one allowed IP address.
func encodeAllowedIP(prefix netip.Prefix) []byte {
	var entry nlmsg.NestedAttr
	addr := prefix.Addr()
	family := uint16(linux.AF_INET)
	if addr.Is6() {
		family = linux.AF_INET6
	}
	entry.PutAttr(allowedIPAttrFamily, primitive.AllocateUint16(family))
	ip := primitive.ByteSlice(addr.AsSlice())
	entry.PutAttr(allowedIPAttrIPAddr, &ip)
	entry.PutAttr(allowedIPAttrCIDR, primitive.AllocateUint8(uint8(prefix.Bits())))
	var out nlmsg.NestedAttr
	out.PutAttr(0|linux.NLA_F_NESTED, primitive.AsByteSlice(entry))
	return out
}

// encodePeer returns the attributes of a peer without its allowed IP
// addresses, as drivers/net/wireguard/netlink.c:get_peer.
func encodePeer(p *peerInfo) nlmsg.NestedAttr {
	var n nlmsg.NestedAttr
	key := primitive.ByteSlice(p.publicKey[:])
	n.PutAttr(peerAttrPublicKey, &key)
	psk := primitive.ByteSlice(p.presharedKey[:])
	n.PutAttr(peerAttrPresharedKey, &psk)
	if p.endpoint.IsValid() {
		ep := primitive.ByteSlice(encodeEndpoint(p.endpoint))
		n.PutAttr(peerAttrEndpoint, &ep)
	}
	n.PutAttr(peerAttrKeepalive, primitive.AllocateUint16(p.keepalive))
	var ts [16]byte
	hostarch.ByteOrder.PutUint64(ts[:], uint64(p.handshakeSec))
	hostarch.ByteOrder.PutUint64(ts[8:], uint64(p.handshakeNsec))
	tsAttr := primitive.ByteSlice(ts[:])
	n.PutAttr(peerAttrLastHshake, &tsAttr)
	n.PutAttr(peerAttrRxBytes, primitive.AllocateUint64(p.rxBytes))
	n.PutAttr(peerAttrTxBytes, primitive.AllocateUint64(p.txBytes))
	n.PutAttr(peerAttrProtoVersion, primitive.AllocateUint32(1))
	return n
}

// encodeKeyOnlyPeer returns the attributes of a peer that continues in a
// later message. It holds only the public key.
func encodeKeyOnlyPeer(p *peerInfo) nlmsg.NestedAttr {
	var n nlmsg.NestedAttr
	key := primitive.ByteSlice(p.publicKey[:])
	n.PutAttr(peerAttrPublicKey, &key)
	return n
}
