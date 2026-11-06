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
	"strconv"
	"strings"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/marshal/primitive"
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

// parseIpcGet parses the text of Device.IpcGet. The peers come in the order of
// a map of wireguard-go, so the caller orders them.
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

// endpointText returns the endpoint of a struct sockaddr_in or a struct
// sockaddr_in6, in the form that wireguard-go reads. It reports false for any
// other value. set_peer ignores such an endpoint without an error: it accepts
// an address only when its length matches its family.
func endpointText(v nlmsg.BytesView) (string, bool) {
	if len(v) < 2 {
		return "", false
	}
	family := hostarch.ByteOrder.Uint16(v)
	switch {
	case family == linux.AF_INET && len(v) == sockaddrInSize:
		port := binary.BigEndian.Uint16(v[2:])
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(v[4:8])), port).String(), true
	case family == linux.AF_INET6 && len(v) == sockaddrIn6Size:
		port := binary.BigEndian.Uint16(v[2:])
		return netip.AddrPortFrom(netip.AddrFrom16([16]byte(v[8:24])), port).String(), true
	}
	return "", false
}

// decodeAllowedIP decodes the attributes of one allowed IP address, as
// set_allowedip does. Every violation is EINVAL.
func decodeAllowedIP(attrs map[uint16]nlmsg.BytesView) (netip.Prefix, bool, *syserr.Error) {
	fam, haveFamily := attrs[allowedIPAttrFamily]
	addr, haveAddr := attrs[allowedIPAttrIPAddr]
	cidrAttr, haveCIDR := attrs[allowedIPAttrCIDR]
	if !haveFamily || !haveAddr || !haveCIDR {
		return netip.Prefix{}, false, syserr.ErrInvalidArgument
	}
	family, _ := fam.Uint16()
	cidr, _ := cidrAttr.Uint8()
	var ip netip.Addr
	switch {
	case family == linux.AF_INET && cidr <= 32 && len(addr) == 4:
		ip = netip.AddrFrom4([4]byte(addr))
	case family == linux.AF_INET6 && cidr <= 128 && len(addr) == 16:
		ip = netip.AddrFrom16([16]byte(addr))
	default:
		return netip.Prefix{}, false, syserr.ErrInvalidArgument
	}
	var remove bool
	if v, ok := attrs[allowedIPAttrFlags]; ok {
		flags, _ := v.Uint32()
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
	// get_allowedips puts the mask, the family, and the address, in this order.
	entry.PutAttr(allowedIPAttrCIDR, primitive.AllocateUint8(uint8(prefix.Bits())))
	entry.PutAttr(allowedIPAttrFamily, primitive.AllocateUint16(family))
	ip := primitive.ByteSlice(addr.AsSlice())
	entry.PutAttr(allowedIPAttrIPAddr, &ip)
	var out nlmsg.NestedAttr
	out.PutAttr(0|linux.NLA_F_NESTED, primitive.AsByteSlice(entry))
	return out
}

// encodePeer returns the attributes of a peer without its allowed IP
// addresses, in the order of drivers/net/wireguard/netlink.c:get_peer.
func encodePeer(p *peerInfo) nlmsg.NestedAttr {
	var n nlmsg.NestedAttr
	key := primitive.ByteSlice(p.publicKey[:])
	n.PutAttr(peerAttrPublicKey, &key)
	psk := primitive.ByteSlice(p.presharedKey[:])
	n.PutAttr(peerAttrPresharedKey, &psk)
	var ts [16]byte
	hostarch.ByteOrder.PutUint64(ts[:], uint64(p.handshakeSec))
	hostarch.ByteOrder.PutUint64(ts[8:], uint64(p.handshakeNsec))
	tsAttr := primitive.ByteSlice(ts[:])
	n.PutAttr(peerAttrLastHshake, &tsAttr)
	n.PutAttr(peerAttrKeepalive, primitive.AllocateUint16(p.keepalive))
	n.PutAttr(peerAttrTxBytes, primitive.AllocateUint64(p.txBytes))
	n.PutAttr(peerAttrRxBytes, primitive.AllocateUint64(p.rxBytes))
	n.PutAttr(peerAttrProtoVersion, primitive.AllocateUint32(1))
	if p.endpoint.IsValid() {
		ep := primitive.ByteSlice(encodeEndpoint(p.endpoint))
		n.PutAttr(peerAttrEndpoint, &ep)
	}
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
