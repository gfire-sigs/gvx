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
	"crypto/ecdh"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/genetlink"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
)

// errNoDeviceSelector is EBADR, the answer of Linux to a request that names
// no device.
var errNoDeviceSelector = syserr.FromError(linuxerr.EBADR)

// lookupDevice finds the wireguard link that the request names with
// WGDEVICE_A_IFINDEX or WGDEVICE_A_IFNAME in the network namespace of the
// socket. The index wins when both are present. From
// drivers/net/wireguard/netlink.c:lookup_interface.
func lookupDevice(req *genetlink.Request, attrs map[uint16]nlmsg.BytesView) (*linkEndpoint, tcpip.NICID, string, *syserr.Error) {
	st, ok := req.Socket.NetworkNamespace().Stack().(*netstack.Stack)
	if !ok {
		return nil, 0, "", syserr.ErrNoDevice
	}
	var (
		id   tcpip.NICID
		name string
	)
	if v, ok := attrs[deviceAttrIfindex]; ok {
		idx, ok := v.Uint32()
		if !ok {
			return nil, 0, "", syserr.ErrInvalidArgument
		}
		info, ok := st.Stack.SingleNICInfo(tcpip.NICID(idx))
		if !ok {
			return nil, 0, "", syserr.ErrNoDevice
		}
		id, name = tcpip.NICID(idx), info.Name
	} else if v, ok := attrs[deviceAttrIfname]; ok {
		want := v.String()
		for nid, info := range st.Stack.NICInfo() {
			if info.Name == want {
				id, name = nid, info.Name
				break
			}
		}
		if name == "" {
			return nil, 0, "", syserr.ErrNoDevice
		}
	} else {
		return nil, 0, "", errNoDeviceSelector
	}
	ep, ok := st.Stack.GetLinkEndpointByName(name).(*linkEndpoint)
	if !ok {
		return nil, 0, "", syserr.ErrNotSupported
	}
	return ep, id, name, nil
}

// setDevice answers WG_CMD_SET_DEVICE. It validates the whole request, then
// hands it to wireguard-go as one configuration text.
func setDevice(_ context.Context, req *genetlink.Request, _ *genetlink.Reply) *syserr.Error {
	attrs, ok := req.ParseAttrs()
	if !ok {
		return syserr.ErrInvalidArgument
	}
	ep, _, _, err := lookupDevice(req, attrs)
	if err != nil {
		return err
	}
	conf, err := parseSetDevice(attrs)
	if err != nil {
		return err
	}
	if conf == "" {
		return nil
	}
	if ipcErr := ep.dev.IpcSet(conf); ipcErr != nil {
		return bindSyserr(ipcErr)
	}
	return nil
}

// getDevice answers WG_CMD_GET_DEVICE with NLM_F_DUMP. The first message holds
// the device attributes and the peers that fit. Later messages hold the
// remaining peers, and they repeat the public key of a peer that continues.
func getDevice(_ context.Context, req *genetlink.Request, dump *genetlink.Dump) *syserr.Error {
	attrs, ok := req.ParseAttrs()
	if !ok {
		return syserr.ErrInvalidArgument
	}
	ep, id, name, err := lookupDevice(req, attrs)
	if err != nil {
		return err
	}
	text, ipcErr := ep.dev.IpcGet()
	if ipcErr != nil {
		return syserr.ErrIO
	}
	info, parseErr := parseIpcGet(text)
	if parseErr != nil {
		return syserr.ErrIO
	}

	d := &deviceDumper{dump: dump, ifindex: uint32(id), name: name, limit: dump.MessageLimit()}
	if err := d.begin(info); err != nil {
		return err
	}
	for i := range info.peers {
		if err := d.peer(&info.peers[i]); err != nil {
			return err
		}
	}
	d.end()
	return nil
}

// deviceDumper packs peers into dump messages that stay below a size limit.
type deviceDumper struct {
	dump    *genetlink.Dump
	ifindex uint32
	name    string
	limit   int

	// m is the message under construction. prefix is its size before the
	// list of peers, and peers is the content of that list.
	m      *nlmsg.Message
	prefix int
	peers  nlmsg.NestedAttr
}

// begin starts a message. A message with info also carries the attributes
// of the device.
func (d *deviceDumper) begin(info *deviceInfo) *syserr.Error {
	m, err := d.dump.Message(cmdGetDevice)
	if err != nil {
		return err
	}
	m.PutAttr(deviceAttrIfindex, primitive.AllocateUint32(d.ifindex))
	m.PutAttrString(deviceAttrIfname, d.name)
	if info != nil {
		putDeviceAttrs(m, info)
	}
	d.m, d.prefix, d.peers = m, len(m.Buffer()), nil
	return nil
}

// putDeviceAttrs adds the keys, the port, and the mark. Linux reports the
// keys only when the device has a private key.
func putDeviceAttrs(m *nlmsg.Message, info *deviceInfo) {
	if info.privateKey != [keyLen]byte{} {
		priv := primitive.ByteSlice(info.privateKey[:])
		m.PutAttr(deviceAttrPrivateKey, &priv)
		if key, err := ecdh.X25519().NewPrivateKey(info.privateKey[:]); err == nil {
			pub := primitive.ByteSlice(key.PublicKey().Bytes())
			m.PutAttr(deviceAttrPublicKey, &pub)
		}
	}
	m.PutAttr(deviceAttrListenPort, primitive.AllocateUint16(info.listenPort))
	m.PutAttr(deviceAttrFwmark, primitive.AllocateUint32(info.fwmark))
}

// end closes the message under construction.
func (d *deviceDumper) end() {
	if len(d.peers) > 0 {
		d.m.PutNestedAttr(deviceAttrPeers|linux.NLA_F_NESTED, d.peers)
	}
}

// room returns the bytes that the list of peers can still take.
func (d *deviceDumper) room() int {
	return d.limit - d.prefix - linux.NetlinkAttrHeaderSize - len(d.peers)
}

// rollover closes the current message and starts one without device
// attributes.
func (d *deviceDumper) rollover() *syserr.Error {
	d.end()
	return d.begin(nil)
}

// peer adds one peer. It splits a peer with many allowed IP addresses
// across messages.
func (d *deviceDumper) peer(p *peerInfo) *syserr.Error {
	head := encodePeer(p)
	if pieceSize(head, 0, 0) > d.room() && len(d.peers) > 0 {
		if err := d.rollover(); err != nil {
			return err
		}
	}
	var ips nlmsg.NestedAttr
	for _, prefix := range p.allowedIPs {
		enc := encodeAllowedIP(prefix)
		for pieceSize(head, len(ips), len(enc)) > d.room() {
			if len(d.peers) == 0 && len(ips) == 0 {
				// The entry cannot fit anywhere else.
				break
			}
			if len(ips) > 0 {
				d.addPiece(head, ips)
				head, ips = encodeKeyOnlyPeer(p), nil
			}
			if err := d.rollover(); err != nil {
				return err
			}
		}
		ips = append(ips, enc...)
	}
	d.addPiece(head, ips)
	return nil
}

// pieceSize returns the size of one entry of the peer list that holds head
// and ipsLen plus extra bytes of allowed IP addresses.
func pieceSize(head nlmsg.NestedAttr, ipsLen, extra int) int {
	n := len(head)
	if ipsLen+extra > 0 {
		n += linux.NetlinkAttrHeaderSize + ipsLen + extra
	}
	return linux.NetlinkAttrHeaderSize + n
}

// addPiece appends one entry to the list of peers.
func (d *deviceDumper) addPiece(head, ips nlmsg.NestedAttr) {
	if len(ips) > 0 {
		head.PutAttr(peerAttrAllowedIPs|linux.NLA_F_NESTED, primitive.AsByteSlice(ips))
	}
	d.peers.PutAttr(0|linux.NLA_F_NESTED, primitive.AsByteSlice(head))
}
