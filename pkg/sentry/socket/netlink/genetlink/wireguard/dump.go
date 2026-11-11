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
	"z.gfire.dev/gvx/pkg/abi/linux"
	gvxcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/genetlink"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/syserr"
)

// getDevice starts the answer to WG_CMD_GET_DEVICE with NLM_F_DUMP. The dump
// reads the state of the device one time, when it starts, and then sends one
// message for each chunk. A device with any count of peers therefore needs no
// more room in the receive queue of the socket than one message.
func getDevice(_ gvxcontext.Context, req *genetlink.Request) (genetlink.Dumper, *syserr.Error) {
	attrs, err := parseWithPolicy(req.Attrs, getDevicePolicy)
	if err != nil {
		return nil, err
	}
	ep, id, name, err := lookupDevice(req, attrs)
	if err != nil {
		return nil, err
	}
	d, err := ep.snapshot()
	if err != nil {
		return nil, err
	}
	d.ifindex, d.name = uint32(id), name
	return d, nil
}

// snapshot reads the device under the update lock, so the dump shows one
// consistent state, and Linux has no equivalent for a device that changes
// during a dump: it marks such a dump with NLM_F_DUMP_INTR.
func (e *linkEndpoint) snapshot() (*deviceDump, *syserr.Error) {
	e.updateMu.Lock()
	defer e.updateMu.Unlock()
	if e.closed {
		return nil, syserr.ErrNoDevice
	}
	e.ensureDeviceLocked()
	text, err := e.dev.IpcGet()
	if err != nil {
		return nil, syserr.ErrIO
	}
	info, err := parseIpcGet(text)
	if err != nil {
		return nil, syserr.ErrIO
	}
	e.peers.sortPeers(info.peers)
	info.listenPort = e.bind.incomingPort()
	info.fwmark = e.fwmark
	return &deviceDump{info: info, public: e.public}, nil
}

// deviceDump sends the snapshot of a device, one message for each chunk.
//
// +stateify savable
type deviceDump struct {
	ifindex uint32
	name    string
	info    *deviceInfo
	public  [keyLen]byte

	// peer is the index of the next peer to send. When midPeer is true, the
	// message before already sent a part of the allowed IP addresses of that
	// peer, and ip is the index of the next address.
	peer    int
	midPeer bool
	ip      int
	// started is true after the first message, which holds the device.
	started bool
}

var _ genetlink.Dumper = (*deviceDump)(nil)

// DumpChunk implements genetlink.Dumper.DumpChunk. It writes one message, as
// wg_get_device_dumpit does for each call. The first message holds the
// attributes of the device and as many peers as fit. A later message holds
// the peers that remain. A peer whose allowed IP addresses do not fit in one
// message continues in the next one with its public key only.
func (d *deviceDump) DumpChunk(_ gvxcontext.Context, chunk *genetlink.Chunk) (bool, *syserr.Error) {
	m := chunk.Message(cmdGetDevice)
	if !d.started {
		d.started = true
		putDeviceAttrs(m, d)
	}
	prefix := len(m.Buffer())
	limit := chunk.Limit()
	var peers nlmsg.NestedAttr
	// room reports whether an entry of n bytes still fits in the message.
	room := func(n int) bool {
		return prefix+linux.NetlinkAttrHeaderSize+len(peers)+n <= limit
	}
	for d.peer < len(d.info.peers) {
		p := &d.info.peers[d.peer]
		var head nlmsg.NestedAttr
		if d.midPeer {
			head = encodeKeyOnlyPeer(p)
		} else {
			head = encodePeer(p)
		}
		first := len(peers) == 0
		if !first && !room(pieceSize(head, 0, 0)) {
			break
		}
		var ips nlmsg.NestedAttr
		i := 0
		if d.midPeer {
			i = d.ip
		}
		for ; i < len(p.allowedIPs); i++ {
			enc := encodeAllowedIP(p.allowedIPs[i])
			// A message holds at least one entry, so the dump always advances.
			if !room(pieceSize(head, len(ips), len(enc))) && !(first && len(ips) == 0) {
				break
			}
			ips = append(ips, enc...)
		}
		d.addPiece(&peers, head, ips)
		if i < len(p.allowedIPs) {
			d.midPeer, d.ip = true, i
			break
		}
		d.peer++
		d.midPeer, d.ip = false, 0
	}
	if len(peers) > 0 {
		m.PutNestedAttr(deviceAttrPeers|linux.NLA_F_NESTED, peers)
	}
	return d.peer < len(d.info.peers), nil
}

// DumpDone implements genetlink.Dumper.DumpDone.
func (d *deviceDump) DumpDone() { d.info = nil }

// putDeviceAttrs adds the port, the mark, the interface, and the keys of the
// first message, in the order of wg_get_device_dumpit. Linux reports the keys
// only when the device has a private key.
func putDeviceAttrs(m *nlmsg.Message, d *deviceDump) {
	m.PutAttr(deviceAttrListenPort, primitive.AllocateUint16(d.info.listenPort))
	m.PutAttr(deviceAttrFwmark, primitive.AllocateUint32(d.info.fwmark))
	m.PutAttr(deviceAttrIfindex, primitive.AllocateUint32(d.ifindex))
	m.PutAttrString(deviceAttrIfname, d.name)
	if d.info.privateKey != [keyLen]byte{} {
		priv := primitive.ByteSlice(d.info.privateKey[:])
		m.PutAttr(deviceAttrPrivateKey, &priv)
		pub := primitive.ByteSlice(d.public[:])
		m.PutAttr(deviceAttrPublicKey, &pub)
	}
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
func (d *deviceDump) addPiece(peers *nlmsg.NestedAttr, head, ips nlmsg.NestedAttr) {
	if len(ips) > 0 {
		head.PutAttr(peerAttrAllowedIPs|linux.NLA_F_NESTED, primitive.AsByteSlice(ips))
	}
	peers.PutAttr(0|linux.NLA_F_NESTED, primitive.AsByteSlice(head))
}
