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
	"fmt"
	"strings"

	"golang.zx2c4.com/wireguard/device"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
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
// socket. A request with both attributes or with neither fails with EBADR. From
// drivers/net/wireguard/netlink.c:lookup_interface.
func lookupDevice(req *genetlink.Request, attrs map[uint16]nlmsg.BytesView) (*linkEndpoint, tcpip.NICID, string, *syserr.Error) {
	st, ok := req.Socket.NetworkNamespace().Stack().(*netstack.Stack)
	if !ok {
		return nil, 0, "", syserr.ErrNoDevice
	}
	idxAttr, haveIdx := attrs[deviceAttrIfindex]
	nameAttr, haveName := attrs[deviceAttrIfname]
	if haveIdx == haveName {
		return nil, 0, "", errNoDeviceSelector
	}
	var (
		id   tcpip.NICID
		name string
	)
	if haveIdx {
		idx, _ := idxAttr.Uint32()
		info, ok := st.Stack.SingleNICInfo(tcpip.NICID(idx))
		if !ok {
			return nil, 0, "", syserr.ErrNoDevice
		}
		id, name = tcpip.NICID(idx), info.Name
	} else {
		want := nameAttr.String()
		for nid, info := range st.Stack.NICInfo() {
			if info.Name == want {
				id, name = nid, info.Name
				break
			}
		}
		if name == "" {
			return nil, 0, "", syserr.ErrNoDevice
		}
	}
	ep, ok := st.Stack.GetLinkEndpointByName(name).(*linkEndpoint)
	if !ok {
		return nil, 0, "", syserr.ErrNotSupported
	}
	return ep, id, name, nil
}

// setDevice answers WG_CMD_SET_DEVICE. The attributes pass the policy of the
// command first. The request then runs in the order of Linux, and a failure in
// the middle keeps the changes before it, as in Linux.
//
// A request that sets the listen port or the mark needs CAP_NET_ADMIN in the
// user namespace of the namespace that created the link, because the socket of
// the link belongs to that namespace.
func setDevice(ctx context.Context, req *genetlink.Request, _ *genetlink.Reply) *syserr.Error {
	attrs, err := parseWithPolicy(req.Attrs, setDevicePolicy)
	if err != nil {
		return err
	}
	ep, _, _, err := lookupDevice(req, attrs)
	if err != nil {
		return err
	}
	canSetSocket := ep.userNS == nil || auth.CredentialsFromContext(ctx).HasCapabilityIn(linux.CAP_NET_ADMIN, ep.userNS)
	return ep.applySet(attrs, canSetSocket)
}

// applySet runs a validated WG_CMD_SET_DEVICE request, as
// drivers/net/wireguard/netlink.c:wg_set_device_doit does: the mark, the port,
// the removal of every peer, the private key, and then the peers.
func (e *linkEndpoint) applySet(attrs map[uint16]nlmsg.BytesView, canSetSocket bool) *syserr.Error {
	e.updateMu.Lock()
	defer e.updateMu.Unlock()
	if e.closed {
		return syserr.ErrNoDevice
	}
	var flags uint32
	if v, ok := attrs[deviceAttrFlags]; ok {
		flags, _ = v.Uint32()
	}
	markAttr, haveMark := attrs[deviceAttrFwmark]
	portAttr, havePort := attrs[deviceAttrListenPort]
	if (haveMark || havePort) && !canSetSocket {
		return syserr.ErrNotPermitted
	}
	if haveMark {
		mark, _ := markAttr.Uint32()
		e.fwmark = mark
		e.bind.setMark(mark)
	}
	if havePort {
		port, _ := portAttr.Uint16()
		if err := e.setPort(port); err != nil {
			return err
		}
	}
	if flags&deviceFlagReplacePeers != 0 {
		e.dev.RemoveAllPeers()
		e.peers.clear()
		e.resizeCharge()
	}
	if v, ok := attrs[deviceAttrPrivateKey]; ok {
		if err := e.setPrivateKey(v); err != nil {
			return err
		}
	}
	if v, ok := attrs[deviceAttrPeers]; ok {
		return e.setPeers(nlmsg.AttrsView(v))
	}
	return nil
}

// setPort changes the listen port. A port that the device already has needs no
// change. A device that is down only stores the port. A device that is up binds
// the new sockets first, so a busy port fails and leaves the old sockets in
// place. From netlink.c:set_port.
//
// Preconditions: e.updateMu is held.
func (e *linkEndpoint) setPort(port uint16) *syserr.Error {
	if e.bind.incomingPort() == port {
		return nil
	}
	if !e.up {
		e.bind.setIncoming(port)
		return nil
	}
	if err := e.bind.prepare(port); err != nil {
		return bindSyserr(err)
	}
	if err := e.dev.BindUpdate(); err != nil {
		return bindSyserr(err)
	}
	return nil
}

// setPrivateKey sets the private key. A key of zeros removes the identity, as
// curve25519_generate_public of Linux reports for it. A peer with the public
// key of the new identity leaves the device.
//
// Preconditions: e.updateMu is held.
func (e *linkEndpoint) setPrivateKey(v nlmsg.BytesView) *syserr.Error {
	var priv [keyLen]byte
	copy(priv[:], v)
	if err := e.dev.IpcSet(fmt.Sprintf("private_key=%x\n", priv)); err != nil {
		return bindSyserr(err)
	}
	e.hasKey = priv != [keyLen]byte{}
	e.public = [keyLen]byte{}
	if e.hasKey {
		key, err := ecdh.X25519().NewPrivateKey(priv[:])
		if err != nil {
			return syserr.ErrInvalidArgument
		}
		copy(e.public[:], key.PublicKey().Bytes())
		e.syncPeer(e.public)
		e.resizeCharge()
	}
	return nil
}

// syncPeer makes the peer list agree with the device after a change of the
// peer with the key.
//
// Preconditions: e.updateMu is held.
func (e *linkEndpoint) syncPeer(key [keyLen]byte) {
	if e.dev.LookupPeer(device.NoisePublicKey(key)) != nil {
		e.peers.add(key)
	} else {
		e.peers.remove(key)
	}
}

// setPeers runs the peer entries of the request, one after the other.
//
// Preconditions: e.updateMu is held.
func (e *linkEndpoint) setPeers(list nlmsg.AttrsView) *syserr.Error {
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
		if err := e.setPeer(attrs); err != nil {
			return err
		}
	}
	return nil
}

// setPeer runs one peer entry, in the order of netlink.c:set_peer. It writes
// the lines for wireguard-go while it validates, and it applies the lines that
// it wrote before an error, as Linux keeps the changes before a failure.
//
// Preconditions: e.updateMu is held.
func (e *linkEndpoint) setPeer(attrs map[uint16]nlmsg.BytesView) *syserr.Error {
	keyAttr, ok := attrs[peerAttrPublicKey]
	if !ok || len(keyAttr) != keyLen {
		return syserr.ErrInvalidArgument
	}
	var key [keyLen]byte
	copy(key[:], keyAttr)
	var flags uint32
	if v, ok := attrs[peerAttrFlags]; ok {
		flags, _ = v.Uint32()
	}
	if v, ok := attrs[peerAttrProtoVersion]; ok {
		if version, _ := v.Uint32(); version != 1 {
			return errProtocolVersion
		}
	}
	exists := e.peers.has(key)
	if !exists {
		if flags&(peerFlagRemoveMe|peerFlagUpdateOnly) != 0 {
			return nil
		}
		// A new peer has no allowed IP addresses to replace.
		flags &^= peerFlagReplaceAllowedIP
		if e.hasKey && key == e.public {
			// Linux ignores a peer with the public key of the device without
			// an error, so a caller can send one list of peers to every device.
			return nil
		}
		if e.peers.len() >= peerLimit {
			return syserr.ErrNoMemory
		}
		if err := chargeMemory(e.acct, peerMemory); err != nil {
			return err
		}
		e.charged += peerMemory
	}
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%x\n", key)
	result := e.buildPeer(&b, attrs, flags)
	if err := e.dev.IpcSet(b.String()); err != nil && result == nil {
		result = bindSyserr(err)
	}
	e.syncPeer(key)
	e.resizeCharge()
	return result
}

// buildPeer appends the lines for the attributes of a peer that exists. It
// returns the first error and keeps the lines that come before it.
func (e *linkEndpoint) buildPeer(b *strings.Builder, attrs map[uint16]nlmsg.BytesView, flags uint32) *syserr.Error {
	if flags&peerFlagRemoveMe != 0 {
		b.WriteString("remove=true\n")
		return nil
	}
	if v, ok := attrs[peerAttrPresharedKey]; ok {
		fmt.Fprintf(b, "preshared_key=%x\n", []byte(v))
	}
	if v, ok := attrs[peerAttrEndpoint]; ok {
		if ep, ok := endpointText(v); ok {
			fmt.Fprintf(b, "endpoint=%s\n", ep)
		}
	}
	if flags&peerFlagReplaceAllowedIP != 0 {
		b.WriteString("replace_allowed_ips=true\n")
	}
	if v, ok := attrs[peerAttrAllowedIPs]; ok {
		if err := appendAllowedIPs(b, nlmsg.AttrsView(v)); err != nil {
			return err
		}
	}
	if v, ok := attrs[peerAttrKeepalive]; ok {
		secs, _ := v.Uint16()
		fmt.Fprintf(b, "persistent_keepalive_interval=%d\n", secs)
	}
	return nil
}

// appendAllowedIPs appends one "allowed_ip" line for each entry of the list. It
// stops at the first invalid entry and keeps the lines before it.
func appendAllowedIPs(b *strings.Builder, list nlmsg.AttrsView) *syserr.Error {
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
