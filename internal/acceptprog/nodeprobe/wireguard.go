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

//go:build linux

package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// The genetlink checks use the family list of libnl. The wireguard checks
// build two network namespaces A and B that a veth pair links, put one
// wireguard link in each namespace, and send ICMP echo requests between the
// links. A raw generic netlink client sets and reads the configuration, so the
// encoding of the guest kernel meets an independent encoder.

// Numbers of include/uapi/linux/wireguard.h.
const (
	wgCmdGetDevice = 0
	wgCmdSetDevice = 1

	wgDeviceReplacePeers = 1 << 0

	wgDevIfindex    = 1
	wgDevIfname     = 2
	wgDevPrivateKey = 3
	wgDevPublicKey  = 4
	wgDevFlags      = 5
	wgDevListenPort = 6
	wgDevFwmark     = 7
	wgDevPeers      = 8

	wgPeerRemoveMe         = 1 << 0
	wgPeerReplaceAllowedIP = 1 << 1
	wgPeerUpdateOnly       = 1 << 2

	wgPeerPublicKey  = 1
	wgPeerPresharedK = 2
	wgPeerFlags      = 3
	wgPeerEndpoint   = 4
	wgPeerKeepalive  = 5
	wgPeerHandshake  = 6
	wgPeerRx         = 7
	wgPeerTx         = 8
	wgPeerAllowedIPs = 9
	wgPeerProtoVer   = 10

	wgIPFamily = 1
	wgIPAddr   = 2
	wgIPCIDR   = 3

	genlCtrlID    = 0x10
	genlOpNetPerm = 0x10
)

// wgPeer is the configuration of one peer in a set request.
type wgPeer struct {
	pub       [32]byte
	psk       *[32]byte
	endpoint  string // "ip:port", or empty to leave the endpoint
	keepalive *uint16
	flags     uint32
	allowed   []string // CIDR strings
	proto     *uint32  // protocol version, or nil for 1
}

// wgConfig is a set request.
type wgConfig struct {
	priv  *[32]byte
	port  *uint16
	mark  *uint32
	flags uint32
	peers []wgPeer
}

// wgPeerState is a peer as a get request returns it.
type wgPeerState struct {
	pub, psk  [32]byte
	endpoint  string
	keepalive uint16
	hsSec     int64
	hsNsec    int64
	rx, tx    uint64
	allowed   []string
}

// wgState is a device as a get request returns it.
type wgState struct {
	ifindex uint32
	ifname  string
	priv    []byte
	pub     []byte
	port    uint16
	mark    uint32
	peers   []*wgPeerState
}

// wgKey returns a key pair. The private key is clamped, as the output of
// "wg genkey" is, because the device returns the clamped form.
func wgKey() (priv, pub [32]byte, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return priv, pub, err
	}
	copy(priv[:], k.Bytes())
	priv[0] &= 248
	priv[31] = priv[31]&127 | 64
	if k, err = ecdh.X25519().NewPrivateKey(priv[:]); err != nil {
		return priv, pub, err
	}
	copy(pub[:], k.PublicKey().Bytes())
	return priv, pub, nil
}

// wgFamily returns the family ID of "wireguard".
func wgFamily() (uint16, error) {
	f, err := netlink.GenlFamilyGet("wireguard")
	if err != nil {
		return 0, err
	}
	return f.ID, nil
}

func nested(typ int) *nl.RtAttr { return nl.NewRtAttr(typ|unix.NLA_F_NESTED, nil) }

func sockaddr(ep string) ([]byte, error) {
	ap, err := netip.ParseAddrPort(ep)
	if err != nil {
		return nil, err
	}
	if ap.Addr().Is4() {
		b := make([]byte, 16)
		binary.LittleEndian.PutUint16(b, unix.AF_INET)
		binary.BigEndian.PutUint16(b[2:], ap.Port())
		a := ap.Addr().As4()
		copy(b[4:], a[:])
		return b, nil
	}
	b := make([]byte, 28)
	binary.LittleEndian.PutUint16(b, unix.AF_INET6)
	binary.BigEndian.PutUint16(b[2:], ap.Port())
	a := ap.Addr().As16()
	copy(b[8:], a[:])
	return b, nil
}

func u16(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }
func u32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

// wgSet sends WG_CMD_SET_DEVICE for the link in the namespace of the calling
// thread.
func wgSet(ifname string, c wgConfig) error {
	return wgSetWith(c, nl.NewRtAttr(wgDevIfname, nl.ZeroTerminated(ifname)))
}

// wgSetWith sends WG_CMD_SET_DEVICE with the given selector attributes.
func wgSetWith(c wgConfig, selectors ...*nl.RtAttr) error {
	fam, err := wgFamily()
	if err != nil {
		return err
	}
	req := nl.NewNetlinkRequest(int(fam), unix.NLM_F_ACK)
	req.AddData(&nl.Genlmsg{Command: wgCmdSetDevice, Version: 1})
	for _, a := range selectors {
		req.AddData(a)
	}
	if c.flags != 0 {
		req.AddData(nl.NewRtAttr(wgDevFlags, u32(c.flags)))
	}
	if c.priv != nil {
		req.AddData(nl.NewRtAttr(wgDevPrivateKey, c.priv[:]))
	}
	if c.port != nil {
		req.AddData(nl.NewRtAttr(wgDevListenPort, u16(*c.port)))
	}
	if c.mark != nil {
		req.AddData(nl.NewRtAttr(wgDevFwmark, u32(*c.mark)))
	}
	if len(c.peers) > 0 {
		peers := nested(wgDevPeers)
		for _, p := range c.peers {
			peer := nested(0)
			peer.AddRtAttr(wgPeerPublicKey, p.pub[:])
			if p.flags != 0 {
				peer.AddRtAttr(wgPeerFlags, u32(p.flags))
			}
			if p.psk != nil {
				peer.AddRtAttr(wgPeerPresharedK, p.psk[:])
			}
			if p.endpoint != "" {
				sa, err := sockaddr(p.endpoint)
				if err != nil {
					return err
				}
				peer.AddRtAttr(wgPeerEndpoint, sa)
			}
			if p.keepalive != nil {
				peer.AddRtAttr(wgPeerKeepalive, u16(*p.keepalive))
			}
			proto := uint32(1)
			if p.proto != nil {
				proto = *p.proto
			}
			peer.AddRtAttr(wgPeerProtoVer, u32(proto))
			if len(p.allowed) > 0 {
				ips := nested(wgPeerAllowedIPs)
				for _, cidr := range p.allowed {
					prefix, err := netip.ParsePrefix(cidr)
					if err != nil {
						return err
					}
					ip := nested(0)
					family := uint16(unix.AF_INET)
					if prefix.Addr().Is6() {
						family = unix.AF_INET6
					}
					ip.AddRtAttr(wgIPFamily, u16(family))
					ip.AddRtAttr(wgIPAddr, prefix.Addr().AsSlice())
					ip.AddRtAttr(wgIPCIDR, []byte{byte(prefix.Bits())})
					ips.AddChild(ip)
				}
				peer.AddChild(ips)
			}
			peers.AddChild(peer)
		}
		req.AddData(peers)
	}
	_, err = req.Execute(unix.NETLINK_GENERIC, 0)
	return err
}

// wgGet sends WG_CMD_GET_DEVICE with NLM_F_DUMP and merges the messages.
func wgGet(ifname string) (*wgState, error) {
	return wgGetWith(nl.NewRtAttr(wgDevIfname, nl.ZeroTerminated(ifname)))
}

// wgGetWith sends WG_CMD_GET_DEVICE with the given selector attributes.
func wgGetWith(selectors ...*nl.RtAttr) (*wgState, error) {
	fam, err := wgFamily()
	if err != nil {
		return nil, err
	}
	req := nl.NewNetlinkRequest(int(fam), unix.NLM_F_DUMP|unix.NLM_F_ACK)
	req.AddData(&nl.Genlmsg{Command: wgCmdGetDevice, Version: 1})
	for _, a := range selectors {
		req.AddData(a)
	}
	msgs, err := req.Execute(unix.NETLINK_GENERIC, 0)
	if err != nil {
		return nil, err
	}
	st := &wgState{}
	var cur *wgPeerState
	for _, m := range msgs {
		if len(m) < 4 {
			return nil, errors.New("short generic netlink message")
		}
		attrs, err := nl.ParseRouteAttr(m[4:])
		if err != nil {
			return nil, err
		}
		for _, a := range attrs {
			switch a.Attr.Type &^ unix.NLA_F_NESTED {
			case wgDevIfindex:
				st.ifindex = binary.LittleEndian.Uint32(a.Value)
			case wgDevIfname:
				st.ifname = string(bytes.TrimRight(a.Value, "\x00"))
			case wgDevPrivateKey:
				st.priv = slices.Clone(a.Value)
			case wgDevPublicKey:
				st.pub = slices.Clone(a.Value)
			case wgDevListenPort:
				st.port = binary.LittleEndian.Uint16(a.Value)
			case wgDevFwmark:
				st.mark = binary.LittleEndian.Uint32(a.Value)
			case wgDevPeers:
				list, err := nl.ParseRouteAttr(a.Value)
				if err != nil {
					return nil, err
				}
				for _, entry := range list {
					p, err := parseWgPeer(entry.Value)
					if err != nil {
						return nil, err
					}
					if cur != nil && cur.pub == p.pub {
						cur.allowed = append(cur.allowed, p.allowed...)
						continue
					}
					cur = p
					st.peers = append(st.peers, p)
				}
			}
		}
	}
	return st, nil
}

func parseWgPeer(b []byte) (*wgPeerState, error) {
	attrs, err := nl.ParseRouteAttr(b)
	if err != nil {
		return nil, err
	}
	p := &wgPeerState{}
	for _, a := range attrs {
		switch a.Attr.Type &^ unix.NLA_F_NESTED {
		case wgPeerPublicKey:
			copy(p.pub[:], a.Value)
		case wgPeerPresharedK:
			copy(p.psk[:], a.Value)
		case wgPeerEndpoint:
			switch len(a.Value) {
			case 16:
				p.endpoint = netip.AddrPortFrom(netip.AddrFrom4([4]byte(a.Value[4:8])), binary.BigEndian.Uint16(a.Value[2:])).String()
			case 28:
				p.endpoint = netip.AddrPortFrom(netip.AddrFrom16([16]byte(a.Value[8:24])), binary.BigEndian.Uint16(a.Value[2:])).String()
			default:
				return nil, fmt.Errorf("endpoint has %d bytes", len(a.Value))
			}
		case wgPeerKeepalive:
			p.keepalive = binary.LittleEndian.Uint16(a.Value)
		case wgPeerHandshake:
			if len(a.Value) != 16 {
				return nil, fmt.Errorf("handshake time has %d bytes", len(a.Value))
			}
			p.hsSec = int64(binary.LittleEndian.Uint64(a.Value))
			p.hsNsec = int64(binary.LittleEndian.Uint64(a.Value[8:]))
		case wgPeerRx:
			p.rx = binary.LittleEndian.Uint64(a.Value)
		case wgPeerTx:
			p.tx = binary.LittleEndian.Uint64(a.Value)
		case wgPeerAllowedIPs:
			list, err := nl.ParseRouteAttr(a.Value)
			if err != nil {
				return nil, err
			}
			for _, entry := range list {
				fields, err := nl.ParseRouteAttrAsMap(entry.Value)
				if err != nil {
					return nil, err
				}
				addr, ok := netip.AddrFromSlice(fields[wgIPAddr].Value)
				if !ok || len(fields[wgIPCIDR].Value) != 1 {
					return nil, errors.New("malformed allowed IP address")
				}
				p.allowed = append(p.allowed, netip.PrefixFrom(addr, int(fields[wgIPCIDR].Value[0])).String())
			}
		}
	}
	return p, nil
}

// genlChecks checks NETLINK_GENERIC and the controller family.
func genlChecks() []check {
	return []check{
		{"controller-resolves-nlctrl", func() error {
			f, err := netlink.GenlFamilyGet("nlctrl")
			if err != nil {
				return err
			}
			if f.ID != genlCtrlID || f.Version != 2 || f.MaxAttr != 10 || len(f.Ops) != 1 || f.Ops[0].ID != 3 {
				return fmt.Errorf("nlctrl = %+v, want ID 16, version 2, maxattr 10, and the command 3", *f)
			}
			return nil
		}},
		{"controller-resolves-wireguard", func() error {
			f, err := netlink.GenlFamilyGet("wireguard")
			if err != nil {
				return err
			}
			if f.ID <= genlCtrlID || f.Version != 1 || f.MaxAttr != 8 || f.HdrSize != 0 {
				return fmt.Errorf("wireguard = %+v, want version 1, maxattr 8, and a dynamic ID", *f)
			}
			ops := map[uint32]uint32{}
			for _, op := range f.Ops {
				ops[op.ID] = op.Flags
			}
			// GET is a dump (0x04) and SET is a doit (0x02). Both need CAP_NET_ADMIN.
			if len(ops) != 2 || ops[wgCmdGetDevice] != genlOpNetPerm|0x04 || ops[wgCmdSetDevice] != genlOpNetPerm|0x02 {
				return fmt.Errorf("wireguard commands = %v", ops)
			}
			return nil
		}},
		{"controller-resolves-a-family-by-id", func() error {
			f, err := netlink.GenlFamilyGet("wireguard")
			if err != nil {
				return err
			}
			req := nl.NewNetlinkRequest(genlCtrlID, unix.NLM_F_ACK)
			req.AddData(&nl.Genlmsg{Command: nl.GENL_CTRL_CMD_GETFAMILY, Version: nl.GENL_CTRL_VERSION})
			req.AddData(nl.NewRtAttr(nl.GENL_CTRL_ATTR_FAMILY_ID, u16(f.ID)))
			msgs, err := req.Execute(unix.NETLINK_GENERIC, 0)
			if err != nil {
				return err
			}
			if len(msgs) != 1 || !bytes.Contains(msgs[0], []byte("wireguard\x00")) {
				return fmt.Errorf("the answer for ID %d has %d messages and lacks the name", f.ID, len(msgs))
			}
			return nil
		}},
		{"controller-dump-lists-the-families", func() error {
			list, err := netlink.GenlFamilyList()
			if err != nil {
				return err
			}
			names := map[string]uint16{}
			for _, f := range list {
				names[f.Name] = f.ID
			}
			if names["nlctrl"] != genlCtrlID || names["wireguard"] <= genlCtrlID {
				return fmt.Errorf("family list = %v", names)
			}
			return nil
		}},
		{"unknown-family-name-is-enoent", func() error {
			_, err := netlink.GenlFamilyGet("no-such-family")
			if !errors.Is(err, syscall.ENOENT) {
				return fmt.Errorf("GenlFamilyGet = %v, want ENOENT", err)
			}
			return nil
		}},
		{"unknown-family-id-is-enoent", func() error {
			req := nl.NewNetlinkRequest(0x3ff, unix.NLM_F_ACK)
			req.AddData(&nl.Genlmsg{Command: 0, Version: 1})
			_, err := req.Execute(unix.NETLINK_GENERIC, 0)
			if !errors.Is(err, syscall.ENOENT) {
				return fmt.Errorf("request to family 0x3ff = %v, want ENOENT", err)
			}
			return nil
		}},
		{"unknown-command-is-eopnotsupp", func() error {
			req := nl.NewNetlinkRequest(genlCtrlID, unix.NLM_F_ACK)
			req.AddData(&nl.Genlmsg{Command: 99, Version: 2})
			_, err := req.Execute(unix.NETLINK_GENERIC, 0)
			if !errors.Is(err, syscall.EOPNOTSUPP) {
				return fmt.Errorf("command 99 = %v, want EOPNOTSUPP", err)
			}
			return nil
		}},
		{"wireguard-needs-cap-net-admin", func() error {
			t, err := newThread(false, true)
			if err != nil {
				return err
			}
			defer t.close()
			return t.do(func() error {
				if _, err := wgGet("wg0"); !errors.Is(err, syscall.EPERM) {
					return fmt.Errorf("get as nobody = %v, want EPERM", err)
				}
				if err := wgSet("wg0", wgConfig{}); !errors.Is(err, syscall.EPERM) {
					return fmt.Errorf("set as nobody = %v, want EPERM", err)
				}
				return nil
			})
		}},
	}
}

// wireguardLink creates a wireguard link, gives it an address, and brings it up.
func wireguardLink(name, cidr string) error {
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if link.Type() != "wireguard" || link.Attrs().MTU != 1420 {
		return fmt.Errorf("%s has kind %q and MTU %d, want wireguard and 1420", name, link.Type(), link.Attrs().MTU)
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

// waitFor polls cond every 100 ms until it returns nil or the time ends.
func waitFor(timeout time.Duration, cond func() error) error {
	deadline := time.Now().Add(timeout)
	for {
		err := cond()
		if err == nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func wireguardChecks() []check {
	var (
		a, b                     *nsThread
		privA, pubA, privB, pubB [32]byte
		psk                      [32]byte
		portA, portB             = uint16(51820), uint16(51821)
	)
	const (
		addrA = "10.9.0.1"
		addrB = "10.9.0.2"
	)
	pingAB := func(from *nsThread, dst string, timeout time.Duration) error {
		return from.do(func() error { return ping(net.ParseIP(dst), timeout) })
	}
	return []check{
		{"namespaces-and-veth", func() error {
			var err error
			if a, err = newNsThread(); err != nil {
				return err
			}
			if b, err = newNsThread(); err != nil {
				return err
			}
			if privA, pubA, err = wgKey(); err != nil {
				return err
			}
			if privB, pubB, err = wgKey(); err != nil {
				return err
			}
			if _, err = rand.Read(psk[:]); err != nil {
				return err
			}
			if err := addLinkPair(a, "va0", "vb0", b); err != nil {
				return err
			}
			if err := a.do(func() error { return configureLink("va0", "10.1.0.1/30") }); err != nil {
				return err
			}
			return b.do(func() error { return configureLink("vb0", "10.1.0.2/30") })
		}},
		{"links-start-with-the-default-mtu", func() error {
			if err := a.do(func() error { return wireguardLink("wg0", addrA+"/24") }); err != nil {
				return err
			}
			return b.do(func() error { return wireguardLink("wg0", addrB+"/24") })
		}},
		{"link-names-are-unique", func() error {
			err := a.do(func() error {
				return netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "wg0"}})
			})
			if !errors.Is(err, syscall.EEXIST) {
				return fmt.Errorf("a second wg0 = %v, want EEXIST", err)
			}
			return nil
		}},
		{"set-and-get-round-trip", func() error {
			ka := uint16(25)
			mark := uint32(0x1234)
			err := a.do(func() error {
				return wgSet("wg0", wgConfig{priv: &privA, port: &portA, mark: &mark, peers: []wgPeer{{
					pub: pubB, psk: &psk, endpoint: "10.1.0.2:51821", keepalive: &ka,
					allowed: []string{addrB + "/32", "192.168.50.0/24", "fd00:50::/64"},
				}}})
			})
			if err != nil {
				return err
			}
			if err := b.do(func() error {
				return wgSet("wg0", wgConfig{priv: &privB, port: &portB, peers: []wgPeer{{
					pub: pubA, psk: &psk, endpoint: "10.1.0.1:51820", allowed: []string{addrA + "/32"},
				}}})
			}); err != nil {
				return err
			}
			var st *wgState
			if err := a.do(func() (err error) { st, err = wgGet("wg0"); return }); err != nil {
				return err
			}
			if st.ifname != "wg0" || st.ifindex == 0 || !bytes.Equal(st.priv, privA[:]) || !bytes.Equal(st.pub, pubA[:]) ||
				st.port != portA || st.mark != mark || len(st.peers) != 1 {
				return fmt.Errorf("device = %+v", *st)
			}
			p := st.peers[0]
			slices.Sort(p.allowed)
			want := []string{"10.9.0.2/32", "192.168.50.0/24", "fd00:50::/64"}
			if p.pub != pubB || p.psk != psk || p.endpoint != "10.1.0.2:51821" || p.keepalive != 25 || !slices.Equal(p.allowed, want) {
				return fmt.Errorf("peer = %+v, want allowed %v", *p, want)
			}
			return nil
		}},
		{"ping-crosses-the-tunnel", func() error {
			if err := pingAB(a, addrB, 10*time.Second); err != nil {
				return fmt.Errorf("A to B: %w", err)
			}
			return pingAB(b, addrA, 5*time.Second)
		}},
		{"tcp-transfer-crosses-the-tunnel", func() error {
			// B sends 1 MiB of random bytes to a listener in A. Both sides hash
			// what they handled.
			var ln net.Listener
			if err := a.do(func() (err error) {
				ln, err = net.Listen("tcp", addrA+":9000")
				return err
			}); err != nil {
				return err
			}
			defer ln.Close()
			type result struct {
				sum [sha256.Size]byte
				n   int64
				err error
			}
			got := make(chan result, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					got <- result{err: err}
					return
				}
				defer c.Close()
				h := sha256.New()
				n, err := io.Copy(h, c)
				var r result
				r.n, r.err = n, err
				copy(r.sum[:], h.Sum(nil))
				got <- r
			}()
			data := make([]byte, 1<<20)
			if _, err := rand.Read(data); err != nil {
				return err
			}
			if err := b.do(func() error {
				c, err := net.DialTimeout("tcp", addrA+":9000", 10*time.Second)
				if err != nil {
					return err
				}
				defer c.Close()
				_, err = c.Write(data)
				return err
			}); err != nil {
				return fmt.Errorf("send from B: %w", err)
			}
			select {
			case r := <-got:
				if r.err != nil || r.n != int64(len(data)) || r.sum != sha256.Sum256(data) {
					return fmt.Errorf("A received %d bytes with error %v, want %d bytes with the same hash", r.n, r.err, len(data))
				}
				return nil
			case <-time.After(30 * time.Second):
				return errors.New("A did not receive the whole stream in 30s")
			}
		}},
		{"get-reports-handshake-and-counters", func() error {
			return waitFor(5*time.Second, func() error {
				var st *wgState
				if err := a.do(func() (err error) { st, err = wgGet("wg0"); return }); err != nil {
					return err
				}
				p := st.peers[0]
				if p.hsSec == 0 || p.rx == 0 || p.tx == 0 {
					return fmt.Errorf("peer counters = %+v", *p)
				}
				if d := time.Since(time.Unix(p.hsSec, p.hsNsec)); d < 0 || d > time.Minute {
					return fmt.Errorf("last handshake %v ago", d)
				}
				return nil
			})
		}},
		{"get-splits-many-allowed-ips-across-messages", func() error {
			var ips []string
			for i := range 300 {
				ips = append(ips, fmt.Sprintf("172.16.%d.%d/32", i/200, i%200))
			}
			if err := a.do(func() error {
				return wgSet("wg0", wgConfig{peers: []wgPeer{{pub: pubB, flags: wgPeerReplaceAllowedIP, allowed: append([]string{addrB + "/32"}, ips...)}}})
			}); err != nil {
				return err
			}
			var st *wgState
			if err := a.do(func() (err error) { st, err = wgGet("wg0"); return }); err != nil {
				return err
			}
			if len(st.peers) != 1 || len(st.peers[0].allowed) != 301 {
				return fmt.Errorf("got %d peers, and %d allowed IP addresses in the first", len(st.peers), len(st.peers[0].allowed))
			}
			return a.do(func() error {
				return wgSet("wg0", wgConfig{peers: []wgPeer{{pub: pubB, flags: wgPeerReplaceAllowedIP, allowed: []string{addrB + "/32"}}}})
			})
		}},
		{"update-only-ignores-an-unknown-peer", func() error {
			_, pubX, err := wgKey()
			if err != nil {
				return err
			}
			var st *wgState
			err = a.do(func() error {
				if err := wgSet("wg0", wgConfig{peers: []wgPeer{{pub: pubX, flags: wgPeerUpdateOnly, allowed: []string{"10.77.0.0/16"}}}}); err != nil {
					return err
				}
				st, err = wgGet("wg0")
				return err
			})
			if err != nil {
				return err
			}
			if len(st.peers) != 1 {
				return fmt.Errorf("A has %d peers, want 1", len(st.peers))
			}
			return nil
		}},
		{"invalid-requests-fail", func() error {
			return a.do(func() error {
				if err := wgSet("wg0", wgConfig{flags: 0x80}); !errors.Is(err, syscall.EOPNOTSUPP) {
					return fmt.Errorf("unknown device flag = %v, want EOPNOTSUPP", err)
				}
				if err := wgSet("wg0", wgConfig{peers: []wgPeer{{pub: pubB, flags: 0x80}}}); !errors.Is(err, syscall.EOPNOTSUPP) {
					return fmt.Errorf("unknown peer flag = %v, want EOPNOTSUPP", err)
				}
				if err := wgSet("wg0", wgConfig{peers: []wgPeer{{pub: pubB, allowed: []string{"10.0.0.0/33"}}}}); err == nil {
					return errors.New("a /33 prefix succeeded, want an error")
				}
				if err := wgSet("no-such", wgConfig{}); !errors.Is(err, syscall.ENODEV) {
					return fmt.Errorf("unknown link = %v, want ENODEV", err)
				}
				if _, err := wgGet("va0"); !errors.Is(err, syscall.EOPNOTSUPP) {
					return fmt.Errorf("get on a veth = %v, want EOPNOTSUPP", err)
				}
				return nil
			})
		}},
		{"removing-the-peer-stops-the-traffic", func() error {
			if err := a.do(func() error {
				return wgSet("wg0", wgConfig{peers: []wgPeer{{pub: pubB, flags: wgPeerRemoveMe}}})
			}); err != nil {
				return err
			}
			var st *wgState
			if err := a.do(func() (err error) { st, err = wgGet("wg0"); return }); err != nil {
				return err
			}
			if len(st.peers) != 0 {
				return fmt.Errorf("A still has %d peers", len(st.peers))
			}
			if err := pingAB(a, addrB, 1500*time.Millisecond); err == nil {
				return errors.New("A reached B after the peer was removed")
			}
			return nil
		}},
		{"keepalive-teaches-a-peer-the-endpoint", func() error {
			// A has no endpoint for B. B sends a keepalive every second. B drops
			// its session with A first, so the keepalive starts a new handshake.
			ka := uint16(1)
			if err := a.do(func() error {
				return wgSet("wg0", wgConfig{peers: []wgPeer{{pub: pubB, psk: &psk, allowed: []string{addrB + "/32"}}}})
			}); err != nil {
				return err
			}
			if err := b.do(func() error {
				return wgSet("wg0", wgConfig{peers: []wgPeer{{pub: pubA, flags: wgPeerRemoveMe}}})
			}); err != nil {
				return err
			}
			if err := b.do(func() error {
				return wgSet("wg0", wgConfig{peers: []wgPeer{{
					pub: pubA, psk: &psk, endpoint: "10.1.0.1:51820", keepalive: &ka, allowed: []string{addrA + "/32"},
				}}})
			}); err != nil {
				return err
			}
			err := waitFor(15*time.Second, func() error {
				var st *wgState
				if err := a.do(func() (err error) { st, err = wgGet("wg0"); return }); err != nil {
					return err
				}
				if len(st.peers) != 1 || st.peers[0].endpoint != "10.1.0.2:51821" {
					if len(st.peers) == 1 {
						return fmt.Errorf("peer = %+v", *st.peers[0])
					}
					return fmt.Errorf("%d peers", len(st.peers))
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("A did not learn the endpoint of B: %w", err)
			}
			return pingAB(a, addrB, 5*time.Second)
		}},
		{"replace-peers-removes-every-peer", func() error {
			var st *wgState
			err := a.do(func() error {
				if err := wgSet("wg0", wgConfig{flags: wgDeviceReplacePeers}); err != nil {
					return err
				}
				var err error
				st, err = wgGet("wg0")
				return err
			})
			if err != nil {
				return err
			}
			if len(st.peers) != 0 || !bytes.Equal(st.priv, privA[:]) {
				return fmt.Errorf("device after replace = %+v", *st)
			}
			return nil
		}},
		{"deleting-the-link-removes-the-device", func() error {
			err := a.do(func() error {
				link, err := netlink.LinkByName("wg0")
				if err != nil {
					return err
				}
				return netlink.LinkDel(link)
			})
			if err != nil {
				return err
			}
			return a.do(func() error {
				if _, err := netlink.LinkByName("wg0"); err == nil {
					return errors.New("wg0 still exists")
				}
				if _, err := wgGet("wg0"); !errors.Is(err, syscall.ENODEV) {
					return fmt.Errorf("get after delete = %v, want ENODEV", err)
				}
				// The UDP port of the deleted device is free again.
				return bindPort(syscall.AF_INET, syscall.SOCK_DGRAM, int(portA))
			})
		}},
		{"namespaces-end", func() error {
			a.close()
			b.close()
			return nil
		}},
	}
}
