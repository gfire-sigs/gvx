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
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The vxlan checks build two network namespaces A and B that a veth pair
// links. The namespaces set up one vxlan link each with the calls that the
// flannel vxlan back end makes through github.com/vishvananda/netlink: a
// link with VNI 1 and port 8472 and no learning, a permanent neighbor entry
// for the VTEP address of the peer, an FDB entry that maps the VTEP MAC of the
// peer to the address of its node, and a route with the onlink flag.

const (
	vxNodeA = "10.1.0.1"
	vxNodeB = "10.1.0.2"
	// vxOverlay are the VTEP addresses and the subnets that sit behind them.
	vxOverlayA = "10.244.1.0"
	vxOverlayB = "10.244.2.0"
)

// vxlanDevice creates a vxlan link as flannel does: with a local address and a
// port and with learning off. A non-zero parent selects the underlay link.
func vxlanDevice(name string, vni int, port int, local string, parent int, learning bool) (*netlink.Vxlan, error) {
	link := &netlink.Vxlan{
		LinkAttrs:    netlink.LinkAttrs{Name: name},
		VxlanId:      vni,
		VtepDevIndex: parent,
		SrcAddr:      net.ParseIP(local),
		Port:         port,
		Learning:     learning,
		GBP:          false,
	}
	if err := netlink.LinkAdd(link); err != nil {
		return nil, fmt.Errorf("create %s: %w", name, err)
	}
	return vxlanByName(name)
}

// vxlanByName reads a vxlan link back.
func vxlanByName(name string) (*netlink.Vxlan, error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("find %s: %w", name, err)
	}
	v, ok := l.(*netlink.Vxlan)
	if !ok {
		return nil, fmt.Errorf("%s has kind %q, want vxlan", name, l.Type())
	}
	return v, nil
}

// vxlanAddress gives the link an address with a host prefix, as flannel does,
// and brings it up.
func vxlanAddress(name, ip string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	addr, err := netlink.ParseAddr(ip + "/32")
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("add %s to %s: %w", ip, name, err)
	}
	return netlink.LinkSetUp(link)
}

// vxlanPeer adds what flannel adds for a remote node: an ARP entry for the VTEP
// address of the remote node, an FDB entry for its MAC, and the route to its
// subnet through the VTEP address.
func vxlanPeer(name string, mac net.HardwareAddr, overlay, node string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	idx := link.Attrs().Index
	if err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex: idx, State: netlink.NUD_PERMANENT, Type: syscall.RTN_UNICAST,
		IP: net.ParseIP(overlay), HardwareAddr: mac,
	}); err != nil {
		return fmt.Errorf("set the ARP entry: %w", err)
	}
	if err := vxlanFDB(idx, mac, node); err != nil {
		return err
	}
	_, subnet, _ := net.ParseCIDR(overlay + "/24")
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: idx, Gw: net.ParseIP(overlay), Dst: subnet, Flags: syscall.RTNH_F_ONLINK,
	}); err != nil {
		return fmt.Errorf("replace the route to %s: %w", subnet, err)
	}
	return nil
}

// vxlanFDB sets the FDB entry for mac, as the vxlan device of flannel does.
func vxlanFDB(idx int, mac net.HardwareAddr, node string) error {
	err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex: idx, State: netlink.NUD_PERMANENT, Family: syscall.AF_BRIDGE,
		Flags: netlink.NTF_SELF, IP: net.ParseIP(node), HardwareAddr: mac,
	})
	if err != nil {
		return fmt.Errorf("set the FDB entry: %w", err)
	}
	return nil
}

// vxlanFDBList returns the FDB entries of the link.
func vxlanFDBList(idx int) ([]netlink.Neigh, error) {
	return netlink.NeighList(idx, syscall.AF_BRIDGE)
}

// findNeigh returns the entry for the IP address and the link, or nil.
func findNeigh(list []netlink.Neigh, ip string, mac net.HardwareAddr) *netlink.Neigh {
	for i := range list {
		n := &list[i]
		if n.IP.Equal(net.ParseIP(ip)) && (mac == nil || bytes.Equal(n.HardwareAddr, mac)) {
			return n
		}
	}
	return nil
}

// pingPayload sends ICMP echo requests with payload bytes of data to dst and
// waits for a reply. The IP packet has payload+28 bytes. It returns nil when a
// reply arrives within the timeout.
func pingPayload(dst net.IP, payload int, timeout time.Duration) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer syscall.Close(fd)
	tv := syscall.NsecToTimeval(int64(400 * time.Millisecond))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("SO_RCVTIMEO: %w", err)
	}
	var to syscall.SockaddrInet4
	copy(to.Addr[:], dst.To4())
	buf := make([]byte, payload+64)
	deadline := time.Now().Add(timeout)
	for seq := 1; time.Now().Before(deadline); seq++ {
		req := make([]byte, 8+payload)
		req[0], req[5], req[6], req[7] = 8, 1, byte(seq>>8), byte(seq)
		for i := 8; i < len(req); i++ {
			req[i] = byte(i)
		}
		sum := icmpChecksum(req)
		req[2], req[3] = byte(sum>>8), byte(sum)
		if err := syscall.Sendto(fd, req, 0, &to); err != nil {
			return fmt.Errorf("send %d bytes: %w", len(req)+20, err)
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) {
				continue
			}
			return fmt.Errorf("receive: %w", err)
		}
		if n == len(req) && buf[0] == 0 {
			return nil
		}
	}
	return fmt.Errorf("no echo reply with %d bytes from %s in %v", payload+28, dst, timeout)
}

func vxlanPing(from *nsThread, dst string, timeout time.Duration) error {
	return from.do(func() error { return ping(net.ParseIP(dst), timeout) })
}

// vxlanTCP sends 1 MiB of random bytes from the thread "from" to a listener in
// "to" at addr and compares the hashes.
func vxlanTCP(from, to *nsThread, addr string) error {
	var ln net.Listener
	if err := to.do(func() (err error) {
		ln, err = net.Listen("tcp", addr)
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
		r := result{n: n, err: err}
		copy(r.sum[:], h.Sum(nil))
		got <- r
	}()
	data := make([]byte, 1<<20)
	if _, err := rand.Read(data); err != nil {
		return err
	}
	if err := from.do(func() error {
		c, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			return err
		}
		defer c.Close()
		_, err = c.Write(data)
		return err
	}); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	select {
	case r := <-got:
		if r.err != nil || r.n != int64(len(data)) || r.sum != sha256.Sum256(data) {
			return fmt.Errorf("received %d bytes with error %v, want %d bytes with the same hash", r.n, r.err, len(data))
		}
		return nil
	case <-time.After(30 * time.Second):
		return errors.New("the listener did not receive the whole stream in 30s")
	}
}

// wantErrno returns an error unless err wraps the errno.
func wantErrno(what string, err error, want syscall.Errno) error {
	if !errors.Is(err, want) {
		return fmt.Errorf("%s = %v, want %v", what, err, want)
	}
	return nil
}

func vxlanChecks() []check {
	var (
		a, b         *nsThread
		macA, macB   net.HardwareAddr
		idxA         int
		underlayAIdx int
	)
	linkOf := func(t *nsThread, name string) (idx int, mac net.HardwareAddr, err error) {
		err = t.do(func() error {
			l, e := netlink.LinkByName(name)
			if e != nil {
				return e
			}
			idx, mac = l.Attrs().Index, l.Attrs().HardwareAddr
			return nil
		})
		return
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
			if err := addLinkPair(a, "va0", "vb0", b); err != nil {
				return err
			}
			if err := a.do(func() error { return configureLink("va0", vxNodeA+"/30") }); err != nil {
				return err
			}
			if err := b.do(func() error { return configureLink("vb0", vxNodeB+"/30") }); err != nil {
				return err
			}
			underlayAIdx, _, err = linkOf(a, "va0")
			return err
		}},
		{"flannel-links-report-kind-mtu-and-attributes", func() error {
			for _, ns := range []struct {
				t     *nsThread
				local string
			}{{a, vxNodeA}, {b, vxNodeB}} {
				err := ns.t.do(func() error {
					v, err := vxlanDevice("flannel.1", 1, 8472, ns.local, 0, false)
					if err != nil {
						return err
					}
					if v.Type() != "vxlan" || v.MTU != 1450 {
						return fmt.Errorf("flannel.1 has kind %q and MTU %d, want vxlan and 1450", v.Type(), v.MTU)
					}
					if v.VxlanId != 1 || v.Port != 8472 || !v.SrcAddr.Equal(net.ParseIP(ns.local)) || v.Learning || v.GBP || v.VtepDevIndex != 0 {
						return fmt.Errorf("flannel.1 = %+v, want VNI 1, port 8472, local %s, no learning, no GBP", *v, ns.local)
					}
					if len(v.HardwareAddr) != 6 || v.HardwareAddr[0]&1 != 0 {
						return fmt.Errorf("flannel.1 has the address %v, want a unicast Ethernet address", v.HardwareAddr)
					}
					return nil
				})
				if err != nil {
					return err
				}
			}
			var err error
			if idxA, macA, err = linkOf(a, "flannel.1"); err != nil {
				return err
			}
			_, macB, err = linkOf(b, "flannel.1")
			return err
		}},
		{"link-attributes-round-trip", func() error {
			return a.do(func() error {
				link := &netlink.Vxlan{
					LinkAttrs: netlink.LinkAttrs{Name: "vx2"},
					VxlanId:   5, VtepDevIndex: underlayAIdx, SrcAddr: net.ParseIP(vxNodeA), Port: 4789,
					TTL: 10, TOS: 4, Learning: true, GBP: true, UDPCSum: true, Age: 120, Limit: 100,
					PortLow: 40000, PortHigh: 40100, Proxy: true, L2miss: true, L3miss: true,
				}
				if err := netlink.LinkAdd(link); err != nil {
					return err
				}
				v, err := vxlanByName("vx2")
				if err != nil {
					return err
				}
				under, err := netlink.LinkByIndex(underlayAIdx)
				if err != nil {
					return err
				}
				if want := under.Attrs().MTU - 50; v.MTU != want {
					return fmt.Errorf("vx2 has MTU %d, want the underlay MTU %d minus 50 = %d", v.MTU, under.Attrs().MTU, want)
				}
				if v.VxlanId != 5 || v.VtepDevIndex != underlayAIdx || !v.SrcAddr.Equal(net.ParseIP(vxNodeA)) || v.Port != 4789 ||
					v.TTL != 10 || v.TOS != 4 || !v.Learning || !v.GBP || !v.UDPCSum || v.Age != 120 || v.Limit != 100 ||
					v.PortLow != 40000 || v.PortHigh != 40100 || !v.Proxy || !v.L2miss || !v.L3miss {
					return fmt.Errorf("vx2 = %+v, want the attributes that the request set", *v)
				}
				return netlink.LinkDel(v)
			})
		}},
		{"invalid-and-duplicate-requests-fail", func() error {
			return a.do(func() error {
				err := netlink.LinkAdd(&netlink.Vxlan{LinkAttrs: netlink.LinkAttrs{Name: "dup"}, VxlanId: 1, SrcAddr: net.ParseIP(vxNodeA), Port: 8472})
				if e := wantErrno("a second link with VNI 1 on port 8472", err, syscall.EEXIST); e != nil {
					return e
				}
				// The same port with another VNI shares the UDP endpoint.
				if err := netlink.LinkAdd(&netlink.Vxlan{LinkAttrs: netlink.LinkAttrs{Name: "other"}, VxlanId: 2, SrcAddr: net.ParseIP(vxNodeA), Port: 8472}); err != nil {
					return fmt.Errorf("a link with VNI 2 on port 8472: %w", err)
				}
				if l, err := netlink.LinkByName("other"); err != nil {
					return err
				} else if err := netlink.LinkDel(l); err != nil {
					return err
				}
				err = netlink.LinkAdd(&netlink.Vxlan{LinkAttrs: netlink.LinkAttrs{Name: "big"}, VxlanId: 1 << 24, Port: 4790})
				if e := wantErrno("VNI 2^24", err, syscall.ERANGE); e != nil {
					return e
				}
				err = netlink.LinkAdd(&netlink.Vxlan{LinkAttrs: netlink.LinkAttrs{Name: "flow"}, FlowBased: true, Port: 4790})
				if e := wantErrno("a flow-based link", err, syscall.EOPNOTSUPP); e != nil {
					return e
				}
				err = netlink.LinkAdd(&netlink.Vxlan{LinkAttrs: netlink.LinkAttrs{Name: "nodev"}, VxlanId: 3, VtepDevIndex: 4242, Port: 4790})
				if e := wantErrno("an unknown underlay link", err, syscall.ENODEV); e != nil {
					return e
				}
				err = netlink.LinkAdd(&netlink.Vxlan{LinkAttrs: netlink.LinkAttrs{Name: "mcast"}, VxlanId: 3, Group: net.ParseIP("239.1.1.1"), Port: 4790})
				if e := wantErrno("a multicast group", err, syscall.EOPNOTSUPP); e != nil {
					return e
				}
				err = netlink.LinkAdd(&netlink.Vxlan{LinkAttrs: netlink.LinkAttrs{Name: "mixed"}, VxlanId: 3, SrcAddr: net.ParseIP(vxNodeA), Group: net.ParseIP("fd00::1"), Port: 4790})
				return wantErrno("mixed address families", err, syscall.EINVAL)
			})
		}},
		{"changing-an-existing-link-is-refused", func() error {
			return a.do(func() error {
				err := netlink.LinkModify(&netlink.Vxlan{LinkAttrs: netlink.LinkAttrs{Name: "flannel.1"}, VxlanId: 1, Port: 8472, Learning: true})
				if e := wantErrno("a change of the attributes", err, syscall.EOPNOTSUPP); e != nil {
					return e
				}
				v, err := vxlanByName("flannel.1")
				if err != nil {
					return err
				}
				if v.Learning || v.VxlanId != 1 {
					return fmt.Errorf("flannel.1 = %+v after the refused change, want the old attributes", *v)
				}
				// A change of the MTU or the address has no IFLA_INFO_DATA and works.
				return nil
			})
		}},
		{"mtu-stays-in-the-range-of-the-link", func() error {
			return a.do(func() error {
				l, err := netlink.LinkByName("flannel.1")
				if err != nil {
					return err
				}
				for _, mtu := range []int{67, 65486, 70000} {
					if e := wantErrno(fmt.Sprintf("MTU %d", mtu), netlink.LinkSetMTU(l, mtu), syscall.EINVAL); e != nil {
						return e
					}
				}
				for _, mtu := range []int{68, 65485, 1450} {
					if err := netlink.LinkSetMTU(l, mtu); err != nil {
						return fmt.Errorf("MTU %d: %w", mtu, err)
					}
				}
				v, err := vxlanByName("flannel.1")
				if err != nil {
					return err
				}
				if v.MTU != 1450 {
					return fmt.Errorf("MTU = %d, want 1450", v.MTU)
				}
				return nil
			})
		}},
		{"fdb-limit-answers-enospc", func() error {
			return a.do(func() error {
				link := &netlink.Vxlan{LinkAttrs: netlink.LinkAttrs{Name: "vxlim"}, VxlanId: 12, SrcAddr: net.ParseIP(vxNodeA), Port: 4792, Limit: 3}
				if err := netlink.LinkAdd(link); err != nil {
					return err
				}
				v, err := vxlanByName("vxlim")
				if err != nil {
					return err
				}
				add := func(i int) error {
					mac := net.HardwareAddr{2, 0, 0, 0, 0, byte(i)}
					return vxlanFDB(v.Index, mac, "10.1.0.70")
				}
				// IFLA_VXLAN_LIMIT is the only cap, and getlink reports it.
				if v.Limit != 3 {
					return fmt.Errorf("vxlim reports the limit %d, want 3", v.Limit)
				}
				// vxlan_changelink refuses IFLA_VXLAN_LIMIT with "Cannot change limit".
				change := &netlink.Vxlan{LinkAttrs: netlink.LinkAttrs{Name: "vxlim"}, VxlanId: 12, Port: 4792, Limit: 5}
				if e := wantErrno("a change of the limit", netlink.LinkModify(change), syscall.EOPNOTSUPP); e != nil {
					return e
				}
				if v, err = vxlanByName("vxlim"); err != nil || v.Limit != 3 {
					return fmt.Errorf("vxlim reports the limit %d (%v) after the refused change, want 3", v.Limit, err)
				}
				for i := range 3 {
					if err := add(i); err != nil {
						return fmt.Errorf("entry %d: %w", i, err)
					}
				}
				if e := wantErrno("the fourth entry with the limit 3", add(3), syscall.ENOSPC); e != nil {
					return e
				}
				// A change of an existing entry needs no new slot.
				if err := vxlanFDB(v.Index, net.HardwareAddr{2, 0, 0, 0, 0, 1}, "10.1.0.71"); err != nil {
					return fmt.Errorf("a change at the limit: %w", err)
				}
				return netlink.LinkDel(v)
			})
		}},
		{"fdb-and-remotes-have-no-default-cap", func() error {
			// The old table held 65,536 entries, and an entry held 1,024 remotes.
			// Reuse one netlink handle so the 67,100 requests do not open a new
			// socket for each entry.
			return a.doWithin(3*time.Minute, func() error {
				h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
				if err != nil {
					return err
				}
				defer h.Close()
				link := &netlink.Vxlan{LinkAttrs: netlink.LinkAttrs{Name: "vxfree"}, VxlanId: 13, SrcAddr: net.ParseIP(vxNodeA), Port: 4793}
				if err := h.LinkAdd(link); err != nil {
					return err
				}
				v, err := vxlanByName("vxfree")
				if err != nil {
					return err
				}
				if v.Limit != 0 {
					return fmt.Errorf("a link without IFLA_VXLAN_LIMIT reports the limit %d, want 0 (no limit)", v.Limit)
				}
				const entries = 66000
				nodeIP := net.IPv4(10, 1, 0, 80)
				for i := range entries {
					mac := net.HardwareAddr{2, 0, 0, byte(i >> 16), byte(i >> 8), byte(i)}
					if err := h.NeighSet(&netlink.Neigh{
						LinkIndex: v.Index, State: netlink.NUD_PERMANENT, Family: syscall.AF_BRIDGE,
						Flags: netlink.NTF_SELF, IP: nodeIP, HardwareAddr: mac,
					}); err != nil {
						return fmt.Errorf("entry %d: %w", i, err)
					}
				}
				const remotes = 1100
				zero := net.HardwareAddr{0, 0, 0, 0, 0, 0}
				for i := range remotes {
					if err := h.NeighAppend(&netlink.Neigh{
						LinkIndex: v.Index, State: netlink.NUD_PERMANENT, Family: syscall.AF_BRIDGE,
						Flags: netlink.NTF_SELF, IP: net.IPv4(10, 3, byte(i>>8), byte(i)), HardwareAddr: zero,
					}); err != nil {
						return fmt.Errorf("remote %d: %w", i, err)
					}
				}
				fdb, err := h.NeighList(v.Index, syscall.AF_BRIDGE)
				if err != nil {
					return err
				}
				unicast, zeroRemotes := 0, 0
				for _, n := range fdb {
					if bytes.Equal(n.HardwareAddr, zero) {
						zeroRemotes++
					} else {
						unicast++
					}
				}
				if unicast != entries || zeroRemotes != remotes {
					return fmt.Errorf("the FDB lists %d entries and %d remotes of the all-zeros entry, want %d and %d", unicast, zeroRemotes, entries, remotes)
				}
				return h.LinkDel(v)
			})
		}},
		{"flannel-setup-adds-neighbor-fdb-and-onlink-route", func() error {
			if err := a.do(func() error {
				if err := vxlanAddress("flannel.1", vxOverlayA); err != nil {
					return err
				}
				return vxlanPeer("flannel.1", macB, vxOverlayB, vxNodeB)
			}); err != nil {
				return fmt.Errorf("A: %w", err)
			}
			if err := b.do(func() error {
				if err := vxlanAddress("flannel.1", vxOverlayB); err != nil {
					return err
				}
				return vxlanPeer("flannel.1", macA, vxOverlayA, vxNodeA)
			}); err != nil {
				return fmt.Errorf("B: %w", err)
			}
			return a.do(func() error {
				routes, err := netlink.RouteList(nil, syscall.AF_INET)
				if err != nil {
					return err
				}
				for _, r := range routes {
					if r.LinkIndex == idxA && r.Dst != nil && r.Dst.String() == vxOverlayB+"/24" {
						if !r.Gw.Equal(net.ParseIP(vxOverlayB)) {
							return fmt.Errorf("route = %+v, want the gateway %s", r, vxOverlayB)
						}
						return nil
					}
				}
				return fmt.Errorf("no route to %s/24 on flannel.1 in %v", vxOverlayB, routes)
			})
		}},
		{"neighbor-and-fdb-lists-return-what-was-set", func() error {
			return a.do(func() error {
				arp, err := netlink.NeighList(idxA, syscall.AF_INET)
				if err != nil {
					return err
				}
				n := findNeigh(arp, vxOverlayB, macB)
				if n == nil || n.State != netlink.NUD_PERMANENT || n.LinkIndex != idxA || n.Family != syscall.AF_INET {
					return fmt.Errorf("NeighList(AF_INET) = %+v, want a permanent entry %s -> %v", arp, vxOverlayB, macB)
				}
				all, err := netlink.NeighList(0, syscall.AF_UNSPEC)
				if err != nil {
					return err
				}
				if findNeigh(all, vxOverlayB, macB) == nil {
					return fmt.Errorf("NeighList(AF_UNSPEC) = %+v lacks the entry", all)
				}
				if v6, err := netlink.NeighList(idxA, syscall.AF_INET6); err != nil || findNeigh(v6, vxOverlayB, nil) != nil {
					return fmt.Errorf("NeighList(AF_INET6) = %+v, %v, want no IPv4 entry", v6, err)
				}
				fdb, err := vxlanFDBList(idxA)
				if err != nil {
					return err
				}
				f := findNeigh(fdb, vxNodeB, macB)
				if f == nil || f.State != netlink.NUD_PERMANENT || f.Flags&netlink.NTF_SELF == 0 || f.Family != syscall.AF_BRIDGE || f.LinkIndex != idxA {
					return fmt.Errorf("NeighList(AF_BRIDGE) = %+v, want a permanent self entry %v -> %s", fdb, macB, vxNodeB)
				}
				if other, err := vxlanFDBList(underlayAIdx); err != nil || len(other) != 0 {
					return fmt.Errorf("NeighList(AF_BRIDGE) of the veth = %+v, %v, want no entry", other, err)
				}
				return nil
			})
		}},
		{"ping-crosses-the-vxlan", func() error {
			if err := vxlanPing(a, vxOverlayB, 10*time.Second); err != nil {
				return fmt.Errorf("A to B: %w", err)
			}
			if err := vxlanPing(b, vxOverlayA, 5*time.Second); err != nil {
				return fmt.Errorf("B to A: %w", err)
			}
			return nil
		}},
		{"ping-with-the-full-mtu-crosses-the-vxlan", func() error {
			// The vxlan MTU is 1450, so the IP packet of 1450 bytes is a full
			// frame. The outer packet exceeds the veth MTU and the underlay
			// fragments it.
			if err := a.do(func() error { return pingPayload(net.ParseIP(vxOverlayB), 1450-28, 10*time.Second) }); err != nil {
				return fmt.Errorf("A to B: %w", err)
			}
			return b.do(func() error { return pingPayload(net.ParseIP(vxOverlayA), 1450-28, 10*time.Second) })
		}},
		{"tcp-transfer-crosses-the-vxlan", func() error {
			return vxlanTCP(a, b, vxOverlayB+":9000")
		}},
		{"neighbor-requests-follow-linux", func() error {
			return a.do(func() error {
				mac1, _ := net.ParseMAC("02:00:00:00:00:11")
				mac2, _ := net.ParseMAC("02:00:00:00:00:22")
				n := &netlink.Neigh{LinkIndex: underlayAIdx, State: netlink.NUD_PERMANENT, IP: net.ParseIP("10.1.0.99"), HardwareAddr: mac1}
				if err := netlink.NeighAdd(n); err != nil {
					return fmt.Errorf("add: %w", err)
				}
				if e := wantErrno("add of an existing entry", netlink.NeighAdd(n), syscall.EEXIST); e != nil {
					return e
				}
				n.HardwareAddr = mac2
				if err := netlink.NeighSet(n); err != nil {
					return fmt.Errorf("replace: %w", err)
				}
				list, err := netlink.NeighList(underlayAIdx, syscall.AF_INET)
				if err != nil {
					return err
				}
				if got := findNeigh(list, "10.1.0.99", mac2); got == nil || got.State != netlink.NUD_PERMANENT {
					return fmt.Errorf("NeighList = %+v, want 10.1.0.99 -> %v permanent", list, mac2)
				}
				if err := netlink.NeighDel(n); err != nil {
					return fmt.Errorf("delete: %w", err)
				}
				if e := wantErrno("delete of a missing entry", netlink.NeighDel(n), syscall.ENOENT); e != nil {
					return e
				}
				v6 := &netlink.Neigh{LinkIndex: underlayAIdx, State: netlink.NUD_PERMANENT, IP: net.ParseIP("fd00:1::99"), HardwareAddr: mac1}
				if err := netlink.NeighSet(v6); err != nil {
					return fmt.Errorf("set IPv6: %w", err)
				}
				list, err = netlink.NeighList(underlayAIdx, syscall.AF_INET6)
				if err != nil {
					return err
				}
				if findNeigh(list, "fd00:1::99", mac1) == nil {
					return fmt.Errorf("NeighList(AF_INET6) = %+v lacks the entry", list)
				}
				if err := netlink.NeighDel(v6); err != nil {
					return err
				}
				stale := &netlink.Neigh{LinkIndex: underlayAIdx, State: netlink.NUD_STALE, IP: net.ParseIP("10.1.0.98"), HardwareAddr: mac1}
				if e := wantErrno("a dynamic state", netlink.NeighSet(stale), syscall.EOPNOTSUPP); e != nil {
					return e
				}
				missing := &netlink.Neigh{LinkIndex: underlayAIdx, State: netlink.NUD_PERMANENT, IP: net.ParseIP("10.1.0.97")}
				if e := wantErrno("an entry without an address", netlink.NeighSet(missing), syscall.EINVAL); e != nil {
					return e
				}
				gone := &netlink.Neigh{LinkIndex: 4242, State: netlink.NUD_PERMANENT, IP: net.ParseIP("10.1.0.96"), HardwareAddr: mac1}
				if e := wantErrno("an unknown link", netlink.NeighSet(gone), syscall.ENODEV); e != nil {
					return e
				}
				lo, err := netlink.LinkByName("lo")
				if err != nil {
					return err
				}
				onLo := &netlink.Neigh{LinkIndex: lo.Attrs().Index, State: netlink.NUD_PERMANENT, IP: net.ParseIP("127.0.0.9"), HardwareAddr: mac1}
				return wantErrno("an entry on a link without address resolution", netlink.NeighSet(onLo), syscall.EOPNOTSUPP)
			})
		}},
		{"fdb-requests-follow-linux", func() error {
			return a.do(func() error {
				mac1, _ := net.ParseMAC("02:00:00:00:00:31")
				zero, _ := net.ParseMAC("00:00:00:00:00:00")
				fdb := func(mac net.HardwareAddr, node string) *netlink.Neigh {
					return &netlink.Neigh{
						LinkIndex: idxA, State: netlink.NUD_PERMANENT, Family: syscall.AF_BRIDGE,
						Flags: netlink.NTF_SELF, IP: net.ParseIP(node), HardwareAddr: mac,
					}
				}
				if err := netlink.NeighAdd(fdb(mac1, "10.1.0.50")); err != nil {
					return fmt.Errorf("add: %w", err)
				}
				if e := wantErrno("add of an existing entry", netlink.NeighAdd(fdb(mac1, "10.1.0.51")), syscall.EEXIST); e != nil {
					return e
				}
				// Append does not change a unicast entry.
				if err := netlink.NeighAppend(fdb(mac1, "10.1.0.52")); err != nil {
					return fmt.Errorf("append to a unicast entry: %w", err)
				}
				list, err := vxlanFDBList(idxA)
				if err != nil {
					return err
				}
				if findNeigh(list, "10.1.0.50", mac1) == nil || findNeigh(list, "10.1.0.52", mac1) != nil {
					return fmt.Errorf("after the append to a unicast entry: %+v, want only 10.1.0.50", list)
				}
				if err := netlink.NeighSet(fdb(mac1, "10.1.0.53")); err != nil {
					return fmt.Errorf("replace: %w", err)
				}
				// Two appends build a list of remotes for the all-zeros address.
				for _, n := range []string{"10.1.0.60", "10.1.0.61"} {
					if err := netlink.NeighAppend(fdb(zero, n)); err != nil {
						return fmt.Errorf("append %s: %w", n, err)
					}
				}
				if e := wantErrno("replace of the all-zeros entry", netlink.NeighSet(fdb(zero, "10.1.0.62")), syscall.EOPNOTSUPP); e != nil {
					return e
				}
				if list, err = vxlanFDBList(idxA); err != nil {
					return err
				}
				if findNeigh(list, "10.1.0.53", mac1) == nil || findNeigh(list, "10.1.0.50", mac1) != nil ||
					findNeigh(list, "10.1.0.60", zero) == nil || findNeigh(list, "10.1.0.61", zero) == nil {
					return fmt.Errorf("FDB = %+v, want 10.1.0.53 for the unicast address and both remotes for the zero address", list)
				}
				if err := netlink.NeighDel(fdb(zero, "10.1.0.60")); err != nil {
					return fmt.Errorf("delete one remote: %w", err)
				}
				if list, err = vxlanFDBList(idxA); err != nil {
					return err
				}
				if findNeigh(list, "10.1.0.60", zero) != nil || findNeigh(list, "10.1.0.61", zero) == nil {
					return fmt.Errorf("FDB = %+v, want only the remote 10.1.0.61 for the zero address", list)
				}
				if e := wantErrno("delete of a missing remote", netlink.NeighDel(fdb(zero, "10.1.0.60")), syscall.ENOENT); e != nil {
					return e
				}
				// The last remote removes the entry.
				if err := netlink.NeighDel(fdb(zero, "10.1.0.61")); err != nil {
					return fmt.Errorf("delete the last remote: %w", err)
				}
				if err := netlink.NeighDel(fdb(mac1, "10.1.0.53")); err != nil {
					return err
				}
				if list, err = vxlanFDBList(idxA); err != nil {
					return err
				}
				if findNeigh(list, "10.1.0.61", zero) != nil || findNeigh(list, "10.1.0.53", mac1) != nil {
					return fmt.Errorf("FDB = %+v, want both entries gone", list)
				}
				stale := fdb(mac1, "10.1.0.50")
				stale.State = netlink.NUD_STALE
				if e := wantErrno("a state that is neither permanent nor reachable", netlink.NeighSet(stale), syscall.EINVAL); e != nil {
					return e
				}
				onVeth := fdb(mac1, "10.1.0.50")
				onVeth.LinkIndex = underlayAIdx
				return wantErrno("an FDB entry on a veth", netlink.NeighSet(onVeth), syscall.EOPNOTSUPP)
			})
		}},
		{"deleting-the-fdb-entry-stops-the-traffic", func() error {
			if err := a.do(func() error {
				return netlink.NeighDel(&netlink.Neigh{LinkIndex: idxA, Family: syscall.AF_BRIDGE, Flags: netlink.NTF_SELF, IP: net.ParseIP(vxNodeB), HardwareAddr: macB})
			}); err != nil {
				return err
			}
			if err := vxlanPing(a, vxOverlayB, 3*time.Second); err == nil {
				return errors.New("A reached B after the FDB entry for B was deleted")
			}
			if err := a.do(func() error { return vxlanFDB(idxA, macB, vxNodeB) }); err != nil {
				return err
			}
			return vxlanPing(a, vxOverlayB, 10*time.Second)
		}},
		{"all-zeros-entry-carries-unknown-destinations", func() error {
			zero, _ := net.ParseMAC("00:00:00:00:00:00")
			if err := a.do(func() error {
				if err := netlink.NeighDel(&netlink.Neigh{LinkIndex: idxA, Family: syscall.AF_BRIDGE, Flags: netlink.NTF_SELF, IP: net.ParseIP(vxNodeB), HardwareAddr: macB}); err != nil {
					return err
				}
				return netlink.NeighAppend(&netlink.Neigh{
					LinkIndex: idxA, State: netlink.NUD_PERMANENT, Family: syscall.AF_BRIDGE,
					Flags: netlink.NTF_SELF, IP: net.ParseIP(vxNodeB), HardwareAddr: zero,
				})
			}); err != nil {
				return err
			}
			if err := vxlanPing(a, vxOverlayB, 10*time.Second); err != nil {
				return fmt.Errorf("A to B through the all-zeros entry: %w", err)
			}
			return a.do(func() error {
				if err := netlink.NeighDel(&netlink.Neigh{LinkIndex: idxA, Family: syscall.AF_BRIDGE, Flags: netlink.NTF_SELF, IP: net.ParseIP(vxNodeB), HardwareAddr: zero}); err != nil {
					return err
				}
				return vxlanFDB(idxA, macB, vxNodeB)
			})
		}},
		{"learning-link-learns-the-peer", func() error {
			// B has no FDB entry for A. Its link learns the MAC of A from the
			// request, so the reply finds its way back.
			var macLA, macLB net.HardwareAddr
			setup := func(t *nsThread, local, overlay string, self *net.HardwareAddr) error {
				return t.do(func() error {
					v, err := vxlanDevice("lrn0", 9, 4790, local, 0, true)
					if err != nil {
						return err
					}
					*self = v.HardwareAddr
					return vxlanAddress("lrn0", overlay)
				})
			}
			if err := setup(a, vxNodeA, "10.245.1.0", &macLA); err != nil {
				return err
			}
			if err := setup(b, vxNodeB, "10.245.2.0", &macLB); err != nil {
				return err
			}
			if err := a.do(func() error { return learningPeer("lrn0", macLB, "10.245.2.0", vxNodeB, true) }); err != nil {
				return err
			}
			if err := b.do(func() error { return learningPeer("lrn0", macLA, "10.245.1.0", vxNodeA, false) }); err != nil {
				return err
			}
			if err := vxlanPing(a, "10.245.2.0", 10*time.Second); err != nil {
				return fmt.Errorf("A to B: %w", err)
			}
			return b.do(func() error {
				l, err := netlink.LinkByName("lrn0")
				if err != nil {
					return err
				}
				fdb, err := vxlanFDBList(l.Attrs().Index)
				if err != nil {
					return err
				}
				f := findNeigh(fdb, vxNodeA, macLA)
				if f == nil || f.State != netlink.NUD_REACHABLE {
					return fmt.Errorf("FDB of B = %+v, want a reachable entry %v -> %s that it learned", fdb, macLA, vxNodeA)
				}
				return nil
			})
		}},
		{"deleting-the-link-frees-the-port", func() error {
			if err := a.do(func() error {
				l, err := netlink.LinkByName("flannel.1")
				if err != nil {
					return err
				}
				if err := netlink.LinkDel(l); err != nil {
					return err
				}
				if _, err := netlink.LinkByName("flannel.1"); err == nil {
					return errors.New("flannel.1 exists after the deletion")
				}
				if err := bindPort(syscall.AF_INET, syscall.SOCK_DGRAM, 4790); err == nil {
					return errors.New("port 4790 is free while lrn0 holds it")
				}
				l, err = netlink.LinkByName("lrn0")
				if err != nil {
					return err
				}
				if err := netlink.LinkDel(l); err != nil {
					return err
				}
				if err := bindPort(syscall.AF_INET, syscall.SOCK_DGRAM, 4790); err != nil {
					return fmt.Errorf("port 4790 stays busy after the deletion: %w", err)
				}
				if err := bindPort(syscall.AF_INET, syscall.SOCK_DGRAM, 8472); err != nil {
					return fmt.Errorf("port 8472 stays busy after the deletion: %w", err)
				}
				_, err = vxlanDevice("flannel.1", 1, 8472, vxNodeA, 0, false)
				return err
			}); err != nil {
				return err
			}
			// The new link starts with an empty FDB.
			return a.do(func() error {
				l, err := netlink.LinkByName("flannel.1")
				if err != nil {
					return err
				}
				fdb, err := vxlanFDBList(l.Attrs().Index)
				if err != nil || len(fdb) != 0 {
					return fmt.Errorf("FDB of the new link = %+v, %v, want empty", fdb, err)
				}
				return nil
			})
		}},
		{"static-neighbors-have-no-limit", func() error {
			// The old cap was 65,536 for each link and family. Linux keeps a
			// NUD_PERMANENT entry off the garbage collection list, so it has no
			// limit. The check covers an Ethernet link, a vxlan link, and IPv6.
			// It makes 210,000 netlink requests, which take more than 30 s on
			// a loaded runner with the whpx backend or under QEMU TCG.
			return a.doWithin(6*time.Minute, func() error {
				h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
				if err != nil {
					return err
				}
				defer h.Close()
				mac1, _ := net.ParseMAC("02:00:00:00:00:44")
				mac2, _ := net.ParseMAC("02:00:00:00:00:45")
				// An earlier check recreated flannel.1, so read its index again.
				flannel, err := vxlanByName("flannel.1")
				if err != nil {
					return err
				}
				const count = 70000
				v4 := func(i int) net.IP { return net.IPv4(10, 2+byte(i>>16), byte(i>>8), byte(i)) }
				v6 := func(i int) net.IP {
					return net.IP{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
				}
				for _, tc := range []struct {
					name   string
					link   int
					family int
					ip     func(int) net.IP
				}{
					{"Ethernet link", underlayAIdx, netlink.FAMILY_V4, v4},
					{"vxlan link", flannel.Index, netlink.FAMILY_V4, v4},
					{"Ethernet link over IPv6", underlayAIdx, netlink.FAMILY_V6, v6},
				} {
					entry := func(i int) *netlink.Neigh {
						return &netlink.Neigh{LinkIndex: tc.link, State: netlink.NUD_PERMANENT, IP: tc.ip(i), HardwareAddr: mac1}
					}
					for i := range count {
						if err := h.NeighSet(entry(i)); err != nil {
							return fmt.Errorf("%s: entry %d: %w", tc.name, i, err)
						}
					}
					changed := entry(5)
					changed.HardwareAddr = mac2
					if err := h.NeighSet(changed); err != nil {
						return fmt.Errorf("%s: change: %w", tc.name, err)
					}
					list, err := h.NeighList(tc.link, tc.family)
					if err != nil {
						return fmt.Errorf("%s: list: %w", tc.name, err)
					}
					n := 0
					for _, e := range list {
						if e.State&netlink.NUD_PERMANENT != 0 && (bytes.Equal(e.HardwareAddr, mac1) || bytes.Equal(e.HardwareAddr, mac2)) {
							n++
						}
					}
					if n != count {
						return fmt.Errorf("%s: the list holds %d static entries, want %d", tc.name, n, count)
					}
					if err := h.NeighDel(entry(0)); err != nil {
						return fmt.Errorf("%s: delete: %w", tc.name, err)
					}
				}
				return nil
			})
		}},
		{"namespaces-end", func() error {
			a.close()
			b.close()
			return nil
		}},
	}
}

// learningPeer adds the neighbor entry for the peer VTEP address on a link that
// learns. withFDB also adds the FDB entry for the peer MAC and the route.
func learningPeer(name string, mac net.HardwareAddr, overlay, node string, withFDB bool) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	idx := link.Attrs().Index
	if err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex: idx, State: netlink.NUD_PERMANENT, Type: syscall.RTN_UNICAST,
		IP: net.ParseIP(overlay), HardwareAddr: mac,
	}); err != nil {
		return err
	}
	if withFDB {
		if err := vxlanFDB(idx, mac, node); err != nil {
			return err
		}
	}
	_, subnet, _ := net.ParseCIDR(overlay + "/24")
	return netlink.RouteReplace(&netlink.Route{LinkIndex: idx, Gw: net.ParseIP(overlay), Dst: subnet, Flags: syscall.RTNH_F_ONLINK})
}
