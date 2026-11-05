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
	"errors"
	"fmt"
	"net"
	"slices"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
)

// The state checks cover the link state of a wireguard link, as the driver
// of Linux has it: a new link is down and owns no UDP socket, "ip link set up"
// opens the socket on the listen port, "ip link set down" closes it and stops
// the traffic, and a listen port of 0 becomes a port at the first up and stays
// for later ups. The socket belongs to the namespace that created the link,
// also after the link moves to another namespace.

// wgLink returns the link wg name of the calling thread.
func wgLink(name string) (netlink.Link, error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	if l.Type() != "wireguard" {
		return nil, fmt.Errorf("%s has kind %q, want wireguard", name, l.Type())
	}
	return l, nil
}

// requireFlags checks the IFF_UP flag and the operstate of a link.
func requireFlags(name string, up bool) error {
	l, err := wgLink(name)
	if err != nil {
		return err
	}
	a := l.Attrs()
	if got := a.Flags&net.FlagUp != 0; got != up {
		return fmt.Errorf("%s has flags %v, want IFF_UP = %v", name, a.Flags, up)
	}
	if a.Flags&net.FlagPointToPoint == 0 || a.Flags&net.FlagBroadcast != 0 || a.RawFlags&syscall.IFF_NOARP == 0 {
		return fmt.Errorf("%s has flags %v (raw %#x), want POINTOPOINT and NOARP without BROADCAST", name, a.Flags, a.RawFlags)
	}
	var wantOper netlink.LinkOperState = netlink.OperDown
	if up {
		// A Linux wireguard link never sets a carrier, so its operstate is UNKNOWN.
		wantOper = netlink.OperUnknown
	}
	if a.OperState != wantOper {
		return fmt.Errorf("%s has operstate %v, want %v", name, a.OperState, wantOper)
	}
	return nil
}

// portFree reports whether a UDP socket can bind port on the wildcard address
// in the namespace of the calling thread.
func portFree(port uint16) error {
	fd, err := holdUDPPort(int(port))
	if err != nil {
		return err
	}
	return syscall.Close(fd)
}

func wgStateChecks() []check {
	var (
		a, b, c, d               *nsThread
		privA, pubA, privB, pubB [32]byte
	)
	const (
		addrA = "10.9.0.1"
		addrB = "10.9.0.2"
		portA = uint16(51820)
		portB = uint16(51821)
	)
	getFrom := func(t *nsThread, name string) (st *wgState, err error) {
		err = t.do(func() (err error) { st, err = wgGet(name); return })
		return
	}
	pingFrom := func(from *nsThread, dst string, timeout time.Duration) error {
		return from.do(func() error { return ping(net.ParseIP(dst), timeout) })
	}
	return []check{
		{"namespaces-and-veth", func() error {
			var err error
			for _, t := range []**nsThread{&a, &b, &c, &d} {
				if *t, err = newNsThread(); err != nil {
					return err
				}
			}
			if privA, pubA, err = wgKey(); err != nil {
				return err
			}
			if privB, pubB, err = wgKey(); err != nil {
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
		{"new-link-is-down-and-owns-no-port", func() error {
			return a.do(func() error {
				if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "wg0"}}); err != nil {
					return err
				}
				if err := requireFlags("wg0", false); err != nil {
					return err
				}
				port := portA
				if err := wgSet("wg0", wgConfig{priv: &privA, port: &port, peers: []wgPeer{{
					pub: pubB, endpoint: "10.1.0.2:51821", allowed: []string{addrB + "/32"},
				}}}); err != nil {
					return err
				}
				st, err := wgGet("wg0")
				if err != nil {
					return err
				}
				if st.port != portA {
					return fmt.Errorf("listen port of the link that is down = %d, want %d", st.port, portA)
				}
				if err := portFree(portA); err != nil {
					return fmt.Errorf("the link that is down owns the port: %w", err)
				}
				return nil
			})
		}},
		{"up-opens-the-listen-port", func() error {
			return a.do(func() error {
				l, err := wgLink("wg0")
				if err != nil {
					return err
				}
				addr, err := netlink.ParseAddr(addrA + "/24")
				if err != nil {
					return err
				}
				if err := netlink.AddrAdd(l, addr); err != nil {
					return err
				}
				if err := netlink.LinkSetUp(l); err != nil {
					return err
				}
				if err := requireFlags("wg0", true); err != nil {
					return err
				}
				if err := portFree(portA); !errors.Is(err, syscall.EADDRINUSE) {
					return fmt.Errorf("bind of the port of the link that is up = %v, want EADDRINUSE", err)
				}
				return nil
			})
		}},
		{"tunnel-carries-traffic-while-both-links-are-up", func() error {
			if err := b.do(func() error {
				if err := wireguardLinkDown("wg0", addrB+"/24"); err != nil {
					return err
				}
				port := portB
				if err := wgSet("wg0", wgConfig{priv: &privB, port: &port, peers: []wgPeer{{
					pub: pubA, endpoint: "10.1.0.1:51820", allowed: []string{addrA + "/32"},
				}}}); err != nil {
					return err
				}
				l, err := wgLink("wg0")
				if err != nil {
					return err
				}
				return netlink.LinkSetUp(l)
			}); err != nil {
				return err
			}
			if err := pingFrom(a, addrB, 10*time.Second); err != nil {
				return fmt.Errorf("A to B: %w", err)
			}
			return pingFrom(b, addrA, 5*time.Second)
		}},
		{"down-stops-the-traffic-and-frees-the-port", func() error {
			if err := a.do(func() error {
				l, err := wgLink("wg0")
				if err != nil {
					return err
				}
				if err := netlink.LinkSetDown(l); err != nil {
					return err
				}
				if err := requireFlags("wg0", false); err != nil {
					return err
				}
				if err := portFree(portA); err != nil {
					return fmt.Errorf("the port after down: %w", err)
				}
				// The configuration stays, with the port.
				st, err := wgGet("wg0")
				if err != nil {
					return err
				}
				if st.port != portA || len(st.peers) != 1 || st.peers[0].pub != pubB {
					return fmt.Errorf("device after down = port %d with %d peers, want port %d and the peer B", st.port, len(st.peers), portA)
				}
				return nil
			}); err != nil {
				return err
			}
			if err := pingFrom(b, addrA, 2*time.Second); err == nil {
				return errors.New("B reached A while the link of A was down")
			}
			if err := pingFrom(a, addrB, 1500*time.Millisecond); err == nil {
				return errors.New("A reached B while its own link was down")
			}
			return nil
		}},
		{"up-restores-the-traffic", func() error {
			if err := a.do(func() error {
				l, err := wgLink("wg0")
				if err != nil {
					return err
				}
				if err := netlink.LinkSetUp(l); err != nil {
					return err
				}
				if err := portFree(portA); !errors.Is(err, syscall.EADDRINUSE) {
					return fmt.Errorf("bind after up = %v, want EADDRINUSE", err)
				}
				return nil
			}); err != nil {
				return err
			}
			if err := pingFrom(a, addrB, 10*time.Second); err != nil {
				return fmt.Errorf("A to B after up: %w", err)
			}
			return pingFrom(b, addrA, 5*time.Second)
		}},
		{"longest-prefix-wins-and-an-allowed-ip-moves-between-peers", func() error {
			_, pubX, err := wgKey()
			if err != nil {
				return err
			}
			has := func(p *wgPeerState, cidr string) bool { return p != nil && slices.Contains(p.allowed, cidr) }
			peerOf := func(st *wgState, pub [32]byte) *wgPeerState {
				for _, p := range st.peers {
					if p.pub == pub {
						return p
					}
				}
				return nil
			}
			// X owns the network and has no endpoint, and B owns one address of it. The
			// longest prefix sends the address of B to B.
			if err := a.do(func() error {
				return wgSet("wg0", wgConfig{peers: []wgPeer{{pub: pubX, allowed: []string{"10.9.0.0/24"}}}})
			}); err != nil {
				return err
			}
			if err := pingFrom(a, addrB, 10*time.Second); err != nil {
				return fmt.Errorf("A to B with the longer prefix on B: %w", err)
			}
			// X takes the address of B. B loses it, and X has no endpoint.
			if err := a.do(func() error {
				return wgSet("wg0", wgConfig{peers: []wgPeer{{pub: pubX, allowed: []string{addrB + "/32"}}}})
			}); err != nil {
				return err
			}
			st, err := getFrom(a, "wg0")
			if err != nil {
				return err
			}
			if has(peerOf(st, pubB), addrB+"/32") || !has(peerOf(st, pubX), addrB+"/32") {
				return fmt.Errorf("after the move B has %v and X has %v", peerOf(st, pubB).allowed, peerOf(st, pubX).allowed)
			}
			if err := pingFrom(a, addrB, 1500*time.Millisecond); err == nil {
				return errors.New("A reached B after X took its address")
			}
			// B takes the address back.
			if err := a.do(func() error {
				return wgSet("wg0", wgConfig{peers: []wgPeer{{pub: pubB, allowed: []string{addrB + "/32"}}}})
			}); err != nil {
				return err
			}
			if err := pingFrom(a, addrB, 10*time.Second); err != nil {
				return fmt.Errorf("A to B after B took its address back: %w", err)
			}
			return a.do(func() error {
				return wgSet("wg0", wgConfig{peers: []wgPeer{{pub: pubX, flags: wgPeerRemoveMe}}})
			})
		}},
		{"port-zero-becomes-a-port-at-the-first-up-and-stays", func() error {
			var first uint16
			return c.do(func() error {
				if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "wg1"}}); err != nil {
					return err
				}
				zero := uint16(0)
				if err := wgSet("wg1", wgConfig{priv: &privA, port: &zero}); err != nil {
					return err
				}
				if st, err := wgGet("wg1"); err != nil || st.port != 0 {
					return fmt.Errorf("port before the first up = %v, %v, want 0", st, err)
				}
				l, err := wgLink("wg1")
				if err != nil {
					return err
				}
				if err := netlink.LinkSetUp(l); err != nil {
					return err
				}
				st, err := wgGet("wg1")
				if err != nil {
					return err
				}
				if first = st.port; first == 0 {
					return errors.New("the port is still 0 after up")
				}
				if err := portFree(first); !errors.Is(err, syscall.EADDRINUSE) {
					return fmt.Errorf("bind of the picked port %d = %v, want EADDRINUSE", first, err)
				}
				if err := netlink.LinkSetDown(l); err != nil {
					return err
				}
				if st, err = wgGet("wg1"); err != nil || st.port != first {
					return fmt.Errorf("port after down = %v, %v, want the picked port %d", st, err, first)
				}
				if err := netlink.LinkSetUp(l); err != nil {
					return err
				}
				if st, err = wgGet("wg1"); err != nil || st.port != first {
					return fmt.Errorf("port after the second up = %v, %v, want %d again", st, err, first)
				}
				// A set to 0 on a link that is up picks a new port.
				if err := wgSet("wg1", wgConfig{port: &zero}); err != nil {
					return err
				}
				if st, err = wgGet("wg1"); err != nil || st.port == 0 || st.port == first {
					return fmt.Errorf("port after the set to 0 = %v, %v, want a new port", st, err)
				}
				return nil
			})
		}},
		{"busy-port-fails-the-up-and-the-link-stays-down", func() error {
			return c.do(func() error {
				fd, err := holdUDPPort(52001)
				if err != nil {
					return err
				}
				defer syscall.Close(fd)
				if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "wg2"}}); err != nil {
					return err
				}
				port := uint16(52001)
				// Linux binds at up, so the set of a busy port on a link that is down succeeds.
				if err := wgSet("wg2", wgConfig{port: &port}); err != nil {
					return fmt.Errorf("set of a busy port on a link that is down = %w", err)
				}
				l, err := wgLink("wg2")
				if err != nil {
					return err
				}
				if err := netlink.LinkSetUp(l); !errors.Is(err, syscall.EADDRINUSE) {
					return fmt.Errorf("up on the busy port = %v, want EADDRINUSE", err)
				}
				if err := requireFlags("wg2", false); err != nil {
					return err
				}
				syscall.Close(fd)
				fd = -1
				if err := netlink.LinkSetUp(l); err != nil {
					return fmt.Errorf("up after the port became free: %w", err)
				}
				return requireFlags("wg2", true)
			})
		}},
		{"socket-stays-in-the-namespace-of-the-creation", func() error {
			const port = uint16(52010)
			// c creates wg3 and moves it to d. The socket belongs to c.
			if err := c.do(func() error {
				if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "wg3"}}); err != nil {
					return err
				}
				l, err := wgLink("wg3")
				if err != nil {
					return err
				}
				return netlink.LinkSetNsFd(l, d.fd)
			}); err != nil {
				return err
			}
			if err := c.do(func() error {
				if _, err := wgLink("wg3"); err == nil {
					return errors.New("wg3 is still in the namespace that created it")
				}
				return nil
			}); err != nil {
				return err
			}
			if err := d.do(func() error {
				p := port
				if err := wgSet("wg3", wgConfig{port: &p}); err != nil {
					return err
				}
				l, err := wgLink("wg3")
				if err != nil {
					return err
				}
				// Linux closes a device that moves to another namespace.
				if err := requireFlags("wg3", false); err != nil {
					return fmt.Errorf("after the move: %w", err)
				}
				if err := netlink.LinkSetUp(l); err != nil {
					return err
				}
				return portFree(port)
			}); err != nil {
				return fmt.Errorf("in the new namespace the port must be free, because the socket is in the old one: %w", err)
			}
			if err := c.do(func() error {
				if err := portFree(port); !errors.Is(err, syscall.EADDRINUSE) {
					return fmt.Errorf("bind in the namespace of the creation = %v, want EADDRINUSE", err)
				}
				return nil
			}); err != nil {
				return err
			}
			// Deleting the link frees the socket in the old namespace.
			if err := d.do(func() error {
				l, err := wgLink("wg3")
				if err != nil {
					return err
				}
				return netlink.LinkDel(l)
			}); err != nil {
				return err
			}
			return c.do(func() error { return portFree(port) })
		}},
		{"namespaces-end", func() error {
			for _, t := range []*nsThread{a, b, c, d} {
				t.close()
			}
			return nil
		}},
	}
}

// wireguardLinkDown creates a wireguard link with an address and leaves it down.
func wireguardLinkDown(name, cidr string) error {
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
		return err
	}
	l, err := wgLink(name)
	if err != nil {
		return err
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return err
	}
	return netlink.AddrAdd(l, addr)
}
