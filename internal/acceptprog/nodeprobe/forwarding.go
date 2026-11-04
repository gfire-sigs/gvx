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
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
)

// The forwarding check builds three network namespaces in a line: A, R, and B.
// A links to R over 10.1.0.0/24, and R links to B over 10.2.0.0/24. A and B
// send everything to R. A reaches B only when R forwards packets.

// icmpChecksum returns the Internet checksum of b.
func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// ping sends ICMP echo requests to dst on a datagram ICMP socket and waits for
// an echo reply. It returns nil when a reply arrives within the timeout.
func ping(dst net.IP, timeout time.Duration) error {
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
	buf := make([]byte, 128)
	deadline := time.Now().Add(timeout)
	for seq := 1; time.Now().Before(deadline); seq++ {
		req := []byte{8, 0, 0, 0, 0, 1, byte(seq >> 8), byte(seq), 'g', 'v', 'x'}
		sum := icmpChecksum(req)
		req[2], req[3] = byte(sum>>8), byte(sum)
		if err := syscall.Sendto(fd, req, 0, &to); err != nil {
			return fmt.Errorf("send: %w", err)
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) {
				continue
			}
			return fmt.Errorf("receive: %w", err)
		}
		if n >= 8 && buf[0] == 0 {
			return nil
		}
	}
	return fmt.Errorf("no echo reply from %s in %v", dst, timeout)
}

// configureLink sets the address of a link, brings it up, and brings lo up. It
// runs on the thread of the namespace that holds the link.
func configureLink(name, cidr string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("find %s: %w", name, err)
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("add %s to %s: %w", cidr, name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("set %s up: %w", name, err)
	}
	return nil
}

// addDefaultRoute sends all IPv4 traffic to gateway through the link.
func addDefaultRoute(name, gateway string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Gw: net.ParseIP(gateway)}); err != nil {
		return fmt.Errorf("add the default route through %s: %w", gateway, err)
	}
	return nil
}

// forwardingFiles are the files that switch forwarding of the links that exist.
// conf/default/forwarding sets only the links that the guest creates later.
var forwardingFiles = []string{forwardingAllFile, ipForwardFile}

// addLinkPair creates a veth pair on the thread of near and moves the far end
// into the namespace of peer.
func addLinkPair(near *nsThread, nearName, farName string, peer *nsThread) error {
	return near.do(func() error {
		veth := &netlink.Veth{
			LinkAttrs:     netlink.LinkAttrs{Name: nearName},
			PeerName:      farName,
			PeerNamespace: netlink.NsFd(peer.fd),
		}
		if err := netlink.LinkAdd(veth); err != nil {
			return fmt.Errorf("create %s and %s: %w", nearName, farName, err)
		}
		return nil
	})
}

// addRoute sends the destination network to gateway through the link.
func addRoute(name, dst, gateway string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	_, network, err := net.ParseCIDR(dst)
	if err != nil {
		return err
	}
	if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: network, Gw: net.ParseIP(gateway)}); err != nil {
		return fmt.Errorf("add the route to %s through %s: %w", dst, gateway, err)
	}
	return nil
}

// inheritChecks checks that a new network namespace gets the IPv4 forwarding
// switches of the root namespace, and the default of 0 for IPv6.
func inheritChecks() []check {
	const ipv6All = "/proc/sys/net/ipv6/conf/all/forwarding"
	childValues := func(files map[string]string) error {
		return inNewNetns(func() error {
			for file, want := range files {
				if err := expectValue(file, want); err != nil {
					return fmt.Errorf("in a new namespace: %w", err)
				}
			}
			return nil
		})
	}
	return []check{
		{"new-netns-inherits-ipv4-forwarding-of-the-root", func() error {
			// All on and default off: the new namespace gets the same pair.
			if err := writeValue(ipForwardFile, "1"); err != nil {
				return err
			}
			defer writeValue(ipForwardFile, "0")
			if err := writeAndExpect(forwardingDefaultFile, "0", "0"); err != nil {
				return err
			}
			return childValues(map[string]string{forwardingAllFile: "1", ipForwardFile: "1", forwardingDefaultFile: "0"})
		}},
		{"new-netns-starts-with-ipv6-forwarding-off", func() error {
			if err := writeValue(ipv6All, "1"); err != nil {
				return err
			}
			defer writeValue(ipv6All, "0")
			return childValues(map[string]string{ipv6All: "0"})
		}},
		{"new-netns-follows-the-root-when-forwarding-is-off", func() error {
			if err := writeAndExpect(ipForwardFile, "0", "0"); err != nil {
				return err
			}
			return childValues(map[string]string{forwardingAllFile: "0", forwardingDefaultFile: "0"})
		}},
	}
}

func forwardingChecks() []check {
	var a, r, b *nsThread
	target := net.IPv4(10, 2, 0, 2)
	checks := inheritChecks()
	checks = append(checks, []check{
		{"three-namespaces-start", func() error {
			var err error
			for _, t := range []**nsThread{&a, &r, &b} {
				if *t, err = newNsThread(); err != nil {
					return err
				}
			}
			return nil
		}},
		{"veth-pairs-link-the-namespaces", func() error {
			// R creates both pairs and moves the far ends into A and B.
			if err := addLinkPair(r, "r0", "a0", a); err != nil {
				return err
			}
			return addLinkPair(r, "r1", "b0", b)
		}},
		{"addresses-and-routes", func() error {
			steps := []struct {
				t    *nsThread
				fn   func() error
				what string
			}{
				{a, func() error { return configureLink("a0", "10.1.0.2/24") }, "A"},
				{a, func() error { return addDefaultRoute("a0", "10.1.0.1") }, "A route"},
				{b, func() error { return configureLink("b0", "10.2.0.2/24") }, "B"},
				{b, func() error { return addDefaultRoute("b0", "10.2.0.1") }, "B route"},
				{r, func() error { return configureLink("r0", "10.1.0.1/24") }, "R 0"},
				{r, func() error { return configureLink("r1", "10.2.0.1/24") }, "R 1"},
			}
			for _, s := range steps {
				if err := s.t.do(s.fn); err != nil {
					return fmt.Errorf("%s: %w", s.what, err)
				}
			}
			return nil
		}},
		{"router-starts-with-forwarding-off", func() error {
			return r.do(func() error { return expectValue(forwardingAllFile, "0") })
		}},
		{"a-reaches-r", func() error {
			return a.do(func() error { return ping(net.IPv4(10, 1, 0, 1), 5*time.Second) })
		}},
	}...)
	for _, file := range forwardingFiles {
		checks = append(checks,
			check{"forwarding-off-blocks-a-to-b via " + file, func() error {
				if err := r.do(func() error { return writeAndExpect(file, "0", "0") }); err != nil {
					return err
				}
				if err := a.do(func() error { return ping(target, 1500*time.Millisecond) }); err == nil {
					return fmt.Errorf("A reached %s while forwarding was off", target)
				}
				return nil
			}},
			check{"forwarding-on-lets-a-reach-b via " + file, func() error {
				if err := r.do(func() error { return writeAndExpect(file, "1", "1") }); err != nil {
					return err
				}
				return a.do(func() error { return ping(target, 5*time.Second) })
			}},
		)
	}
	newTarget := net.IPv4(10, 4, 0, 2)
	checks = append(checks,
		check{"default-forwarding-leaves-existing-links-off", func() error {
			err := r.do(func() error {
				if err := writeAndExpect(forwardingAllFile, "0", "0"); err != nil {
					return err
				}
				if err := writeAndExpect(forwardingDefaultFile, "1", "1"); err != nil {
					return err
				}
				return expectValue(forwardingAllFile, "0")
			})
			if err != nil {
				return err
			}
			if err := a.do(func() error { return ping(target, 1500*time.Millisecond) }); err == nil {
				return fmt.Errorf("A reached %s over links that existed before conf/default/forwarding changed", target)
			}
			return nil
		}},
		check{"links-created-after-default-forwarding-forward", func() error {
			// Both new links of R take forwarding from the default of R.
			if err := addLinkPair(r, "r2", "a1", a); err != nil {
				return err
			}
			if err := addLinkPair(r, "r3", "b1", b); err != nil {
				return err
			}
			steps := []struct {
				t  *nsThread
				fn func() error
			}{
				{a, func() error { return configureLink("a1", "10.3.0.2/24") }},
				{a, func() error { return addRoute("a1", "10.4.0.0/24", "10.3.0.1") }},
				{b, func() error { return configureLink("b1", "10.4.0.2/24") }},
				{b, func() error { return addRoute("b1", "10.3.0.0/24", "10.4.0.1") }},
				{r, func() error { return configureLink("r2", "10.3.0.1/24") }},
				{r, func() error { return configureLink("r3", "10.4.0.1/24") }},
			}
			for _, s := range steps {
				if err := s.t.do(s.fn); err != nil {
					return err
				}
			}
			return a.do(func() error { return ping(newTarget, 5*time.Second) })
		}},
	)
	return checks
}
