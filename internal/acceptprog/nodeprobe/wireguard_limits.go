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
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

// The limits checks cover the rules of the wireguard link that the basic
// checks leave out: the order and the atomicity of a set request, the lookup
// of the device, the capability check of the creating namespace, the size of a
// dump, and the limits of 256 links in a sandbox and 4,096 peers on a device.

const (
	// wgMaxLinks and wgMaxPeers are the limits of the guest kernel.
	wgMaxLinks = 256
	wgMaxPeers = 4096
)

// holdUDPPort binds a UDP socket to the wildcard address and keeps it open.
func holdUDPPort(port int) (fd int, err error) {
	fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return -1, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: port}); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

// addExtraPeers sends the set requests that add the extra peers first to
// last-1, a hundred in each request. Each peer has a random key and one allowed IP
// address of 172.16.0.0/12.
func addExtraPeers(t *nsThread, ifname string, first, last int) error {
	for start := first; start < last; start += 100 {
		var peers []wgPeer
		for i := start; i < min(start+100, last); i++ {
			var p wgPeer
			if _, err := rand.Read(p.pub[:]); err != nil {
				return err
			}
			p.allowed = []string{fmt.Sprintf("172.%d.%d.%d/32", 16+i>>16, i>>8&255, i&255)}
			peers = append(peers, p)
		}
		if err := t.do(func() error { return wgSet(ifname, wgConfig{peers: peers}) }); err != nil {
			return fmt.Errorf("peers %d to %d: %w", start, start+len(peers), err)
		}
	}
	return nil
}

func wgLimitsChecks() []check {
	var (
		a, b                     *nsThread
		privA, pubA, privB, pubB [32]byte
		portA, portB             = uint16(51820), uint16(51821)
	)
	const (
		addrA = "10.9.0.1"
		addrB = "10.9.0.2"
	)
	pingFrom := func(from *nsThread, dst string, timeout time.Duration) error {
		return from.do(func() error { return ping(net.ParseIP(dst), timeout) })
	}
	getA := func() (st *wgState, err error) {
		err = a.do(func() (err error) { st, err = wgGet("wg0"); return })
		return
	}
	// total is the count of peers on A.
	total := 2
	return []check{
		{"pair-starts-with-two-peers-on-a", func() error {
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
			if err := addLinkPair(a, "va0", "vb0", b); err != nil {
				return err
			}
			if err := a.do(func() error { return configureLink("va0", "10.1.0.1/30") }); err != nil {
				return err
			}
			if err := b.do(func() error { return configureLink("vb0", "10.1.0.2/30") }); err != nil {
				return err
			}
			if err := a.do(func() error { return wireguardLink("wg0", addrA+"/24") }); err != nil {
				return err
			}
			if err := b.do(func() error { return wireguardLink("wg0", addrB+"/24") }); err != nil {
				return err
			}
			_, pubX, err := wgKey()
			if err != nil {
				return err
			}
			if err := a.do(func() error {
				return wgSet("wg0", wgConfig{priv: &privA, port: &portA, peers: []wgPeer{
					{pub: pubB, endpoint: "10.1.0.2:51821", allowed: []string{addrB + "/32"}},
					{pub: pubX, allowed: []string{"10.8.0.0/16"}},
				}})
			}); err != nil {
				return err
			}
			if err := b.do(func() error {
				return wgSet("wg0", wgConfig{priv: &privB, port: &portB, peers: []wgPeer{
					{pub: pubA, endpoint: "10.1.0.1:51820", allowed: []string{addrA + "/32"}},
				}})
			}); err != nil {
				return err
			}
			return pingFrom(a, addrB, 10*time.Second)
		}},
		{"busy-port-is-refused-before-any-change", func() error {
			var fd int
			if err := a.do(func() (err error) { fd, err = holdUDPPort(51900); return }); err != nil {
				return err
			}
			defer syscall.Close(fd)
			port := uint16(51900)
			err := a.do(func() error {
				return wgSet("wg0", wgConfig{flags: wgDeviceReplacePeers, port: &port, priv: &privB})
			})
			if !errors.Is(err, syscall.EADDRINUSE) {
				return fmt.Errorf("set to a busy port = %v, want EADDRINUSE", err)
			}
			st, err := getA()
			if err != nil {
				return err
			}
			if st.port != portA || len(st.peers) != 2 || !bytes.Equal(st.priv, privA[:]) {
				return fmt.Errorf("device after the refused set = port %d, %d peers", st.port, len(st.peers))
			}
			return pingFrom(a, addrB, 5*time.Second)
		}},
		{"set-to-the-current-port-succeeds", func() error {
			if err := a.do(func() error { return wgSet("wg0", wgConfig{port: &portA}) }); err != nil {
				return err
			}
			return pingFrom(a, addrB, 5*time.Second)
		}},
		{"set-to-a-free-port-moves-the-socket", func() error {
			port := uint16(51901)
			if err := a.do(func() error { return wgSet("wg0", wgConfig{port: &port}) }); err != nil {
				return err
			}
			st, err := getA()
			if err != nil {
				return err
			}
			if st.port != port {
				return fmt.Errorf("port after the set = %d, want %d", st.port, port)
			}
			if err := b.do(func() error {
				return wgSet("wg0", wgConfig{peers: []wgPeer{{pub: pubA, endpoint: "10.1.0.1:51901"}}})
			}); err != nil {
				return err
			}
			if err := pingFrom(a, addrB, 10*time.Second); err != nil {
				return err
			}
			// The old port is free again.
			return a.do(func() error { return bindPort(syscall.AF_INET, syscall.SOCK_DGRAM, int(portA)) })
		}},
		{"lookup-needs-exactly-one-selector", func() error {
			return a.do(func() error {
				idx := nl.NewRtAttr(wgDevIfindex, u32(1))
				name := nl.NewRtAttr(wgDevIfname, nl.ZeroTerminated("wg0"))
				if err := wgSetWith(wgConfig{}, idx, name); !errors.Is(err, syscall.EBADR) {
					return fmt.Errorf("set with both selectors = %v, want EBADR", err)
				}
				if err := wgSetWith(wgConfig{}); !errors.Is(err, syscall.EBADR) {
					return fmt.Errorf("set with no selector = %v, want EBADR", err)
				}
				if _, err := wgGetWith(idx, name); !errors.Is(err, syscall.EBADR) {
					return fmt.Errorf("get with both selectors = %v, want EBADR", err)
				}
				if _, err := wgGetWith(); !errors.Is(err, syscall.EBADR) {
					return fmt.Errorf("get with no selector = %v, want EBADR", err)
				}
				return nil
			})
		}},
		{"unsupported-protocol-version-is-epfnosupport", func() error {
			v := uint32(2)
			err := a.do(func() error {
				return wgSet("wg0", wgConfig{peers: []wgPeer{{pub: pubB, proto: &v}}})
			})
			if !errors.Is(err, syscall.EPFNOSUPPORT) {
				return fmt.Errorf("set with protocol version 2 = %v, want EPFNOSUPPORT", err)
			}
			return nil
		}},
		{"listen-port-needs-cap-net-admin-in-the-creating-namespace", wgChildCheck},
		{"dump-of-800-peers-is-complete", func() error {
			if err := addExtraPeers(a, "wg0", total-2, 798); err != nil {
				return err
			}
			total = 800
			st, err := getA()
			if err != nil {
				return err
			}
			if len(st.peers) != total {
				return fmt.Errorf("the dump has %d peers, want %d", len(st.peers), total)
			}
			return nil
		}},
		{"dump-over-the-queue-fails-with-enobufs", func() error {
			if err := addExtraPeers(a, "wg0", total-2, 1998); err != nil {
				return err
			}
			total = 2000
			st, err := getA()
			if err == nil {
				// A complete answer is also correct. A short one is not.
				if len(st.peers) != total {
					return fmt.Errorf("the dump has %d peers and no error, want %d or an error", len(st.peers), total)
				}
				return nil
			}
			if !errors.Is(err, syscall.ENOBUFS) {
				return fmt.Errorf("dump of %d peers = %v, want ENOBUFS", total, err)
			}
			return nil
		}},
		{"peer-limit-is-enomem", func() error {
			if err := addExtraPeers(a, "wg0", total-2, wgMaxPeers-2); err != nil {
				return err
			}
			total = wgMaxPeers
			var extra wgPeer
			if _, err := rand.Read(extra.pub[:]); err != nil {
				return err
			}
			err := a.do(func() error { return wgSet("wg0", wgConfig{peers: []wgPeer{extra}}) })
			if !errors.Is(err, syscall.ENOMEM) {
				return fmt.Errorf("peer %d = %v, want ENOMEM", wgMaxPeers+1, err)
			}
			// A request that replaces every peer is within the limit.
			return a.do(func() error {
				return wgSet("wg0", wgConfig{flags: wgDeviceReplacePeers, peers: []wgPeer{extra}})
			})
		}},
		{"link-limit-is-enomem", func() error {
			// The pair holds two links. A third thread adds the rest.
			l, err := newNsThread()
			if err != nil {
				return err
			}
			defer l.close()
			var names []string
			var addErr error
			err = l.do(func() error {
				for i := range wgMaxLinks + 10 {
					name := fmt.Sprintf("wl%d", i)
					if addErr = netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name}}); addErr != nil {
						return nil
					}
					names = append(names, name)
				}
				return nil
			})
			if err != nil {
				return err
			}
			if !errors.Is(addErr, syscall.ENOMEM) || len(names) != wgMaxLinks-2 {
				return fmt.Errorf("the links ended with %v after %d links, want ENOMEM after %d", addErr, len(names), wgMaxLinks-2)
			}
			return l.do(func() error {
				for _, name := range names[:2] {
					link, err := netlink.LinkByName(name)
					if err != nil {
						return err
					}
					if err := netlink.LinkDel(link); err != nil {
						return err
					}
				}
				// A deleted link frees its place.
				if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "wlx"}}); err != nil {
					return fmt.Errorf("a link after two deletions: %w", err)
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

// wgChildCheck creates a link in a namespace of the init user namespace, moves
// it into a network namespace of a child user namespace, and runs "nodeprobe
// wgchild" there. The child has CAP_NET_ADMIN over its own namespaces only.
func wgChildCheck() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	parent, err := newNsThread()
	if err != nil {
		return err
	}
	defer parent.close()
	if err := parent.do(func() error {
		if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "wg0"}}); err != nil {
			return err
		}
		port := uint16(51910)
		return wgSet("wg0", wgConfig{port: &port})
	}); err != nil {
		return err
	}
	cmd := exec.Command(exe, "wgchild")
	// The child maps its user to root of its user namespace, so that execve
	// keeps its capabilities there.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}},
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start the child in new user and network namespaces: %w", err)
	}
	lines := bufio.NewScanner(stdout)
	waitErr := func() error {
		if err := cmd.Wait(); err != nil {
			return fmt.Errorf("child: %w\n%s", err, stderr.String())
		}
		return nil
	}
	if !lines.Scan() || lines.Text() != "CHILD-READY" {
		cmd.Process.Kill()
		waitErr()
		return fmt.Errorf("the child did not start: %q %s", lines.Text(), stderr.String())
	}
	fd, err := syscall.Open(fmt.Sprintf("/proc/%d/ns/net", cmd.Process.Pid), syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		cmd.Process.Kill()
		waitErr()
		return fmt.Errorf("open the network namespace of the child: %w", err)
	}
	defer syscall.Close(fd)
	if err := parent.do(func() error {
		link, err := netlink.LinkByName("wg0")
		if err != nil {
			return err
		}
		return netlink.LinkSetNsFd(link, fd)
	}); err != nil {
		cmd.Process.Kill()
		waitErr()
		return fmt.Errorf("move the link: %w", err)
	}
	var out []string
	for lines.Scan() {
		out = append(out, lines.Text())
	}
	if err := waitErr(); err != nil {
		return fmt.Errorf("%w\nchild output: %s", err, strings.Join(out, "; "))
	}
	if len(out) == 0 || out[len(out)-1] != "CHILD-OK" {
		return fmt.Errorf("child output: %s", strings.Join(out, "; "))
	}
	return nil
}

// wgChild runs in a network namespace of a child user namespace. It waits for
// the link wg0 and checks which requests it may send.
func wgChild() error {
	fmt.Println("CHILD-READY")
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := netlink.LinkByName("wg0"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("the link wg0 did not arrive in 30s")
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, pub, err := wgKey()
	if err != nil {
		return err
	}
	// The namespace of the child owns the link now, but the sockets belong to
	// the namespace that created it.
	if err := wgSet("wg0", wgConfig{peers: []wgPeer{{pub: pub, allowed: []string{"10.5.0.0/16"}}}}); err != nil {
		return fmt.Errorf("set of a peer: %w", err)
	}
	port := uint16(51911)
	if err := wgSet("wg0", wgConfig{port: &port}); !errors.Is(err, syscall.EPERM) {
		return fmt.Errorf("set of the listen port = %v, want EPERM", err)
	}
	mark := uint32(7)
	if err := wgSet("wg0", wgConfig{mark: &mark}); !errors.Is(err, syscall.EPERM) {
		return fmt.Errorf("set of the mark = %v, want EPERM", err)
	}
	st, err := wgGet("wg0")
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	if st.port != 51910 || len(st.peers) != 1 {
		return fmt.Errorf("device = port %d, %d peers, want port 51910 and 1 peer", st.port, len(st.peers))
	}
	fmt.Println("CHILD-OK")
	return nil
}
