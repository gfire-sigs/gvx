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
	"os"
	"syscall"

	"github.com/vishvananda/netlink"
)

// The neighgc checks cover the neighbor table limits of Linux: the files
// gc_thresh1, gc_thresh2, and gc_thresh3 for ARP and ND, the namespace of the
// reader, and the effect of gc_thresh3 on dynamic entries.

var neighFamilies = []string{"ipv4", "ipv6"}

func gcThreshPath(family string, n int) string {
	return fmt.Sprintf("/proc/sys/net/%s/neigh/default/gc_thresh%d", family, n)
}

var gcThreshDefaults = [4]string{"", "128", "512", "1024"}

// dynamicNeighbors returns the entries of the link that are not permanent.
func dynamicNeighbors(link int) (int, error) {
	list, err := netlink.NeighList(link, syscall.AF_INET)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range list {
		if e.State&netlink.NUD_PERMANENT == 0 {
			n++
		}
	}
	return n, nil
}

// sendTo sends one UDP datagram to the address. Its route resolution creates a
// dynamic neighbor entry, which the stack removes after a failed resolution.
func sendTo(fd int, ip string) error {
	return syscall.Sendto(fd, []byte("x"), 0, &syscall.SockaddrInet4{Port: 9, Addr: [4]byte(net.ParseIP(ip).To4())})
}

func neighGCChecks() []check {
	var a, b *nsThread
	var link int
	return []check{
		{"gc-thresh-files-start-at-the-linux-defaults", func() error {
			for _, family := range neighFamilies {
				for n := 1; n <= 3; n++ {
					if err := expectValue(gcThreshPath(family, n), gcThreshDefaults[n]); err != nil {
						return err
					}
					fi, err := os.Stat(gcThreshPath(family, n))
					if err != nil || fi.Mode().Perm() != 0644 {
						return fmt.Errorf("%s has mode %v (%v), want 0644", gcThreshPath(family, n), fi.Mode().Perm(), err)
					}
				}
			}
			return nil
		}},
		{"gc-thresh-files-accept-0-to-int-max", func() error {
			for _, family := range neighFamilies {
				for n := 1; n <= 3; n++ {
					path := gcThreshPath(family, n)
					for _, text := range []string{"-1", "2147483648", "x", "1 2"} {
						if err := rejectValue(path, text); err != nil {
							return err
						}
					}
					for _, v := range []string{"0", "2147483647", gcThreshDefaults[n]} {
						if err := writeAndExpect(path, v+"\n", v); err != nil {
							return err
						}
					}
				}
			}
			// Linux does not compare the three values with each other.
			if err := writeAndExpect(gcThreshPath("ipv4", 3), "1", "1"); err != nil {
				return err
			}
			return writeAndExpect(gcThreshPath("ipv4", 3), "1024", "1024")
		}},
		{"gc-thresh-files-belong-to-the-network-namespace", func() error {
			child, err := newNsThread()
			if err != nil {
				return err
			}
			defer child.close()
			err = child.do(func() error {
				for _, family := range neighFamilies {
					for n := 1; n <= 3; n++ {
						if err := expectValue(gcThreshPath(family, n), gcThreshDefaults[n]); err != nil {
							return fmt.Errorf("new namespace: %w", err)
						}
					}
				}
				if err := writeAndExpect(gcThreshPath("ipv4", 3), "7", "7"); err != nil {
					return err
				}
				return writeAndExpect(gcThreshPath("ipv6", 2), "9", "9")
			})
			if err != nil {
				return err
			}
			if err := expectValue(gcThreshPath("ipv4", 3), "1024"); err != nil {
				return fmt.Errorf("a write in the child changed the parent: %w", err)
			}
			if err := expectValue(gcThreshPath("ipv6", 2), "512"); err != nil {
				return fmt.Errorf("a write in the child changed the parent: %w", err)
			}
			if err := writeAndExpect(gcThreshPath("ipv4", 1), "5", "5"); err != nil {
				return err
			}
			err = child.do(func() error { return expectValue(gcThreshPath("ipv4", 1), "128") })
			if err != nil {
				return fmt.Errorf("a write in the parent changed the child: %w", err)
			}
			return writeAndExpect(gcThreshPath("ipv4", 1), "128", "128")
		}},
		{"link-and-sender", func() error {
			var err error
			if a, err = newNsThread(); err != nil {
				return err
			}
			if b, err = newNsThread(); err != nil {
				return err
			}
			if err := addLinkPair(a, "ng0", "ng1", b); err != nil {
				return err
			}
			if err := b.do(func() error { return configureLink("ng1", "10.50.0.2/24") }); err != nil {
				return err
			}
			return a.do(func() error {
				if err := configureLink("ng0", "10.50.0.1/24"); err != nil {
					return err
				}
				l, err := netlink.LinkByName("ng0")
				link = l.Attrs().Index
				return err
			})
		}},
		{"dynamic-entries-stop-at-gc-thresh3-and-static-entries-do-not-count", func() error {
			return a.do(func() error {
				if err := writeValue(gcThreshPath("ipv4", 2), "3"); err != nil {
					return err
				}
				if err := writeValue(gcThreshPath("ipv4", 3), "3"); err != nil {
					return err
				}
				// Nobody answers ARP, so the entries stay incomplete for about
				// three seconds. A forced collection cannot remove them.
				fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
				if err != nil {
					return err
				}
				defer syscall.Close(fd)
				for i := range 3 {
					if err := sendTo(fd, fmt.Sprintf("10.50.0.%d", 11+i)); err != nil {
						return fmt.Errorf("datagram %d: %w", i, err)
					}
				}
				// Static entries do not count, so 100 of them leave the limit alone.
				mac, _ := net.ParseMAC("02:00:00:00:00:77")
				for i := range 100 {
					err := netlink.NeighSet(&netlink.Neigh{
						LinkIndex: link, State: netlink.NUD_PERMANENT, IP: net.IPv4(10, 60, 0, byte(i+1)), HardwareAddr: mac,
					})
					if err != nil {
						return fmt.Errorf("static entry %d: %w", i, err)
					}
				}
				// The datagram that needs a fourth entry is dropped. Linux logs
				// "neighbor table overflow!", and the table keeps three entries.
				_ = sendTo(fd, "10.50.0.21")
				if n, err := dynamicNeighbors(link); err != nil || n != 3 {
					return fmt.Errorf("the table holds %d dynamic entries (%v), want 3", n, err)
				}
				// Raising gc_thresh3 makes room at once.
				if err := writeValue(gcThreshPath("ipv4", 3), "1024"); err != nil {
					return err
				}
				if err := sendTo(fd, "10.50.0.21"); err != nil {
					return fmt.Errorf("the datagram after the rise of gc_thresh3: %w", err)
				}
				if n, err := dynamicNeighbors(link); err != nil || n != 4 {
					return fmt.Errorf("the table holds %d dynamic entries (%v), want 4", n, err)
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

// recentParamChecks checks the module parameters of xt_recent that
// /sys/module/xt_recent/parameters shows.
func recentParamChecks() []check {
	const dir = "/sys/module/xt_recent/parameters/"
	return []check{
		{"parameters-start-at-the-linux-defaults", func() error {
			if err := expectValue(dir+"ip_list_tot", "100"); err != nil {
				return err
			}
			return expectValue(dir+"ip_pkt_list_tot", "0")
		}},
		{"parameters-have-mode-0400", func() error {
			for _, name := range []string{"ip_list_tot", "ip_pkt_list_tot"} {
				fi, err := os.Stat(dir + name)
				if err != nil || fi.Mode().Perm() != 0400 {
					return fmt.Errorf("%s has mode %v (%v), want 0400", name, fi.Mode().Perm(), err)
				}
			}
			return nil
		}},
		{"values-that-recent_mt_init-refuses-fail-with-einval", func() error {
			for _, tc := range []struct{ name, text string }{
				{"ip_list_tot", "0"}, {"ip_list_tot", "x"}, {"ip_list_tot", "-1"}, {"ip_list_tot", "1 2"},
				{"ip_pkt_list_tot", "65536"},
			} {
				if err := rejectValue(dir+tc.name, tc.text); err != nil {
					return err
				}
			}
			return nil
		}},
		{"values-above-32-bits-fail-with-erange", func() error {
			for _, name := range []string{"ip_list_tot", "ip_pkt_list_tot"} {
				if err := writeValue(dir+name, "4294967296"); !errors.Is(err, syscall.ERANGE) {
					return fmt.Errorf("write 2^32 to %s = %v, want ERANGE", name, err)
				}
			}
			return expectValue(dir+"ip_list_tot", "100")
		}},
		{"root-writes-while-no-list-exists", func() error {
			if err := writeAndExpect(dir+"ip_list_tot", "2\n", "2"); err != nil {
				return err
			}
			if err := writeAndExpect(dir+"ip_pkt_list_tot", "0x10", "16"); err != nil {
				return err
			}
			if err := writeAndExpect(dir+"ip_list_tot", "4294967295", "4294967295"); err != nil {
				return err
			}
			if err := writeAndExpect(dir+"ip_pkt_list_tot", "65535", "65535"); err != nil {
				return err
			}
			if err := writeAndExpect(dir+"ip_list_tot", "100", "100"); err != nil {
				return err
			}
			return writeAndExpect(dir+"ip_pkt_list_tot", "0", "0")
		}},
		{"a-child-namespace-reads-the-same-values", func() error {
			if err := writeValue(dir+"ip_list_tot", "11"); err != nil {
				return err
			}
			child, err := newNsThread()
			if err != nil {
				return err
			}
			defer child.close()
			if err := child.do(func() error { return expectValue(dir+"ip_list_tot", "11") }); err != nil {
				return fmt.Errorf("module parameters belong to the kernel: %w", err)
			}
			return writeAndExpect(dir+"ip_list_tot", "100", "100")
		}},
	}
}
