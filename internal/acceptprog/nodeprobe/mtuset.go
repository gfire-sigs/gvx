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
	"runtime"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The mtuset checks change the MTU of eth0 with RTM_SETLINK, as "ip link set
// dev eth0 mtu N" does. After each change they read the MTU through netlink and
// sysfs, and they move 1 MiB in each direction through the NAT to a server on
// the host. They also check the Linux range: a link accepts 68 to 65535, and a
// value outside that range fails with EINVAL.

const (
	linuxMinMTU = 68
	linuxMaxMTU = 65535
	mtuSetMiB   = 1
)

// setLinkMTU sets the MTU of a link and checks the value in netlink and sysfs.
func setLinkMTU(name string, mtu int) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return fmt.Errorf("set the MTU of %s to %d: %w", name, mtu, err)
	}
	if link, err = netlink.LinkByName(name); err != nil {
		return err
	}
	if got := link.Attrs().MTU; got != mtu {
		return fmt.Errorf("%s has MTU %d after the change to %d", name, got, mtu)
	}
	got, err := sysfsMTU(name)
	if err != nil {
		return err
	}
	if got != mtu {
		return fmt.Errorf("/sys/class/net/%s/mtu = %d after the change to %d", name, got, mtu)
	}
	return nil
}

// rejectLinkMTU checks that a change of the MTU fails with EINVAL and leaves
// the old value.
func rejectLinkMTU(name string, mtu int) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	before := link.Attrs().MTU
	if err := netlink.LinkSetMTU(link, mtu); !errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("set the MTU of %s to %d = %v, want EINVAL", name, mtu, err)
	}
	if got, err := sysfsMTU(name); err != nil || got != before {
		return fmt.Errorf("/sys/class/net/%s/mtu = %d, %v after the refused change, want %d", name, got, err, before)
	}
	return nil
}

// ioctlMTU sends SIOCGIFMTU or SIOCSIFMTU for the link name, as the busybox
// tools "ifconfig" and "ip" do. The value of a get request is the result.
func ioctlMTU(req uint, name string, mtu uint32) (uint32, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return 0, err
	}
	if req == unix.SIOCSIFMTU {
		ifr.SetUint32(mtu)
	}
	if err := unix.IoctlIfreq(fd, req, ifr); err != nil {
		return 0, err
	}
	return ifr.Uint32(), nil
}

// ioctlSetMTU sets the MTU with SIOCSIFMTU and checks it with SIOCGIFMTU,
// netlink, and sysfs.
func ioctlSetMTU(name string, mtu int) error {
	if _, err := ioctlMTU(unix.SIOCSIFMTU, name, uint32(mtu)); err != nil {
		return fmt.Errorf("SIOCSIFMTU %s %d: %w", name, mtu, err)
	}
	got, err := ioctlMTU(unix.SIOCGIFMTU, name, 0)
	if err != nil || int(got) != mtu {
		return fmt.Errorf("SIOCGIFMTU %s = %d, %v after SIOCSIFMTU %d", name, got, err, mtu)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if link.Attrs().MTU != mtu {
		return fmt.Errorf("netlink MTU of %s = %d after SIOCSIFMTU %d", name, link.Attrs().MTU, mtu)
	}
	if sys, err := sysfsMTU(name); err != nil || sys != mtu {
		return fmt.Errorf("/sys/class/net/%s/mtu = %d, %v after SIOCSIFMTU %d", name, sys, err, mtu)
	}
	return nil
}

// ioctlRejectsMTU checks that SIOCSIFMTU fails with want and leaves the MTU.
func ioctlRejectsMTU(name string, mtu uint32, want error) error {
	before, err := sysfsMTU(name)
	if err != nil {
		return err
	}
	if _, err := ioctlMTU(unix.SIOCSIFMTU, name, mtu); !errors.Is(err, want) {
		return fmt.Errorf("SIOCSIFMTU %s %d = %v, want %v", name, int32(mtu), err, want)
	}
	if got, err := sysfsMTU(name); err != nil || got != before {
		return fmt.Errorf("/sys/class/net/%s/mtu = %d, %v after the refused change, want %d", name, got, err, before)
	}
	return nil
}

// ioctlNeedsNetAdmin drops CAP_NET_ADMIN from the effective set of one thread
// and checks that SIOCSIFMTU fails with EPERM there. The thread never returns
// to the pool, because it keeps the lower set.
func ioctlNeedsNetAdmin(name string) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		var data [2]unix.CapUserData
		if err := unix.Capget(&hdr, &data[0]); err != nil {
			done <- fmt.Errorf("capget: %w", err)
			return
		}
		data[0].Effective &^= 1 << unix.CAP_NET_ADMIN
		if err := unix.Capset(&hdr, &data[0]); err != nil {
			done <- fmt.Errorf("capset: %w", err)
			return
		}
		done <- ioctlRejectsMTU(name, 1400, unix.EPERM)
	}()
	return <-done
}

// ipv6Addrs returns the IPv6 addresses of a link.
func ipv6Addrs(link netlink.Link) ([]netlink.Addr, error) {
	return netlink.AddrList(link, netlink.FAMILY_V6)
}

// ipv6StopsBelow1280 checks the Linux rule for IPv6 and a low MTU on a link:
// the IPv6 addresses go, the link accepts no new one, and the link accepts one
// again when the MTU is 1280. The Sentry makes no link-local address, so the
// check expects one at 1280 only when the link had one before.
func ipv6StopsBelow1280(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if err := setLinkMTU(name, natEthernetMTU); err != nil {
		return err
	}
	global := &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP("fd00:1::1"), Mask: net.CIDRMask(64, 128)}}
	if err := netlink.AddrAdd(link, global); err != nil {
		return fmt.Errorf("add an IPv6 address at MTU %d: %w", natEthernetMTU, err)
	}
	before, err := ipv6Addrs(link)
	if err != nil {
		return err
	}
	hadLinkLocal := false
	for _, a := range before {
		hadLinkLocal = hadLinkLocal || a.IP.IsLinkLocalUnicast()
	}

	if err := setLinkMTU(name, 1279); err != nil {
		return err
	}
	if left, err := ipv6Addrs(link); err != nil || len(left) != 0 {
		return fmt.Errorf("IPv6 addresses at MTU 1279 = %v, %v, want none", left, err)
	}
	if err := netlink.AddrAdd(link, global); !errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("add an IPv6 address at MTU 1279 = %v, want EINVAL", err)
	}
	v4 := &netlink.Addr{IPNet: &net.IPNet{IP: net.IPv4(10, 77, 0, 1), Mask: net.CIDRMask(24, 32)}}
	if err := netlink.AddrAdd(link, v4); err != nil {
		return fmt.Errorf("add an IPv4 address at MTU 1279: %w", err)
	}

	if err := setLinkMTU(name, 1280); err != nil {
		return err
	}
	after, err := ipv6Addrs(link)
	if err != nil {
		return err
	}
	gotLinkLocal := false
	for _, a := range after {
		gotLinkLocal = gotLinkLocal || a.IP.IsLinkLocalUnicast()
	}
	if hadLinkLocal && !gotLinkLocal {
		return fmt.Errorf("the link-local address did not return at MTU 1280: %v", after)
	}
	if err := netlink.AddrAdd(link, global); err != nil {
		return fmt.Errorf("add an IPv6 address at MTU 1280: %w", err)
	}
	return nil
}

func mtuSetChecks(addr string) []check {
	transfer := func(mtu int) check {
		return check{fmt.Sprintf("tcp-transfer-at-mtu-%d", mtu), func() error {
			if _, err := tputDownload(addr, mtuSetMiB); err != nil {
				return fmt.Errorf("download: %w", err)
			}
			if _, err := tputUpload(addr, mtuSetMiB); err != nil {
				return fmt.Errorf("upload: %w", err)
			}
			return nil
		}}
	}
	setAndTransfer := func(mtu int) []check {
		return []check{
			{fmt.Sprintf("set-eth0-mtu-%d", mtu), func() error { return setLinkMTU("eth0", mtu) }},
			transfer(mtu),
		}
	}
	checks := []check{transfer(natEthernetMTU)}
	for _, mtu := range []int{1400, 576, 9000, linuxMaxMTU, natEthernetMTU} {
		checks = append(checks, setAndTransfer(mtu)...)
	}
	checks = append(checks,
		check{"eth0-refuses-mtu-below-68", func() error { return rejectLinkMTU("eth0", linuxMinMTU-1) }},
		check{"eth0-refuses-mtu-above-65535", func() error { return rejectLinkMTU("eth0", linuxMaxMTU+1) }},
		check{"eth0-accepts-the-minimum-68", func() error {
			if err := setLinkMTU("eth0", linuxMinMTU); err != nil {
				return err
			}
			return setLinkMTU("eth0", natEthernetMTU)
		}},
		check{"veth-follows-the-same-range", func() error {
			if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "mtuv0"}, PeerName: "mtuv1"}); err != nil {
				return err
			}
			if got, err := sysfsMTU("mtuv0"); err != nil || got != natEthernetMTU {
				return fmt.Errorf("a new veth link has MTU %d, %v, want %d", got, err, natEthernetMTU)
			}
			if err := rejectLinkMTU("mtuv0", linuxMinMTU-1); err != nil {
				return err
			}
			if err := rejectLinkMTU("mtuv0", linuxMaxMTU+1); err != nil {
				return err
			}
			if err := setLinkMTU("mtuv0", linuxMaxMTU); err != nil {
				return err
			}
			return setLinkMTU("mtuv0", linuxMinMTU)
		}},
		check{"veth-ends-have-their-own-mtu", func() error {
			// mtuv0 has MTU 68 from the check above, and mtuv1 never changed.
			for name, want := range map[string]int{"mtuv0": linuxMinMTU, "mtuv1": natEthernetMTU} {
				if got, err := sysfsMTU(name); err != nil || got != want {
					return fmt.Errorf("MTU of %s = %d, %v, want %d: the other end changed it", name, got, err, want)
				}
			}
			if err := setLinkMTU("mtuv1", 9000); err != nil {
				return err
			}
			if got, err := sysfsMTU("mtuv0"); err != nil || got != linuxMinMTU {
				return fmt.Errorf("MTU of mtuv0 = %d, %v after the change of mtuv1, want %d", got, err, linuxMinMTU)
			}
			return setLinkMTU("mtuv0", 1400)
		}},
		check{"siocsifmtu-sets-eth0-and-siocgifmtu-reads-it", func() error {
			if err := ioctlSetMTU("eth0", 1400); err != nil {
				return err
			}
			if err := ioctlSetMTU("eth0", linuxMaxMTU); err != nil {
				return err
			}
			return ioctlSetMTU("eth0", natEthernetMTU)
		}},
		check{"siocsifmtu-sets-a-veth-end", func() error { return ioctlSetMTU("mtuv1", 1300) }},
		check{"siocsifmtu-follows-the-linux-range", func() error {
			for _, bad := range []uint32{linuxMinMTU - 1, linuxMaxMTU + 1, ^uint32(0)} {
				if err := ioctlRejectsMTU("eth0", bad, unix.EINVAL); err != nil {
					return err
				}
			}
			if _, err := ioctlMTU(unix.SIOCSIFMTU, "no-such-link", 1400); !errors.Is(err, unix.ENODEV) {
				return fmt.Errorf("SIOCSIFMTU on a link that does not exist = %v, want ENODEV", err)
			}
			return nil
		}},
		check{"siocsifmtu-needs-cap-net-admin", func() error { return ioctlNeedsNetAdmin("eth0") }},
		check{"tcp-transfer-after-siocsifmtu", func() error {
			if err := ioctlSetMTU("eth0", 1200); err != nil {
				return err
			}
			if _, err := tputDownload(addr, mtuSetMiB); err != nil {
				return fmt.Errorf("download: %w", err)
			}
			if _, err := tputUpload(addr, mtuSetMiB); err != nil {
				return fmt.Errorf("upload: %w", err)
			}
			return ioctlSetMTU("eth0", natEthernetMTU)
		}},
		check{"ipv6-stops-below-1280-and-returns-at-1280", func() error { return ipv6StopsBelow1280("mtuv0") }},
	)
	return checks
}
