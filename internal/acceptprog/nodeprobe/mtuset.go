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
	)
	return checks
}
