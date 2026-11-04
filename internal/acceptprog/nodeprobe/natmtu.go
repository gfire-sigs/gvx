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
	"fmt"

	"github.com/vishvananda/netlink"
)

// The natmtu checks run in a sandbox with the NAT network. They check that
// eth0 has the MTU of an Ethernet link, and that the tunnels that flannel
// builds on eth0 get the MTU that flannel derives on Linux: eth0 minus 50 for
// vxlan, and eth0 minus 80 for WireGuard.

const (
	natEthernetMTU = 1500
	natLoopbackMTU = 65536
	flannelVxlan   = 50
	flannelWG      = 80
)

func natMTUChecks() []check {
	var eth0 netlink.Link
	return []check{
		{"eth0-has-the-ethernet-mtu-and-lo-keeps-65536", func() error {
			var err error
			if eth0, err = netlink.LinkByName("eth0"); err != nil {
				return err
			}
			lo, err := netlink.LinkByName("lo")
			if err != nil {
				return err
			}
			if eth0.Attrs().MTU != natEthernetMTU || lo.Attrs().MTU != natLoopbackMTU {
				return fmt.Errorf("eth0 has MTU %d and lo has MTU %d, want %d and %d", eth0.Attrs().MTU, lo.Attrs().MTU, natEthernetMTU, natLoopbackMTU)
			}
			return nil
		}},
		{"vxlan-over-eth0-gets-1450", func() error {
			addrs, err := netlink.AddrList(eth0, netlink.FAMILY_V4)
			if err != nil || len(addrs) == 0 {
				return fmt.Errorf("addresses of eth0 = %v, %v", addrs, err)
			}
			// flannel passes the index and the address of eth0 and no port.
			v, err := vxlanDevice("flannel.1", 1, 0, addrs[0].IP.String(), eth0.Attrs().Index, false)
			if err != nil {
				return err
			}
			if want := eth0.Attrs().MTU - flannelVxlan; v.MTU != want || v.MTU != 1450 {
				return fmt.Errorf("flannel.1 has MTU %d, want %d", v.MTU, want)
			}
			if v.Port != 8472 || v.VtepDevIndex != eth0.Attrs().Index || !v.SrcAddr.Equal(addrs[0].IP) {
				return fmt.Errorf("flannel.1 = %+v, want port 8472, underlay eth0, and local %v", *v, addrs[0].IP)
			}
			return nil
		}},
		{"wireguard-over-eth0-with-the-formula-of-flannel-gets-1420", func() error {
			if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "flannel-wg"}}); err != nil {
				return err
			}
			wg, err := netlink.LinkByName("flannel-wg")
			if err != nil {
				return err
			}
			if err := netlink.LinkSetMTU(wg, eth0.Attrs().MTU-flannelWG); err != nil {
				return err
			}
			if wg, err = netlink.LinkByName("flannel-wg"); err != nil {
				return err
			}
			if wg.Attrs().MTU != 1420 {
				return fmt.Errorf("flannel-wg has MTU %d, want 1420", wg.Attrs().MTU)
			}
			return nil
		}},
	}
}
