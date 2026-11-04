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

//go:build darwin || windows || linux

package e2e

import (
	"testing"

	"z.gfire.dev/gvx/pkg/gvx"
)

// GVXIP-005 section 4.1 test A13 checks the "vxlan" link, the neighbor
// netlink, and the FDB netlink. The probe sets up two vxlan links with the
// calls that the flannel vxlan back end makes through
// github.com/vishvananda/netlink. It needs no image, so it runs on every
// backend, including whpx. The tool tests in vxlan_tools_e2e_test.go run
// "ip" and "bridge" in Alpine.

// TestE2EVxlanA13OneSandbox checks two vxlan links in two network
// namespaces of one guest. A veth pair is the underlay, so the encapsulated
// packets cross the network stack of the guest and need no second sandbox. The
// test also runs on whpx, which cannot hold two partitions in one process.
func TestE2EVxlanA13OneSandbox(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		code, out := runNodeProbe(t, b, bin, nil, "vxlan")
		requireNodeChecks(t, code, out,
			"namespaces-and-veth", "flannel-links-report-kind-mtu-and-attributes", "link-attributes-round-trip",
			"invalid-and-duplicate-requests-fail", "changing-an-existing-link-is-refused",
			"mtu-stays-in-the-range-of-the-link", "fdb-limit-answers-enospc",
			"flannel-setup-adds-neighbor-fdb-and-onlink-route",
			"neighbor-and-fdb-lists-return-what-was-set", "ping-crosses-the-vxlan",
			"ping-with-the-full-mtu-crosses-the-vxlan", "tcp-transfer-crosses-the-vxlan",
			"neighbor-requests-follow-linux", "fdb-requests-follow-linux", "deleting-the-fdb-entry-stops-the-traffic",
			"all-zeros-entry-carries-unknown-destinations", "learning-link-learns-the-peer",
			"deleting-the-link-frees-the-port", "neighbor-table-is-bounded", "namespaces-end")
	})
}

// TestE2EVxlanA13NATLinkMTU checks the MTU of eth0 in a sandbox with the NAT
// network, and the MTU that flannel derives from it. eth0 has 1500 and lo keeps
// 65536, as on Linux. A vxlan link on eth0 gets 1450, and a WireGuard link set
// to the MTU of eth0 minus 80 reads 1420. A larger MTU of eth0 would give
// tunnel datagrams that the NAT relay cannot send through a host UDP socket.
func TestE2EVxlanA13NATLinkMTU(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		code, out := runNodeProbe(t, b, bin, func(cfg *gvx.Config) {
			cfg.NetworkMode = gvx.NetModeNAT
		}, "natmtu")
		requireNodeChecks(t, code, out,
			"eth0-has-the-ethernet-mtu-and-lo-keeps-65536", "vxlan-over-eth0-gets-1450",
			"wireguard-over-eth0-with-the-formula-of-flannel-gets-1420")
	})
}
