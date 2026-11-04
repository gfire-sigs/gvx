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
)

// GVXIP-005 section 4.1 test A12 checks the "wireguard" link and generic
// netlink. The guest programs set no flag and use no setting that is specific
// to Kubernetes. The probe runs without an image, so it runs on every backend
// and needs no registry. The tool tests install wireguard-tools in Alpine.

// TestE2EWireGuardA12GenericNetlink checks NETLINK_GENERIC with a raw
// generic netlink client: the controller resolves the families "nlctrl" and
// "wireguard" by name and by ID, a dump lists them, and the errors of Linux
// come back for an unknown family, an unknown command, and a caller without
// CAP_NET_ADMIN.
func TestE2EWireGuardA12GenericNetlink(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		code, out := runNodeProbe(t, b, bin, nil, "genl")
		requireNodeChecks(t, code, out,
			"controller-resolves-nlctrl", "controller-resolves-wireguard",
			"controller-resolves-a-family-by-id", "controller-dump-lists-the-families",
			"unknown-family-name-is-enoent", "unknown-family-id-is-enoent",
			"unknown-command-is-eopnotsupp", "wireguard-needs-cap-net-admin")
	})
}

// TestE2EWireGuardA12OneSandbox checks two wireguard links in two network
// namespaces of one guest. A veth pair links the namespaces, so the encrypted
// packets cross the guest network stack and need no second sandbox. The test
// also runs on whpx, which cannot hold two partitions in one process.
func TestE2EWireGuardA12OneSandbox(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		code, out := runNodeProbe(t, b, bin, nil, "wireguard")
		requireNodeChecks(t, code, out,
			"namespaces-and-veth", "links-start-with-the-default-mtu", "link-names-are-unique",
			"set-and-get-round-trip", "ping-crosses-the-tunnel", "tcp-transfer-crosses-the-tunnel", "get-reports-handshake-and-counters",
			"get-splits-many-allowed-ips-across-messages", "update-only-ignores-an-unknown-peer",
			"invalid-requests-fail", "removing-the-peer-stops-the-traffic",
			"keepalive-teaches-a-peer-the-endpoint", "replace-peers-removes-every-peer",
			"deleting-the-link-removes-the-device", "namespaces-end")
	})
}
