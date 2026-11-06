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
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/gvx"
)

// TestE2EEthtoolOffload checks SIOCETHTOOL with the calls of Calico Felix,
// github.com/safchain/ethtool, and the ethtool tool: the feature names, the
// read and write of the feature bits, the legacy commands, the refusal of fixed
// features, the capability check, and the feature state of a link that moves to
// another network namespace. The guest is the program nodeprobe, so the test
// needs no registry.
func TestE2EEthtoolOffload(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		code, out := runNodeProbe(t, b, bin, nil, "ethtool")
		requireNodeChecks(t, code, out,
			"ethtool-namespaces-and-links", "ethtool-feature-names-come-from-sset-info-and-strings",
			"ethtool-new-links-have-offloads-on", "ethtool-felix-switches-tx-checksum-off-on-vxlan",
			"ethtool-tx-checksum-on-brings-the-dependent-features-back", "ethtool-rx-checksum-toggles-alone",
			"ethtool-legacy-offload-commands", "ethtool-fixed-features-are-refused-as-in-linux",
			"ethtool-drvinfo-names-the-driver-and-link-reports-the-carrier", "ethtool-unknown-link-and-command",
			"ethtool-features-stay-with-a-link-that-changes-namespace", "ethtool-a-new-link-starts-with-the-defaults",
			"ethtool-a-set-command-needs-cap-net-admin")
	})
}

// ethtoolCLIScript runs the ethtool tool of Alpine against links of the guest.
// It reads the features with -k, switches the transmit checksum of a vxlan link
// off as Felix does, and reads the result back.
const ethtoolCLIScript = `set -e
apk add --no-cache ethtool iproute2 >/dev/null
ok() { echo "$1"; }
bad() { echo "FAIL $*"; }
ip link add veth0 type veth peer name veth1
ip link add vxlan.calico type vxlan id 4096 dstport 4789
feat() { ethtool -k "$1" | sed -n "s/^[[:space:]]*$2: \([a-z]*\).*/\1/p"; }
[ "$(feat vxlan.calico tx-checksum-ip-generic)" = on ] && ok VXLAN-TX-ON || bad "vxlan tx checksum $(feat vxlan.calico tx-checksum-ip-generic)"
[ "$(feat veth0 tx-scatter-gather)" = on ] && ok VETH-SG-ON || bad "veth sg"
ethtool -K vxlan.calico tx-checksum-ip-generic off && ok SET-TX-OFF || bad "ethtool -K tx off"
[ "$(feat vxlan.calico tx-checksum-ip-generic)" = off ] && ok VXLAN-TX-OFF || bad "tx checksum after off: $(feat vxlan.calico tx-checksum-ip-generic)"
[ "$(feat veth0 tx-checksum-ip-generic)" = on ] && ok VETH-UNCHANGED || bad "veth changed"
ethtool -K vxlan.calico tx on rx off && ok SET-ALIAS || bad "ethtool -K tx on rx off"
[ "$(feat vxlan.calico rx-checksumming)" = off ] && [ "$(feat vxlan.calico tx-checksum-ip-generic)" = on ] && ok ALIAS-APPLIED || bad "alias result"
ethtool -i veth0 | grep -q '^driver: veth' && ok DRVINFO-OK || bad drvinfo
if ethtool -K lo tx off 2>/dev/null; then bad "lo tx off was accepted"; else ok LO-TX-FIXED; fi
ethtool -k lo | grep -q '^[[:space:]]*tx-checksum-ip-generic: on \[fixed\]' && ok LO-FIXED-LABEL || bad "lo fixed label"
echo ETHTOOL-DONE
`

// TestE2EEthtoolCLI runs the ethtool tool of the guest, which uses SIOCETHTOOL
// because the guest has no ethtool netlink family.
func TestE2EEthtoolCLI(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, guestSpec{
				plat:   b.plat,
				image:  "alpine:3.20",
				argv:   []string{"sh", "-c", ethtoolCLIScript},
				net:    gvx.NetModeNAT,
				netRaw: true,
			})
			requireContains(t, "guest output", out,
				"VXLAN-TX-ON\n", "VETH-SG-ON\n", "SET-TX-OFF\n", "VXLAN-TX-OFF\n", "VETH-UNCHANGED\n", "SET-ALIAS\n",
				"ALIAS-APPLIED\n", "DRVINFO-OK\n", "LO-TX-FIXED\n", "LO-FIXED-LABEL\n", "ETHTOOL-DONE\n")
			if strings.Contains(out, "FAIL ") {
				t.Errorf("guest reported failures:\n%s", out)
			}
		})
	}
}
