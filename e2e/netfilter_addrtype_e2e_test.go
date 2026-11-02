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

// TestE2EIptablesAddrtypeAndInterfaceInversion drives the legacy iptables
// binary in the guest with the rules that dockerd installs. It verifies that
// the guest accepts the rules, reports them back in the form that "iptables -C"
// and "iptables -D" need, and applies the addrtype match to real packets.
// The unit tests in pkg/sentry/socket/netfilter carry the offline coverage.
func TestE2EIptablesAddrtypeAndInterfaceInversion(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			script := `set -e
apk add --no-cache iptables iptables-legacy >/dev/null
ipt=iptables-legacy
$ipt -t nat -N DOCKER
$ipt -t nat -A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
$ipt -t nat -A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
$ipt -t nat -A POSTROUTING -m addrtype --src-type LOCAL --limit-iface-out -j RETURN
$ipt -t nat -A DOCKER ! -i docker0 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80
$ipt -t nat -S | grep -v '^-[NP] '
$ipt -t nat -C PREROUTING -m addrtype --dst-type LOCAL -j DOCKER && echo CHECK-ADDRTYPE-OK
$ipt -t nat -C DOCKER ! -i docker0 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80 && echo CHECK-DNAT-OK
$ipt -t nat -D DOCKER ! -i docker0 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80 && echo DELETE-DNAT-OK

(while true; do echo hi | nc -l -p 8080; done) &
probe() { sleep 1; nc -w 3 127.0.0.1 8080 </dev/null 2>/dev/null | grep -q hi; }
probe && echo LOOPBACK-BEFORE-OK
$ipt -t filter -A OUTPUT -m addrtype --dst-type LOCAL -j DROP
if probe; then echo LOOPBACK-DROP-FAILED; else echo LOOPBACK-DROPPED; fi
$ipt -t filter -F OUTPUT
$ipt -t filter -A OUTPUT -m addrtype ! --dst-type LOCAL -j DROP
probe && echo LOOPBACK-INVERTED-OK
kill %1 2>/dev/null || true
`
			out := mustRunGuest(t, guestSpec{
				plat:   b.plat,
				image:  "alpine:3.20",
				argv:   []string{"sh", "-c", script},
				net:    gvx.NetModeNAT,
				netRaw: true,
			})
			requireContains(t, "guest output", out,
				"-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER\n",
				"-A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER\n",
				"-A POSTROUTING -m addrtype --src-type LOCAL --limit-iface-out -j RETURN\n",
				"-A DOCKER ! -i docker0 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80\n",
				"CHECK-ADDRTYPE-OK\n", "CHECK-DNAT-OK\n", "DELETE-DNAT-OK\n",
				"LOOPBACK-BEFORE-OK\n", "LOOPBACK-DROPPED\n", "LOOPBACK-INVERTED-OK\n")
		})
	}
}
