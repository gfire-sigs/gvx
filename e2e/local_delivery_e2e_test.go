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

// TestE2EPacketForAnotherLinkAddressIsLocal checks the weak host model of
// Linux. A namespace connects through a veth link to the address of eth0. The
// packet is local: it passes INPUT and not FORWARD, and it needs no IP
// forwarding.
func TestE2EPacketForAnotherLinkAddressIsLocal(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			script := `set -e
apk add --no-cache iproute2 iptables iptables-legacy socat >/dev/null
ipt="iptables-legacy -w"
eth=$(ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1)
ip netns add ns1
ip link add veth0 type veth peer name veth1
ip link set veth1 netns ns1
ip addr add 10.9.0.1/24 dev veth0
ip link set veth0 up
ip -n ns1 addr add 10.9.0.2/24 dev veth1
ip -n ns1 link set veth1 up
ip -n ns1 link set lo up
ip -n ns1 route add default via 10.9.0.1
echo 0 > /proc/sys/net/ipv4/ip_forward
socat TCP-LISTEN:7000,fork,reuseaddr SYSTEM:'echo local' &
sleep 1
probe() { ip netns exec ns1 socat -T 3 -u TCP:$eth:7000,connect-timeout=3 - 2>/dev/null; }
[ "$(probe)" = local ] && echo NO-FORWARDING-OK
echo 1 > /proc/sys/net/ipv4/ip_forward
$ipt -P FORWARD DROP
$ipt -A FORWARD -j DROP
[ "$(probe)" = local ] && echo FORWARD-DROP-IGNORED
fwd=$($ipt -L FORWARD -v -x -n | awk 'NR>2 {s+=$1} END {print s+0}')
echo "FORWARD-PACKETS $fwd"
$ipt -A INPUT -i veth0 -p tcp --dport 7000 -j DROP
if [ "$(probe)" = local ]; then echo INPUT-DROP-FAILED; else echo INPUT-DROP-OK; fi
`
			out := mustRunGuest(t, guestSpec{
				plat:   b.plat,
				image:  "alpine:3.20",
				argv:   []string{"sh", "-c", script},
				net:    gvx.NetModeNAT,
				netRaw: true,
			})
			requireContains(t, "guest output", out,
				"NO-FORWARDING-OK\n", "FORWARD-DROP-IGNORED\n", "FORWARD-PACKETS 0\n", "INPUT-DROP-OK\n")
		})
	}
}
