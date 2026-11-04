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
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
)

// TestE2EVxlanA13ToolsOneSandbox sets up two vxlan links in two namespaces of
// one Alpine guest with the unmodified tools "ip" and "bridge", in the way of
// flannel: a link with nolearning, a permanent neighbor for the VTEP address
// of the peer, an FDB entry for the VTEP MAC, and an onlink route. It then
// pings and sends 256 KiB over the tunnel, checks the lists and the MTU, and
// checks that the traffic stops after "bridge fdb del" and continues through
// the all-zeros entry. The test runs on whpx too, because it needs one sandbox.
func TestE2EVxlanA13ToolsOneSandbox(t *testing.T) {
	const script = `set -e
apk add --no-cache iproute2 >/dev/null
ip netns add na
ip netns add nb
ip link add va0 type veth peer name vb0
ip link set va0 netns na
ip link set vb0 netns nb
for p in "na va0 10.1.0.1" "nb vb0 10.1.0.2"; do
	set -- $p
	ip -n $1 addr add $3/30 dev $2
	ip -n $1 link set $2 up
	ip -n $1 link set lo up
done
ip -n na link add flannel.1 type vxlan id 1 dstport 8472 local 10.1.0.1 nolearning
ip -n nb link add flannel.1 type vxlan id 1 dstport 8472 local 10.1.0.2 nolearning
ip -n na addr add 10.244.1.0/32 dev flannel.1
ip -n nb addr add 10.244.2.0/32 dev flannel.1
ip -n na link set flannel.1 up
ip -n nb link set flannel.1 up
mac() { ip -n $1 link show flannel.1 | awk '/link\/ether/ {print $2}'; }
MACA=$(mac na)
MACB=$(mac nb)
echo LINK $(ip -n na -d link show flannel.1 | tr '\n' ' ')
ip -n na neigh replace 10.244.2.0 lladdr $MACB dev flannel.1 nud permanent
bridge -n na fdb append $MACB dst 10.1.0.2 dev flannel.1
ip -n na route replace 10.244.2.0/24 via 10.244.2.0 dev flannel.1 onlink
ip -n nb neigh replace 10.244.1.0 lladdr $MACA dev flannel.1 nud permanent
bridge -n nb fdb append $MACA dst 10.1.0.1 dev flannel.1
ip -n nb route replace 10.244.1.0/24 via 10.244.1.0 dev flannel.1 onlink
echo NEIGH $(ip -n na neigh show dev flannel.1)
echo FDB $(bridge -n na fdb show dev flannel.1)
echo ROUTE $(ip -n na route show dev flannel.1)
if ip netns exec na ping -c 3 -W 3 10.244.2.0 >/dev/null; then echo PING-AB-OK; else echo PING-AB-FAILED; fi
if ip netns exec nb ping -c 3 -W 3 10.244.1.0 >/dev/null; then echo PING-BA-OK; else echo PING-BA-FAILED; fi
head -c 262144 /dev/urandom > /tmp/data
ip netns exec nb nc -l -p 9000 > /tmp/in &
sleep 1
ip netns exec na nc -w 5 10.244.2.0 9000 < /tmp/data
wait
echo SUM-SENT $(sha256sum < /tmp/data)
echo SUM-GOT $(sha256sum < /tmp/in)
bridge -n na fdb del $MACB dev flannel.1 dst 10.1.0.2
echo FDB-AFTER-DEL $(bridge -n na fdb show dev flannel.1 | grep -c "$MACB" || true)
if ip netns exec na ping -c 2 -W 2 10.244.2.0 >/dev/null 2>&1; then echo PING-AFTER-DEL-REACHED; else echo PING-AFTER-DEL-BLOCKED; fi
bridge -n na fdb append 00:00:00:00:00:00 dst 10.1.0.2 dev flannel.1
echo FDB-ZERO $(bridge -n na fdb show dev flannel.1)
if ip netns exec na ping -c 3 -W 3 10.244.2.0 >/dev/null 2>&1; then echo PING-ZERO-OK; else echo PING-ZERO-FAILED; fi
bridge -n na fdb del 00:00:00:00:00:00 dev flannel.1
echo FDB-ZERO-AFTER-DEL $(bridge -n na fdb show dev flannel.1 | grep -c 00:00:00:00:00:00 || true)
ip -n na neigh del 10.244.2.0 dev flannel.1
echo NEIGH-AFTER-DEL $(ip -n na neigh show dev flannel.1 | grep -c 10.244.2.0 || true)
ip -n na link del flannel.1
if ip -n na link show flannel.1 >/dev/null 2>&1; then echo LINK-STILL-THERE; else echo LINK-GONE; fi
`
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, guestSpec{
				plat: b.plat, image: "alpine:3.20", argv: []string{"sh", "-c", script}, net: gvx.NetModeNAT, netRaw: true,
			})
			t.Log(out)
			field := func(name string) string {
				for _, l := range strings.Split(out, "\n") {
					if rest, ok := strings.CutPrefix(l, name+" "); ok {
						return rest
					}
				}
				t.Fatalf("output lacks %s; full output:\n%s", name, out)
				return ""
			}
			requireContains(t, "ip -d link show", field("LINK"), "mtu 1450", "vxlan id 1", "local 10.1.0.1", "dstport 8472", "nolearning")
			requireContains(t, "ip neigh show", field("NEIGH"), "10.244.2.0 lladdr", "PERMANENT")
			requireContains(t, "bridge fdb show", field("FDB"), "dst 10.1.0.2", "self", "permanent")
			requireContains(t, "ip route show", field("ROUTE"), "10.244.2.0/24 via 10.244.2.0")
			requireContains(t, "traffic", out, "PING-AB-OK\n", "PING-BA-OK\n", "PING-AFTER-DEL-BLOCKED\n", "PING-ZERO-OK\n")
			if sent, got := field("SUM-SENT"), field("SUM-GOT"); sent != got || len(strings.Fields(sent)[0]) != 64 {
				t.Errorf("the listener received sha256 %q, the sender sent %q", got, sent)
			}
			requireContains(t, "removal", out, "FDB-AFTER-DEL 0\n", "FDB-ZERO-AFTER-DEL 0\n", "NEIGH-AFTER-DEL 0\n", "LINK-GONE\n")
			requireContains(t, "all-zeros entry", field("FDB-ZERO"), "00:00:00:00:00:00 dst 10.1.0.2")
		})
	}
}

// TestE2EVxlanA13TwoSandboxesOverWireGuard builds the topology T2 of GVXIP-005
// on two sandboxes of one host. A publishes UDP port 51820, and the WireGuard
// link wg0 of B reaches it through the host gateway. The vxlan link vxlan1
// of each sandbox uses wg0 as its underlay link, so the encapsulated packets
// follow the guest routes into the tunnel. B pings A and sends 256 KiB over
// the vxlan, A pings B, and the traffic stops after A deletes the FDB entry.
// The MTU of vxlan1 is the MTU of wg0 minus 50.
func TestE2EVxlanA13TwoSandboxesOverWireGuard(t *testing.T) {
	const common = "ip link add wg0 type wireguard\n"
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			a, bg := wgTwoSandboxes(t, b, common+`wg set wg0 private-key /tmp/key listen-port 51820 peer "$WG_PUB_PEER" allowed-ips 10.77.0.2/32
ip addr add 10.77.0.1/24 dev wg0
ip link set wg0 up
ip link add vxlan1 address 02:00:00:00:00:0a type vxlan id 42 dstport 4789 local 10.77.0.1 dev wg0 nolearning
ip addr add 10.99.0.1/24 dev vxlan1
ip link set vxlan1 up
ip neigh replace 10.99.0.2 lladdr 02:00:00:00:00:0b dev vxlan1 nud permanent
bridge fdb append 02:00:00:00:00:0b dst 10.77.0.2 dev vxlan1
echo A-LINK $(ip -d link show vxlan1 | tr '\n' ' ')
echo A-READY
nc -l -p 9000 > /tmp/in < /dev/null
echo A-BYTES $(wc -c < /tmp/in)
echo A-SUM $(sha256sum /tmp/in | cut -d' ' -f1)
if ping -c 3 -W 3 10.99.0.2 >/dev/null; then echo A-VX-PING-OK; else echo A-VX-PING-FAILED; fi
bridge fdb del 02:00:00:00:00:0b dev vxlan1 dst 10.77.0.2
if ping -c 2 -W 2 10.99.0.2 >/dev/null 2>&1; then echo A-AFTER-DEL-REACHED; else echo A-AFTER-DEL-BLOCKED; fi
echo A-DONE
`, common+`wg set wg0 private-key /tmp/key peer "$WG_PUB_PEER" endpoint "10.0.2.2:$WG_HOST_PORT" allowed-ips 10.77.0.1/32
ip addr add 10.77.0.2/24 dev wg0
ip link set wg0 up
ip link add vxlan1 address 02:00:00:00:00:0b type vxlan id 42 dstport 4789 local 10.77.0.2 dev wg0 nolearning
ip addr add 10.99.0.2/24 dev vxlan1
ip link set vxlan1 up
ip neigh replace 10.99.0.1 lladdr 02:00:00:00:00:0a dev vxlan1 nud permanent
bridge fdb append 02:00:00:00:00:0a dst 10.77.0.1 dev vxlan1
echo B-LINK $(ip -d link show vxlan1 | tr '\n' ' ')
if ping -c 3 -W 5 10.77.0.1 >/dev/null; then echo B-WG-PING-OK; else echo B-WG-PING-FAILED; fi
if ping -c 3 -W 5 10.99.0.1 >/dev/null; then echo B-VX-PING-OK; else echo B-VX-PING-FAILED; fi
head -c 262144 /dev/urandom > /tmp/data
echo B-SUM $(sha256sum /tmp/data | cut -d' ' -f1)
nc -w 5 10.99.0.1 9000 < /tmp/data
echo B-SENT
read x || true
echo B-DONE
`)
			bg.wait(t, "B-WG-PING-OK", 4*time.Minute)
			bg.wait(t, "B-VX-PING-OK", time.Minute)
			bSum := bg.wait(t, "B-SUM ", time.Minute)
			bg.wait(t, "B-SENT", time.Minute)
			aSum := a.wait(t, "A-SUM ", time.Minute)
			if aSum != bSum || len(aSum) != 64 {
				t.Errorf("A received sha256 %q, B sent %q", aSum, bSum)
			}
			a.wait(t, "A-VX-PING-OK", time.Minute)
			a.wait(t, "A-AFTER-DEL-BLOCKED", time.Minute)
			a.wait(t, "A-DONE", time.Minute)
			bg.stdin.Close()
			bg.wait(t, "B-DONE", time.Minute)
			all := a.out.String() + bg.out.String()
			requireContains(t, "vxlan1 link", all, "mtu 1370", "vxlan id 42", "local 10.77.0.1", "local 10.77.0.2", "dev wg0", "dstport 4789", "nolearning")
			if strings.Contains(all, "AFTER-DEL-REACHED") {
				t.Errorf("traffic crossed the vxlan after the FDB entry was deleted\nA:\n%s\nB:\n%s", a.out.String(), bg.out.String())
			}
		})
	}
}
