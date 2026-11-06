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

// proxyARPScript sets up the data path that Calico builds for a pod. The
// namespace "pod" has one address and the default route through the link-local
// gateway 169.254.1.1, which no host owns. The host answers the ARP request for
// the gateway only with proxy_arp on the link of the pod and a route for the
// gateway that leaves through another link. The script also reads and writes
// the sysctl files that the Calico CNI plugin and Felix write.
const proxyARPScript = `set -e
apk add --no-cache iproute2 >/dev/null
ok() { echo "$1"; }
sysctl -qw net.ipv4.ip_forward=1

ip netns add pod
ip link add p0 type veth peer name p1
ip link set p1 netns pod
ip link add q0 type veth peer name q1
ip addr add 10.6.0.1/24 dev q0
ip link set q0 up
ip link set q1 up
ip link set p0 up
ip -n pod link set lo up
ip -n pod link set p1 up
ip -n pod addr add 10.5.0.2/32 dev p1
ip -n pod route add 169.254.1.1 dev p1 scope link
ip -n pod route add default via 169.254.1.1 dev p1
ip route add 10.5.0.2/32 dev p0 scope link

echo SYSCTL-DEFAULTS $(cat /proc/sys/net/ipv4/conf/p0/proxy_arp) $(cat /proc/sys/net/ipv4/conf/all/proxy_arp) $(cat /proc/sys/net/ipv4/conf/default/src_valid_mark) $(cat /proc/sys/net/ipv4/neigh/p0/proxy_delay) $(cat /proc/sys/net/ipv4/neigh/default/gc_thresh3) $(cat /proc/sys/net/ipv4/conf/p0/arp_ignore)
if ip netns exec pod ping -c 2 -W 2 10.6.0.1 >/dev/null 2>&1; then echo FAIL ping-before-proxy-arp; else ok PING-BEFORE-BLOCKED; fi
echo NEIGH-BEFORE $(ip -n pod neigh show 169.254.1.1 | awk '{print $NF}')

echo 1 > /proc/sys/net/ipv4/conf/p0/proxy_arp
echo 0 > /proc/sys/net/ipv4/neigh/p0/proxy_delay
sysctl -qw net.ipv4.conf.all.src_valid_mark=1
echo SYSCTL-AFTER $(cat /proc/sys/net/ipv4/conf/p0/proxy_arp) $(cat /proc/sys/net/ipv4/conf/all/src_valid_mark) $(cat /proc/sys/net/ipv4/neigh/p0/proxy_delay) $(cat /proc/sys/net/ipv4/conf/q0/proxy_arp)
ip -n pod neigh flush dev p1
if ip netns exec pod ping -c 3 -W 3 10.6.0.1 >/dev/null; then ok PING-AFTER-OK; else echo FAIL ping-after-proxy-arp; fi
# The host side of the pod has no address. The host still resolves the pod, with
# the address of another link as the ARP sender, as inet_select_addr() does.
ip neigh flush dev p0
if ping -c 3 -W 3 10.5.0.2 >/dev/null; then ok HOST-TO-POD-OK; else echo FAIL ping-host-to-pod; fi
echo GATEWAY-MAC-IS-P0 $([ "$(ip -n pod neigh show 169.254.1.1 | awk '{print $5}')" = "$(cat /sys/class/net/p0/address)" ] && echo yes || echo no)

# A host without forwarding does not answer.
echo 0 > /proc/sys/net/ipv4/conf/p0/forwarding
ip -n pod neigh flush dev p1
if ip netns exec pod ping -c 2 -W 2 10.6.0.1 >/dev/null 2>&1; then echo FAIL ping-without-forwarding; else ok PING-NO-FORWARDING-BLOCKED; fi
echo 1 > /proc/sys/net/ipv4/conf/p0/forwarding

# conf/all also turns the answers on, and a link keeps its own value.
echo 0 > /proc/sys/net/ipv4/conf/p0/proxy_arp
echo 1 > /proc/sys/net/ipv4/conf/all/proxy_arp
ip -n pod neigh flush dev p1
if ip netns exec pod ping -c 3 -W 3 10.6.0.1 >/dev/null; then ok PING-ALL-OK; else echo FAIL ping-with-all; fi
echo LINK-KEEPS $(cat /proc/sys/net/ipv4/conf/p0/proxy_arp)
echo 0 > /proc/sys/net/ipv4/conf/all/proxy_arp

# A link that appears later follows conf/default.
echo 1 > /proc/sys/net/ipv4/conf/default/arp_ignore
ip link add n0 type veth peer name n1
echo NEW-LINK-DEFAULT $(cat /proc/sys/net/ipv4/conf/n0/arp_ignore)
echo 0 > /proc/sys/net/ipv4/conf/default/arp_ignore
ok PROXY-ARP-DONE
`

// TestE2EProxyARPAndLinkConf proves that a link with proxy_arp answers the ARP
// request for the link-local gateway of a pod, as the Calico CNI plugin
// needs, and that the guest has the sysctl files that Calico and wg-quick write
// under net/ipv4/conf and net/ipv4/neigh.
func TestE2EProxyARPAndLinkConf(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, guestSpec{
				plat: b.plat, image: "alpine:3.20", argv: []string{"sh", "-c", proxyARPScript}, net: gvx.NetModeNAT, netRaw: true,
			})
			t.Log(out)
			requireContains(t, "defaults", out, "SYSCTL-DEFAULTS 0 0 0 80 1024 0\n")
			requireContains(t, "before proxy ARP", out, "PING-BEFORE-BLOCKED\n")
			requireContains(t, "after the writes", out, "SYSCTL-AFTER 1 1 0 0\n")
			requireContains(t, "proxy ARP", out, "PING-AFTER-OK\n", "HOST-TO-POD-OK\n", "GATEWAY-MAC-IS-P0 yes\n")
			requireContains(t, "forwarding", out, "PING-NO-FORWARDING-BLOCKED\n")
			requireContains(t, "conf/all", out, "PING-ALL-OK\n", "LINK-KEEPS 0\n")
			requireContains(t, "default", out, "NEW-LINK-DEFAULT 1\n", "PROXY-ARP-DONE\n")
			if strings.Contains(out, "FAIL ") {
				t.Errorf("guest reported failures:\n%s", out)
			}
		})
	}
}
