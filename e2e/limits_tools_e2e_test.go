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

// TestE2ENeighborAndFDBLimitsTools runs the unmodified tools "ip" and "bridge"
// against the limits that Linux has. Linux has no cap on static neighbors, so
// "ip -batch" adds 70,000 of them to a veth link and to a vxlan link. A vxlan
// link has no limit on its FDB unless the user sets "maxaddr", and "ip -d link
// show" reports the limit. The files gc_thresh1 to gc_thresh3 read 128, 512,
// and 1024 in every network namespace.
func TestE2ENeighborAndFDBLimitsTools(t *testing.T) {
	const script = `set -e
apk add --no-cache iproute2 >/dev/null
ip netns add na
ip netns add nb
ip link add va0 type veth peer name vb0
ip link set va0 netns na
ip link set vb0 netns nb
ip -n na addr add 10.1.0.1/30 dev va0
ip -n na link set va0 up
ip -n nb link set vb0 up
ip -n na link add vx0 type vxlan id 5 dstport 4789 local 10.1.0.1 nolearning
ip -n na link set vx0 up
ip -n na link add vx1 type vxlan id 6 dstport 4790 local 10.1.0.1 nolearning maxaddr 3
echo LINK-DEFAULT $(ip -n na -d link show vx0 | tr '\n' ' ')
echo LINK-LIMIT $(ip -n na -d link show vx1 | tr '\n' ' ')
if ip -n na link set vx1 type vxlan maxaddr 5 2>/tmp/err; then echo LIMIT-CHANGED; else echo LIMIT-CHANGE-REFUSED $(cat /tmp/err); fi
for i in 1 2 3; do bridge -n na fdb add 02:00:00:00:00:0$i dev vx1 dst 10.9.0.1 self permanent; done
if bridge -n na fdb add 02:00:00:00:00:04 dev vx1 dst 10.9.0.1 self permanent 2>/tmp/err; then echo FDB-FOURTH-ADDED; else echo FDB-FOURTH-REFUSED $(cat /tmp/err); fi
awk 'BEGIN { for (i = 0; i < 70000; i++) printf "neigh add 10.%d.%d.%d lladdr 02:00:00:00:%02x:%02x dev va0 nud permanent\n", 2 + int(i / 65536), int(i / 256) % 256, i % 256, int(i / 256) % 256, i % 256 }' > /tmp/neigh.batch
ip -n na -batch /tmp/neigh.batch
echo VETH-NEIGH $(ip -n na neigh show dev va0 nud permanent | wc -l)
awk 'BEGIN { for (i = 0; i < 70000; i++) printf "neigh add 10.%d.%d.%d lladdr 02:00:00:00:%02x:%02x dev vx0 nud permanent\n", 2 + int(i / 65536), int(i / 256) % 256, i % 256, int(i / 256) % 256, i % 256 }' > /tmp/neigh2.batch
ip -n na -batch /tmp/neigh2.batch
echo VXLAN-NEIGH $(ip -n na neigh show dev vx0 nud permanent | wc -l)
awk 'BEGIN { for (i = 0; i < 70000; i++) printf "fdb add 02:00:%02x:%02x:%02x:00 dev vx0 dst 10.9.0.1 self permanent\n", int(i / 65536), int(i / 256) % 256, i % 256 }' > /tmp/fdb.batch
bridge -n na -batch /tmp/fdb.batch
echo FDB-ENTRIES $(bridge -n na fdb show dev vx0 | grep -c 'dst 10.9.0.1')
echo GC-ROOT $(cat /proc/sys/net/ipv4/neigh/default/gc_thresh1 /proc/sys/net/ipv4/neigh/default/gc_thresh2 /proc/sys/net/ipv4/neigh/default/gc_thresh3 /proc/sys/net/ipv6/neigh/default/gc_thresh1 /proc/sys/net/ipv6/neigh/default/gc_thresh2 /proc/sys/net/ipv6/neigh/default/gc_thresh3)
echo GC-NS $(ip netns exec na cat /proc/sys/net/ipv4/neigh/default/gc_thresh1 /proc/sys/net/ipv4/neigh/default/gc_thresh2 /proc/sys/net/ipv4/neigh/default/gc_thresh3 /proc/sys/net/ipv6/neigh/default/gc_thresh3)
ip netns exec na sh -c 'echo 77 > /proc/sys/net/ipv4/neigh/default/gc_thresh3'
echo GC-NS-AFTER $(ip netns exec na cat /proc/sys/net/ipv4/neigh/default/gc_thresh3) ROOT $(cat /proc/sys/net/ipv4/neigh/default/gc_thresh3) OTHER $(ip netns exec nb cat /proc/sys/net/ipv4/neigh/default/gc_thresh3)
`
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, guestSpec{
				plat: b.plat, image: "alpine:3.20", argv: []string{"sh", "-c", script}, net: gvx.NetModeNAT, netRaw: true,
			})
			t.Log(out)
			requireContains(t, "limits", out,
				"VETH-NEIGH 70000\n", "VXLAN-NEIGH 70000\n", "FDB-ENTRIES 70000\n",
				"LIMIT-CHANGE-REFUSED RTNETLINK answers: Not supported\n",
				"FDB-FOURTH-REFUSED RTNETLINK answers: No space left on device\n",
				"GC-ROOT 128 512 1024 128 512 1024\n", "GC-NS 128 512 1024 1024\n",
				"GC-NS-AFTER 77 ROOT 1024 OTHER 1024\n")
			field := func(name string) string {
				for _, l := range strings.Split(out, "\n") {
					if rest, ok := strings.CutPrefix(l, name+" "); ok {
						return rest
					}
				}
				t.Fatalf("output lacks %s; full output:\n%s", name, out)
				return ""
			}
			requireContains(t, "ip -d link show vx1", field("LINK-LIMIT"), "vxlan id 6", "maxaddr 3")
			if line := field("LINK-DEFAULT"); strings.Contains(line, "maxaddr") {
				t.Errorf("a link without a limit reports one: %s", line)
			}
		})
	}
}

// TestE2EXtRecentParametersAffectTheList sets ip_list_tot to 2 before the first
// recent rule. A third address then evicts the oldest address of the list, and
// the address that left the list counts as new. Once a list exists, the file no
// longer takes a write, as the file of a loaded module.
func TestE2EXtRecentParametersAffectTheList(t *testing.T) {
	const script = `set -e
apk add --no-cache iptables iptables-legacy socat >/dev/null
ipt="iptables-legacy -w"
echo MODE $(stat -c %a /sys/module/xt_recent/parameters/ip_list_tot /sys/module/xt_recent/parameters/ip_pkt_list_tot)
echo DEFAULTS $(cat /sys/module/xt_recent/parameters/ip_list_tot /sys/module/xt_recent/parameters/ip_pkt_list_tot)
echo 2 > /sys/module/xt_recent/parameters/ip_list_tot
echo SET $(cat /sys/module/xt_recent/parameters/ip_list_tot)
socat TCP-LISTEN:8081,fork,reuseaddr SYSTEM:'echo known' &
socat TCP-LISTEN:8082,fork,reuseaddr SYSTEM:'echo new' &
for p in 8081 8082; do
  i=0; until socat -u TCP:127.0.0.1:$p - >/dev/null 2>&1; do i=$((i+1)); [ $i -gt 50 ] && exit 1; sleep 0.1; done
done
ip addr add 10.96.0.11/32 dev lo
ip addr add 10.96.0.12/32 dev lo
ip addr add 10.96.0.13/32 dev lo
$ipt -t nat -N SVC
$ipt -t nat -N FRESH
$ipt -t nat -A OUTPUT -d 10.96.0.0/24 -p tcp --dport 80 -j SVC
$ipt -t nat -A SVC -p tcp -m recent --name L --rdest --rcheck -j DNAT --to-destination 127.0.0.1:8081
$ipt -t nat -A SVC -j FRESH
$ipt -t nat -A FRESH -p tcp -m recent --name L --rdest --set -j DNAT --to-destination 127.0.0.1:8082
r() { socat -u TCP:$1:80 -; }
echo FIRST $(r 10.96.0.11) $(r 10.96.0.12) $(r 10.96.0.13)
echo AGAIN $(r 10.96.0.12) $(r 10.96.0.13) $(r 10.96.0.11)
if echo 5 > /sys/module/xt_recent/parameters/ip_list_tot 2>/tmp/err; then echo WRITE-WITH-LIST-ACCEPTED; else echo WRITE-WITH-LIST-REFUSED $(cat /tmp/err); fi
echo AFTER $(cat /sys/module/xt_recent/parameters/ip_list_tot)
`
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, guestSpec{
				plat: b.plat, image: "alpine:3.20", argv: []string{"sh", "-c", script}, net: gvx.NetModeNAT, netRaw: true,
			})
			t.Log(out)
			// The list holds two addresses. The third first-time address pushes out
			// the address 11, so after FIRST the list is 12 and 13. The checks of 12
			// and 13 find them, and the check of 11 finds a new address.
			requireContains(t, "xt_recent", out,
				"MODE 400 400\n", "DEFAULTS 100 0\n", "SET 2\n",
				"FIRST new new new\n", "AGAIN known known new\n", "AFTER 2\n")
			requireContains(t, "write with a list", out, "WRITE-WITH-LIST-REFUSED")
		})
	}
}
