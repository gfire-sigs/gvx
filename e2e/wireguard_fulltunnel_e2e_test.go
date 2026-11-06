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

// wgFullTunnelScript brings up a full tunnel with the unmodified wg-quick. The
// guest is the client. The namespace "peer" is the server: it owns the
// endpoint 192.0.2.7 and the "internet" address 1.2.3.4. The endpoint is
// reachable only through the default route of the client, so the encrypted
// packets arrive only if the mark of the tunnel socket skips the rule that
// sends everything else to the table 51820.
const wgFullTunnelScript = `set -e
apk add --no-cache wireguard-tools wireguard-tools-wg-quick iproute2 iptables iptables-legacy conntrack-tools bash >/dev/null
# wg-quick calls iptables-restore. The guest has the legacy tables only.
for t in iptables iptables-restore iptables-save; do
	legacy=$(command -v "${t%-*}-legacy-${t#*-}" || command -v "$t-legacy")
	ln -sf "$legacy" "$(dirname "$legacy")/$t"
done
umask 077
ok() { echo "$1"; }
wg genkey > /tmp/cpriv
wg pubkey < /tmp/cpriv > /tmp/cpub
wg genkey > /tmp/ppriv
wg pubkey < /tmp/ppriv > /tmp/ppub

ip netns add peer
ip link add v0 type veth peer name v1
ip link set v1 netns peer
ip addr add 10.1.0.1/24 dev v0
ip link set v0 up
ip -n peer addr add 10.1.0.2/24 dev v1
ip -n peer link set v1 up
ip -n peer link set lo up
ip -n peer addr add 192.0.2.7/32 dev lo
ip -n peer addr add 1.2.3.4/32 dev lo
ip -n peer route add default via 10.1.0.1
ip route replace default via 10.1.0.2

ip -n peer link add wg0 type wireguard
ip netns exec peer wg set wg0 private-key /tmp/ppriv listen-port 51820 peer $(cat /tmp/cpub) allowed-ips 10.9.0.2/32
ip -n peer addr add 10.9.0.1/24 dev wg0
ip -n peer link set wg0 up

mkdir -p /etc/wireguard
cat > /etc/wireguard/wgf.conf <<EOF
[Interface]
Address = 10.9.0.2/32
PrivateKey = $(cat /tmp/cpriv)
[Peer]
PublicKey = $(cat /tmp/ppub)
Endpoint = 192.0.2.7:51820
AllowedIPs = 0.0.0.0/0
EOF
wg-quick up wgf 2>&1 | sed 's/^/QUICK /'
echo RULES $(ip rule show | tr '\t\n' '  ')
echo TABLE $(ip route show table 51820 | tr '\n' ';')
echo MAIN $(ip route show | tr '\n' ';')
echo FWMARK $(wg show wgf fwmark)
echo GET-INTERNET $(ip route get 1.2.3.4 | head -1)
echo GET-ENDPOINT-MARKED $(ip route get 192.0.2.7 mark 51820 | head -1)
echo GET-LOCAL-SUBNET $(ip route get 10.1.0.2 | head -1)
echo GET-ENDPOINT-UNMARKED $(ip route get 192.0.2.7 | head -1)
if ping -c 3 -W 3 10.9.0.1 >/dev/null; then ok PING-PEER-OK; else echo FAIL ping 10.9.0.1; fi
if ping -c 3 -W 3 1.2.3.4 >/dev/null; then ok PING-INTERNET-OK; else echo FAIL ping 1.2.3.4; fi
echo HANDSHAKE $(wg show wgf latest-handshakes | awk '{print ($2 > 0) ? "yes" : "no"}')
echo TRANSFER $(wg show wgf transfer | awk '{print ($2 > 0 && $3 > 0) ? "both" : "none"}')
echo CONNMARK $(conntrack -L -p udp 2>/dev/null | grep ' dport=51820 ' | sed -n 's/.* mark=\([0-9]*\).*/\1/p' | head -1)
echo IPT-RAW $(iptables -t raw -S PREROUTING | grep -c addrtype || true)
echo IPT-MANGLE $(iptables -t mangle -S | grep -c CONNMARK || true)
wg-quick down wgf 2>&1 | sed 's/^/QUICK /'
echo RULES-AFTER $(ip rule show | tr '\t\n' '  ')
echo TABLE-AFTER $(ip route show table 51820 | wc -l)
ok FULLTUNNEL-DONE
`

// TestE2EWireGuardFullTunnel runs wg-quick with AllowedIPs 0.0.0.0/0, which
// adds the rules "not fwmark 51820 table 51820" and "table main
// suppress_prefixlength 0". The traffic to the internet address crosses the
// tunnel, and the tunnel socket still reaches its endpoint through the table
// main.
func TestE2EWireGuardFullTunnel(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, guestSpec{
				plat: b.plat, image: "alpine:3.20", argv: []string{"sh", "-c", wgFullTunnelScript}, net: gvx.NetModeNAT, netRaw: true,
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
			requireContains(t, "ip rule", field("RULES"),
				"32764: from all lookup main suppress_prefixlength 0", "32765: not from all fwmark 0xca6c lookup 51820")
			requireContains(t, "table 51820", field("TABLE"), "default dev wgf")
			requireContains(t, "wg fwmark", field("FWMARK"), "0xca6c")
			requireContains(t, "route get of the internet", field("GET-INTERNET"), "1.2.3.4 dev wgf table 51820")
			requireContains(t, "route get of the endpoint with the mark", field("GET-ENDPOINT-MARKED"), "192.0.2.7 via 10.1.0.2 dev v0")
			requireContains(t, "route get of the local subnet", field("GET-LOCAL-SUBNET"), "10.1.0.2 dev v0")
			requireContains(t, "route get of the endpoint without the mark", field("GET-ENDPOINT-UNMARKED"), "192.0.2.7 dev wgf table 51820")
			requireContains(t, "traffic", out, "PING-PEER-OK\n", "PING-INTERNET-OK\n")
			requireContains(t, "tunnel state", out, "HANDSHAKE yes\n", "TRANSFER both\n")
			// wg-quick saves the fwmark of the tunnel packets in their connection.
			if got := field("CONNMARK"); got != "51820" {
				t.Errorf("connection mark of the tunnel flow = %q, want 51820", got)
			}
			requireContains(t, "iptables rules of wg-quick", out, "IPT-RAW 1\n", "IPT-MANGLE 2\n")
			requireContains(t, "wg-quick down", field("RULES-AFTER"), "0: from all lookup local", "32766: from all lookup main", "32767: from all lookup default")
			if strings.Contains(field("RULES-AFTER"), "51820") || strings.Contains(field("RULES-AFTER"), "suppress") {
				t.Errorf("rules after wg-quick down = %q, want the default rules", field("RULES-AFTER"))
			}
			requireContains(t, "table after down", out, "TABLE-AFTER 0\n", "FULLTUNNEL-DONE\n")
			if strings.Contains(out, "FAIL ") {
				t.Errorf("guest reported failures:\n%s", out)
			}
		})
	}
}
