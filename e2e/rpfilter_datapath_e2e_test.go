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

// rpFilterDatapathScript sets the sysctls rp_filter and src_valid_mark and
// sends UDP datagrams with a spoofed source to a router. The namespace "peer"
// owns the address 10.9.9.9 on its loopback device. The router has a default
// route through eth0 and no route that leads to 10.9.9.9 through v0, so a
// datagram from 10.9.9.9 on v0 has an invalid source for the strict check.
const rpFilterDatapathScript = `set -e
apk add --no-cache iptables iptables-legacy iproute2 python3 >/dev/null
IPT=iptables-legacy
# The router forwards, as a node of a cluster does.
sysctl -qw net.ipv4.ip_forward=1
ip netns add peer
ip link add v0 type veth peer name v1
ip link set v1 netns peer
ip addr add 10.1.0.1/24 dev v0
ip link set v0 up
ip -n peer addr add 10.1.0.2/24 dev v1
ip -n peer link set v1 up
ip -n peer link set lo up
ip -n peer addr add 10.9.9.9/32 dev lo
ip -n peer route add default via 10.1.0.1
cat >/tmp/spoof.py <<'EOF'
import socket, sys
if sys.argv[1] == "serve":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 9001))
    s.settimeout(1.5)
    try:
        s.recvfrom(16)
        print("passed")
    except TimeoutError:
        print("dropped")
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((sys.argv[2], 0))
    s.sendto(b"x", ("10.1.0.1", 9001))
EOF
# probe prints "passed" when the router received the datagram from the source.
probe() {
	python3 /tmp/spoof.py serve &
	sleep 0.5
	ip netns exec peer python3 /tmp/spoof.py send "$1"
	wait
}
# setconf sets conf/all/rp_filter and conf/v0/rp_filter.
setconf() {
	sysctl -qw net.ipv4.conf.all.rp_filter=$1
	sysctl -qw net.ipv4.conf.v0.rp_filter=$2
}
echo READ-ALL $(sysctl -n net.ipv4.conf.all.rp_filter)
echo READ-V0 $(sysctl -n net.ipv4.conf.v0.rp_filter)

# The default is off, so a spoofed source arrives.
echo OFF-SPOOF $(probe 10.9.9.9)

# Strict: only the real source and a source that v0 routes arrive.
setconf 0 1
echo STRICT-REAL $(probe 10.1.0.2)
echo STRICT-SPOOF $(probe 10.9.9.9)
ip route add 10.9.9.9/32 dev v0
echo STRICT-ROUTED $(probe 10.9.9.9)
ip route del 10.9.9.9/32 dev v0

# Loose: any route to the source is enough, and no route drops the datagram.
setconf 0 2
echo LOOSE-REAL $(probe 10.1.0.2)
echo LOOSE-SPOOF $(probe 10.9.9.9)
DEFAULT=$(ip route show default)
ip route del default
echo LOOSE-NO-ROUTE $(probe 10.9.9.9)
setconf 0 1
echo STRICT-NO-ROUTE $(probe 10.9.9.9)
ip route add $DEFAULT

# The check takes the larger value of conf/all and conf/v0.
setconf 1 0
echo ALL1-LINK0 $(probe 10.9.9.9)
setconf 2 1
echo ALL2-LINK1 $(probe 10.9.9.9)
setconf 1 2
echo ALL1-LINK2 $(probe 10.9.9.9)
setconf 0 0
echo ALL0-LINK0 $(probe 10.9.9.9)

# The mangle table marks the datagrams, and a rule sends the marked lookup to
# a table with a route to 10.9.9.9 through v0. Only src_valid_mark makes the
# check use the mark.
$IPT -t mangle -A PREROUTING -i v0 -j MARK --set-mark 5
ip route add 10.9.9.9/32 dev v0 table 100
ip rule add fwmark 5 table 100
setconf 0 1
echo MARK-IGNORED $(probe 10.9.9.9)
sysctl -qw net.ipv4.conf.v0.src_valid_mark=1
echo MARK-LINK $(probe 10.9.9.9)
sysctl -qw net.ipv4.conf.v0.src_valid_mark=0
sysctl -qw net.ipv4.conf.all.src_valid_mark=1
echo MARK-ALL $(probe 10.9.9.9)
echo RPF-DONE
`

// TestE2ERPFilterDatapath checks that the sysctls rp_filter and src_valid_mark
// change what the IPv4 receive path accepts, as in Linux.
func TestE2ERPFilterDatapath(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, guestSpec{
				plat: b.plat, image: "alpine:3.20", argv: []string{"sh", "-c", rpFilterDatapathScript}, net: gvx.NetModeNAT, netRaw: true,
			})
			t.Log(out)
			requireContains(t, "files", out, "READ-ALL 0\n", "READ-V0 0\n")
			requireContains(t, "off", out, "OFF-SPOOF passed\n")
			requireContains(t, "strict", out, "STRICT-REAL passed\n", "STRICT-SPOOF dropped\n", "STRICT-ROUTED passed\n", "STRICT-NO-ROUTE dropped\n")
			requireContains(t, "loose", out, "LOOSE-REAL passed\n", "LOOSE-SPOOF passed\n", "LOOSE-NO-ROUTE dropped\n")
			requireContains(t, "all and link", out, "ALL1-LINK0 dropped\n", "ALL2-LINK1 passed\n", "ALL1-LINK2 passed\n", "ALL0-LINK0 passed\n")
			requireContains(t, "src_valid_mark", out, "MARK-IGNORED dropped\n", "MARK-LINK passed\n", "MARK-ALL passed\n", "RPF-DONE\n")
			if strings.Contains(out, "FAIL ") {
				t.Errorf("guest reported failures:\n%s", out)
			}
		})
	}
}
