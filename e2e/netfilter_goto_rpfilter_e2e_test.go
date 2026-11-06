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

// gotoRPFilterScript checks two matches and targets that Calico uses: the goto
// of a rule ("-g chain") and the match rpfilter. The guest is a router. The
// namespace "peer" pings from a spoofed source.
const gotoRPFilterScript = `set -e
apk add --no-cache iptables iptables-legacy iproute2 python3 >/dev/null
IPT=iptables-legacy
ok() { echo "$1"; }
sysctl -qw net.ipv4.ip_forward=1

# A goto enters the chain without a return address. The chain A ends with RETURN.
# After a jump the next rule of INPUT runs and drops the datagram. After a goto
# the end of A returns to the end of INPUT, so the policy accepts it.
cat >/tmp/udp.py <<'EOF'
import socket, sys
port = int(sys.argv[1])
if sys.argv[2] == "serve":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    s.settimeout(2)
    try:
        data, _ = s.recvfrom(16)
        print("received", data.decode())
    except TimeoutError:
        print("nothing")
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"ping", ("127.0.0.1", port))
EOF
try_udp() {
	python3 /tmp/udp.py 9000 serve &
	sleep 0.5
	python3 /tmp/udp.py 9000 send
	wait
}
$IPT -N A
$IPT -A A -j RETURN
$IPT -A INPUT -i lo -p udp --dport 9000 -j A
$IPT -A INPUT -i lo -p udp --dport 9000 -j DROP
echo JUMP $(try_udp)
$IPT -F INPUT
$IPT -A INPUT -i lo -p udp --dport 9000 -g A
$IPT -A INPUT -i lo -p udp --dport 9000 -j DROP
echo GOTO $(try_udp)
echo SAVE-GOTO $($IPT -S INPUT | grep -c -- '-g A' || true)
$IPT -F INPUT
$IPT -F A
$IPT -X A

# rpfilter on the table raw: strict, loose, and inverted.
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
# The default route of the router leaves through eth0, so a datagram from 10.9.9.9
# on v0 has a source that the strict check rejects. The router listens on UDP
# port 9001 and tells whether a datagram of the source arrived.
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
rpf() {
	python3 /tmp/spoof.py serve &
	sleep 0.5
	ip netns exec peer python3 /tmp/spoof.py send "$1"
	wait
}
$IPT -t raw -A PREROUTING -i v0 -m rpfilter --invert -j DROP
echo STRICT-REAL $(rpf 10.1.0.2)
echo STRICT-SPOOF $(rpf 10.9.9.9)
echo SAVE-RPF $($IPT -t raw -S PREROUTING | grep -c 'rpfilter --invert' || true)

# A route to the spoofed source through v0 makes it valid.
ip route add 10.9.9.9/32 dev v0
echo STRICT-ROUTED $(rpf 10.9.9.9)
ip route del 10.9.9.9/32 dev v0

# A route through another link passes in loose mode only.
ip link add d0 type veth peer name d1
ip link set d0 up
ip link set d1 up
ip route add 10.9.9.9/32 dev d0
echo STRICT-OTHER-LINK $(rpf 10.9.9.9)
$IPT -t raw -F PREROUTING
$IPT -t raw -A PREROUTING -i v0 -m rpfilter --loose --invert -j DROP
echo LOOSE-OTHER-LINK $(rpf 10.9.9.9)
echo SAVE-LOOSE $($IPT -t raw -S PREROUTING | grep -c -- '--loose --invert' || true)
ip route del 10.9.9.9/32 dev d0
ip route del default
echo LOOSE-NO-ROUTE $(rpf 10.9.9.9)
ok RPF-DONE
`

// TestE2ENetfilterGotoAndRPFilter checks the goto of a rule and the match
// rpfilter of iptables, which Calico adds to its chains.
func TestE2ENetfilterGotoAndRPFilter(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, guestSpec{
				plat: b.plat, image: "alpine:3.20", argv: []string{"sh", "-c", gotoRPFilterScript}, net: gvx.NetModeNAT, netRaw: true,
			})
			t.Log(out)
			requireContains(t, "jump and goto", out, "JUMP nothing\n", "GOTO received ping\n", "SAVE-GOTO 1\n")
			requireContains(t, "strict", out, "STRICT-REAL passed\n", "STRICT-SPOOF dropped\n", "SAVE-RPF 1\n", "STRICT-ROUTED passed\n", "STRICT-OTHER-LINK dropped\n")
			requireContains(t, "loose", out, "LOOSE-OTHER-LINK passed\n", "SAVE-LOOSE 1\n", "LOOSE-NO-ROUTE dropped\n", "RPF-DONE\n")
			if strings.Contains(out, "FAIL ") {
				t.Errorf("guest reported failures:\n%s", out)
			}
		})
	}
}
