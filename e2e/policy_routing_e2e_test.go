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

// policyRoutingScript drives "ip rule" and "ip route" of iproute2 against the
// routing rules and tables of the guest kernel. The guest is a router between
// two namespaces: sa and sb both own the address 10.3.3.3, so the namespace that
// answers a TCP connection shows which table the connection used. Each check
// prints one marker line.
const policyRoutingScript = `set -e
apk add --no-cache iproute2 python3 >/dev/null
ok() { echo "$1"; }
bad() { echo "FAIL $*"; }
sysctl -qw net.ipv4.ip_forward=1

ip netns add sa
ip netns add sb
ip link add a0 type veth peer name a1
ip link add b0 type veth peer name b1
ip link set a1 netns sa
ip link set b1 netns sb
ip addr add 10.1.0.1/24 dev a0
ip addr add 10.2.0.1/24 dev b0
ip link set a0 up
ip link set b0 up
for p in "sa a1 10.1.0.2 10.1.0.1" "sb b1 10.2.0.2 10.2.0.1"; do
	set -- $p
	ip -n $1 addr add $3/24 dev $2
	ip -n $1 link set $2 up
	ip -n $1 link set lo up
	ip -n $1 addr add 10.3.3.3/32 dev lo
	ip -n $1 route add default via $4
done

cat >/tmp/serve.py <<'EOF'
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9000))
s.listen(8)
while True:
    c, _ = s.accept()
    c.sendall(sys.argv[1].encode())
    c.close()
EOF
cat >/tmp/dial.py <<'EOF'
import errno, socket, sys
host, mark = sys.argv[1], int(sys.argv[2])
s = socket.socket()
s.settimeout(3)
if mark:
    s.setsockopt(socket.SOL_SOCKET, 36, mark)  # SO_MARK
try:
    s.connect((host, 9000))
    print("got", s.recv(16).decode())
except TimeoutError:
    print("timeout")
except OSError as e:
    print("errno", e.errno, errno.errorcode.get(e.errno, "?"))
EOF
ip -n sa addr add 10.42.7.70/32 dev lo
ip -n sa addr add 10.42.7.9/32 dev lo
ip netns exec sa python3 /tmp/serve.py A &
ip netns exec sb python3 /tmp/serve.py B &
sleep 2

# The default rules of Linux.
echo RULES4 $(ip rule show | tr '\t\n' '  ')
echo RULES6 $(ip -6 rule show | tr '\t\n' '  ')
# busybox asks for the rules with struct rtgenmsg, a body of one byte.
echo BUSYBOX-RULES $(busybox ip rule list | tr '\t\n' '  ')

ip route replace default via 10.1.0.2
ip route add default via 10.2.0.2 table 200
echo TABLE200 $(ip route show table 200)
echo MAIN-HAS-NO-200 $(ip route show | grep -c 'via 10.2.0.2' || true)
echo TABLE-ALL $(ip route show table all | grep -c 'via 10.2.0.2' || true)

echo GET-PLAIN $(ip route get 10.3.3.3 | head -1)
ip rule add fwmark 7 lookup 200
echo RULE-ADDED $(ip rule show | grep fwmark | tr '\t' ' ')
echo GET-MARK7 $(ip route get 10.3.3.3 mark 7 | head -1)
echo GET-MARK6 $(ip route get 10.3.3.3 mark 6 | head -1)
echo DIAL-PLAIN $(python3 /tmp/dial.py 10.3.3.3 0)
echo DIAL-MARK7 $(python3 /tmp/dial.py 10.3.3.3 7)
echo DIAL-MARK6 $(python3 /tmp/dial.py 10.3.3.3 6)
# A rule without a priority gets a new one, so only the same priority is a duplicate.
if ip rule add priority 32765 fwmark 7 lookup 200 2>/tmp/dup-err; then bad "duplicate rule accepted"; else echo RULE-DUP $(cat /tmp/dup-err); fi
ip rule del fwmark 7 lookup 200
echo RULE-DELETED $(ip rule show | grep -c fwmark || true)
echo DIAL-AFTER-DEL $(python3 /tmp/dial.py 10.3.3.3 7)
if ip rule del fwmark 7 lookup 200 2>/tmp/del-err; then bad "missing rule deleted"; else echo RULE-DEL-MISSING $(cat /tmp/del-err); fi

# Source, input interface, priority, and goto.
ip rule add from 10.1.0.0/24 to 10.3.3.0/24 iif a0 lookup 200 priority 100
echo RULE-SRC $(ip rule show | grep 'iif a0' | tr '\t' ' ')
ip rule del priority 100
# rule_exists() compares the mark, so a rule without the mark is a new rule.
ip rule add priority 90 fwmark 5 iif a0 lookup 200
if ip rule add priority 90 iif a0 lookup 200 2>/tmp/excl-err; then ok RULE-EXCL-MARK-DIFFERS; else echo FAIL "rule without the mark of an existing rule: $(cat /tmp/excl-err)"; fi
ip rule del priority 90
ip rule del priority 90
ip rule add priority 50 goto 70
ip rule add priority 60 blackhole
ip rule add priority 70 fwmark 9 unreachable
echo RULE-GOTO $(ip rule show | grep goto | tr '\t' ' ')
echo GET-GOTO $(ip route get 10.3.3.3 mark 9 2>&1 | head -1)
ip rule del priority 70
ip rule del priority 60
ip rule del priority 50

# The rules of wg-quick for a full tunnel.
ip route add default dev b0 table 51820
ip rule add not fwmark 51820 table 51820
ip rule add table main suppress_prefixlength 0
echo WG-RULES $(ip rule show | grep -E 'not|suppress' | tr '\t' ' ')
echo WG-GET-PLAIN $(ip route get 1.2.3.4 | head -1)
echo WG-GET-MARKED $(ip route get 1.2.3.4 mark 51820 | head -1)
echo WG-GET-LOCAL-SUBNET $(ip route get 10.1.0.2 | head -1)
ip rule del table main suppress_prefixlength 0
ip rule del not fwmark 51820 table 51820
ip route flush table 51820

# Route types, the dump, and the errors for a local sender.
ip route add blackhole 10.42.7.0/26
ip route add unreachable 10.42.8.0/26
ip route add prohibit 10.42.9.0/26 proto 80
ip route add throw 10.42.10.0/26 table 200
echo ROUTES $(ip route show | grep -E '^(blackhole|unreachable|prohibit)' | tr '\n' ';')
echo THROW-DUMP $(ip route show table 200 | grep throw)
echo DIAL-BLACKHOLE $(python3 /tmp/dial.py 10.42.7.5 0)
echo DIAL-UNREACHABLE $(python3 /tmp/dial.py 10.42.8.5 0)
echo DIAL-PROHIBIT $(python3 /tmp/dial.py 10.42.9.5 0)
echo GET-BLACKHOLE $(ip route get 10.42.7.5 2>&1 | head -1)
echo GET-UNREACHABLE $(ip route get 10.42.8.5 2>&1 | head -1)
echo GET-PROHIBIT $(ip route get 10.42.9.5 2>&1 | head -1)
echo DIAL-BLOCK-NEIGHBOR $(python3 /tmp/dial.py 10.42.7.70 0)
if ip route add blackhole 10.42.7.0/26 2>/tmp/err; then bad "duplicate blackhole accepted"; else echo ROUTE-DUP $(cat /tmp/err); fi
# fib_check_nh() refuses a gateway that a route of another type covers, and takes
# one that a unicast route of another table covers.
if ip route add 10.79.0.0/24 via 10.42.7.5 2>/tmp/err; then bad "gateway behind a blackhole accepted"; else echo GW-BLACKHOLE $(cat /tmp/err); fi
if ip route add 10.79.1.0/24 via 10.1.0.2 table 300 2>/tmp/err; then ok GW-OTHER-TABLE-OK; else echo FAIL "gateway of the table main for table 300: $(cat /tmp/err)"; fi
ip route flush table 300
if ip route add blackhole 10.42.11.0/26 dev a0 2>/tmp/err; then bad "blackhole with a device accepted"; else echo BLACKHOLE-DEV $(cat /tmp/err); fi

# The router answers for a forwarded packet as Linux does.
echo FWD-BLACKHOLE $(ip netns exec sa python3 /tmp/dial.py 10.42.7.5 0)
echo FWD-UNREACHABLE $(ip netns exec sa python3 /tmp/dial.py 10.42.8.5 0)
echo FWD-PROHIBIT $(ip netns exec sa python3 /tmp/dial.py 10.42.9.5 0)

ip route del blackhole 10.42.7.0/26
ip route del unreachable 10.42.8.0/26
ip route del prohibit 10.42.9.0/26
ip route del throw 10.42.10.0/26 table 200
echo ROUTES-AFTER-DEL $(ip route show | grep -cE '^(blackhole|unreachable|prohibit)' || true)
echo DIAL-AFTER-ROUTE-DEL $(python3 /tmp/dial.py 10.42.7.9 0)

# Metrics, protocols, tables above 255, and replace.
ip route add 10.77.0.0/24 via 10.1.0.2 metric 100 proto static
ip route add 10.77.0.0/24 via 10.2.0.2 metric 50
echo METRIC $(ip route get 10.77.0.9 | head -1)
echo METRIC-DUMP $(ip route show 10.77.0.0/24 | tr '\n' ';')
ip route del 10.77.0.0/24 metric 50
ip route replace 10.77.0.0/24 via 10.2.0.2 metric 100
echo REPLACE $(ip route show 10.77.0.0/24 | tr '\n' ';')
ip route add 10.78.0.0/24 via 10.2.0.2 table 1000
echo BIGTABLE $(ip route show table 1000)
ip route del 10.78.0.0/24 table 1000
if ip route add 10.79.0.0/24 2>/tmp/err; then bad "route without a device accepted"; else echo NODEV $(cat /tmp/err); fi
if ip route add 10.79.0.5/24 dev a0 2>/tmp/err; then bad "prefix with host bits accepted"; else echo HOSTBITS $(cat /tmp/err); fi
ok POLICY-DONE
`

// TestE2EPolicyRouting proves the routing rules, the tables, and the route
// types of the guest kernel with the unmodified tool ip. It also sends TCP
// connections with SO_MARK through two routers and checks the errors that Linux
// gives a local sender and a forwarded packet for a blackhole, unreachable, and
// prohibit route.
func TestE2EPolicyRouting(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, guestSpec{
				plat: b.plat, image: "alpine:3.20", argv: []string{"sh", "-c", policyRoutingScript}, net: gvx.NetModeNAT, netRaw: true,
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
			requireContains(t, "ip rule", field("RULES4"), "0: from all lookup local", "32766: from all lookup main", "32767: from all lookup default")
			requireContains(t, "busybox ip rule", field("BUSYBOX-RULES"), "0:", "32766:", "32767:")
			requireContains(t, "ip -6 rule", field("RULES6"), "0: from all lookup local", "32766: from all lookup main")
			if strings.Contains(field("RULES6"), "32767") {
				t.Errorf("IPv6 rules = %q, want no rule for the table default", field("RULES6"))
			}
			requireContains(t, "table 200", field("TABLE200"), "default via 10.2.0.2 dev b0")
			if got := field("MAIN-HAS-NO-200"); got != "0" {
				t.Errorf("the table main holds %s routes of table 200, want 0", got)
			}
			if got := field("TABLE-ALL"); got != "1" {
				t.Errorf("table all shows %s routes via 10.2.0.2, want 1", got)
			}
			requireContains(t, "route get", field("GET-PLAIN"), "10.3.3.3 via 10.1.0.2 dev a0")
			requireContains(t, "rule with a mark", field("RULE-ADDED"), "32765: from all fwmark 0x7 lookup 200")
			requireContains(t, "route get with a mark", field("GET-MARK7"), "10.3.3.3 via 10.2.0.2 dev b0")
			requireContains(t, "route get with another mark", field("GET-MARK6"), "10.3.3.3 via 10.1.0.2 dev a0")
			requireContains(t, "connections", out, "DIAL-PLAIN got A\n", "DIAL-MARK7 got B\n", "DIAL-MARK6 got A\n", "DIAL-AFTER-DEL got A\n")
			requireContains(t, "duplicate rule", field("RULE-DUP"), "File exists")
			requireContains(t, "deleted rule", out, "RULE-DELETED 0\n")
			requireContains(t, "missing rule", field("RULE-DEL-MISSING"), "No such file or directory")
			requireContains(t, "source rule", field("RULE-SRC"), "100: from 10.1.0.0/24 to 10.3.3.0/24 iif a0 lookup 200")
			requireContains(t, "rule that differs in the mark", out, "RULE-EXCL-MARK-DIFFERS\n")
			requireContains(t, "goto rule", field("RULE-GOTO"), "50: from all goto 70")
			requireContains(t, "route get through goto", field("GET-GOTO"), "Network unreachable")
			requireContains(t, "wg-quick rules", field("WG-RULES"), "32765: not from all fwmark 0xca6c lookup 51820", "32764: from all lookup main suppress_prefixlength 0")
			requireContains(t, "route get through the tunnel table", field("WG-GET-PLAIN"), "1.2.3.4 dev b0")
			requireContains(t, "route get of the tunnel socket", field("WG-GET-MARKED"), "1.2.3.4 via 10.1.0.2 dev a0")
			requireContains(t, "route get of the local subnet", field("WG-GET-LOCAL-SUBNET"), "10.1.0.2 dev a0")
			requireContains(t, "route dump", field("ROUTES"), "blackhole 10.42.7.0/26", "unreachable 10.42.8.0/26", "prohibit 10.42.9.0/26 proto 80")
			requireContains(t, "gateway behind a blackhole", field("GW-BLACKHOLE"), "Invalid argument")
			requireContains(t, "gateway through another table", out, "GW-OTHER-TABLE-OK\n")
			requireContains(t, "throw dump", field("THROW-DUMP"), "throw 10.42.10.0/26")
			requireContains(t, "local sender", out,
				"DIAL-BLACKHOLE errno 22 EINVAL\n", "DIAL-UNREACHABLE errno 113 EHOSTUNREACH\n", "DIAL-PROHIBIT errno 13 EACCES\n")
			requireContains(t, "route get of a blackhole", field("GET-BLACKHOLE"), "Invalid argument")
			requireContains(t, "route get of an unreachable route", field("GET-UNREACHABLE"), "Host is unreachable")
			requireContains(t, "route get of a prohibit route", field("GET-PROHIBIT"), "Permission denied")
			requireContains(t, "neighbor address", out, "DIAL-BLOCK-NEIGHBOR got A\n")
			requireContains(t, "duplicate route", field("ROUTE-DUP"), "File exists")
			requireContains(t, "blackhole with a device", field("BLACKHOLE-DEV"), "Invalid argument")
			requireContains(t, "forwarded packet", out, "FWD-BLACKHOLE timeout\n", "FWD-UNREACHABLE errno 113 EHOSTUNREACH\n", "FWD-PROHIBIT errno 113 EHOSTUNREACH\n")
			requireContains(t, "route removal", out, "ROUTES-AFTER-DEL 0\n", "DIAL-AFTER-ROUTE-DEL got A\n")
			requireContains(t, "metric", field("METRIC"), "10.77.0.9 via 10.2.0.2 dev b0")
			requireContains(t, "metric dump", field("METRIC-DUMP"), "10.77.0.0/24 via 10.2.0.2 dev b0 metric 50", "10.77.0.0/24 via 10.1.0.2 dev a0 proto static metric 100")
			requireContains(t, "replace", field("REPLACE"), "10.77.0.0/24 via 10.2.0.2 dev b0 metric 100")
			requireContains(t, "table above 255", field("BIGTABLE"), "10.78.0.0/24 via 10.2.0.2 dev b0")
			requireContains(t, "route without a device", field("NODEV"), "No such device")
			requireContains(t, "prefix with host bits", field("HOSTBITS"), "Invalid argument")
			requireContains(t, "end marker", out, "POLICY-DONE\n")
			if strings.Contains(out, "FAIL ") {
				t.Errorf("guest reported failures:\n%s", out)
			}
		})
	}
}

// TestE2EFelixRoutes sends the route requests of Calico Felix through
// github.com/vishvananda/netlink: a blackhole, unreachable, prohibit, or throw
// route without a device, with the protocol 80, the universe scope, and the
// table 254. Felix then lists the routes with a filter on the table and the
// protocol. The guest is the program nodeprobe, so the test needs no registry.
func TestE2EFelixRoutes(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		code, out := runNodeProbe(t, b, bin, nil, "felixroutes")
		requireNodeChecks(t, code, out,
			"felixroutes-blackhole-without-device", "felixroutes-replace-and-duplicate",
			"felixroutes-ipv6-blackhole-on-lo", "felixroutes-unicast-without-device-fails")
	})
}
