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

// ipsetCLIScript drives the ipset tool of Alpine against the NFNL_SUBSYS_IPSET
// subsystem of the guest kernel. It creates a set of every type, adds, tests,
// and deletes elements, saves and restores all sets, swaps two sets, and lets a
// timeout expire. Each check prints one marker line.
const ipsetCLIScript = `set -e
apk add --no-cache ipset >/dev/null
# ipset 7.21 of Alpine copies 256 bytes of the comment argument (fixed in 7.23).
# It crashes on any kernel when less than 256 bytes follow the argument on the
# stack, so the script gives the environment a long variable.
export IPSET_PAD=$(head -c 600 /dev/zero | tr '\0' x)
ok() { echo "$1"; }
bad() { echo "FAIL $*"; }
has() { ipset test "$@" >/dev/null 2>&1; }
# Every set type that kube-router and Calico use.
ipset create t_ip hash:ip
ipset create t_net hash:net
ipset create t_ipport hash:ip,port
ipset create t_netport hash:net,port
ipset create t_ippip hash:ip,port,ip
ipset create t_ippnet hash:ip,port,net
ipset create t_netnet hash:net,net
ipset create t_ports bitmap:port range 1-1024
ipset create t_list list:set
ipset create t_v6 hash:ip family inet6
ipset create t_opt hash:ip family inet hashsize 128 maxelem 100 timeout 0 counters comment
ok TYPES-CREATED

ipset add t_ip 10.0.0.1
has t_ip 10.0.0.1 && ! has t_ip 10.0.0.2 && ok HASH-IP-OK || bad hash:ip
ipset add t_ip 10.1.0.0/30
has t_ip 10.1.0.3 && ok HASH-IP-CIDR-OK || bad "hash:ip cidr"
ipset add t_ip 10.2.0.1-10.2.0.4
has t_ip 10.2.0.4 && ! has t_ip 10.2.0.5 && ok HASH-IP-RANGE-OK || bad "hash:ip range"
ipset del t_ip 10.0.0.1
! has t_ip 10.0.0.1 && ok DEL-OK || bad del

ipset add t_net 10.0.0.0/8
ipset add t_net 10.1.0.0/16 nomatch
has t_net 10.2.3.4 && ! has t_net 10.1.3.4 && ! has t_net 11.0.0.1 && ok HASH-NET-NOMATCH-OK || bad "hash:net nomatch"

ipset add t_ipport 10.0.0.1,tcp:80
ipset add t_ipport 10.0.0.1,udp:53
has t_ipport 10.0.0.1,tcp:80 && has t_ipport 10.0.0.1,udp:53 && ! has t_ipport 10.0.0.1,tcp:81 && ! has t_ipport 10.0.0.1,udp:80 && ok HASH-IPPORT-OK || bad "hash:ip,port"
ipset add t_netport 10.0.0.0/24,tcp:443
has t_netport 10.0.0.77,tcp:443 && ! has t_netport 10.0.1.77,tcp:443 && ok HASH-NETPORT-OK || bad "hash:net,port"
ipset add t_ippip 10.0.0.1,tcp:80,10.0.0.2
has t_ippip 10.0.0.1,tcp:80,10.0.0.2 && ! has t_ippip 10.0.0.1,tcp:80,10.0.0.3 && ok HASH-IPPORTIP-OK || bad "hash:ip,port,ip"
ipset add t_ippnet 10.0.0.1,tcp:80,172.16.0.0/12
has t_ippnet 10.0.0.1,tcp:80,172.20.1.1 && ! has t_ippnet 10.0.0.1,tcp:80,173.0.0.1 && ok HASH-IPPORTNET-OK || bad "hash:ip,port,net"
ipset add t_netnet 10.0.0.0/8,192.168.0.0/16
has t_netnet 10.9.9.9,192.168.7.7 && ! has t_netnet 10.9.9.9,192.169.7.7 && ok HASH-NETNET-OK || bad "hash:net,net"
ipset add t_ports 22
ipset add t_ports 100-110
has t_ports 22 && has t_ports 105 && ! has t_ports 23 && ok BITMAP-PORT-OK || bad "bitmap:port"
ipset add t_v6 fd00::1
has t_v6 fd00::1 && ! has t_v6 fd00::2 && ok HASH-IP-V6-OK || bad "hash:ip inet6"
ipset add t_opt 10.0.0.9 timeout 100 comment "web server" packets 5 bytes 600
opt=$(ipset list t_opt)
echo "$opt" | grep -q 'Header: family inet hashsize 128 maxelem 100 timeout 0 counters comment' && \
  echo "$opt" | grep -q '10.0.0.9 timeout .* packets 5 bytes 600 comment "web server"' && ok OPTIONS-OK || { bad options; echo "$opt"; }

ipset add t_list t_ip
ipset add t_list t_net
[ "$(ipset list t_list | grep -c '^t_')" = 2 ] && ok LIST-SET-OK || bad "list:set members"
if ipset destroy t_ip 2>/dev/null; then bad "destroy of a list member"; else ok DESTROY-BUSY-OK; fi
ipset list -n | grep -q t_netnet && ok LIST-NAMES-OK || bad "list names"
ipset list t_ports | grep -q 'Header: range 1-1024' && ok BITMAP-HEADER-OK || bad "bitmap header"

# Errors that the tool decodes from the kernel.
ipset create t_ip hash:ip 2>&1 | grep -q 'already exists' && ok EXISTS-ERROR-OK || bad "exists error"
ipset add t_net 10.0.0.0/8 2>&1 | grep -q 'already added' && ok ADDED-ERROR-OK || bad "added error"
ipset create t_ip hash:ip -exist && ok CREATE-EXIST-OK || bad "create -exist"
ipset create t_ip hash:ip maxelem 5 -exist 2>&1 | grep -q 'already exists' && ok CREATE-EXIST-DIFF-OK || bad "create -exist with other options"
ipset add t_ip 10.0.0.1 -exist && ipset add t_ip 10.0.0.1 -exist && ok ADD-EXIST-OK || bad "add -exist"

# Save, destroy, restore. The listing of the restored sets equals the listing before.
# The remaining time of a timeout runs down between two saves, so the comparison drops it.
ipset save | sed 's/ timeout [0-9]*//' | sort > /tmp/before.save
ipset save > /tmp/all.save
ipset flush
ipset destroy
[ -z "$(ipset list -n)" ] && ok DESTROY-ALL-OK || bad "destroy all"
ipset restore < /tmp/all.save
ipset save | sed 's/ timeout [0-9]*//' | sort > /tmp/after.save
if cmp -s /tmp/before.save /tmp/after.save; then ok SAVE-RESTORE-OK; else bad "save restore"; diff /tmp/before.save /tmp/after.save | head -20; fi

# Swap and rename.
ipset create sw_a hash:ip
ipset create sw_b hash:ip
ipset add sw_a 10.5.0.1
ipset swap sw_a sw_b
has sw_b 10.5.0.1 && ! has sw_a 10.5.0.1 && ok SWAP-OK || bad swap
ipset rename sw_b sw_c
has sw_c 10.5.0.1 && ok RENAME-OK || bad rename
if ipset swap sw_c t_ports 2>/dev/null; then bad "swap of different types"; else ok SWAP-MISMATCH-OK; fi

# A large restore needs several messages in the answer of a listing.
{ echo "create big hash:ip maxelem 100000"; awk 'BEGIN { for (i = 0; i < 6000; i++) printf "add big 10.%d.%d.%d\n", int(i / 65025), int(i / 255) % 255, i % 255 + 1 }'; } > /tmp/big.restore
ipset restore < /tmp/big.restore && ok BIG-RESTORE-OK || bad "big restore"
[ "$(ipset list big | grep -c '^10\.')" = 6000 ] && ok BIG-LIST-OK || bad "big list $(ipset list big | grep -c '^10\.')"
[ "$(ipset save big | grep -c '^add big ')" = 6000 ] && ok BIG-SAVE-OK || bad "big save"
ipset list big -terse | grep -q 'Number of entries: 6000' && ok TERSE-OK || bad terse

# Timeouts.
ipset create ttl hash:ip timeout 2
ipset add ttl 1.1.1.1
has ttl 1.1.1.1 && ok TIMEOUT-ADDED-OK || bad "timeout add"
sleep 4
! has ttl 1.1.1.1 && ok TIMEOUT-EXPIRED-OK || bad "timeout expiry"
cat /sys/module/ip_set/parameters/max_sets | sed 's/^/MAXSETS /'
echo IPSET-DONE
`

// TestE2EIPSetCLI runs the ipset tool of the guest through every set type, a
// save and restore round trip, a swap, and a timeout.
func TestE2EIPSetCLI(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, guestSpec{
				plat:   b.plat,
				image:  "alpine:3.20",
				argv:   []string{"sh", "-c", ipsetCLIScript},
				net:    gvx.NetModeNAT,
				netRaw: true,
			})
			requireContains(t, "guest output", out,
				"TYPES-CREATED\n", "HASH-IP-OK\n", "HASH-IP-CIDR-OK\n", "HASH-IP-RANGE-OK\n", "DEL-OK\n",
				"HASH-NET-NOMATCH-OK\n", "HASH-IPPORT-OK\n", "HASH-NETPORT-OK\n", "HASH-IPPORTIP-OK\n",
				"HASH-IPPORTNET-OK\n", "HASH-NETNET-OK\n", "BITMAP-PORT-OK\n", "HASH-IP-V6-OK\n", "OPTIONS-OK\n",
				"LIST-SET-OK\n", "DESTROY-BUSY-OK\n", "LIST-NAMES-OK\n", "BITMAP-HEADER-OK\n",
				"EXISTS-ERROR-OK\n", "ADDED-ERROR-OK\n", "CREATE-EXIST-OK\n", "CREATE-EXIST-DIFF-OK\n", "ADD-EXIST-OK\n",
				"DESTROY-ALL-OK\n", "SAVE-RESTORE-OK\n", "SWAP-OK\n", "RENAME-OK\n", "SWAP-MISMATCH-OK\n",
				"BIG-RESTORE-OK\n", "BIG-LIST-OK\n", "BIG-SAVE-OK\n", "TERSE-OK\n", "TIMEOUT-ADDED-OK\n", "TIMEOUT-EXPIRED-OK\n",
				"MAXSETS 256\n", "IPSET-DONE\n")
			if strings.Contains(out, "FAIL ") {
				t.Errorf("guest reported failures:\n%s", out)
			}
		})
	}
}

// ipsetNetfilterScript uses sets in iptables rules. A rule with the match set
// drops the traffic of a member and lets a non-member pass. The target SET adds
// the source of a packet to a set. A rule holds a reference to its set.
const ipsetNetfilterScript = `set -e
apk add --no-cache ipset iptables iptables-legacy socat >/dev/null
ok() { echo "$1"; }
bad() { echo "FAIL $*"; }
ipt="iptables-legacy -w"
ip addr add 10.77.0.2/32 dev lo
ip addr add 10.77.0.3/32 dev lo
socat TCP-LISTEN:9000,fork,reuseaddr SYSTEM:'echo hello' &
i=0; until socat -u TCP:127.0.0.1:9000 - >/dev/null 2>&1; do i=$((i+1)); [ $i -gt 50 ] && exit 1; sleep 0.1; done
reach() { socat -u -T2 TCP:127.0.0.1:9000,bind=$1,connect-timeout=2 - 2>/dev/null | grep -q hello; }

reach 10.77.0.2 && reach 10.77.0.3 && ok BASELINE-OK || bad baseline
ipset create blocked hash:ip
ipset add blocked 10.77.0.2
$ipt -A INPUT -m set --match-set blocked src -j DROP
if reach 10.77.0.2; then bad "member was not blocked"; else ok MEMBER-BLOCKED-OK; fi
reach 10.77.0.3 && ok NONMEMBER-PASSES-OK || bad "non-member blocked"
$ipt -S INPUT | grep -q -- '-A INPUT -m set --match-set blocked src -j DROP' && ok SAVE-MATCH-OK || { bad "iptables -S"; $ipt -S INPUT; }
iptables-legacy-save | grep -q -- '-A INPUT -m set --match-set blocked src -j DROP' && ok SAVE-OK || bad "iptables-save"
if ipset destroy blocked 2>/dev/null; then bad "destroy with a rule"; else ok RULE-HOLDS-SET-OK; fi
ipset del blocked 10.77.0.2
reach 10.77.0.2 && ok DEL-UNBLOCKS-OK || bad "del did not unblock"

# A packet counter with the match option.
ipset create counted hash:ip counters
ipset add counted 10.77.0.3
$ipt -A INPUT -m set --match-set counted src --packets-gt 1000 -j DROP
reach 10.77.0.3 && ok COUNTER-MATCH-OK || bad "counter match"
$ipt -D INPUT -m set --match-set counted src --packets-gt 1000 -j DROP
ipset test counted 10.77.0.3 >/dev/null 2>&1

# Two dimensions with src,dst flags and a negated match.
ipset create svc hash:ip,port
ipset add svc 127.0.0.1,tcp:9000
$ipt -A OUTPUT -m set --match-set svc dst,dst -j REJECT
if reach 10.77.0.3; then bad "ip,port set did not reject"; else ok IPPORT-MATCH-OK; fi
$ipt -F OUTPUT
# The replies of the listener also pass the OUTPUT chain, so the rule looks at SYN packets only.
$ipt -A OUTPUT -p tcp --syn -m set ! --match-set svc dst,dst -j REJECT
reach 10.77.0.3 && ok NEGATED-MATCH-OK || bad "negated match"
$ipt -F OUTPUT

# A net set with nomatch and the option --return-nomatch.
ipset create nets hash:net
ipset add nets 127.0.0.0/8
ipset add nets 127.0.0.1 nomatch
$ipt -A OUTPUT -m set --match-set nets dst -j REJECT
reach 10.77.0.3 && ok NOMATCH-OK || bad nomatch
$ipt -F OUTPUT
$ipt -A OUTPUT -m set --match-set nets dst --return-nomatch -j REJECT
if reach 10.77.0.3; then bad "return-nomatch"; else ok RETURN-NOMATCH-OK; fi
$ipt -F OUTPUT
$ipt -F INPUT

# The target SET adds the source address of each packet.
ipset create seen hash:ip timeout 60
$ipt -A INPUT -p tcp --dport 9000 -j SET --add-set seen src --exist --timeout 30
reach 10.77.0.3 >/dev/null
ipset test seen 10.77.0.3 >/dev/null 2>&1 && ok SET-ADD-OK || bad "SET --add-set"
$ipt -S INPUT | grep -q -- '-j SET --add-set seen src --exist --timeout 30' && ok SET-SAVE-OK || { bad "SET save"; $ipt -S INPUT; }
$ipt -F INPUT
$ipt -A INPUT -p tcp --dport 9000 -j SET --del-set seen src
reach 10.77.0.3 >/dev/null
! ipset test seen 10.77.0.3 >/dev/null 2>&1 && ok SET-DEL-OK || bad "SET --del-set"
$ipt -F INPUT

# The target LOG takes a rule, keeps it for iptables-save, and lets the traffic pass.
$ipt -A INPUT -p tcp --dport 9000 -j LOG --log-prefix "t: " --log-level 3
reach 10.77.0.3 && ok LOG-PASSES-OK || bad "LOG blocked the traffic"
$ipt -S INPUT | grep -q -- '-j LOG --log-prefix "t: " --log-level 3' && ok LOG-SAVE-OK || { bad "LOG save"; $ipt -S INPUT; }
$ipt -F INPUT

# A set in the IPv6 tables.
ipset create blocked6 hash:ip family inet6
ip6tables-legacy -w -A INPUT -m set --match-set blocked6 src -j DROP
ip6tables-legacy-save | grep -q -- '-m set --match-set blocked6 src -j DROP' && ok IPV6-RULE-OK || bad "ip6tables"
ip6tables-legacy -w -F INPUT
echo IPSET-NETFILTER-DONE
`

// TestE2EIPSetNetfilter proves the iptables match set and the target SET on
// real traffic: a rule with the match set drops the traffic of a set member,
// and a rule keeps its set alive.
func TestE2EIPSetNetfilter(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, guestSpec{
				plat:   b.plat,
				image:  "alpine:3.20",
				argv:   []string{"sh", "-c", ipsetNetfilterScript},
				net:    gvx.NetModeNAT,
				netRaw: true,
			})
			requireContains(t, "guest output", out,
				"BASELINE-OK\n", "MEMBER-BLOCKED-OK\n", "NONMEMBER-PASSES-OK\n", "SAVE-MATCH-OK\n", "SAVE-OK\n",
				"RULE-HOLDS-SET-OK\n", "DEL-UNBLOCKS-OK\n", "COUNTER-MATCH-OK\n", "IPPORT-MATCH-OK\n",
				"NEGATED-MATCH-OK\n", "NOMATCH-OK\n", "RETURN-NOMATCH-OK\n", "SET-ADD-OK\n", "SET-SAVE-OK\n",
				"SET-DEL-OK\n", "LOG-PASSES-OK\n", "LOG-SAVE-OK\n", "IPV6-RULE-OK\n", "IPSET-NETFILTER-DONE\n")
			if strings.Contains(out, "FAIL ") {
				t.Errorf("guest reported failures:\n%s", out)
			}
		})
	}
}
