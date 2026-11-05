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
	"time"
)

// The connection tracker follows the timeouts and the limit of Linux. These
// tests set the sysctl files of /proc/sys/net/netfilter, send traffic through a
// DNAT rule, and read the table with conntrack.

// conntrackTimeoutsScript sets three timeouts, opens an idle TCP flow, a closed
// TCP flow, and a UDP flow, and reads the table until each entry is gone.
const conntrackTimeoutsScript = `set -e
apk add --no-cache iptables iptables-legacy iproute2 conntrack-tools socat >/dev/null
ipt=iptables-legacy
ct=/proc/sys/net/netfilter
socat TCP-LISTEN:8081,fork,reuseaddr SYSTEM:cat &
until nc -z 127.0.0.1 8081; do sleep 0.2; done

echo "DEFAULTS $(for f in tcp_timeout_established tcp_timeout_syn_sent tcp_timeout_syn_recv tcp_timeout_fin_wait tcp_timeout_close_wait tcp_timeout_last_ack tcp_timeout_time_wait tcp_timeout_close tcp_timeout_max_retrans tcp_timeout_unacknowledged udp_timeout udp_timeout_stream icmp_timeout icmpv6_timeout generic_timeout; do cat $ct/nf_conntrack_$f; done | tr '\n' ' ')"
if echo -1 > $ct/nf_conntrack_tcp_timeout_established 2>/dev/null; then echo NEGATIVE-ACCEPTED; else echo NEGATIVE-REFUSED; fi
if echo 8589935 > $ct/nf_conntrack_tcp_timeout_established 2>/dev/null; then echo HUGE-ACCEPTED; else echo HUGE-REFUSED; fi

echo 5 > $ct/nf_conntrack_tcp_timeout_established
echo 3 > $ct/nf_conntrack_tcp_timeout_time_wait
echo 11 > $ct/nf_conntrack_udp_timeout
$ipt -t nat -A OUTPUT -d 10.96.0.1 -p tcp --dport 80 -j DNAT --to-destination 127.0.0.1:8081
$ipt -t nat -A OUTPUT -d 10.96.0.2 -p udp --dport 9000 -j DNAT --to-destination 127.0.0.1:9001

(sleep 60 | socat -T70 - TCP:10.96.0.1:80 >/dev/null 2>&1) &
sleep 2
echo "EST-LISTED $(conntrack -L -p tcp --dport 80 2>&1 | grep -cE 'tcp +6 [0-5] ESTABLISHED' || true)"
echo hi | socat -t1 - TCP:10.96.0.1:80 >/dev/null 2>&1 || true
sleep 1
echo "TW-LISTED $(conntrack -L -p tcp --dport 80 2>&1 | grep -cE 'tcp +6 [0-3] TIME_WAIT' || true)"
echo x | nc -u -w1 10.96.0.2 9000 || true
echo "UDP-LISTED $(conntrack -L -p udp --dport 9000 2>&1 | grep -cE 'udp +17 ([0-9]|1[01]) .*UNREPLIED' || true)"
sleep 8
echo "EST-GONE $(conntrack -L -p tcp --dport 80 2>&1 | grep -c ESTABLISHED || true)"
echo "TW-GONE $(conntrack -L -p tcp --dport 80 2>&1 | grep -c TIME_WAIT || true)"
sleep 4
echo "UDP-GONE $(conntrack -L -p udp --dport 9000 2>&1 | grep -c UNREPLIED || true)"

ip netns add n1
echo "NS-DEFAULT $(ip netns exec n1 cat $ct/nf_conntrack_tcp_timeout_established)"
ip netns exec n1 sh -c "echo 9 > $ct/nf_conntrack_tcp_timeout_established"
echo "NS-WRITE root=$(cat $ct/nf_conntrack_tcp_timeout_established) ns=$(ip netns exec n1 cat $ct/nf_conntrack_tcp_timeout_established)"
`

// TestE2EConntrackTimeouts checks the per-state timeouts. A guest sets
// nf_conntrack_tcp_timeout_established to 5 and opens an idle TCP flow through
// a DNAT rule. conntrack lists the flow with a timeout of at most 5 seconds,
// and it lists the flow no more after the timeout. The TIME_WAIT and UDP
// timeouts work the same way, and a network namespace keeps its own values.
func TestE2EConntrackTimeouts(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			out := runServicePathGuestFor(t, b, nil, conntrackTimeoutsScript, 5*time.Minute)
			requireContains(t, "guest output", out,
				"DEFAULTS 432000 120 60 120 60 30 120 10 300 300 30 120 30 30 600 \n",
				"NEGATIVE-REFUSED\n",
				"HUGE-REFUSED\n",
				"EST-LISTED 1\n",
				"TW-LISTED 1\n",
				"UDP-LISTED 1\n",
				"EST-GONE 0\n",
				"TW-GONE 0\n",
				"UDP-GONE 0\n",
				"NS-DEFAULT 432000\n",
				"NS-WRITE root=5 ns=9\n")
		})
	}
}

// conntrackMaxScript limits the table to three connections, fills it with
// established flows, and shows that a fourth flow does not start until the
// guest raises the limit.
const conntrackMaxScript = `set -e
apk add --no-cache iptables iptables-legacy iproute2 conntrack-tools socat >/dev/null
ipt=iptables-legacy
ct=/proc/sys/net/netfilter
socat TCP-LISTEN:8081,fork,reuseaddr SYSTEM:cat &
until nc -z 127.0.0.1 8081; do sleep 0.2; done

echo "MAX-DEFAULT $(cat $ct/nf_conntrack_max) $(cat /proc/sys/net/nf_conntrack_max)"
echo "BUCKETS $(cat $ct/nf_conntrack_buckets)"
if echo 5 > $ct/nf_conntrack_buckets 2>/dev/null; then echo BUCKETS-WRITABLE; else echo BUCKETS-READONLY; fi
if echo 5 > $ct/nf_conntrack_count 2>/dev/null; then echo COUNT-WRITABLE; else echo COUNT-READONLY; fi
echo "COUNT-START $(cat $ct/nf_conntrack_count)"

$ipt -t nat -A OUTPUT -d 10.96.0.1 -p tcp --dport 80 -j DNAT --to-destination 127.0.0.1:8081
echo 3 > $ct/nf_conntrack_max
echo "MAX-SET $(cat $ct/nf_conntrack_max) $(cat /proc/sys/net/nf_conntrack_max)"
for i in 1 2 3; do (sleep 60 | socat -T70 - TCP:10.96.0.1:80 >/dev/null 2>&1) & done
sleep 2
echo "COUNT-FULL $(cat $ct/nf_conntrack_count)"
if timeout 8 socat -u /dev/null TCP:10.96.0.1:80,connect-timeout=3 >/dev/null 2>&1; then echo FOURTH-ACCEPTED; else echo FOURTH-DROPPED; fi
echo "COUNT-AFTER-DROP $(cat $ct/nf_conntrack_count)"
echo 100000 > /proc/sys/net/nf_conntrack_max
if timeout 8 socat -u /dev/null TCP:10.96.0.1:80,connect-timeout=3 >/dev/null 2>&1; then echo FIFTH-ACCEPTED; else echo FIFTH-DROPPED; fi
echo "COUNT-AFTER-RAISE $(cat $ct/nf_conntrack_count)"

ip netns add n1
echo "NS-MAX $(ip netns exec n1 cat $ct/nf_conntrack_max) $(ip netns exec n1 cat /proc/sys/net/nf_conntrack_max)"
if ip netns exec n1 sh -c "echo 7 > $ct/nf_conntrack_max" 2>/dev/null; then echo NS-MAX-WRITABLE; else echo NS-MAX-READONLY; fi
echo "NS-COUNT $(ip netns exec n1 cat $ct/nf_conntrack_count)"
echo "MAX-AFTER-NS $(cat $ct/nf_conntrack_max)"
`

// TestE2EConntrackMax checks nf_conntrack_max. A small limit makes the tracker
// drop the packets of a new flow while established flows fill the table.
// nf_conntrack_count counts the table of the network namespace, and
// nf_conntrack_buckets is read-only. The limit belongs to the kernel: a
// network namespace shows it and cannot change it.
func TestE2EConntrackMax(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			out := runServicePathGuestFor(t, b, nil, conntrackMaxScript, 5*time.Minute)
			requireContains(t, "guest output", out,
				"MAX-DEFAULT 262144 262144\n",
				"BUCKETS 16384\n",
				"BUCKETS-READONLY\n",
				"COUNT-READONLY\n",
				"COUNT-START 0\n",
				"MAX-SET 3 3\n",
				"COUNT-FULL 3\n",
				"FOURTH-DROPPED\n",
				"COUNT-AFTER-DROP 3\n",
				"FIFTH-ACCEPTED\n",
				"COUNT-AFTER-RAISE 4\n",
				"NS-MAX 100000 100000\n",
				"NS-MAX-READONLY\n",
				"NS-COUNT 0\n",
				"MAX-AFTER-NS 100000\n")
		})
	}
}
