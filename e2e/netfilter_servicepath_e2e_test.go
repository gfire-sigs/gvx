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

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/pkg/gvx"
)

// GVXIP-005 section 4.1 tests A10 and A11 check the iptables hooks for bridged
// frames and the connection tracking netlink that kube-proxy uses. Each guest is
// Alpine with the tools of a node: iptables-legacy, iproute2, and conntrack-tools.
// One sandbox holds every network namespace, so the tests also run on the whpx
// backend, which cannot start a second partition in one process.

// runServicePathGuest runs script in an Alpine guest and returns its output. The
// workspace holds the guest probes that the names list, built for the host
// architecture, under /workspace. Raw sockets and the NAT network let the guest
// install the tools.
func runServicePathGuest(t *testing.T, b gateBackend, probes map[string]string, script string) string {
	t.Helper()
	dir := t.TempDir()
	for name, build := range probes {
		data, err := os.ReadFile(build)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o755); err != nil {
			t.Fatalf("copy %s into the workspace: %v", name, err)
		}
	}
	return mustRunGuest(t, guestSpec{
		plat:      b.plat,
		image:     "alpine:3.20",
		argv:      []string{"sh", "-c", script},
		workspace: dir,
		net:       gvx.NetModeNAT,
		netRaw:    true,
		timeout:   5 * time.Minute,
	})
}

// bridgeNetfilterScript builds a bridge with three network namespaces. Each
// namespace serves its name on TCP port 8080. The addresses 10.0.0.100 and
// fd00::100 belong to ns2, which answers the neighbor request for them. A DNAT
// rule sends the traffic of each address to ns3. A SNAT rule changes the source
// address of ns1 to 10.0.0.77, which ns1 also holds, and a FORWARD rule drops
// the traffic of ns1 to ns3. The script sends each request with
// bridge-nf-call-iptables and bridge-nf-call-ip6tables at 1 and at 0.
const bridgeNetfilterScript = `set -e
apk add --no-cache iptables iptables-legacy iproute2 >/dev/null
cp /workspace/svcprobe /usr/local/bin/svcprobe
chmod 755 /usr/local/bin/svcprobe
ipt=iptables-legacy; ipt6=ip6tables-legacy
ip link add br0 type bridge
ip addr add 10.0.0.1/24 dev br0
ip -6 addr add fd00::1/64 dev br0 nodad
ip link set br0 up
for n in 1 2 3; do
  ip netns add ns$n
  ip link add v$n type veth peer name p$n
  ip link set p$n netns ns$n
  ip link set v$n master br0
  ip link set v$n up
  ip netns exec ns$n ip addr add 10.0.0.$((n+1))/24 dev p$n
  ip netns exec ns$n ip -6 addr add fd00::$((n+1))/64 dev p$n nodad
  ip netns exec ns$n ip link set p$n up
  ip netns exec ns$n ip link set lo up
done
ip netns exec ns2 ip addr add 10.0.0.100/32 dev p2
ip netns exec ns2 ip -6 addr add fd00::100/128 dev p2 nodad
ip netns exec ns1 ip addr add 10.0.0.77/32 dev p1
for n in 2 3; do ip netns exec ns$n svcprobe serve [::]:8080 ns$n & done
for n in 2 3; do
  for i in $(seq 1 60); do ip netns exec ns$n svcprobe dial [::1]:8080 >/dev/null 2>&1 && break; sleep 0.5; done
done
$ipt -t nat -A PREROUTING -d 10.0.0.100 -p tcp --dport 80 -j DNAT --to-destination 10.0.0.4:8080
$ipt6 -t nat -A PREROUTING -d fd00::100 -p tcp --dport 80 -j DNAT --to-destination [fd00::4]:8080
$ipt -t nat -A POSTROUTING -s 10.0.0.2 -d 10.0.0.3 -p tcp --dport 8080 -j SNAT --to-source 10.0.0.77
$ipt -A FORWARD -s 10.0.0.2 -d 10.0.0.4 -p tcp --dport 8080 -j DROP
dial() { ip netns exec ns1 svcprobe dial "$1" || true; }
echo "default=$(cat /proc/sys/net/bridge/bridge-nf-call-iptables)/$(cat /proc/sys/net/bridge/bridge-nf-call-ip6tables)"
for nf in 1 0; do
  echo $nf > /proc/sys/net/bridge/bridge-nf-call-iptables
  echo $nf > /proc/sys/net/bridge/bridge-nf-call-ip6tables
  echo "nf=$nf v4-dnat $(dial 10.0.0.100:80)"
  echo "nf=$nf v4-snat $(dial 10.0.0.3:8080)"
  echo "nf=$nf v4-forward-drop $(dial 10.0.0.4:8080)"
  echo "nf=$nf v6-dnat $(dial [fd00::100]:80)"
done
echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables
echo 0 > /proc/sys/net/bridge/bridge-nf-call-ip6tables
echo "mixed v4-dnat $(dial 10.0.0.100:80)"
echo "mixed v6-dnat $(dial [fd00::100]:80)"
echo "values root=$(cat /proc/sys/net/bridge/bridge-nf-call-iptables)/$(cat /proc/sys/net/bridge/bridge-nf-call-ip6tables) ns1=$(ip netns exec ns1 cat /proc/sys/net/bridge/bridge-nf-call-ip6tables)"
`

// TestE2ENetfilterBridgeA10 checks that a bridge passes the IP frames that it
// forwards through the iptables hooks while bridge-nf-call-iptables is 1: a
// DNAT rule for a virtual address sends a TCP connection to a host on the same
// bridge, the reply returns un-NATed, a SNAT rule changes the source address,
// and a FORWARD rule drops a connection. With 0, the rules do not apply to
// bridged frames. The IPv6 files switch the IPv6 hooks on their own, and each
// network namespace has its own value.
func TestE2ENetfilterBridgeA10(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			out := runServicePathGuest(t, b, map[string]string{"svcprobe": acceptprog.BuildSvcProbe(t, hostArch())}, bridgeNetfilterScript)
			requireContains(t, "guest output", out,
				"default=1/1\n",
				"nf=1 v4-dnat REPLY ns3 from=",
				"nf=1 v4-snat REPLY ns2 from=10.0.0.77\n",
				"nf=1 v4-forward-drop ERROR dial tcp 10.0.0.4:8080: i/o timeout\n",
				"nf=1 v6-dnat REPLY ns3 from=fd00::2\n",
				"nf=0 v4-dnat ERROR dial tcp 10.0.0.100:80: connect: connection refused\n",
				"nf=0 v4-snat REPLY ns2 from=10.0.0.2\n",
				"nf=0 v4-forward-drop REPLY ns3 from=10.0.0.2\n",
				"nf=0 v6-dnat ERROR dial tcp [fd00::100]:80: connect: connection refused\n",
				"mixed v4-dnat REPLY ns3 from=",
				"mixed v6-dnat ERROR dial tcp [fd00::100]:80: connect: connection refused\n",
				"values root=1/0 ns1=1\n")
		})
	}
}

// ctnetlinkScript routes UDP traffic through the root namespace, as a node
// routes the traffic of a service. ns1 sends datagrams from the fixed port 5555
// to the virtual address 10.9.9.9:9000. A DNAT rule in the PREROUTING chain of
// the root namespace sends them to ns2 first and to ns3 after the rule changes.
// The script runs conntrack for the listing, the single lookup, and the
// deletions of the table.
const ctnetlinkScript = `set -e
apk add --no-cache iptables iptables-legacy iproute2 conntrack-tools >/dev/null
ipt=iptables-legacy
for n in 1 2 3; do
  ip netns add ns$n
  ip link add r$n type veth peer name e$n
  ip link set e$n netns ns$n
  ip addr add 10.0.$n.1/24 dev r$n
  ip link set r$n up
  ip netns exec ns$n ip addr add 10.0.$n.2/24 dev e$n
  ip netns exec ns$n ip link set e$n up
  ip netns exec ns$n ip link set lo up
  ip netns exec ns$n ip route add default via 10.0.$n.1
done
echo 1 > /proc/sys/net/ipv4/ip_forward
$ipt -t nat -A PREROUTING -d 10.9.9.9 -p udp --dport 9000 -j DNAT --to-destination 10.0.2.2:9001
for n in 2 3; do ip netns exec ns$n sh -c "nc -u -l -p 9001 > /tmp/recv$n &"; done
for n in 2 3; do
  for i in $(seq 1 60); do ip netns exec ns$n grep -q ':2329 ' /proc/net/udp && break; sleep 0.5; done
done
send() { ip netns exec ns1 sh -c "echo $1 | nc -u -p 5555 -w1 10.9.9.9 9000"; sleep 1; }
received() { echo "$1 recv2=[$(cat /tmp/recv2)] recv3=[$(cat /tmp/recv3)]"; }
tuple='-p udp --orig-src 10.0.1.2 --orig-dst 10.9.9.9 --sport 5555 --dport 9000'
send one
received first
echo "LIST $(conntrack -L -p udp 2>&1)"
echo "GET $(conntrack -G $tuple 2>&1)"
$ipt -t nat -R PREROUTING 1 -d 10.9.9.9 -p udp --dport 9000 -j DNAT --to-destination 10.0.3.2:9001
send two
received old-target-kept
echo "DELETE-BY-FILTER $(conntrack -D -p udp --orig-dst 10.9.9.9 --dport 9000 2>&1)"
send three
received new-target
echo "LIST-AFTER $(conntrack -L -p udp 2>&1)"
echo "DELETE-BY-TUPLE $(conntrack -D $tuple 2>&1)"
echo "LIST-EMPTY $(conntrack -L -p udp 2>&1)"
echo "DELETE-MISSING $(conntrack -D $tuple 2>&1 || true)"
echo "EXPECT $(conntrack -L expect 2>&1)"
`

// TestE2ENetfilterCtnetlinkA11 checks that conntrack lists a UDP flow that a
// DNAT rule moved, finds it by tuple, and deletes it by filter and by tuple. The
// DNAT target changes while the flow lives, and the next packet keeps the old
// target until conntrack deletes the flow. Then the packet follows the new
// target.
func TestE2ENetfilterCtnetlinkA11(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			out := runServicePathGuest(t, b, nil, ctnetlinkScript)
			const flow = "src=10.0.1.2 dst=10.9.9.9 sport=5555 dport=9000 [UNREPLIED] src=10.0.2.2 dst=10.0.1.2 sport=9001 dport=5555 mark=0 use=1"
			requireContains(t, "guest output", out,
				"first recv2=[one] recv3=[]\n",
				flow,
				"conntrack v1.4.8 (conntrack-tools): 1 flow entries have been shown.",
				"old-target-kept recv2=[one\ntwo] recv3=[]\n",
				"DELETE-BY-FILTER udp      17 ",
				"1 flow entries have been deleted.",
				"new-target recv2=[one\ntwo] recv3=[three]\n",
				"src=10.0.3.2 dst=10.0.1.2 sport=9001 dport=5555 mark=0 use=1",
				"LIST-EMPTY conntrack v1.4.8 (conntrack-tools): 0 flow entries have been shown.",
				"DELETE-MISSING ",
				"EXPECT conntrack v1.4.8 (conntrack-tools): 0 expectations have been shown.")
		})
	}
}

// TestE2ENetfilterCtnetlinkGoLibrary checks the netlink calls of kube-proxy
// through the Go library github.com/vishvananda/netlink: a table listing with
// both tuples, the TCP state, the timeout, and the mark, and a delete with a
// filter on the protocol, the original destination, and the reply source. The
// delete removes the UDP flow, and the next datagram starts a new flow.
func TestE2ENetfilterCtnetlinkGoLibrary(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			script := `set -e
apk add --no-cache iptables iptables-legacy >/dev/null
ipt=iptables-legacy
$ipt -t nat -A OUTPUT -d 127.0.0.2 -p udp --dport 9000 -j DNAT --to-destination 127.0.0.1:9001
$ipt -t nat -A OUTPUT -d 127.0.0.2 -p tcp --dport 9100 -j DNAT --to-destination 127.0.0.1:9101
cp /workspace/ctprobe /usr/local/bin/ctprobe
chmod 755 /usr/local/bin/ctprobe
ctprobe kubeproxy
`
			out := runServicePathGuest(t, b, map[string]string{"ctprobe": acceptprog.BuildCtProbe(t, hostArch())}, script)
			requireContains(t, "guest output", out,
				"PASS listeners-start\n",
				"PASS udp-flow-reaches-the-backend\n",
				"PASS udp-flow-is-listed-with-both-tuples\n",
				"PASS tcp-flow-is-listed-as-established\n",
				"PASS ipv6-table-lists-without-error\n",
				"PASS delete-filter-removes-the-udp-flow-only\n",
				"PASS udp-flow-is-gone-after-the-delete\n",
				"PASS delete-filter-matches-nothing-twice\n",
				"PASS next-udp-packet-starts-a-new-flow\n",
				"DONE\n")
			if strings.Contains(out, "FAIL ") {
				t.Errorf("a check failed; guest output:\n%s", out)
			}
		})
	}
}

// iccScript starts dockerd with the option in $1 and connects from one
// container to a server container of the same bridge.
const iccScript = `dockerd-entrypoint.sh --tls=false $1 >/tmp/dockerd.log 2>&1 &
for i in $(seq 1 120); do docker info >/dev/null 2>&1 && break; sleep 1; done
docker info >/dev/null 2>&1 || { echo "DOCKERD-FAILED"; tail -n 20 /tmp/dockerd.log; exit 1; }
docker run -d --name srv alpine sh -c 'while true; do echo hi | nc -l -p 8080; done' >/dev/null
srv=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' srv)
sleep 2
echo "RESULT $1 $(docker run --rm alpine sh -c "nc -w 3 $srv 8080 </dev/null || echo BLOCKED")"
`

// TestE2EDockerIccSeparatesContainers checks that the FORWARD rule of dockerd
// applies to the traffic between two containers of one bridge. With --icc=false
// the connection fails. With --icc=true it succeeds.
func TestE2EDockerIccSeparatesContainers(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			for _, tc := range []struct{ arg, want string }{
				{"--icc=false", "RESULT --icc=false BLOCKED\n"},
				{"--icc=true", "RESULT --icc=true hi\n"},
			} {
				out := mustRunGuest(t, guestSpec{
					plat:          b.plat,
					image:         "docker:dind",
					entrypoint:    []string{"sh", "-c"},
					entrypointSet: true,
					cmd:           []string{iccScript, "sh", tc.arg},
					envv:          []string{"DOCKER_TLS_CERTDIR="},
					net:           gvx.NetModeNAT,
					netRaw:        true,
					packetWrite:   true,
					allowSUID:     true,
					mounts:        []gvx.Mount{{Kind: gvx.MountTmpfs, GuestPath: "/var/lib/docker", TmpfsSizeBytes: 6 << 30}},
					timeout:       10 * time.Minute,
				})
				requireContains(t, "guest output of "+tc.arg, out, tc.want)
			}
		})
	}
}
