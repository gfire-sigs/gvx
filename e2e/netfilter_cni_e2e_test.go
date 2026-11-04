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

	"z.gfire.dev/gvx/internal/acceptprog"
)

// cniBridgeScript attaches six network namespaces with the real bridge and
// host-local CNI plugins, as kubelet does for six pods. The configuration holds
// the options of the file that flannel generates for a node. The root
// namespace forwards IP packets as on a node, so each new namespace does too.
//
// The script sends five pings from the first pod to the second pod and to the
// gateway, and from the host to the first pod. It counts the duplicate replies,
// which a pod that forwards a frame for another host causes. Then it removes the
// sixth pod while the host still holds its neighbor entry, and the host sends
// connections to the address of that pod. The bridge floods them, because it no
// longer knows the link address. The script counts the duplicates again and
// sends 200 pings and 200 TCP connections between the first two pods, from each
// of them to the gateway, and from the host to each of them. It counts the
// failures.
const cniBridgeScript = `set -e
apk add --no-cache iptables iptables-legacy iproute2 cni-plugins >/dev/null
ln -sf iptables-legacy /sbin/iptables
cp /workspace/svcprobe /usr/local/bin/svcprobe
chmod 755 /usr/local/bin/svcprobe
cat > /tmp/cni.conf <<'EOF'
{"cniVersion":"1.0.0","name":"cbr0","type":"bridge","bridge":"cni0","isGateway":true,"ipMasq":true,"hairpinMode":true,
 "ipam":{"type":"host-local","ranges":[[{"subnet":"10.244.0.0/24"}]],"routes":[{"dst":"0.0.0.0/0"}]}}
EOF
mkdir -p /var/run/netns
echo 1 > /proc/sys/net/ipv4/ip_forward
for n in 1 2 3 4 5 6; do
  ip netns add ns$n
  CNI_COMMAND=ADD CNI_CONTAINERID=pod$n CNI_NETNS=/var/run/netns/ns$n CNI_IFNAME=eth0 CNI_PATH=/usr/libexec/cni /usr/libexec/cni/bridge </tmp/cni.conf >/dev/null
  ip netns exec ns$n ip link set lo up
done
ip netns exec ns1 svcprobe serve [::]:8080 ns1 &
ip netns exec ns2 svcprobe serve [::]:8080 ns2 &
for n in 1 2; do
  for i in $(seq 1 60); do ip netns exec ns$n svcprobe dial [::1]:8080 >/dev/null 2>&1 && break; sleep 0.5; done
done
ip1=10.244.0.2; ip2=10.244.0.3; gw=10.244.0.1; ip6=10.244.0.7
svcprobe serve [::]:8080 gw &
for i in $(seq 1 60); do svcprobe dial [::1]:8080 >/dev/null 2>&1 && break; sleep 0.5; done
dups() {
  if [ "$2" = host ]; then out=$(ping -c5 -W1 $3); else out=$(ip netns exec $2 ping -c5 -W1 $3); fi
  echo "DUPLICATES $1 $2-to-$3 $(echo "$out" | grep -c DUP || true)"
}
loss() {
  pf=0; tf=0
  for i in $(seq 1 200); do
    if [ "$1" = host ]; then
      ping -c1 -W2 $2 >/dev/null 2>&1 || pf=$((pf+1))
      svcprobe dial $2:8080 >/dev/null 2>&1 || tf=$((tf+1))
    else
      ip netns exec $1 ping -c1 -W2 $2 >/dev/null 2>&1 || pf=$((pf+1))
      ip netns exec $1 svcprobe dial $2:8080 >/dev/null 2>&1 || tf=$((tf+1))
    fi
  done
  echo "LOSS $1-to-$2 ping=$pf tcp=$tf"
}
dups before-stale ns1 $ip2
dups before-stale ns1 $gw
dups before-stale host $ip1
ip netns exec ns6 svcprobe serve [::]:8080 ns6 &
for i in $(seq 1 60); do ip netns exec ns6 svcprobe dial [::1]:8080 >/dev/null 2>&1 && break; sleep 0.5; done
svcprobe dial $ip6:8080 >/dev/null
ping -c1 -W2 $ip6 >/dev/null
CNI_COMMAND=DEL CNI_CONTAINERID=pod6 CNI_NETNS=/var/run/netns/ns6 CNI_IFNAME=eth0 CNI_PATH=/usr/libexec/cni /usr/libexec/cni/bridge </tmp/cni.conf
ip netns del ns6
for i in $(seq 1 10); do svcprobe dial $ip6:8080 >/dev/null 2>&1 || true; done
dups after-stale ns1 $ip2
dups after-stale ns1 $gw
dups after-stale host $ip1
loss ns1 $ip2
loss ns2 $ip1
loss ns1 $gw
loss ns2 $gw
loss host $ip1
loss host $ip2
`

// TestE2ECNIBridgeLossless checks that namespaces which the real bridge and
// host-local CNI plugins attach reach each other and the bridge gateway without
// a single lost ping or TCP connection, also after a pod left. In Linux a veth
// end ignores a unicast frame for another address and a bridge keeps a frame for
// its own address, so no pod forwards a packet. A pod that forwards frames
// of its neighbors makes the copies loop between the pods and the pods lose
// traffic.
func TestE2ECNIBridgeLossless(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			out := runServicePathGuest(t, b, map[string]string{"svcprobe": acceptprog.BuildSvcProbe(t, hostArch())}, cniBridgeScript)
			t.Logf("guest output:\n%s", out)
			requireContains(t, "guest output", out,
				"LOSS ns1-to-10.244.0.3 ping=0 tcp=0\n",
				"LOSS ns2-to-10.244.0.2 ping=0 tcp=0\n",
				"LOSS ns1-to-10.244.0.1 ping=0 tcp=0\n",
				"LOSS ns2-to-10.244.0.1 ping=0 tcp=0\n",
				"LOSS host-to-10.244.0.2 ping=0 tcp=0\n",
				"LOSS host-to-10.244.0.3 ping=0 tcp=0\n",
				"DUPLICATES before-stale ns1-to-10.244.0.3 0\n",
				"DUPLICATES before-stale ns1-to-10.244.0.1 0\n",
				"DUPLICATES before-stale host-to-10.244.0.2 0\n",
				"DUPLICATES after-stale ns1-to-10.244.0.3 0\n",
				"DUPLICATES after-stale ns1-to-10.244.0.1 0\n",
				"DUPLICATES after-stale host-to-10.244.0.2 0\n")
		})
	}
}
