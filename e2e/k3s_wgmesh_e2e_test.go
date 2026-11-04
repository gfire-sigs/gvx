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
	"context"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/pkg/gvx"
)

// wgMeshNetwork is the network of the WireGuard mesh in C2 and C4. Node i
// holds the address 192.168.77.i on wg0.
const wgMeshNetwork = "192.168.77"

// wgToolDir returns a host directory that holds the wg tool and the musl
// loader of Alpine, as the files wg and ld.so. The image rancher/k3s has no
// wg tool, and the test must not change that image. An Alpine guest copies
// the files that the k3s guest then runs. The guest of a node runs wg as
// "ld.so wg", which needs no change to the root file system.
func wgToolDir(t *testing.T, b gateBackend) string {
	t.Helper()
	dir := t.TempDir()
	out := mustRunGuest(t, guestSpec{
		plat: b.plat, image: "alpine:3.20", net: gvx.NetModeNAT, workspace: dir,
		argv: []string{"sh", "-c", `set -e
apk add --no-cache wireguard-tools-wg >/dev/null
cp /usr/bin/wg /workspace/wg
cp /lib/ld-musl-*.so.1 /workspace/ld.so
echo WG-TOOL-COPIED`},
	})
	requireContains(t, "wg tool copy", out, "WG-TOOL-COPIED")
	return dir
}

// wgMeshScript is the shell function wg_up. A node builds its wg0 link with
// the unmodified wg tool and "ip": the tunnel address, one peer for every
// other node, and a keepalive of 25 seconds. Every node publishes its
// WireGuard port on a host port, and the peers dial 10.0.2.2 at the host
// port of the other node. The first input line holds the host ports of all
// nodes in the order of their numbers. The environment holds WG_INDEX, the
// number of this node, WG_KEY, and WG_PUB_<number> for every node.
const wgMeshScript = `
wg() { /tmp/wgtool/ld.so /tmp/wgtool/wg "$@"; }
wg_up() {
  read -r ports
  mkdir -p /tmp/wgtool
  cp /workspace/wg /workspace/ld.so /tmp/wgtool/
  chmod 755 /tmp/wgtool/wg /tmp/wgtool/ld.so
  umask 077
  echo "$WG_KEY" > /tmp/key
  umask 022
  peers=""
  i=1
  for port in $ports; do
    if [ "$i" != "$WG_INDEX" ]; then
      eval "pub=\$WG_PUB_$i"
      peers="$peers peer $pub endpoint 10.0.2.2:$port allowed-ips ` + wgMeshNetwork + `.$i/32 persistent-keepalive 25"
    fi
    i=$((i+1))
  done
  ip link add wg0 type wireguard
  wg set wg0 private-key /tmp/key listen-port 51820 $peers
  ip addr add ` + wgMeshNetwork + `.$WG_INDEX/24 dev wg0
  ip link set wg0 up
  log "WG-UP $WG_INDEX"
}
`

// wgMeshNodes returns the specifications of the nodes of a mesh, one for each
// script. Each node publishes UDP port 51820 on an ephemeral host port. The
// keys come from newWGKeys, and the environment of node i holds WG_INDEX=i.
func wgMeshNodes(t *testing.T, hostnames, scripts []string, extraEnv []string, workspace string) []k3sNodeSpec {
	t.Helper()
	n := len(scripts)
	keys := make([]wgKeys, n)
	for i := range keys {
		keys[i] = newWGKeys(t)
	}
	specs := make([]k3sNodeSpec, n)
	for i := range specs {
		env := append([]string{"WG_INDEX=" + strconv.Itoa(i+1), "WG_KEY=" + keys[i].private}, extraEnv...)
		for j := range keys {
			env = append(env, "WG_PUB_"+strconv.Itoa(j+1)+"="+keys[j].public)
		}
		specs[i] = k3sNodeSpec{
			hostname:  hostnames[i],
			env:       env,
			script:    wgMeshScript + scripts[i],
			workspace: workspace,
			forwards:  []gvx.PortForward{{HostPort: 0, GuestPort: 51820, Protocol: "udp", BindAddress: "127.0.0.1"}},
		}
	}
	return specs
}

// startWGMesh starts the nodes, and sends the host ports of all nodes to
// every node. The scripts of the nodes then run wg_up.
func startWGMesh(t *testing.T, ctx context.Context, b gateBackend, specs []k3sNodeSpec) []*runningGuest {
	t.Helper()
	guests := make([]*runningGuest, len(specs))
	ports := make([]string, len(specs))
	for i, s := range specs {
		guests[i] = startK3sNode(t, ctx, b, s)
		port := guests[i].sb.BoundPort(0)
		if port == 0 {
			t.Fatalf("BoundPort(0) of %s = 0, want the host port of its WireGuard port", s.hostname)
		}
		ports[i] = strconv.Itoa(port)
	}
	for i, g := range guests {
		if _, err := g.stdin.Write([]byte(strings.Join(ports, " ") + "\n")); err != nil {
			t.Fatalf("send the WireGuard host ports to %s: %v", specs[i].hostname, err)
		}
	}
	return guests
}

// c2ServerScript starts a k3s server on the WireGuard address of the node.
// The kubelet uses the address as its node IP, flannel runs its default
// vxlan back end on wg0, and the egress selector is off. The API server
// reaches the kubelet of the agent over wg0 without an agent tunnel.
const c2ServerScript = `
wg_up
k3s server --token "$TOKEN" --node-ip ` + wgMeshNetwork + `.1 --advertise-address ` + wgMeshNetwork + `.1 \
  --tls-san ` + wgMeshNetwork + `.1 --flannel-iface wg0 --egress-selector-mode disabled \
  --disable=traefik,servicelb --write-kubeconfig-mode=644 >/tmp/k3s.log 2>&1 &
t0=$(date +%s)
until k get nodes 2>/dev/null | grep -q " Ready"; do
  if [ $(( $(date +%s) - t0 )) -gt 600 ]; then fail "server node not Ready"; dump; exit 1; fi
  sleep 2
done
log "SERVER-READY $(( $(date +%s) - t0 ))"
` + multiNodeChecks + `
# The kubelet port is 10250 (0x280A). A direct connection of the API server
# shows in /proc/net/tcp as an ESTABLISHED socket (state 01) to the address
# of the agent, 192.168.77.2 (0x024DA8C0).
direct_kubelet() {
  k logs -f pod-agent >/dev/null 2>&1 &
  follower=$!
  found=0
  i=0
  while [ "$i" -lt 60 ]; do
    if grep -qi ' 024DA8C0:280A 01 ' /proc/net/tcp; then found=1; break; fi
    i=$((i+1))
    sleep 1
  done
  kill $follower 2>/dev/null
  if [ "$found" = 1 ]; then log "API-TO-KUBELET-DIRECT-OK"; else fail "no direct connection from the API server to the kubelet"; fi
  log "DIRECT-DONE"
}
checks
direct_kubelet
serve
`

// c2AgentScript joins a k3s agent over the WireGuard address of the server.
const c2AgentScript = `
wg_up
k3s agent --server https://` + wgMeshNetwork + `.1:6443 --token "$TOKEN" \
  --node-ip ` + wgMeshNetwork + `.2 --flannel-iface wg0 >/tmp/k3s.log 2>&1 &
log "AGENT-STARTED"
serve
`

// TestE2EK3sMultiNodeT2Join runs C2 of GVXIP-005. Each guest builds a WireGuard
// mesh with the unmodified wg tool, and k3s uses the wg0 address as the node
// IP. Flannel runs its vxlan back end on wg0, and the egress selector is
// off, so the API server connects to the kubelet of the agent over wg0.
func TestE2EK3sMultiNodeT2Join(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireMultiSandbox(t, b)
			ctx, cancel := context.WithTimeout(context.Background(), 28*time.Minute)
			t.Cleanup(cancel)
			tools := wgToolDir(t, b)

			start := time.Now()
			specs := wgMeshNodes(t, []string{multiNodeServerName, multiNodeAgentName}, []string{c2ServerScript, c2AgentScript},
				[]string{"SERVER_NODE=" + multiNodeServerName, "AGENT_NODE=" + multiNodeAgentName}, tools)
			guests := startWGMesh(t, ctx, b, specs)
			server := guests[0]

			guests[1].wait(t, "AGENT-STARTED", 5*time.Minute)
			server.wait(t, "DIRECT-DONE", 20*time.Minute)
			requireMarkers(t, "server guest", server, append(c1Markers, "API-TO-KUBELET-DIRECT-OK")...)
			requireNoFailures(t, "server guest", server)
			t.Logf("server Ready %ds, agent Ready %ds and pods Ready %ds after it; total %s",
				secondsOf(t, server.wait(t, "SERVER-READY ", time.Second)),
				secondsOf(t, server.wait(t, "NODES-READY ", time.Second)),
				secondsOf(t, server.wait(t, "PODS-READY ", time.Second)),
				time.Since(start).Round(time.Second))
		})
	}
}

// c4Script is the script of one control-plane node. Node 1 starts the etcd
// cluster with --cluster-init. The other nodes join node 1 over wg0 after
// the test sends the line "go". It sends the line to one node at a time,
// when the node before it is Ready, because k3s joins one server at a time. The
// test needs no workload, so the script turns the packaged add-ons off.
//
// After all nodes are Ready, node 1 records the member list and the output
// of "etcdctl check perf". Every node then waits for the test. The line
// "failover" makes the node write a ConfigMap to its own API server until the
// write succeeds, and print the seconds that it needed. The write needs the
// quorum of etcd, so it succeeds only after the cluster has a leader again.
const c4Script = `
wg_up
cp /workspace/etcdctl /tmp/etcdctl
chmod 755 /tmp/etcdctl
etcdctl() {
  /tmp/etcdctl --endpoints=https://127.0.0.1:2379 \
    --cacert=/var/lib/rancher/k3s/server/tls/etcd/server-ca.crt \
    --cert=/var/lib/rancher/k3s/server/tls/etcd/server-client.crt \
    --key=/var/lib/rancher/k3s/server/tls/etcd/server-client.key "$@"
}
join=""
if [ "$WG_INDEX" = 1 ]; then
  join="--cluster-init"
else
  read -r go
  join="--server https://` + wgMeshNetwork + `.1:6443"
fi
k3s server $join --token "$TOKEN" --node-ip ` + wgMeshNetwork + `.$WG_INDEX \
  --advertise-address ` + wgMeshNetwork + `.$WG_INDEX --tls-san ` + wgMeshNetwork + `.$WG_INDEX \
  --flannel-iface wg0 --egress-selector-mode disabled \
  --disable=traefik,servicelb,metrics-server,local-storage,coredns \
  --write-kubeconfig-mode=644 >/tmp/k3s.log 2>&1 &
t0=$(date +%s)
until k get nodes 2>/dev/null | grep -q " Ready"; do
  if [ $(( $(date +%s) - t0 )) -gt 600 ]; then fail "node $WG_INDEX not Ready"; dump; exit 1; fi
  sleep 2
done
log "NODE-READY $WG_INDEX $(( $(date +%s) - t0 ))"

if [ "$WG_INDEX" = 1 ]; then
  until [ "$(k get nodes --no-headers 2>/dev/null | grep -c ' Ready')" -ge 3 ]; do
    if [ $(( $(date +%s) - t0 )) -gt 900 ]; then fail "three nodes not Ready"; dump; exit 1; fi
    sleep 2
  done
  log "CLUSTER-READY $(( $(date +%s) - t0 ))"
  etcdctl member list -w table | sed 's/^/ETCD-MEMBERS /'
  etcdctl endpoint status --cluster | sed 's/^/ETCD-STATUS /'
  leader=$(etcdctl endpoint status --cluster | grep ', true, false,' | cut -d, -f1)
  log "ETCD-LEADER $leader"
  etcdctl check perf 2>&1 | tr '\r' '\n' | grep -v '^ *[0-9]* / [0-9]* ' | grep . | sed 's/^/ETCD-PERF /'
  log "ETCD-PERF-DONE"
fi

while read -r cmd; do
  case "$cmd" in
  dump) dump ;;
  failover)
    f0=$(date +%s)
    until printf '%s\n' 'apiVersion: v1' 'kind: ConfigMap' 'metadata: {name: after-leader-ended}' 'data: {writer: "node-'"$WG_INDEX"'"}' | k apply -f - >/dev/null 2>&1 &&
          [ "$(k get configmap after-leader-ended -o jsonpath='{.data.writer}' 2>/dev/null)" = "node-$WG_INDEX" ]; do
      if [ $(( $(date +%s) - f0 )) -gt 120 ]; then fail "API write after the end of the leader"; break; fi
      sleep 1
    done
    log "FAILOVER-ANSWERED $(( $(date +%s) - f0 ))"
    ;;
  esac
done
`

// TestE2EK3sMultiNodeControlPlaneFailover runs C4 of GVXIP-005. Three server
// sandboxes form an embedded etcd cluster over a WireGuard mesh. The test
// records the output of "etcdctl check perf", ends the sandbox of the etcd
// leader, and requires that a surviving server accepts an API write within
// 30 seconds.
func TestE2EK3sMultiNodeControlPlaneFailover(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireMultiSandbox(t, b)
			ctx, cancel := context.WithTimeout(context.Background(), 28*time.Minute)
			t.Cleanup(cancel)
			tools := wgToolDir(t, b)
			etcdctl := acceptprog.FetchEtcdctl(t, hostArch())
			if err := copyFile(etcdctl, filepath.Join(tools, "etcdctl")); err != nil {
				t.Fatalf("copy etcdctl into the tool directory: %v", err)
			}

			start := time.Now()
			specs := wgMeshNodes(t, []string{"gvx-cp1", "gvx-cp2", "gvx-cp3"}, []string{c4Script, c4Script, c4Script}, nil, tools)
			guests := startWGMesh(t, ctx, b, specs)

			// k3s joins one server at a time. A second member that joins while
			// the first member joins makes the etcd join of that member fail.
			guests[0].wait(t, "NODE-READY 1 ", 12*time.Minute)
			for i, g := range guests[1:] {
				if _, err := g.stdin.Write([]byte("go\n")); err != nil {
					t.Fatalf("release joining node %d: %v", i+2, err)
				}
				g.wait(t, "NODE-READY "+strconv.Itoa(i+2)+" ", 12*time.Minute)
			}
			guests[0].wait(t, "CLUSTER-READY ", 10*time.Minute)
			t.Logf("three nodes Ready %ds after node 1 started; %s since the test began",
				secondsOf(t, guests[0].wait(t, "CLUSTER-READY ", time.Second)), time.Since(start).Round(time.Second))
			guests[0].wait(t, "ETCD-PERF-DONE", 10*time.Minute)
			t.Logf("etcd status and check perf of the cluster:\n%s", etcdTranscript(guests[0].out.String()))

			leader := guests[0].wait(t, "ETCD-LEADER ", time.Second)
			m := regexp.MustCompile(regexp.QuoteMeta(wgMeshNetwork) + `\.(\d+):2379`).FindStringSubmatch(leader)
			if m == nil {
				t.Fatalf("leader line %q names no member address of %s.0/24", leader, wgMeshNetwork)
			}
			leaderIndex, _ := strconv.Atoi(m[1])
			if leaderIndex < 1 || leaderIndex > len(guests) {
				t.Fatalf("leader index %d is outside 1..%d", leaderIndex, len(guests))
			}
			survivor := guests[leaderIndex%len(guests)]
			t.Logf("the etcd leader is node %d; ending its sandbox", leaderIndex)

			guests[leaderIndex-1].end()
			if _, err := survivor.stdin.Write([]byte("failover\n")); err != nil {
				t.Fatalf("ask the surviving node for its API write: %v", err)
			}
			seconds := secondsOf(t, survivor.wait(t, "FAILOVER-ANSWERED ", 3*time.Minute))
			t.Logf("a surviving API server accepted a write %ds after the leader ended", seconds)
			if seconds > 30 {
				t.Errorf("the API answered %ds after the end of the leader, want at most 30s", seconds)
			}
			requireNoFailures(t, "surviving node", survivor)
		})
	}
}

// etcdTranscript returns the lines of a transcript that record the member
// list, the endpoint status, and the check perf output of etcd.
func etcdTranscript(out string) string {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "ETCD-") {
			lines = append(lines, l)
		}
	}
	return strings.Join(lines, "\n")
}
