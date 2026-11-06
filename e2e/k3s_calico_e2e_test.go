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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
)

// calicoScript runs an unmodified k3s server without flannel and without its
// network policy controller. It installs the VXLAN manifest of Calico 3.28.2
// through the manifest directory of k3s. The pods of the cluster get their
// addresses and their policy from Calico. Each check prints one marker line. A
// failed check prints a line that starts with FAIL, and the script goes on.
//
// A systemd Linux node mounts "/" as a shared mount, and calico-node needs a
// shared mount for the bidirectional propagation of /sys/fs. The guest has no
// init, so the script makes "/" shared before it starts k3s, as the entrypoint
// of kind does.
const calicoScript = `
mount --make-rshared /
mkdir -p /var/lib/rancher/k3s/server/manifests
cp /workspace/calico.yaml /var/lib/rancher/k3s/server/manifests/calico.yaml

k3s server --flannel-backend=none --disable-network-policy --cluster-cidr=10.42.0.0/16 \
  --disable=traefik,servicelb --write-kubeconfig-mode=644 >/tmp/k3s.log 2>&1 &

start=$(date +%s)
until k get nodes 2>/dev/null | grep -q " Ready"; do
  if [ $(( $(date +%s) - start )) -gt 600 ]; then
    fail "node not Ready"; tail -40 /tmp/k3s.log; k get pods -A -o wide; log CALICO-DONE; serve; exit 1
  fi
  sleep 2
done
log "NODE-READY"

until k -n kube-system get pods -l k8s-app=calico-node -o name 2>/dev/null | grep -q pod; do sleep 2; done
if k -n kube-system wait --for=condition=Ready pod -l k8s-app=calico-node --timeout=600s >/dev/null 2>&1 &&
   k -n kube-system wait --for=condition=Ready pod -l k8s-app=calico-kube-controllers --timeout=600s >/dev/null 2>&1; then
  log "CALICO-READY"
else
  fail "calico pods not Ready"; k -n kube-system get pods -o wide; k -n kube-system logs ds/calico-node -c calico-node --tail=40
fi
until k -n kube-system get pods -l k8s-app=kube-dns -o name 2>/dev/null | grep -q pod; do sleep 2; done
if k -n kube-system wait --for=condition=Ready pod -l k8s-app=kube-dns --timeout=600s >/dev/null 2>&1; then
  log "COREDNS-RUNNING"
else
  fail "coredns not Ready"; k -n kube-system get pods -o wide
fi
until k get serviceaccount default >/dev/null 2>&1; do sleep 1; done

# Calico gives each pod an address of its IP pool and a host route to the pod.
cat <<'EOF2' | k apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: srv, labels: {app: srv}}
spec:
  containers:
  - name: srv
    image: registry.k8s.io/e2e-test-images/agnhost:2.47
    args: ["netexec", "--http-port=8080"]
---
apiVersion: v1
kind: Service
metadata: {name: srv}
spec:
  selector: {app: srv}
  ports: [{port: 80, targetPort: 8080}]
---
apiVersion: v1
kind: Pod
metadata: {name: cli, labels: {role: client}}
spec:
  containers:
  - name: cli
    image: curlimages/curl:8.11.1
    command: ["sleep", "infinity"]
---
apiVersion: v1
kind: Pod
metadata: {name: other, labels: {role: other}}
spec:
  containers:
  - name: other
    image: curlimages/curl:8.11.1
    command: ["sleep", "infinity"]
EOF2
if k wait --for=condition=Ready pod/srv pod/cli pod/other --timeout=600s >/dev/null 2>&1; then
  log "PODS-READY"
else
  fail "pods not Ready"; k get pods -o wide; k -n kube-system logs ds/calico-node -c calico-node --tail=40; log CALICO-DONE; serve; exit 1
fi
srvip=$(k get pod srv -o jsonpath='{.status.podIP}')
case "$srvip" in 10.42.*) log "POD-IP-FROM-POOL";; *) fail "pod IP $srvip is outside 10.42.0.0/16";; esac

# reach prints the HTTP status that a pod gets from a URL, 000 when it gets none.
reach() { k exec "$1" -- curl -s -m 4 -o /dev/null -w '%{http_code}' "$2" 2>/dev/null || true; }
# until_reach waits up to 300 seconds until the pod reaches the URL (want open) or not (want blocked).
until_reach() { # pod url want
  t0=$(date +%s)
  while :; do
    code=$(reach "$1" "$2")
    if [ "$3" = open ] && [ "$code" = 200 ]; then return 0; fi
    if [ "$3" = blocked ] && [ "$code" != 200 ]; then return 0; fi
    [ $(( $(date +%s) - t0 )) -ge 300 ] && return 1
    sleep 2
  done
}
POD="http://$srvip:8080/hostname"
if until_reach cli "$POD" open && until_reach other "$POD" open; then log "POD-TO-POD-OK"; else fail "pod to pod: $(reach cli "$POD")"; fi
if until_reach cli "http://srv.default.svc.cluster.local/hostname" open; then log "POD-TO-SERVICE-DNS-OK"; else fail "pod to service name"; fi
svcip=$(k get svc srv -o jsonpath='{.spec.clusterIP}')
if until_reach other "http://$svcip/hostname" open; then log "POD-TO-SERVICE-IP-OK"; else fail "pod to service address"; fi

cat <<'EOF2' | k apply -f - >/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny-all, namespace: default}
spec:
  podSelector: {matchLabels: {app: srv}}
  policyTypes: [Ingress]
EOF2
if until_reach cli "$POD" blocked && until_reach other "$POD" blocked && until_reach cli "http://$svcip/hostname" blocked; then
  log "DENY-OK"
else
  fail "deny-all did not block the clients: cli $(reach cli "$POD") other $(reach other "$POD") cli-service $(reach cli "http://$svcip/hostname")"
  k -n kube-system exec ds/calico-node -c calico-node -- iptables-legacy -S 2>&1 | grep -E 'cali-(pi|po|tw|fw)-' | head -30
fi

cat <<'EOF2' | k apply -f - >/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-client, namespace: default}
spec:
  podSelector: {matchLabels: {app: srv}}
  policyTypes: [Ingress]
  ingress:
  - from:
    - podSelector: {matchLabels: {role: client}}
    ports:
    - {protocol: TCP, port: 8080}
EOF2
if until_reach cli "$POD" open && until_reach other "$POD" blocked; then log "ALLOW-OK"; else fail "allow-client: cli $(reach cli "$POD") other $(reach other "$POD")"; fi

k delete networkpolicy deny-all allow-client >/dev/null
if until_reach other "$POD" open; then log "RESTORE-OK"; else fail "traffic did not return after the policies ended"; fi

# Felix programs a blackhole route for its own pod block. A refused route request
# shows in its log as "Failed to add route".
if k -n kube-system logs ds/calico-node -c calico-node 2>/dev/null | grep -q "Failed to add route"; then
  fail "felix could not add a route: $(k -n kube-system logs ds/calico-node -c calico-node | grep -m3 'Failed to add route')"
else
  log "FELIX-ROUTES-OK"
fi

log "CALICO-DONE"
serve
`

// calicoManifest returns the Calico VXLAN manifest with the two edits that a
// k3s cluster needs: the IP pool of the cluster CIDR of k3s, and the legacy
// iptables, because the guest has no nftables. Both are the documented
// settings of Calico.
func calicoManifest(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(acceptprog.FetchCalicoVXLANManifest(t))
	if err != nil {
		t.Fatalf("read the Calico manifest: %v", err)
	}
	m := string(data)
	pool := "            # - name: CALICO_IPV4POOL_CIDR\n            #   value: \"192.168.0.0/16\"\n"
	if !strings.Contains(m, pool) {
		t.Fatalf("the Calico manifest has no commented IP pool setting; the pinned digest changed")
	}
	m = strings.Replace(m, pool, "            - name: CALICO_IPV4POOL_CIDR\n              value: \"10.42.0.0/16\"\n", 1)
	cluster := "            - name: CLUSTER_TYPE\n"
	if !strings.Contains(m, cluster) {
		t.Fatalf("the Calico manifest has no CLUSTER_TYPE setting")
	}
	return strings.Replace(m, cluster, "            - name: FELIX_IPTABLESBACKEND\n              value: \"Legacy\"\n"+cluster, 1)
}

// TestE2EK3sCalico runs k3s with Calico in VXLAN mode instead of flannel. Both
// calico-node and calico-kube-controllers become Ready, coredns runs, pods
// reach each other and a service, a deny-all NetworkPolicy blocks the traffic,
// and a policy that names the client label lets that client through.
func TestE2EK3sCalico(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
			t.Cleanup(cancel)
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "calico.yaml"), []byte(calicoManifest(t)), 0o644); err != nil {
				t.Fatalf("write the manifest into the workspace: %v", err)
			}
			node := startK3sNode(t, ctx, b, k3sNodeSpec{hostname: multiNodeServerName, script: calicoScript, workspace: dir})
			node.wait(t, "CALICO-DONE", 35*time.Minute)
			out := node.out.String()
			requireContains(t, "guest output", out,
				"NODE-READY\n", "CALICO-READY\n", "COREDNS-RUNNING\n", "PODS-READY\n", "POD-IP-FROM-POOL\n",
				"POD-TO-POD-OK\n", "POD-TO-SERVICE-DNS-OK\n", "POD-TO-SERVICE-IP-OK\n", "DENY-OK\n", "ALLOW-OK\n", "RESTORE-OK\n", "FELIX-ROUTES-OK\n")
			if strings.Contains(out, "FAIL ") {
				t.Errorf("guest reported failures:\n%s", out)
			}
		})
	}
}
