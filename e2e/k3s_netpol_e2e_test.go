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
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
)

// k3sNetpolScript starts an unmodified k3s server, whose network policy
// controller (kube-router) programs ipsets and iptables rules with the match
// set. A server pod and two client pods show that a NetworkPolicy blocks and
// allows traffic. Each check prints one marker line. A failed check prints a
// line that starts with FAIL, and the script goes on.
const k3sNetpolScript = `
log() { echo "$@"; }
fail() { echo "FAIL $*"; }
k() { kubectl "$@"; }

k3s server --disable=traefik,servicelb --flannel-backend=host-gw \
  --write-kubeconfig-mode=644 >/tmp/k3s.log 2>&1 &

start=$(date +%s)
until k get nodes 2>/dev/null | grep -q " Ready"; do
  if [ $(( $(date +%s) - start )) -gt 300 ]; then
    fail "node not Ready"; tail -40 /tmp/k3s.log; exit 1
  fi
  sleep 2
done
log "NODE-READY"
until k get serviceaccount default >/dev/null 2>&1; do sleep 1; done

cat <<'EOF' | k apply -f - >/dev/null
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
EOF
if k wait --for=condition=Ready pod/srv pod/cli pod/other --timeout=300s >/dev/null 2>&1; then
  log "PODS-READY"
else
  fail "pods not Ready"; k get pods -o wide; exit 1
fi
srvip=$(k get pod srv -o jsonpath='{.status.podIP}')

# reach prints the HTTP status that a pod gets from the server pod, 000 when it gets none.
reach() { k exec "$1" -- curl -s -m 4 -o /dev/null -w '%{http_code}' "http://$srvip:8080/hostname" 2>/dev/null || true; }
# until_reach waits up to 150 seconds until the pod reaches the server (want 200) or not (want other).
until_reach() { # pod want(open|blocked)
  t0=$(date +%s)
  while :; do
    code=$(reach "$1")
    if [ "$2" = open ] && [ "$code" = 200 ]; then return 0; fi
    if [ "$2" = blocked ] && [ "$code" != 200 ]; then return 0; fi
    [ $(( $(date +%s) - t0 )) -ge 150 ] && return 1
    sleep 2
  done
}

if until_reach cli open && until_reach other open; then log "BASELINE-OK"; else fail "baseline: no traffic before any policy"; fi

# The controller of k3s needs the ipset tool and the set match of iptables.
if grep -q 'ipset save failed\|Skipping network policy controller' /tmp/k3s.log; then
  fail "k3s skipped the network policy controller"; grep 'ipset\|network policy' /tmp/k3s.log | head
else
  log "NO-SKIP-OK"
fi

cat <<'EOF' | k apply -f - >/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny-all, namespace: default}
spec:
  podSelector: {matchLabels: {app: srv}}
  policyTypes: [Ingress]
EOF
if until_reach cli blocked && until_reach other blocked; then log "DENY-OK"; else fail "deny-all did not block the clients"; fi

cat <<'EOF' | k apply -f - >/dev/null
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
EOF
if until_reach cli open && until_reach other blocked; then log "ALLOW-OK"; else fail "allow-client: cli $(reach cli) other $(reach other)"; fi

# kube-router keeps its ipsets in the kernel of the guest.
ipset=$(find /var/lib/rancher/k3s/data -name ipset -type f 2>/dev/null | head -1)
[ -n "$ipset" ] || ipset=$(command -v ipset)
if [ -n "$ipset" ] && [ "$($ipset list -n | grep -c '^KUBE-')" -gt 0 ]; then log "IPSETS-OK"; else fail "no KUBE ipset ($ipset)"; fi
iptables-legacy-save 2>/dev/null | grep -q -- '-m set --match-set KUBE-' && log "SET-RULES-OK" || fail "no rule with the match set"

k delete networkpolicy deny-all allow-client >/dev/null
if until_reach other open; then log "RESTORE-OK"; else fail "traffic did not return after the policies ended"; fi

log "NETPOL-DONE"
`

// TestE2EK3sNetworkPolicy proves that k3s enforces a NetworkPolicy: a deny-all
// ingress policy stops a client pod from reaching a server pod, a policy that
// names the client lets it through, and the controller starts without the
// warning that the guest had no ipset.
func TestE2EK3sNetworkPolicy(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			volume := filepath.Join(t.TempDir(), "k3s.ext4")
			out := runK3sScript(t, b, volume, k3sNetpolScript, "NETPOL-DONE\n")
			requireContains(t, "guest output", out,
				"NODE-READY\n", "PODS-READY\n", "BASELINE-OK\n", "NO-SKIP-OK\n", "DENY-OK\n", "ALLOW-OK\n",
				"IPSETS-OK\n", "SET-RULES-OK\n", "RESTORE-OK\n")
			if strings.Contains(out, "FAIL ") {
				t.Errorf("guest reported failures:\n%s", out)
			}
		})
	}
}

// runK3sScript runs a script in the k3s image and returns its output after it
// printed the done marker.
func runK3sScript(t *testing.T, b gateBackend, volume, script, done string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	stdout, stderr := newOutputLog(), newOutputLog()
	spec := guestSpec{
		plat:          b.plat,
		image:         k3sImage,
		entrypoint:    []string{"/bin/sh", "-c"},
		entrypointSet: true,
		cmd:           []string{script},
		envv:          []string{"IPTABLES_MODE=legacy"},
		net:           gvx.NetModeNAT,
		netRaw:        true,
		packetWrite:   true,
		allowSUID:     true,
		mounts:        []gvx.Mount{{Kind: gvx.MountVolume, ImagePath: volume, GuestPath: "/var/lib/rancher"}},
	}
	sb, err := gvx.New(ctx, spec.config(sharedCacheDir(t), stdout, stderr))
	if err != nil {
		t.Fatalf("gvx.New: %v", err)
	}
	defer func() {
		if err := sb.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()
	var res guestResult
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		res.code, res.err = sb.Run(ctx)
	}()
	stdout.waitFor(t, 0, done, 25*time.Minute, finished)
	<-finished
	if res.err != nil && !errors.Is(res.err, context.Canceled) {
		t.Errorf("Run = (%d, %v)\nstderr:\n%s", res.code, res.err, stderr.String())
	}
	return stdout.String()
}
