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
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
)

// c5Script starts a single k3s server and runs sonobuoy against it. All test
// pods run on the one gvx node. The test passes SONOBUOY_ARGS and E2E_FOCUS. The script
// prints the result summary of sonobuoy, and the name, the message, and the log
// excerpt of each failed test.
const c5Script = `
mkdir -p /usr/local/bin
cp /workspace/sonobuoy /usr/local/bin/sonobuoy && chmod 755 /usr/local/bin/sonobuoy
k3s server --disable=traefik,servicelb --flannel-backend=host-gw --write-kubeconfig-mode=644 $K3S_EXTRA_ARGS >/tmp/k3s.log 2>&1 &
t0=$(date +%s)
until k get nodes 2>/dev/null | grep -q " Ready"; do
  if [ $(( $(date +%s) - t0 )) -gt 600 ]; then fail "node not Ready"; dump; exit 1; fi
  sleep 2
done
# kubectl wait fails at once when the pod does not exist yet.
until k -n kube-system get pod -l k8s-app=kube-dns -o name 2>/dev/null | grep -q .; do
  if [ $(( $(date +%s) - t0 )) -gt 600 ]; then fail "coredns pod missing"; dump; exit 1; fi
  sleep 2
done
if ! k -n kube-system wait --for=condition=Ready pod -l k8s-app=kube-dns --timeout=600s >/dev/null 2>&1; then
  fail "coredns not Ready"; dump; exit 1
fi
log "CLUSTER-READY $(( $(date +%s) - t0 ))"
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
t1=$(date +%s)
if [ -n "$E2E_FOCUS" ]; then set -- "--e2e-focus=$E2E_FOCUS"; else set --; fi
# With C5_PROBE set, a pod of the script opens a connection to the API server
# every second, once through the address of the Service and once directly, and
# the node calls the pod every second. A failed connection prints its time. The
# script prints the state of the network of the node when the pod fails, and
# once at the start for comparison.
netstate() {
  echo "NETSTATE-BEGIN $1 $(date +%T)"
  ip -o addr 2>&1 | grep -v inet6
  ip route 2>&1
  ip neigh 2>&1
  ip -s link 2>&1 | grep -E '^[0-9]+:|RX|TX|^ +[0-9]' | head -n 60
  conntrack -S 2>&1 | head -n 4
  conntrack -L 2>/dev/null | awk '{print $1, $4}' | sort | uniq -c | sort -rn | head -n 12
  conntrack -L 2>/dev/null | grep SYN_RECV | head -n 12
  awk 'NR>1 {c[$4]++} END {for (s in c) print "tcp-state", s, c[s]}' /proc/net/tcp
  awk 'NR>1 && $4=="0A" {print "listen", $2, "queues", $5}' /proc/net/tcp | head -n 20
  iptables-save -c 2>&1 | grep -E 'DROP|REJECT' | head -n 20
  grep -E '^(Ip|Tcp|Udp|Icmp):' /proc/net/snmp
  cat /proc/net/netstat
  echo NETSTATE-END
}
probe() {
  k run c5-probe --image=registry.k8s.io/e2e-test-images/agnhost:2.47 --restart=Never --command -- /bin/sh -c '
    /agnhost netexec --http-port=8080 >/dev/null 2>&1 &
    while :; do
      t=$(date +%T)
      /agnhost connect 10.43.0.1:443 --timeout=2s >/dev/null 2>&1 || echo "POD-VIP-FAIL $t"
      /agnhost connect 10.0.2.15:6443 --timeout=2s >/dev/null 2>&1 || echo "POD-DIRECT-FAIL $t"
      sleep 1
    done' >/dev/null 2>&1
  k wait --for=condition=Ready pod/c5-probe --timeout=300s >/dev/null 2>&1
  ip=$(k get pod c5-probe -o jsonpath='{.status.podIP}')
  k logs -f c5-probe 2>&1 | sed 's/^/PROBE /' &
  sleep 20
  netstate baseline
  next=8; dumps=0
  while :; do
    t=$(date +%T)
    wget -q -T 2 -O /dev/null "http://$ip:8080/hostname" 2>/dev/null || echo "PROBE NODE-POD-FAIL $t"
    n=$(k logs c5-probe 2>/dev/null | grep -c FAIL)
    if [ "$dumps" -lt 3 ] && [ "$n" -ge "$next" ]; then next=$((next*8)); netstate pod-failures; dumps=$((dumps+1)); k exec c5-probe -- cat /proc/net/arp 2>&1 | sed 's/^/NETSTATE pod-arp /'; fi
    sleep 1
  done
}
if [ -n "$C5_PROBE" ]; then probe & fi
sonobuoy run $SONOBUOY_ARGS "$@" --kubernetes-version=v1.31.4 --wait=45 --wait-output=Progress >/tmp/sonobuoy.log 2>&1 &
run=$!
# When the progress stays the same for five minutes, the script prints the state
# of the cluster and the tail of the log of the e2e plugin, once for each five
# minutes, so a stalled run shows which test it waits in.
stall() {
  echo STALL-BEGIN
  sonobuoy status --json 2>&1 | cut -c1-1500
  k -n sonobuoy get pods -o wide 2>&1
  k -n sonobuoy logs -l sonobuoy-plugin=e2e --tail=8 2>&1 | cut -c1-400
  k get pods -A -o wide 2>&1 | grep -v ' Running '
  echo STALL-END
}
last=""; same=0
while kill -0 "$run" 2>/dev/null; do
  sleep 30
  now=$(tail -n 1 /tmp/sonobuoy.log | tr '\r' '\n' | tail -n 1)
  log "SONOBUOY-PROGRESS $now"
  if [ "$now" = "$last" ]; then same=$((same+1)); else same=0; fi
  last=$now
  if [ "$same" -gt 0 ] && [ $((same % 10)) -eq 0 ]; then stall; fi
done
wait "$run"
log "SONOBUOY-RUN-EXIT $? $(( $(date +%s) - t1 ))"
tarball=$(sonobuoy retrieve /tmp 2>/dev/null)
sonobuoy results "$tarball" | sed 's/^/RESULT /'
sonobuoy results "$tarball" --plugin e2e --mode detailed >/tmp/detailed.json 2>&1
grep -E '"status": ?"failed"' /tmp/detailed.json | cut -c1-300 | sed 's/^/FAILED-TEST /'
# The failure message of a test is in the detailed results and in e2e.log of the
# plugin. Both go to the transcript for each failed run.
if grep -qE '"status": ?"failed"' /tmp/detailed.json; then
  grep -E '"failure": ?"' /tmp/detailed.json | sed 's/"system-err".*//' | cut -c1-3000 | sed 's/^/FAILURE-MESSAGE /'
  mkdir -p /tmp/results && tar -xzf "$tarball" -C /tmp/results
  e2elog=$(find /tmp/results -name e2e.log | head -n 1)
  sed -n '/^• \[\(FAILED\|PANICKED\)\]/,/<< Timeline/p' "$e2elog" | cut -c1-400 | head -n 1200 | sed 's/^/FAILURE-LOG /'
fi
log "SONOBUOY-DONE"
serve
`

// requireConformance skips the test unless the user asked for the long
// conformance runs.
func requireConformance(t *testing.T) {
	t.Helper()
	if os.Getenv("GVX_E2E_CONFORMANCE") != "1" {
		t.Skip("the conformance runs take 15 minutes or more; set GVX_E2E_CONFORMANCE=1")
	}
}

// runConformance runs sonobuoy with args and the e2e focus expression in a
// single-node cluster. It requires that the plugin e2e passes at least
// minPassed tests without a failure.
func runConformance(t *testing.T, b gateBackend, args, focus string, minPassed int) {
	t.Helper()
	requireBackend(t, b)
	requireRegistry(t)
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Minute)
	t.Cleanup(cancel)
	dir := t.TempDir()
	if err := copyFile(acceptprog.FetchSonobuoy(t, hostArch()), filepath.Join(dir, "sonobuoy")); err != nil {
		t.Fatalf("copy sonobuoy into the workspace: %v", err)
	}
	node := startK3sNode(t, ctx, b, k3sNodeSpec{
		hostname: multiNodeServerName,
		env: []string{
			"SONOBUOY_ARGS=" + args, "E2E_FOCUS=" + focus,
			"C5_PROBE=" + os.Getenv("GVX_E2E_CONFORMANCE_PROBE"),
			"K3S_EXTRA_ARGS=" + os.Getenv("GVX_E2E_CONFORMANCE_K3S_ARGS"),
		},
		script:    c5Script,
		workspace: dir,
	})
	node.wait(t, "CLUSTER-READY ", 12*time.Minute)
	node.wait(t, "SONOBUOY-DONE", 50*time.Minute)
	out := node.out.String()
	t.Logf("sonobuoy result:\n%s", linesWithPrefix(out, "RESULT ", "FAILED-TEST ", "FAILURE-MESSAGE ", "FAILURE-LOG ", "PROBE ", "NETSTATE", "SONOBUOY-RUN-EXIT "))
	field := func(name string) string {
		m := regexp.MustCompile(`(?m)^RESULT ` + name + `: (.*)$`).FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("sonobuoy output lacks %q; transcript:\n%s", name, out)
		}
		return strings.TrimSpace(m[1])
	}
	if got := field("Status"); got != "passed" {
		t.Errorf("sonobuoy status = %q, want passed", got)
	}
	if got := field("Failed"); got != "0" {
		t.Errorf("sonobuoy failed tests = %s, want 0", got)
	}
	if passed, err := strconv.Atoi(field("Passed")); err != nil || passed < minPassed {
		t.Errorf("sonobuoy passed %q tests, want at least %d", field("Passed"), minPassed)
	}
}

// linesWithPrefix returns the lines of text that start with one of prefixes.
func linesWithPrefix(text string, prefixes ...string) string {
	var lines []string
	for _, l := range strings.Split(text, "\n") {
		for _, p := range prefixes {
			if strings.HasPrefix(l, p) {
				lines = append(lines, l)
				break
			}
		}
	}
	return strings.Join(lines, "\n")
}

// TestE2EK3sConformanceQuick runs the quick mode of sonobuoy, which is the
// first part of C5 of GVXIP-005. The test pods run on the only node, a gvx
// sandbox. Both runs use the plugin e2e only. The plugin systemd-logs reads
// the journal of systemd, which the guest does not have, so it never ends.
func TestE2EK3sConformanceQuick(t *testing.T) {
	requireConformance(t)
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) { runConformance(t, b, "--mode quick --plugin e2e", "", 1) })
	}
}

// TestE2EK3sConformanceServices runs the conformance tests of the
// "[sig-network] Services" group, which is the second part of C5 of
// GVXIP-005. The test pods run on the only node, a gvx sandbox. The variable
// GVX_E2E_CONFORMANCE_FOCUS replaces the focus expression, for a fast run of a
// few tests.
func TestE2EK3sConformanceServices(t *testing.T) {
	requireConformance(t)
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			focus, minPassed := `\[sig-network\] Services.*\[Conformance\]`, 10
			if f := os.Getenv("GVX_E2E_CONFORMANCE_FOCUS"); f != "" {
				focus, minPassed = f, 1
			}
			runConformance(t, b, "--plugin e2e", focus, minPassed)
		})
	}
}
