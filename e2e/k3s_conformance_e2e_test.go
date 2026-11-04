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
// prints the result summary of sonobuoy and the name of each failed test.
const c5Script = `
mkdir -p /usr/local/bin
cp /workspace/sonobuoy /usr/local/bin/sonobuoy && chmod 755 /usr/local/bin/sonobuoy
k3s server --disable=traefik,servicelb --flannel-backend=host-gw --write-kubeconfig-mode=644 >/tmp/k3s.log 2>&1 &
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
sonobuoy run $SONOBUOY_ARGS "$@" --kubernetes-version=v1.31.4 --wait=45 --wait-output=Progress >/tmp/sonobuoy.log 2>&1 &
run=$!
while kill -0 "$run" 2>/dev/null; do
  sleep 30
  log "SONOBUOY-PROGRESS $(tail -n 1 /tmp/sonobuoy.log | tr '\r' '\n' | tail -n 1)"
done
wait "$run"
log "SONOBUOY-RUN-EXIT $? $(( $(date +%s) - t1 ))"
tarball=$(sonobuoy retrieve /tmp 2>/dev/null)
sonobuoy results "$tarball" | sed 's/^/RESULT /'
sonobuoy results "$tarball" --plugin e2e --mode detailed | grep -E '"status": ?"failed"' | cut -c1-300 | sed 's/^/FAILED-TEST /'
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
		hostname:  multiNodeServerName,
		env:       []string{"SONOBUOY_ARGS=" + args, "E2E_FOCUS=" + focus},
		script:    c5Script,
		workspace: dir,
	})
	node.wait(t, "CLUSTER-READY ", 12*time.Minute)
	node.wait(t, "SONOBUOY-DONE", 50*time.Minute)
	out := node.out.String()
	t.Logf("sonobuoy result:\n%s", linesWithPrefix(out, "RESULT ", "FAILED-TEST ", "SONOBUOY-RUN-EXIT "))
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
// GVXIP-005. The test pods run on the only node, a gvx sandbox.
func TestE2EK3sConformanceServices(t *testing.T) {
	requireConformance(t)
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			runConformance(t, b, "--plugin e2e", `\[sig-network\] Services.*\[Conformance\]`, 10)
		})
	}
}
