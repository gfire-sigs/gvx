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
	"io"
	"net/http"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
)

// The tests of this file run an unmodified k3s server in one sandbox. They
// prove the single-node behavior of GVXIP-005, section 4.2. The guest uses
// only k3s settings: IPTABLES_MODE selects the legacy iptables, and the
// flannel back end is host-gw because one node needs no tunnel.

const k3sImage = "rancher/k3s:v1.31.4-k3s1"

// k3sNodePort is the NodePort of the test service. The host reaches it
// through a published port.
const k3sNodePort = 30080

// k3sScript starts the server and runs the checks of one phase. PHASE=1 runs
// B1 to B10 and leaves the cluster state on the volume. PHASE=2 runs B11 on
// the same volume. Each check prints one marker line. A failed check prints
// a line that starts with FAIL and the script goes on, so one run reports
// every result.
const k3sScript = `
log() { echo "$@"; }
fail() { echo "FAIL $*"; }
k() { kubectl "$@"; }

k3s server --disable=traefik,servicelb --flannel-backend=host-gw \
  --write-kubeconfig-mode=644 >/tmp/k3s.log 2>&1 &

start=$(date +%s)
until k get nodes 2>/dev/null | grep -q " Ready"; do
  if [ $(( $(date +%s) - start )) -gt 300 ]; then
    fail "B1 node not Ready"; tail -40 /tmp/k3s.log; exit 1
  fi
  sleep 2
done
ready=$(( $(date +%s) - start ))
node=$(k get nodes -o jsonpath='{.items[0].metadata.name}')
log "NODE-READY $node $ready"

# wait_ready waits until pods of the selector exist and are Ready.
wait_ready() { # namespace selector seconds
  t0=$(date +%s)
  until [ -n "$(k -n "$1" get pods -l "$2" -o name 2>/dev/null)" ]; do
    [ $(( $(date +%s) - t0 )) -ge "$3" ] && return 1
    sleep 2
  done
  k -n "$1" wait --for=condition=Ready pod -l "$2" --timeout="$(( $3 - ($(date +%s) - t0) ))s" >/dev/null 2>&1
}

if [ "$PHASE" = 2 ]; then
  if [ "$node" = "$EXPECT_NODE" ]; then log "B11-SAME-NODE"; else fail "B11 node $node want $EXPECT_NODE"; fi
  if k rollout status deploy/web --timeout=300s >/dev/null 2>&1; then log "B11-PODS-OK"; else fail "B11 web not ready"; fi
  log "PHASE2-DONE"
  exit 0
fi

if [ "$ready" -le 120 ]; then log "B1-OK"; else fail "B1 Ready after ${ready}s"; fi

if wait_ready kube-system k8s-app=kube-dns 300 && wait_ready kube-system app=local-path-provisioner 300; then
  log "B2-SYSTEM-OK"
else
  fail "B2 system pods"; k get pods -A -o wide; k -n kube-system describe pod -l k8s-app=kube-dns | tail -30
fi
until k get serviceaccount default >/dev/null 2>&1; do sleep 1; done

cat <<'EOF' | k apply -f - >/dev/null
apiVersion: apps/v1
kind: Deployment
metadata: {name: web}
spec:
  replicas: 2
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
      - name: web
        image: registry.k8s.io/e2e-test-images/agnhost:2.47
        args: ["netexec", "--http-port=8080"]
---
apiVersion: v1
kind: Service
metadata: {name: web}
spec:
  selector: {app: web}
  ports: [{port: 80, targetPort: 8080}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: solo}
spec:
  replicas: 1
  selector: {matchLabels: {app: solo}}
  template:
    metadata: {labels: {app: solo}}
    spec:
      containers:
      - name: solo
        image: registry.k8s.io/e2e-test-images/agnhost:2.47
        args: ["netexec", "--http-port=8080"]
---
apiVersion: v1
kind: Service
metadata: {name: solo}
spec:
  selector: {app: solo}
  ports: [{port: 80, targetPort: 8080}]
---
apiVersion: v1
kind: Service
metadata: {name: web-np}
spec:
  type: NodePort
  selector: {app: web}
  ports: [{port: 80, targetPort: 8080, nodePort: NODEPORT}]
---
apiVersion: v1
kind: Pod
metadata: {name: client}
spec:
  containers:
  - name: client
    image: curlimages/curl:8.11.1
    command: ["sleep", "infinity"]
---
apiVersion: v1
kind: Pod
metadata: {name: sysctls}
spec:
  securityContext:
    sysctls:
    - {name: net.ipv4.ip_unprivileged_port_start, value: "0"}
    - {name: net.ipv4.ip_local_port_range, value: "40000 50000"}
  containers:
  - name: sysctls
    image: registry.k8s.io/e2e-test-images/agnhost:2.47
    args: ["pause"]
EOF

if k rollout status deploy/web --timeout=300s >/dev/null 2>&1; then
  log "B2-WEB-OK"
else
  fail "B2 web not ready"; k get pods -o wide
fi
k rollout status deploy/solo --timeout=300s >/dev/null 2>&1
wait_ready default 'app!=web,app!=solo' 300

# B3: both endpoints answer within 50 requests.
names=$(k exec client -- sh -c 'for i in $(seq 1 50); do curl -s -m 3 http://web/hostname; echo; done' | sort -u | grep -c .)
if [ "$names" -eq 2 ]; then log "B3-OK"; else fail "B3 distinct endpoints $names"; fi

# B4: the only endpoint of a service reaches that service.
solo=$(k get pod -l app=solo -o jsonpath='{.items[0].metadata.name}')
if k exec "$solo" -- /agnhost connect solo.default.svc.cluster.local:80 --timeout=5s; then
  log "B4-OK"
else
  fail "B4 hairpin"
fi

# B5: a pod reaches the NodePort through the node address; the host part
# runs in the test after the marker.
nodeip=$(k get node "$node" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
if k exec client -- curl -s -m 5 -o /dev/null -w '%{http_code}' "http://$nodeip:NODEPORT/hostname" | grep -q 200; then
  log "B5-POD-OK"
else
  fail "B5 pod to NodePort"
fi
log "B5-HOST-READY"
read -r go

# B6: name resolution works again within 10 seconds after a CoreDNS restart.
k -n kube-system delete pod -l k8s-app=kube-dns --wait=false >/dev/null
sleep 2
# kubectl wait on the label also waits for the deleted pod, which never becomes
# Ready, so the loop looks only at pods without a deletion time stamp.
t0=$(date +%s)
until [ "$(k -n kube-system get pods -l k8s-app=kube-dns -o go-template='{{range .items}}{{if not .metadata.deletionTimestamp}}{{range .status.conditions}}{{if eq .type "Ready"}}{{.status}}{{end}}{{end}}{{end}}{{end}}' 2>/dev/null)" = True ]; do
  [ $(( $(date +%s) - t0 )) -ge 300 ] && break
  sleep 1
done
t0=$(date +%s)
ok=0
while [ $(( $(date +%s) - t0 )) -le 10 ]; do
  if k exec client -- nslookup web.default.svc.cluster.local >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
if [ "$ok" = 1 ]; then log "B6-OK"; else fail "B6 DNS after restart"; fi

# B7: logs, exec, and port-forward.
webpod=$(k get pod -l app=web -o jsonpath='{.items[0].metadata.name}')
if k logs "$webpod" >/dev/null 2>&1; then log "B7-LOGS-OK"; else fail "B7 logs"; fi
if k exec "$webpod" -- /agnhost connect web:80 --timeout=5s >/dev/null 2>&1; then log "B7-EXEC-OK"; else fail "B7 exec"; fi
k port-forward svc/web 18080:80 >/tmp/pf.log 2>&1 &
pf=$!
sleep 3
if wget -q -T 5 -O - http://127.0.0.1:18080/hostname | grep -q web-; then log "B7-PORTFORWARD-OK"; else fail "B7 port-forward"; fi
kill $pf 2>/dev/null

# B8: the pod sees its sysctls.
# kubectl exec of a command that ends at once can return an empty output when the
# stream closes before the data arrives, so each read tries up to three times.
sysctl_read() {
  for i in 1 2 3; do
    out=$(k exec sysctls -- cat "$1" 2>/tmp/b8.err | tr -s ' \t' ' ')
    [ -n "$out" ] && break
    echo "B8-RETRY $1 attempt $i: $(cat /tmp/b8.err)"
    sleep 2
  done
  echo "$out"
}
v1=$(sysctl_read /proc/sys/net/ipv4/ip_unprivileged_port_start)
v2=$(sysctl_read /proc/sys/net/ipv4/ip_local_port_range)
if [ "$v1" = 0 ] && [ "$v2" = "40000 50000" ]; then log "B8-OK"; else fail "B8 sysctls '$v1' '$v2'"; fi

# B9: a CPU limit of 500m and a memory limit.
cat <<'EOF' | k apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: burn}
spec:
  containers:
  - name: burn
    image: busybox:1.36
    command: ["sh", "-c", "while :; do :; done"]
    resources: {limits: {cpu: 500m}}
---
apiVersion: v1
kind: Pod
metadata: {name: hog}
spec:
  restartPolicy: Never
  containers:
  - name: hog
    image: busybox:1.36
    command: ["sh", "-c", "a=$(head -c 120m /dev/zero | tr '\\0' x); sleep 60"]
    resources: {limits: {memory: 64Mi}}
EOF
k wait --for=condition=Ready pod/burn --timeout=300s >/dev/null 2>&1
sleep 2
# Each read takes the usage and the uptime of the guest in one exec. The exec of a
# process takes seconds on some hosts, so the wall time between the reads is not 5 s.
# A failed exec gives an empty output, so the sample tries up to five times.
burn_sample() {
  for i in 1 2 3 4 5; do
    out=$(k exec burn -- sh -c "grep usage_usec /sys/fs/cgroup/cpu.stat | cut -d' ' -f2; cut -d' ' -f1 /proc/uptime | tr -d ." 2>/dev/null)
    [ "$(echo $out | wc -w)" = 2 ] && break
    sleep 2
  done
  echo $out
}
set -- $(burn_sample); u0=$1; t0=$2
sleep 5
set -- $(burn_sample); u1=$1; t1=$2
milli=0
if [ -n "$u0" ] && [ -n "$u1" ] && [ "$t1" -gt "$t0" ]; then milli=$(( (u1 - u0) / ((t1 - t0) * 10) )); fi
if [ "$milli" -le 600 ] && [ "$milli" -gt 0 ]; then log "B9-CPU-OK $milli"; else fail "B9 cpu ${milli}m"; fi
if [ "$ENFORCE_MEMORY_MAX" = 1 ]; then
  for i in $(seq 1 60); do
    reason=$(k get pod hog -o jsonpath='{.status.containerStatuses[0].state.terminated.reason}')
    [ -n "$reason" ] && break
    sleep 2
  done
  if [ "$reason" = OOMKilled ]; then log "B9-MEMORY-OK"; else fail "B9 memory reason '$reason'"; fi
else
  log "B9-MEMORY-SKIPPED"
fi
k delete pod burn hog --wait=false >/dev/null

# B10: metrics.
ok=0
for i in $(seq 1 90); do
  if k top node >/dev/null 2>&1 && k top pod -A >/dev/null 2>&1; then ok=1; break; fi
  sleep 2
done
if [ "$ok" = 1 ]; then log "B10-OK"; else fail "B10 metrics"; k top node; k -n kube-system logs deploy/metrics-server --tail=20; k get --raw /api/v1/nodes/$node/proxy/stats/summary | head -c 600; echo; fi

# B10-FS: cAdvisor in the kubelet maps the volume at /var/lib/rancher, which
# is the disk /dev/vdb, to its disk statistics. The metrics of the node
# container name the device /dev/vdb and count the writes of the disk, which
# k3s makes all the time. The summary API gives a real capacity and a real
# inode count for the image file system on that volume.
capacity() { echo "$1" | grep -o '"capacityBytes":[0-9]*' | head -1 | cut -d: -f2; }
inodes() { echo "$1" | grep -o '"inodes":[0-9]*' | head -1 | cut -d: -f2; }
# positive tells whether a metric value is above 0. A metric value can have an
# exponent, such as 6.0014358528e+10.
positive() { awk -v v="$1" 'BEGIN { exit !(v + 0 > 0) }'; }
fsok=0
for i in $(seq 1 60); do
  summary=$(k get --raw /api/v1/nodes/$node/proxy/stats/summary 2>/dev/null | tr -d ' \n\t')
  imagefs=$(echo "$summary" | grep -o '"imageFs":{[^}]*}' | head -1)
  metrics=$(k get --raw /api/v1/nodes/$node/proxy/metrics/cadvisor 2>/dev/null | grep 'device="/dev/vdb"' | grep 'id="/"')
  limit=$(echo "$metrics" | grep '^container_fs_limit_bytes{' | head -1 | sed 's/^.*} //' | cut -d' ' -f1)
  writes=$(echo "$metrics" | grep '^container_fs_writes_total{' | head -1 | sed 's/^.*} //' | cut -d' ' -f1)
  cap=$(capacity "$imagefs"); ino=$(inodes "$imagefs")
  if positive "$limit" && positive "$writes" && [ "${cap:-0}" -gt 0 ] && [ "${cap:-0}" -lt 4611686018427387904 ] && [ "${ino:-0}" -gt 0 ]; then fsok=1; break; fi
  sleep 2
done
if [ "$fsok" = 1 ]; then log "B10-FS-OK limit=$limit writes=$writes imagefs=$cap inodes=$ino"; else fail "B10 fs: limit '$limit' writes '$writes' imageFs '$imagefs'"; echo "$metrics" | head -c 3000; echo; cat /proc/diskstats; fi

log "PHASE1-DONE"
`

// TestE2EK3sSingleNode runs the checks B1 to B11 of GVXIP-005 on each backend.
func TestE2EK3sSingleNode(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			// The Windows systrap engine cannot count the pages of its stub
			// processes, so the Sentry leaves memory.max unenforced there.
			enforce := "1"
			if runtime.GOOS == "windows" && b.plat == gvx.PlatformSystrap {
				enforce = "0"
			}
			volume := filepath.Join(t.TempDir(), "k3s.ext4")
			script := strings.ReplaceAll(k3sScript, "NODEPORT", strconv.Itoa(k3sNodePort))

			out, node := runK3sPhase(t, b, volume, script, "1", "", enforce)
			for _, want := range []string{
				"B1-OK", "B2-SYSTEM-OK", "B2-WEB-OK", "B3-OK", "B4-OK", "B5-POD-OK", "B6-OK",
				"B7-LOGS-OK", "B7-EXEC-OK", "B7-PORTFORWARD-OK", "B8-OK", "B9-CPU-OK", "B10-OK", "B10-FS-OK",
			} {
				requireContains(t, "phase 1 output", out, want)
			}
			if enforce == "1" {
				requireContains(t, "phase 1 output", out, "B9-MEMORY-OK")
			}
			if strings.Contains(out, "FAIL ") {
				t.Errorf("phase 1 reported failures:\n%s", out)
			}

			out2, _ := runK3sPhase(t, b, volume, script, "2", node, enforce)
			requireContains(t, "phase 2 output", out2, "B11-SAME-NODE", "B11-PODS-OK", "PHASE2-DONE")
		})
	}
}

// runK3sPhase runs one phase of k3sScript and returns the guest output and
// the node name. Phase 1 also checks B5 from the host.
func runK3sPhase(t *testing.T, b gateBackend, volume, script, phase, expectNode, enforce string) (string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	stdin, release := io.Pipe()
	defer stdin.Close()
	stdout, stderr := newOutputLog(), newOutputLog()
	spec := guestSpec{
		plat:          b.plat,
		image:         k3sImage,
		entrypoint:    []string{"/bin/sh", "-c"},
		entrypointSet: true,
		cmd:           []string{script},
		envv:          []string{"IPTABLES_MODE=legacy", "PHASE=" + phase, "EXPECT_NODE=" + expectNode, "ENFORCE_MEMORY_MAX=" + enforce},
		net:           gvx.NetModeNAT,
		netRaw:        true,
		packetWrite:   true,
		allowSUID:     true,
		mounts:        []gvx.Mount{{Kind: gvx.MountVolume, ImagePath: volume, GuestPath: "/var/lib/rancher"}},
		forwards:      []gvx.PortForward{{HostPort: 0, GuestPort: k3sNodePort, Protocol: "tcp", BindAddress: "127.0.0.1"}},
		stdin:         stdin,
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

	next := stdout.waitFor(t, 0, "NODE-READY ", 10*time.Minute, finished)
	line := stdout.String()[next:]
	node, _, _ := strings.Cut(line, " ")
	if phase == "1" {
		next = stdout.waitFor(t, next, "B5-HOST-READY\n", 15*time.Minute, finished)
		hostPort := sb.BoundPort(0)
		body, status := httpGet(t, ctx, "http://127.0.0.1:"+strconv.Itoa(hostPort)+"/hostname")
		if status != http.StatusOK || !strings.HasPrefix(body, "web-") {
			t.Errorf("B5: host GET of the NodePort = (%d, %q), want 200 and a web pod name", status, body)
		}
		if _, err := io.WriteString(release, "go\n"); err != nil {
			t.Fatalf("release the guest script: %v", err)
		}
		stdout.waitFor(t, next, "PHASE1-DONE\n", 15*time.Minute, finished)
	} else {
		stdout.waitFor(t, next, "PHASE2-DONE\n", 10*time.Minute, finished)
	}
	<-finished
	if res.err != nil && !errors.Is(res.err, context.Canceled) {
		t.Errorf("Run = (%d, %v)\nstderr:\n%s", res.code, res.err, stderr.String())
	}
	return stdout.String(), node
}
