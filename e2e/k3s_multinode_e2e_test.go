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
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
)

// The tests of this file join several sandboxes into one Kubernetes cluster.
// They prove the multi-node behavior of GVXIP-005, section 4.3. Every sandbox
// of a test runs on one host, and every guest holds the address 10.0.2.15 on
// eth0. A guest reaches the host loopback as 10.0.2.2, so a published port of
// one sandbox is the address of that sandbox for the others. The tests use the
// unmodified image rancher/k3s and standard k3s settings.

const (
	multiNodeServerName = "gvx-server"
	multiNodeAgentName  = "gvx-agent"

	// multiNodeToken is the cluster token of every multi-node test.
	multiNodeToken = "gvx-multinode-token"

	// flannelWireGuardPort is the UDP port of the flannel wireguard back end.
	// k3s fixes it, and the peers of a node dial it at the external address
	// of that node. The server of C1 publishes it on the same host port, so a
	// host process that holds the port makes the test skip.
	flannelWireGuardPort = 51820

	// agnhostImage serves HTTP on the pods of the checks.
	agnhostImage = "registry.k8s.io/e2e-test-images/agnhost:2.47"
)

// k3sNodePrelude holds the shell functions that every node script uses. A
// failed check prints a line that starts with FAIL, and the script goes on,
// so one run reports every result. After its work, a script calls serve. The
// test then asks for the diagnostics of a failed run with the line "dump".
const k3sNodePrelude = `
log() { echo "$@"; }
fail() { echo "FAIL $*"; }
k() { kubectl "$@"; }
dump() {
  echo DUMP-BEGIN
  grep -n -m 5 -A 12 -E '^(fatal error|panic:|SIG[A-Z]+:|runtime:)' /tmp/k3s.log
  tail -n 150 /tmp/k3s.log
  k get nodes -o wide 2>&1
  k get pods -A -o wide 2>&1
  echo DUMP-END
}
serve() {
  while read -r cmd; do
    if [ "$cmd" = dump ]; then dump; fi
  done
}
`

// multiNodeChecks is the shell function checks. It runs next to the API
// server of a cluster with the nodes $SERVER_NODE and $AGENT_NODE. It waits
// for both nodes, starts one pod on each node, and prints one marker for each
// check of GVXIP-005 C1: the pod addresses, the service, the DNS name, and
// the logs and exec calls that cross to the node of the agent.
//
// The pods run agnhost netexec. Its /dial endpoint makes a pod open the HTTP
// connection, so the script needs no client image and each call proves the
// path from pod to pod.
const multiNodeChecks = `
retry() { # tries command...
  n=$1; shift
  i=0
  while ! "$@" >/dev/null 2>&1; do
    i=$((i+1))
    if [ "$i" -ge "$n" ]; then return 1; fi
    sleep 2
  done
}
podip() { k get pod "$1" -o jsonpath='{.status.podIP}'; }
# dial FROM_IP TARGET PORT TRIES asks the netexec pod at FROM_IP to call
# TARGET:PORT TRIES times, and prints the JSON answer.
dial() { wget -q -T 10 -O - "http://$1:8080/dial?request=hostname&protocol=http&host=$2&port=$3&tries=$4"; }
dial_reaches() { # FROM_IP TARGET PORT TRIES NAME...
  from=$1; target=$2; port=$3; tries=$4; shift 4
  answer=$(dial "$from" "$target" "$port" "$tries") || return 1
  for name in "$@"; do
    case "$answer" in *"\"$name\""*) ;; *) return 1 ;; esac
  done
}

checks() {
  t0=$(date +%s)
  until [ "$(k get nodes --no-headers 2>/dev/null | grep -c ' Ready')" -ge 2 ]; do
    if [ $(( $(date +%s) - t0 )) -gt 900 ]; then fail "agent node not Ready"; return 1; fi
    sleep 2
  done
  log "NODES-READY $(( $(date +%s) - t0 ))"
  k get nodes -o wide

  cat <<EOF | k apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: pod-server, labels: {app: web}}
spec:
  nodeSelector: {kubernetes.io/hostname: $SERVER_NODE}
  containers:
  - {name: web, image: ` + agnhostImage + `, args: ["netexec", "--http-port=8080"]}
---
apiVersion: v1
kind: Pod
metadata: {name: pod-agent, labels: {app: web}}
spec:
  nodeSelector: {kubernetes.io/hostname: $AGENT_NODE}
  containers:
  - {name: web, image: ` + agnhostImage + `, args: ["netexec", "--http-port=8080"]}
---
apiVersion: v1
kind: Service
metadata: {name: web}
spec:
  selector: {app: web}
  ports: [{port: 80, targetPort: 8080}]
EOF
  if k wait --for=condition=Ready pod/pod-server pod/pod-agent --timeout=900s >/dev/null 2>&1; then
    log "PODS-READY $(( $(date +%s) - t0 ))"
  else
    fail "pods not Ready"; k get pods -o wide; return 1
  fi
  ps=$(podip pod-server); pa=$(podip pod-agent)
  log "POD-IPS $ps $pa"

  if retry 30 dial_reaches "$ps" "$pa" 8080 1 pod-agent; then log "POD-SERVER-TO-AGENT-OK"; else fail "pod-server to pod-agent"; fi
  if retry 30 dial_reaches "$pa" "$ps" 8080 1 pod-server; then log "POD-AGENT-TO-SERVER-OK"; else fail "pod-agent to pod-server"; fi

  svc=$(k get svc web -o jsonpath='{.spec.clusterIP}')
  if retry 30 dial_reaches "$ps" "$svc" 80 40 pod-server pod-agent; then log "SERVICE-FROM-SERVER-POD-OK"; else fail "service from pod-server: $(dial "$ps" "$svc" 80 40)"; fi
  if retry 30 dial_reaches "$pa" "$svc" 80 40 pod-server pod-agent; then log "SERVICE-FROM-AGENT-POD-OK"; else fail "service from pod-agent: $(dial "$pa" "$svc" 80 40)"; fi
  if retry 30 dial_reaches "$pa" web.default.svc.cluster.local 80 20 pod-server pod-agent; then log "DNS-FROM-AGENT-POD-OK"; else fail "service name from pod-agent: $(dial "$pa" web.default.svc.cluster.local 80 20)"; fi

  logs=$(k logs pod-agent 2>&1)
  case "$logs" in
  *"HTTP server on port 8080"*) log "LOGS-AGENT-OK" ;;
  *) fail "kubectl logs pod-agent: $logs" ;;
  esac
  if [ "$(k exec pod-agent -- hostname 2>&1)" = pod-agent ]; then log "EXEC-AGENT-OK"; else fail "kubectl exec pod-agent"; fi
  if k exec pod-agent -- /agnhost connect "$ps:8080" --timeout=5s >/dev/null 2>&1; then log "EXEC-AGENT-CONNECT-OK"; else fail "kubectl exec pod-agent connect"; fi
  log "CHECKS-DONE $(( $(date +%s) - t0 ))"
}
`

// k3sNodeSpec describes one sandbox of a multi-node cluster.
type k3sNodeSpec struct {
	hostname string
	script   string
	env      []string
	forwards []gvx.PortForward
	// workspace is a host directory that the guest sees as /workspace.
	workspace string
}

// requireMultiSandbox skips the test on a backend that cannot hold several
// sandboxes in one process.
func requireMultiSandbox(t *testing.T, b gateBackend) {
	t.Helper()
	if b.plat == gvx.PlatformWHPX {
		t.Skip("the whpx backend cannot hold two running sandboxes in one process (HRESULT 0xc0370008)")
	}
	requireBackend(t, b)
	requireRegistry(t)
}

// startK3sNode starts the sandbox of n. The guest runs the script of n, and
// keeps the cluster state of /var/lib/rancher in a volume of its own. The
// cleanup of the test ends the guest.
func startK3sNode(t *testing.T, ctx context.Context, b gateBackend, n k3sNodeSpec) *runningGuest {
	t.Helper()
	g := startGuest(t, ctx, guestSpec{
		plat:          b.plat,
		image:         k3sImage,
		entrypoint:    []string{"/bin/sh", "-c"},
		entrypointSet: true,
		cmd:           []string{k3sNodePrelude + n.script},
		envv:          append([]string{"IPTABLES_MODE=legacy", "TOKEN=" + multiNodeToken}, n.env...),
		hostname:      n.hostname,
		workspace:     n.workspace,
		net:           gvx.NetModeNAT,
		netRaw:        true,
		packetWrite:   true,
		allowSUID:     true,
		mounts:        []gvx.Mount{{Kind: gvx.MountVolume, ImagePath: filepath.Join(t.TempDir(), n.hostname+".ext4"), GuestPath: "/var/lib/rancher"}},
		forwards:      n.forwards,
	})
	dumpOnFailure(t, g)
	if os.Getenv("GVX_E2E_K3S_TRACE") != "" {
		traceGuest(t, n.hostname, g)
	}
	return g
}

// traceGuest copies the transcript of the guest to stderr while it grows. A
// long k3s run shows its progress this way, and a hung run shows where it
// stopped. The goroutine ends with the guest.
func traceGuest(t *testing.T, name string, g *runningGuest) {
	t.Helper()
	go func() {
		printed := 0
		for {
			select {
			case <-g.finished:
			case <-time.After(2 * time.Second):
			}
			s := g.out.String()
			if len(s) > printed {
				for _, line := range strings.Split(strings.TrimRight(s[printed:], "\n"), "\n") {
					fmt.Fprintf(os.Stderr, "[%s] %s\n", name, line)
				}
				printed = len(s)
			}
			select {
			case <-g.finished:
				return
			default:
			}
		}
	}()
}

// dumpOnFailure asks the guest for its diagnostics when the test failed, and
// logs them. The cleanup runs before the cleanup that ends the guest.
func dumpOnFailure(t *testing.T, g *runningGuest) {
	t.Helper()
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		select {
		case <-g.finished:
			return
		default:
		}
		// The pipe write blocks until the guest reads it, and a guest that
		// does not read never returns it. The cleanup that closes the pipe
		// ends the goroutine.
		written := make(chan error, 1)
		go func() {
			_, err := g.stdin.Write([]byte("dump\n"))
			written <- err
		}()
		select {
		case err := <-written:
			if err != nil {
				return
			}
		case <-g.finished:
			return
		case <-time.After(30 * time.Second):
			t.Logf("guest did not read the dump request")
			return
		}
		// The guest may be stuck, so the wait is a bounded poll and not a
		// fatal wait.
		deadline := time.Now().Add(2 * time.Minute)
		for time.Now().Before(deadline) {
			if _, ok := g.out.find(0, "DUMP-END\n"); ok {
				return
			}
			select {
			case <-g.finished:
				return
			case <-time.After(500 * time.Millisecond):
			}
		}
	})
}

// requireNoFailures fails the test when a transcript holds a FAIL line.
func requireNoFailures(t *testing.T, what string, g *runningGuest) {
	t.Helper()
	if strings.Contains(g.out.String(), "\nFAIL ") {
		t.Errorf("%s reported failures:\n%s", what, g.out.String())
	}
}

// requireMarkers fails the test when the transcript of the guest lacks a
// marker.
func requireMarkers(t *testing.T, what string, g *runningGuest, markers ...string) {
	t.Helper()
	requireContains(t, what+" transcript", g.out.String(), markers...)
}

// secondsOf returns the whole number that follows a marker line.
func secondsOf(t *testing.T, rest string) int {
	t.Helper()
	n, err := strconv.Atoi(strings.Fields(rest + " ")[0])
	if err != nil {
		t.Fatalf("marker value %q is not a number: %v", rest, err)
	}
	return n
}

// c1Markers are the markers that the checks of C1 print.
var c1Markers = []string{
	"NODES-READY ", "PODS-READY ", "POD-SERVER-TO-AGENT-OK", "POD-AGENT-TO-SERVER-OK",
	"SERVICE-FROM-SERVER-POD-OK", "SERVICE-FROM-AGENT-POD-OK", "DNS-FROM-AGENT-POD-OK",
	"LOGS-AGENT-OK", "EXEC-AGENT-OK", "EXEC-AGENT-CONNECT-OK", "CHECKS-DONE ",
}

// c1ServerScript starts a k3s server that the agent sandbox reaches through
// the host: the API port P is a published port, so the server advertises
// 10.0.2.2:P. The flannel wireguard back end uses 10.0.2.2 as the external
// address, and the host forwards UDP port 51820 to the server. The test sends
// P as the first input line.
const c1ServerScript = `
read -r PORT
k3s server --token "$TOKEN" --tls-san 10.0.2.2 --advertise-address 10.0.2.2 --advertise-port "$PORT" \
  --node-external-ip 10.0.2.2 --flannel-backend=wireguard-native --flannel-external-ip \
  --disable=traefik,servicelb --write-kubeconfig-mode=644 >/tmp/k3s.log 2>&1 &
t0=$(date +%s)
until k get nodes 2>/dev/null | grep -q " Ready"; do
  if [ $(( $(date +%s) - t0 )) -gt 600 ]; then fail "server node not Ready"; dump; exit 1; fi
  sleep 2
done
log "SERVER-READY $(( $(date +%s) - t0 ))"
` + multiNodeChecks + `
checks
serve
`

// c1AgentScript joins a k3s agent through the published port of the server.
// The agent publishes no UDP port. Its external address is unreachable, so
// the server learns the endpoint of the agent from the first handshake, which
// the keepalive of the agent sends.
const c1AgentScript = `
k3s agent --server "https://10.0.2.2:$SERVER_PORT" --token "$TOKEN" \
  --node-external-ip 192.0.2.1 >/tmp/k3s.log 2>&1 &
log "AGENT-STARTED"
serve
`

// requireFreeUDPPort skips the test when another process holds the UDP port on
// the loopback address. Flannel fixes its WireGuard port, so the test cannot
// publish another port. A held port is a property of the host, not a defect of
// the sandbox, and a skip names it.
func requireFreeUDPPort(t *testing.T, port int) {
	t.Helper()
	pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("host UDP port %d is in use, and flannel cannot use another port: %v", port, err)
	}
	if err := pc.Close(); err != nil {
		t.Fatalf("close the probe socket of UDP port %d: %v", port, err)
	}
}

// TestE2EK3sMultiNodeT1Join runs C1 of GVXIP-005. A server sandbox and an agent
// sandbox form one k3s cluster with the flannel wireguard-native back end. The
// server publishes its API port and the WireGuard port. The agent publishes
// nothing, and the agent tunnel carries kubectl logs and exec.
func TestE2EK3sMultiNodeT1Join(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireMultiSandbox(t, b)
			requireFreeUDPPort(t, flannelWireGuardPort)
			ctx, cancel := context.WithTimeout(context.Background(), 28*time.Minute)
			t.Cleanup(cancel)

			start := time.Now()
			server := startK3sNode(t, ctx, b, k3sNodeSpec{
				hostname: multiNodeServerName,
				env:      []string{"SERVER_NODE=" + multiNodeServerName, "AGENT_NODE=" + multiNodeAgentName},
				forwards: []gvx.PortForward{
					{HostPort: 0, GuestPort: 6443, Protocol: "tcp", BindAddress: "127.0.0.1"},
					{HostPort: flannelWireGuardPort, GuestPort: flannelWireGuardPort, Protocol: "udp", BindAddress: "127.0.0.1"},
				},
				script: c1ServerScript,
			})
			apiPort := server.sb.BoundPort(0)
			if apiPort == 0 {
				t.Fatal("BoundPort(0) = 0, want the host port of the published API port")
			}
			if _, err := server.stdin.Write([]byte(strconv.Itoa(apiPort) + "\n")); err != nil {
				t.Fatalf("send the API port to the server guest: %v", err)
			}
			ready := secondsOf(t, server.wait(t, "SERVER-READY ", 12*time.Minute))
			t.Logf("server node Ready after %ds", ready)

			agent := startK3sNode(t, ctx, b, k3sNodeSpec{
				hostname: multiNodeAgentName,
				env:      []string{"SERVER_PORT=" + strconv.Itoa(apiPort)},
				script:   c1AgentScript,
			})
			agent.wait(t, "AGENT-STARTED", time.Minute)

			server.wait(t, "CHECKS-DONE ", 20*time.Minute)
			requireMarkers(t, "server guest", server, c1Markers...)
			requireNoFailures(t, "server guest", server)
			t.Logf("agent Ready %ds and pods Ready %ds after the server was Ready; total %s",
				secondsOf(t, server.wait(t, "NODES-READY ", time.Second)),
				secondsOf(t, server.wait(t, "PODS-READY ", time.Second)),
				time.Since(start).Round(time.Second))
		})
	}
}

// copyFile copies the file src to dst with the mode 0755.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o755)
}

// c3AgentScript joins a k3s agent to the native server of the runner. The
// guest reaches the host through NAT, so the server address is the address of
// the host on its default route. The external address of the agent is
// unreachable, so the native server learns the endpoint of the agent from the
// handshake that the keepalive of the agent sends.
const c3AgentScript = `
k3s agent --server "https://$SERVER_IP:6443" --token "$TOKEN" \
  --node-external-ip 192.0.2.1 >/tmp/k3s.log 2>&1 &
log "AGENT-STARTED"
serve
`

// c3NativeServerName is the node name of the native k3s server of C3.
const c3NativeServerName = "gvx-native-server"

// hostRouteAddress returns the address that the host uses to reach a remote
// network. It opens a UDP socket and sends no packet.
func hostRouteAddress(t *testing.T) string {
	t.Helper()
	conn, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		t.Fatalf("find the address of the default route: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// runHostScript runs a bash script on the host with the kubeconfig of the
// native k3s server, and returns its output. A failed script fails the test.
func runHostScript(t *testing.T, ctx context.Context, script string, env ...string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, "bash", "-c", script)
	cmd.Env = append(os.Environ(), append([]string{"KUBECONFIG=/etc/rancher/k3s/k3s.yaml"}, env...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("host script failed: %v\nscript:\n%s\noutput:\n%s", err, script, out)
	}
	return string(out)
}

// TestE2EK3sMultiNodeMixedKernels runs C3 of GVXIP-005. A native k3s server runs
// on the Linux host with the kernel of the host, and a gvx agent joins it.
// The checks are the checks of C1. The test installs k3s on the host with
// sudo and removes it afterward, so it runs only when GVX_E2E_NATIVE_K3S is 1,
// on a Linux host that the user can discard.
func TestE2EK3sMultiNodeMixedKernels(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("C3 needs a Linux host: the native k3s server uses the kernel of the host")
	}
	if os.Getenv("GVX_E2E_NATIVE_K3S") != "1" {
		t.Skip("C3 installs and removes k3s on the host; set GVX_E2E_NATIVE_K3S=1 on a Linux host that you can discard")
	}
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireMultiSandbox(t, b)
			for _, tool := range []string{"sudo", "curl", "wget", "bash"} {
				if _, err := exec.LookPath(tool); err != nil {
					t.Fatalf("C3 needs %s on the host: %v", tool, err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 28*time.Minute)
			t.Cleanup(cancel)
			hostIP := hostRouteAddress(t)

			// Registered first, so it runs after the guest of the agent ends.
			t.Cleanup(func() {
				if t.Failed() {
					out, _ := exec.Command("sudo", "journalctl", "-u", "k3s", "-n", "200", "--no-pager").CombinedOutput()
					t.Logf("native k3s journal:\n%s", out)
				}
				if _, err := os.Stat("/usr/local/bin/k3s-uninstall.sh"); err == nil {
					if out, err := exec.Command("sudo", "/usr/local/bin/k3s-uninstall.sh").CombinedOutput(); err != nil {
						t.Errorf("k3s-uninstall.sh failed: %v\n%s", err, out)
					}
				}
			})

			start := time.Now()
			install := `curl -sfL https://get.k3s.io | sudo --preserve-env=INSTALL_K3S_VERSION,INSTALL_K3S_EXEC,K3S_TOKEN sh -`
			runHostScript(t, ctx, install,
				"INSTALL_K3S_VERSION=v1.31.4+k3s1",
				"K3S_TOKEN="+multiNodeToken,
				"INSTALL_K3S_EXEC=server --node-name "+c3NativeServerName+" --node-external-ip "+hostIP+
					" --flannel-backend=wireguard-native --flannel-external-ip --disable=traefik,servicelb --write-kubeconfig-mode=644")
			runHostScript(t, ctx, k3sNodePrelude+`
t0=$(date +%s)
until k get nodes 2>/dev/null | grep -q " Ready"; do
  if [ $(( $(date +%s) - t0 )) -gt 600 ]; then echo "native server not Ready"; exit 1; fi
  sleep 2
done
`)
			t.Logf("native server Ready %s after the start of the test", time.Since(start).Round(time.Second))

			agent := startK3sNode(t, ctx, b, k3sNodeSpec{
				hostname: multiNodeAgentName,
				env:      []string{"SERVER_IP=" + hostIP},
				script:   c3AgentScript,
			})
			agent.wait(t, "AGENT-STARTED", time.Minute)

			out := runHostScript(t, ctx, k3sNodePrelude+multiNodeChecks+"\nchecks\n",
				"SERVER_NODE="+c3NativeServerName, "AGENT_NODE="+multiNodeAgentName)
			t.Logf("checks on the native server:\n%s", out)
			requireContains(t, "native checks", out, c1Markers...)
			if strings.Contains(out, "\nFAIL ") || strings.HasPrefix(out, "FAIL ") {
				t.Errorf("native checks reported failures:\n%s", out)
			}
			t.Logf("total %s", time.Since(start).Round(time.Second))
		})
	}
}
