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
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
)

// dindScript runs docker:dind with --userland-proxy=false in the guest and then
// checks the parts of the engine that need guest kernel support: published
// ports without the userland proxy, docker stats, iptables-legacy-save, and a
// memory limit on a container. Each check prints one marker line that the test
// reads. The script waits for a line on its standard input after it published
// a port, so the test can reach the port from the host first.
const dindScript = `
dockerd-entrypoint.sh --tls=false --userland-proxy=false >/tmp/dockerd.log 2>&1 &
fail() { echo "FAIL $1"; tail -n 40 /tmp/dockerd.log; exit 1; }

i=0
until docker info >/dev/null 2>&1; do
  i=$((i+1)); [ $i -gt 180 ] && fail "dockerd did not start"
  sleep 1
done
echo DOCKERD-READY

docker run -d --name web -p 9100:80 nginx:alpine >/dev/null || fail "start nginx"
i=0
until wget -qO- -T 5 http://127.0.0.1:9100/ 2>/dev/null | grep -q "Welcome to nginx"; do
  i=$((i+1)); [ $i -gt 60 ] && fail "no nginx page on 127.0.0.1:9100 in the guest"
  sleep 1
done
echo GUEST-LOOPBACK-PORT-OK
echo HOST-PORT-READY
read -r _

docker run -d --name hog alpine sh -c 'dd if=/dev/zero of=/dev/shm/f bs=1M count=64 2>/dev/null; sleep 600' >/dev/null || fail "start hog"
i=0
while :; do
  usage=$(docker stats --no-stream --format '{{.MemUsage}}' hog | cut -d/ -f1 | tr -d ' ')
  case "$usage" in *MiB) mib=${usage%MiB}; awk -v v="$mib" 'BEGIN{exit !(v>=60 && v<=160)}' && break;; esac
  i=$((i+1)); [ $i -gt 60 ] && fail "docker stats shows $usage for a container that holds 64 MiB"
  sleep 1
done
echo "STATS-MEMORY $usage"

iptables-legacy-save > /tmp/rules.txt
grep -q '^\*nat' /tmp/rules.txt && grep -q '^\*filter' /tmp/rules.txt && grep -q '^:DOCKER ' /tmp/rules.txt && echo IPTABLES-SAVE-OK

docker run --name limited -m 32m alpine sh -c 'dd if=/dev/zero of=/dev/shm/f bs=1M count=128 2>/dev/null; sleep 30'
echo "LIMITED-EXIT $?"
echo "LIMITED-OOMKILLED $(docker inspect -f '{{.State.OOMKilled}}' limited)"
echo "NEIGHBOR-RUNNING $(docker inspect -f '{{.State.Running}}' web) $(docker inspect -f '{{.State.Running}}' hog)"
docker info >/dev/null 2>&1 && echo DOCKERD-ALIVE
echo ALL-DONE
`

// TestE2EDockerRunDindEngine runs docker:dind in the guest with
// --userland-proxy=false. It needs the per-link route_localnet files, the
// bridge-nf-call-iptables file, the hairpin mode of a bridge port, the link
// counters of netlink, memory.stat, the enforcement of memory.max, and
// /proc/net/ip_tables_names.
func TestE2EDockerRunDindEngine(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()

			stdin, release := io.Pipe()
			defer stdin.Close()
			stdout, stderr := newOutputLog(), newOutputLog()
			spec := guestSpec{
				plat:          b.plat,
				image:         "docker:dind",
				entrypoint:    []string{"sh", "-c"},
				entrypointSet: true,
				cmd:           []string{dindScript},
				envv:          []string{"DOCKER_TLS_CERTDIR="},
				net:           gvx.NetModeNAT,
				netRaw:        true,
				packetWrite:   true,
				allowSUID:     true,
				mounts:        []gvx.Mount{{Kind: gvx.MountTmpfs, GuestPath: "/var/lib/docker", TmpfsSizeBytes: 6 << 30}},
				forwards:      []gvx.PortForward{{HostPort: 0, GuestPort: 9100, Protocol: "tcp", BindAddress: "127.0.0.1"}},
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
			hostPort := sb.BoundPort(0)
			if hostPort == 0 {
				t.Fatalf("BoundPort(0) = 0, want the ephemeral host port")
			}

			var res guestResult
			finished := make(chan struct{})
			runCtx, stopGuest := context.WithCancel(ctx)
			defer func() {
				stopGuest()
				<-finished
			}()
			go func() {
				defer close(finished)
				res.code, res.err = sb.Run(runCtx)
			}()

			next := 0
			expect := func(marker string) {
				t.Helper()
				next = stdout.waitFor(t, next, marker, 8*time.Minute, finished)
			}
			expect("DOCKERD-READY\n")
			expect("GUEST-LOOPBACK-PORT-OK\n")
			expect("HOST-PORT-READY\n")

			body, status := httpGet(t, ctx, "http://127.0.0.1:"+strconv.Itoa(hostPort)+"/")
			if status != http.StatusOK || !strings.Contains(body, "Welcome to nginx!") {
				t.Errorf("host GET / on the published port = (%d, %q), want 200 and the default page", status, body)
			}
			if _, err := io.WriteString(release, "go\n"); err != nil {
				t.Fatalf("release the guest script: %v", err)
			}

			expect("STATS-MEMORY ")
			expect("IPTABLES-SAVE-OK\n")
			expect("LIMITED-EXIT 137\n")
			expect("LIMITED-OOMKILLED true\n")
			expect("NEIGHBOR-RUNNING true true\n")
			expect("DOCKERD-ALIVE\n")
			expect("ALL-DONE\n")

			stopGuest()
			<-finished
			if !errors.Is(res.err, context.Canceled) {
				t.Errorf("Run after stop = (%d, %v), want context.Canceled", res.code, res.err)
			}
		})
	}
}
