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
	"io"
	"net"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/gvx"
)

// dindCacheDir returns the layer cache for docker:dind tests. CI sets
// GVX_E2E_DIND_CACHE_DIR to reuse cached docker:dind EROFS layers across runs.
func dindCacheDir(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("GVX_E2E_DIND_CACHE_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("create dind cache dir %q: %v", dir, err)
		}
		return dir
	}
	return sharedCacheDir(t)
}

// requireDindImage allows local-registry dind tests to run when CI provides
// GVX_E2E_DIND_CACHE_DIR, and otherwise falls back to requireRegistry.
func requireDindImage(t *testing.T) {
	t.Helper()
	if os.Getenv("GVX_E2E_DIND_CACHE_DIR") != "" {
		return
	}
	requireRegistry(t)
}

// startHostTCPBanner starts a host loopback TCP server that writes banner and
// closes each accepted connection, returning its TCP port string.
func startHostTCPBanner(t *testing.T, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen host banner server: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.WriteString(c, banner)
			}(conn)
		}
	}()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host banner addr: %v", err)
	}
	return port
}

// closedHostTCPPort opens and closes a loopback TCP listener to obtain a port
// that refuses connections immediately.
func closedHostTCPPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen closed probe port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close probe port: %v", err)
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split closed port addr: %v", err)
	}
	return port
}

// TestE2EDockerBuildDindLocalRegistry starts docker:dind inside gvx and runs a
// multi-stage docker build against an in-process OCI registry on the host. The
// build exercises local registry pulls over host.docker.internal, COPY, RUN
// networking behind dockerd iptables NAT, and NAT dial error classes (#206)
// without contacting external registries during the build.
func TestE2EDockerBuildDindLocalRegistry(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireDindImage(t)

			catBin, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
			if err != nil {
				t.Fatalf("BuildGuestCatELF64: %v", err)
			}
			svcProbePath := acceptprog.BuildSvcProbe(t, runtime.GOARCH)
			svcProbeBin, err := os.ReadFile(svcProbePath)
			if err != nil {
				t.Fatalf("read svcprobe: %v", err)
			}

			baseLayer := mustTar(t,
				testimage.File{Name: "bin/cat", Data: catBin, Mode: 0o755},
				testimage.File{Name: "bin/svcprobe", Data: svcProbeBin, Mode: 0o755},
			)
			regURLRaw := testimage.NewRegistry(t, "gvx/base", "1", testimage.Image{
				Arch:   runtime.GOARCH,
				Layers: [][]byte{baseLayer},
			})
			regURL, err := url.Parse(regURLRaw)
			if err != nil {
				t.Fatalf("parse registry URL: %v", err)
			}
			regHost := "host.docker.internal:" + regURL.Port()
			baseImage := regHost + "/gvx/base:1"

			bannerPort := startHostTCPBanner(t, "host-build-ok\n")
			closedPort := closedHostTCPPort(t)

			script := fmt.Sprintf(`set -eu
dockerd-entrypoint.sh --tls=false --insecure-registry=%s >/tmp/dockerd.log 2>&1 &
fail() { echo "FAIL $1"; tail -n 60 /tmp/dockerd.log; exit 1; }

i=0
until docker info >/dev/null 2>&1; do
  i=$((i+1)); [ $i -gt 180 ] && fail "dockerd did not start"
  sleep 1
done
echo DOCKERD-READY

grep -q '^nameserver 10\.0\.2\.3$' /etc/resolv.conf || fail "resolv.conf missing 10.0.2.3"
echo RESOLV-OK

mkdir -p /tmp/ctx
printf 'dind-build-payload\n' > /tmp/ctx/input.txt
cat <<'DOCKERFILE' > /tmp/ctx/Dockerfile
FROM %s AS stage1
COPY input.txt /input.txt
RUN ["/bin/svcprobe", "dial", "host.docker.internal:%s"]
RUN ["/bin/cat", "/input.txt"]

FROM %s
COPY --from=stage1 /input.txt /final.txt
ENTRYPOINT ["/bin/cat", "/final.txt"]
DOCKERFILE

docker build --progress=plain -t gvx-local-built /tmp/ctx 2>&1 || fail "docker build failed"
echo BUILD-OK

run_out=$(docker run --rm gvx-local-built) || fail "docker run built image failed"
[ "$run_out" = "dind-build-payload" ] || fail "unexpected built image output: $run_out"
echo RUN-OK

refused_out=$(docker run --rm %s /bin/svcprobe dial host.docker.internal:%s 2>&1 || true)
echo "REFUSED: $refused_out"
echo "$refused_out" | grep -qi 'connection refused' || fail "closed port did not return connection refused: $refused_out"
echo REFUSED-OK

timeout_out=$(docker run --rm %s /bin/svcprobe dial 192.0.2.1:80 2>&1 || true)
echo "TIMEOUT: $timeout_out"
echo "$timeout_out" | grep -qi 'i/o timeout' || fail "blackholed target did not time out: $timeout_out"
echo "$timeout_out" | grep -qi 'connection refused' && fail "blackholed target returned connection refused: $timeout_out"
echo TIMEOUT-OK
`, regHost, baseImage, bannerPort, baseImage, baseImage, closedPort, baseImage)

			spec := guestSpec{
				plat:          b.plat,
				image:         "docker:dind",
				entrypoint:    []string{"sh", "-c"},
				entrypointSet: true,
				cmd:           []string{script},
				envv:          []string{"DOCKER_TLS_CERTDIR="},
				net:           gvx.NetModeNAT,
				netRaw:        true,
				packetWrite:   true,
				allowSUID:     true,
				mounts:        []gvx.Mount{{Kind: gvx.MountTmpfs, GuestPath: "/var/lib/docker", TmpfsSizeBytes: 2 << 30}},
				timeout:       10 * time.Minute,
			}

			out := runGuestWithCache(t, spec, dindCacheDir(t))
			requireContains(t, "dind local docker build", out,
				"DOCKERD-READY\n",
				"RESOLV-OK\n",
				"BUILD-OK\n",
				"RUN-OK\n",
				"REFUSED-OK\n",
				"TIMEOUT-OK\n",
			)
		})
	}
}

// TestE2EDockerBuildDindUpstream starts docker:dind inside gvx and builds an
// Alpine image that installs packages over the network during docker build.
// It runs in e2e-images.yml and skips when GVX_E2E_OFFLINE=1.
func TestE2EDockerBuildDindUpstream(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)

			const script = `set -eu
dockerd-entrypoint.sh --tls=false >/tmp/dockerd.log 2>&1 &
fail() { echo "FAIL $1"; tail -n 60 /tmp/dockerd.log; exit 1; }

i=0
until docker info >/dev/null 2>&1; do
  i=$((i+1)); [ $i -gt 180 ] && fail "dockerd did not start"
  sleep 1
done
echo DOCKERD-READY

mkdir -p /tmp/ctx
cat <<'DOCKERFILE' > /tmp/ctx/Dockerfile
FROM alpine:3.20
RUN apk add --no-cache ca-certificates && echo "upstream-build-ok" > /built.txt
CMD ["cat", "/built.txt"]
DOCKERFILE

docker build --progress=plain -t gvx-upstream-built /tmp/ctx 2>&1 || fail "upstream docker build failed"
echo BUILD-OK

run_out=$(docker run --rm gvx-upstream-built) || fail "docker run upstream image failed"
[ "$run_out" = "upstream-build-ok" ] || fail "unexpected output: $run_out"
echo RUN-OK
`
			out := mustRunGuest(t, guestSpec{
				plat:          b.plat,
				image:         "docker:dind",
				entrypoint:    []string{"sh", "-c"},
				entrypointSet: true,
				cmd:           []string{script},
				envv:          []string{"DOCKER_TLS_CERTDIR="},
				net:           gvx.NetModeNAT,
				netRaw:        true,
				packetWrite:   true,
				allowSUID:     true,
				mounts:        []gvx.Mount{{Kind: gvx.MountTmpfs, GuestPath: "/var/lib/docker", TmpfsSizeBytes: 4 << 30}},
				timeout:       12 * time.Minute,
			})
			requireContains(t, "dind upstream docker build", out,
				"DOCKERD-READY\n",
				"BUILD-OK\n",
				"RUN-OK\n",
			)
		})
	}
}

// runGuestWithCache runs g using cacheDir and fails the test unless the guest
// exits with status 0.
func runGuestWithCache(t *testing.T, g guestSpec, cacheDir string) string {
	t.Helper()
	timeout := g.timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	var outBuf, errBuf strings.Builder
	sb, err := gvx.New(ctx, g.config(cacheDir, &outBuf, &errBuf))
	if err != nil {
		t.Fatalf("gvx.New(%s, %s) failed: %v", g.plat, g.image, err)
	}
	defer func() {
		if err := sb.Close(); err != nil {
			t.Errorf("Close(%s, %s) failed: %v", g.plat, g.image, err)
		}
	}()
	code, err := sb.Run(ctx)
	if err != nil || code != 0 {
		t.Fatalf("guest %s exit = (%d, %v)\nstdout:\n%s\nstderr:\n%s", g.image, code, err, outBuf.String(), errBuf.String())
	}
	return outBuf.String()
}
