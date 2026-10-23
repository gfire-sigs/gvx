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
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
)

// The Docker run gates: the settings of `docker run` that rungv now accepts
// reach the guest. Each subtest runs on the hardware backend and on systrap.

func TestE2EDockerRunUserEnvironmentAndHostname(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			script := `echo "uid=$(id -u) gid=$(id -g)"; echo "HOME=$HOME"; echo "A=$A"; echo "HOSTNAME=$HOSTNAME"
hostname; cat /etc/hostname; grep -c " box" /etc/hosts; touch /root-only 2>&1 | head -c 40; echo; ls -ld / | cut -c1-10`
			out := mustRunGuest(t, guestSpec{
				plat:     b.plat,
				image:    "alpine:3.20",
				argv:     []string{"sh", "-c", script},
				envv:     []string{"A=1"},
				user:     "nobody",
				hostname: "box",
			})
			requireContains(t, "guest output", out,
				"uid=65534 gid=65534\n", "HOME=/\n", "A=1\n", "HOSTNAME=box\n", "box\nbox\n",
				"Permission denied", "drwxr-xr-x\n")
		})
	}
}

func TestE2EDockerRunCallerEnvironmentMergesOverImageEnvironment(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, guestSpec{
				plat:  b.plat,
				image: "python:3.12-alpine",
				argv:  []string{"sh", "-c", `echo "PYTHON_VERSION=$PYTHON_VERSION"; echo "LANG=$LANG"; echo "EXTRA=$EXTRA"`},
				envv:  []string{"LANG=C.UTF-8", "EXTRA=1", "LANG=override"},
			})
			if !strings.Contains(out, "PYTHON_VERSION=3.12") {
				t.Errorf("the image variable PYTHON_VERSION is missing from the guest environment:\n%s", out)
			}
			requireContains(t, "guest output", out, "LANG=override\n", "EXTRA=1\n")
		})
	}
}

func TestE2EDockerRunEntrypointAndCmdFollowDockerRules(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			// The image alpine/git has the entrypoint git.
			out := mustRunGuest(t, guestSpec{plat: b.plat, image: gitImage, cmd: []string{"--version"}})
			requireContains(t, "entrypoint plus the cmd of the caller", out, "git version")
			out = mustRunGuest(t, guestSpec{
				plat: b.plat, image: gitImage,
				entrypoint: []string{"sh", "-c"}, entrypointSet: true, cmd: []string{"echo entrypoint-replaced"},
			})
			requireContains(t, "replaced entrypoint", out, "entrypoint-replaced\n")
		})
	}
}

func TestE2EDockerRunMemoryLimitKillsAGuestThatHoldsTheMemory(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			var stdout, stderr strings.Builder
			spec := guestSpec{
				plat:      b.plat,
				image:     "alpine:3.20",
				argv:      []string{"sh", "-c", "dd if=/dev/zero of=/big/f bs=1M count=200 2>/dev/null; sleep 30; echo survived"},
				mounts:    []gvx.Mount{{Kind: gvx.MountTmpfs, GuestPath: "/big"}},
				resources: gvx.Resources{MemoryBytes: 64 << 20},
			}
			sb, err := gvx.New(ctx, spec.config(sharedCacheDir(t), &stdout, &stderr))
			if err != nil {
				t.Fatalf("gvx.New: %v", err)
			}
			defer func() {
				if err := sb.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
			}()
			code, err := sb.Run(ctx)
			if !errors.Is(err, gvx.ErrMemoryLimit) || code != 137 {
				t.Fatalf("Run = (%d, %v), want (137, ErrMemoryLimit)\nstdout=%s\nstderr=%s", code, err, stdout.String(), stderr.String())
			}
			if strings.Contains(stdout.String(), "survived") {
				t.Errorf("the guest outlived the kill: %q", stdout.String())
			}
		})
	}
}

func TestE2EDockerRunPublishAllBindsTheExposedPorts(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			stdout, stderr := newOutputLog(), newOutputLog()
			spec := guestSpec{plat: b.plat, image: "nginx:alpine", net: gvx.NetModeNAT, publishAll: true}
			sb, err := gvx.New(ctx, spec.config(sharedCacheDir(t), stdout, stderr))
			if err != nil {
				t.Fatalf("gvx.New: %v", err)
			}
			defer func() {
				if err := sb.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
			}()
			var hostPort uint16
			for _, p := range sb.PublishedPorts() {
				if p.GuestPort == 80 && p.Protocol == "tcp" && p.HostAddr == "127.0.0.1" {
					hostPort = p.HostPort
				}
			}
			if hostPort == 0 {
				t.Fatalf("PublishedPorts() = %+v, want 80/tcp on 127.0.0.1 with a free host port", sb.PublishedPorts())
			}

			finished := make(chan struct{})
			runCtx, stopGuest := context.WithCancel(ctx)
			defer func() {
				stopGuest()
				<-finished
			}()
			go func() {
				defer close(finished)
				_, _ = sb.Run(runCtx)
			}()
			stderr.waitFor(t, 0, nginxReady, 2*time.Minute, finished)
			body, status := httpGet(t, ctx, "http://127.0.0.1:"+strconv.Itoa(int(hostPort))+"/")
			if status != http.StatusOK || !strings.Contains(body, "Welcome to nginx!") {
				t.Errorf("GET / = (%d, %q), want 200 and the default page", status, body)
			}
		})
	}
}
