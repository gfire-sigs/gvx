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
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/pkg/gvx"
)

// TestE2EMemoryAccountingIsPerSandbox runs a sandbox that holds 256 MiB in a
// memory cgroup while a second sandbox of the same process holds 16 MiB in its
// own memory cgroup, with memory.max of 128 MiB. Both cgroups get the same
// memory cgroup ID in their own sandbox. The second guest must read only its
// own memory in memory.current, memory.stat, the root memory.stat, and
// /proc/meminfo, and the memory.max enforcer must not end its process.
func TestE2EMemoryAccountingIsPerSandbox(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		if b.plat == gvx.PlatformWHPX {
			t.Skip("the whpx backend cannot hold two running sandboxes in one process")
		}
		holdIn, holdEnd := io.Pipe()
		holding := make(chan struct{})
		var holdingOnce sync.Once
		markHolding := func() { holdingOnce.Do(func() { close(holding) }) }
		t.Run("pair", func(t *testing.T) {
			t.Run("holder", func(t *testing.T) {
				t.Parallel()
				defer markHolding()
				code, out := runNodeProbe(t, b, bin, func(cfg *gvx.Config) {
					cfg.Stdin = holdIn
					cfg.Stdout = io.MultiWriter(cfg.Stdout, lineWatcher{marker: "HOLDING", found: markHolding})
				}, "memcg", "256")
				requireNodeChecks(t, code, out, "memcg-child-holds-its-memory", "memcg-readings-after-the-input-ends")
			})
			t.Run("limited", func(t *testing.T) {
				t.Parallel()
				defer holdEnd.Close()
				select {
				case <-holding:
				case <-time.After(2 * time.Minute):
					t.Fatal("the holder sandbox did not commit its memory")
				}
				limitedIn, limitedEnd := io.Pipe()
				// The enforcer checks memory.max every 5 ms near the limit, so 3 s
				// after the child holds its memory cover many checks.
				var endOnce sync.Once
				defer limitedEnd.Close()
				code, out := runNodeProbe(t, b, bin, func(cfg *gvx.Config) {
					cfg.Stdin = limitedIn
					cfg.Stdout = io.MultiWriter(cfg.Stdout, lineWatcher{marker: "HOLDING", found: func() {
						endOnce.Do(func() { time.AfterFunc(3*time.Second, func() { limitedEnd.Close() }) })
					}})
				}, "memcg", "16", "128")
				requireNodeChecks(t, code, out,
					"memcg-child-holds-its-memory", "memcg-current-excludes-other-sandboxes",
					"memcg-stat-excludes-other-sandboxes", "root-memory-stat-excludes-other-sandboxes",
					"meminfo-anon-excludes-other-sandboxes", "memory-max-ignores-other-sandboxes")
			})
		})
	})
}

// TestE2EMemoryAccountingCountsGuestAnonymousMemory verifies that guest
// anonymous memory moves /proc/meminfo counters and triggers the sandbox
// memory guard under a 64 MiB limit on every backend.
func TestE2EMemoryAccountingCountsGuestAnonymousMemory(t *testing.T) {
	bin := acceptprog.BuildNodeProbe(t, runtime.GOARCH)
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			code, out := runNodeProbe(t, b, bin, nil, "memfree", "48")
			requireNodeChecks(t, code, out, "meminfo-tracks-guest-anonymous-commit")

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			inR, inW := io.Pipe()
			defer inW.Close()
			var stdout, stderr bytes.Buffer
			sb, err := gvx.New(ctx, gvx.Config{
				Platform:            b.plat,
				NetworkMode:         gvx.NetModeNone,
				OCICacheDir:         t.TempDir(),
				BinaryPath:          bin,
				Argv:                []string{"/bin/app", "hold", "128"},
				Stdin:               inR,
				Stdout:              &stdout,
				Stderr:              &stderr,
				Resources:           gvx.Resources{MemoryBytes: 64 << 20},
				DisableHostLockdown: true,
			})
			skipWhenFixedAddressRefused(t, "New(nodeprobe hold)", err)
			defer func() {
				if err := sb.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
			}()
			code, err = sb.Run(ctx)
			if err != nil && !errors.Is(err, gvx.ErrMemoryLimit) {
				skipWhenFixedAddressRefused(t, "Run(nodeprobe hold)", err)
			}
			if !errors.Is(err, gvx.ErrMemoryLimit) || code != 137 {
				t.Fatalf("hold 128 MiB under 64 MiB limit = (%d, %v), want (137, ErrMemoryLimit)\nstdout=%s\nstderr=%s",
					code, err, stdout.String(), stderr.String())
			}
		})
	}
}
