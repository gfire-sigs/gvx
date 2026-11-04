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
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
)

// TestE2ECancelEndsGuestThatWaitsForStdin cancels the Run of a guest whose
// init process waits for input on a stdin pipe that stays open. The cancel
// sends SIGKILL to the init process, so Run must return without a close of the
// pipe. A test that ends a sandbox in the middle of a run depends on this.
func TestE2ECancelEndsGuestThatWaitsForStdin(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			t.Cleanup(cancel)
			g := startGuest(t, ctx, guestSpec{
				plat: b.plat, image: "alpine:3.20", net: gvx.NetModeNAT,
				argv: []string{"sh", "-c", "echo READY; read x; echo GOT"},
			})
			g.wait(t, "READY", time.Minute)
			start := time.Now()
			g.stop()
			select {
			case <-g.finished:
				t.Logf("Run returned %s after the cancel", time.Since(start).Round(time.Millisecond))
			case <-time.After(30 * time.Second):
				t.Fatal("Run did not return within 30 seconds after the cancel")
			}
		})
	}
}
