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
// init process waits in a read of a stdin pipe that stays open. SIGKILL ends a
// task that waits in read on Linux, so Run must return without a close of the
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
				argv: []string{"sh", "-c", "echo READY; read x; echo GOT $x"},
			})
			g.wait(t, "READY", time.Minute)
			// The guest must wait in the read when the cancel comes.
			select {
			case <-g.finished:
				t.Fatalf("the guest ended before the cancel; output:\n%s", g.out.String())
			case <-time.After(2 * time.Second):
			}
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

// TestE2EStdinPipeDeliversInputToBlockedRead checks that a guest read that
// waits for input gets a line that the host writes later, and then sees the end
// of input when the host closes the pipe.
func TestE2EStdinPipeDeliversInputToBlockedRead(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			t.Cleanup(cancel)
			g := startGuest(t, ctx, guestSpec{
				plat: b.plat, image: "alpine:3.20", net: gvx.NetModeNAT,
				argv: []string{"sh", "-c", "echo READY; read a; echo GOT-A $a; read b; echo GOT-B $b; if read c; then echo MORE; else echo EOF; fi"},
			})
			g.wait(t, "READY", time.Minute)
			if _, err := g.stdin.Write([]byte("one\ntwo\n")); err != nil {
				t.Fatalf("write stdin: %v", err)
			}
			g.wait(t, "GOT-A one", time.Minute)
			g.wait(t, "GOT-B two", time.Minute)
			g.stdin.Close()
			g.wait(t, "EOF", time.Minute)
		})
	}
}
