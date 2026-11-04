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
	"runtime"
	"strings"
	"testing"

	"z.gfire.dev/gvx/internal/acceptprog"
)

// TestE2EBlockedSocketCallSurvivesSignal checks that a socket call that blocks in
// the guest does not fail with EINTR when a signal arrives, on every backend.
// Linux restarts the call after a signal with a handler that has SA_RESTART and
// after an ignored signal. runc and the kubelet depend on it: a runc init
// process that blocks in recvfrom(2) on its sync socket got EINTR in a k3s node
// and the container failed to start. The guest program also checks that a
// handler without SA_RESTART still gives EINTR.
func TestE2EBlockedSocketCallSurvivesSignal(t *testing.T) {
	bin := acceptprog.BuildEINTRProbe(t, runtime.GOARCH)
	var want []string
	for _, source := range []string{
		"handler-restart-sigurg", "handler-restart-sigusr1",
		"handler-restart-sigchld", "ignored-sigusr2",
	} {
		for _, call := range []string{
			"recvfrom-peek-trunc-seqpacket", "recvmsg-stream", "accept-stream", "sendmsg-full-stream",
		} {
			want = append(want, call+"-"+source)
		}
	}
	want = append(want, "recvfrom-peek-trunc-seqpacket-handler-without-restart-sigusr1")
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			code, out := runParityProbe(t, b, bin, false, "checks")
			if code != 0 || !strings.Contains(out, "DONE") {
				t.Fatalf("eintrprobe checks exited with %d\n%s", code, out)
			}
			for _, name := range want {
				if !strings.Contains(out, "PASS "+name+"\n") {
					t.Errorf("check %s did not pass\n%s", name, out)
				}
			}
			if strings.Contains(out, "FAIL ") {
				t.Errorf("failed checks:\n%s", out)
			}
		})
	}
}
