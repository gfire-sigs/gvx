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

//go:build (linux && !android) || (darwin && !ios) || windows

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
)

func TestE2ENATPolicyRestoreUsesNewerHostRules(t *testing.T) {
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			bin := toolPath(t, rungvPkg)
			guest := acceptprog.BuildCheckpointProbe(t, hostArch())
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()

			private := t.TempDir()
			dir := filepath.Join(private, "rules")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			const deny = "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\nCOMMIT\n"
			allow := strings.Replace(deny, "COMMIT\n", "-A INPUT -p tcp -j ACCEPT\n-A OUTPUT -p tcp -j ACCEPT\nCOMMIT\n", 1)
			rules := filepath.Join(dir, "allow.v4")
			closed := filepath.Join(dir, "closed.rules")
			for path, contents := range map[string]string{rules: allow, closed: deny} {
				if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			control := "tcp://" + freeLoopbackControlSocketAddr(t)
			cache := filepath.Join(private, "cache")
			bundle := filepath.Join(private, "bundle")
			store := filepath.Join(dir, "policy.state")
			userCache := filepath.Join(private, "user-cache")
			env := append(os.Environ(), "XDG_CACHE_HOME="+userCache, "LOCALAPPDATA="+userCache, "HOME="+private)
			run := func(args ...string) []byte {
				t.Helper()
				cmd := exec.CommandContext(ctx, bin, args...)
				cmd.Env = env
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("rungv %v: %v\n%s", args, err, out)
				}
				return out
			}
			type policyReadback struct {
				Revision string          `json:"revision"`
				RulesV4  string          `json:"rules_v4"`
				RX       json.RawMessage `json:"qos_rx"`
			}
			get := func() policyReadback {
				t.Helper()
				var readback policyReadback
				if err := json.Unmarshal(run("net-policy", "get", "-control-socket", control), &readback); err != nil || readback.Revision == "" {
					t.Fatalf("invalid policy readback: %+v, %v", readback, err)
				}
				return readback
			}
			common := []string{
				"-backend=" + b.name, "-net=nat", "-cache-dir=" + cache, "-checkpoint-dir=" + bundle,
				"-control-socket=" + control, "--net-policy-state=" + store, "--net-policy-live", "-p", "127.0.0.1:0:8080",
			}
			args := append([]string{"run"}, common...)
			args = append(args, "--nat-iptables-file="+rules, "--nat-ip6tables-file="+closed, "--qos-tx=unlimited", "--qos-rx=unlimited", "-bin="+guest, "--", "-mode=net-policy")
			child := startPolicyGuest(t, ctx, bin, env, args)
			child.log.waitFor(t, 0, "READY:net\n", 30*time.Second, child.done)
			exchangeForwardedTCP(t, policyGuestPort(t, child.log), "ping-before-ckpt\n", "pong-before-ckpt\n")
			child.log.waitFor(t, 0, "PRE_CONN_DONE:net\n", 10*time.Second, child.done)
			run("checkpoint", "-control-socket", control, "-leave-running")

			before := get()
			if before.RulesV4 != allow || string(before.RX) != `"unlimited"` {
				t.Fatalf("seed readback = %+v, want permit rules and no RX limit", before)
			}
			const rate = "rate-bps=10000000,burst-bytes=131072,queue-bytes=524288"
			run("net-policy", "replace", "-control-socket", control, "--expected-revision", before.Revision, "--file", closed, "--file6", closed, "--qos-tx", "unlimited", "--qos-rx", rate)
			after := get()
			verifyRX := func(readback policyReadback) {
				t.Helper()
				var rx struct {
					RateBPS    uint64 `json:"rate_bps"`
					BurstBytes int    `json:"burst_bytes"`
					QueueBytes int    `json:"queue_bytes"`
				}
				if err := json.Unmarshal(readback.RX, &rx); err != nil || rx.RateBPS != 10000000 || rx.BurstBytes != 131072 || rx.QueueBytes != 524288 {
					t.Fatalf("RX = %s, %v; want %s", readback.RX, err, rate)
				}
			}
			verifyRX(after)
			if after.Revision == before.Revision || after.RulesV4 != deny {
				t.Fatalf("replace readback = %+v, want new revision and closed rules", after)
			}
			child.stop()

			restored := startPolicyGuest(t, ctx, bin, env, append([]string{"restore"}, common...))
			if _, err := io.WriteString(restored.stdin, "RESUME\n"); err != nil {
				t.Fatalf("resume restored guest: %v\n%s", err, restored.log.String())
			}
			restored.log.waitFor(t, 0, "READY_POST_CONN:net\n", 30*time.Second, restored.done)
			reopened := get()
			verifyRX(reopened)
			if reopened.Revision == after.Revision || reopened.RulesV4 != deny {
				t.Fatalf("restore readback = %+v, want a new instance revision with the committed rules and rate", reopened)
			}
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(policyGuestPort(t, restored.log)))
			conn, err := net.DialTimeout("tcp4", addr, 5*time.Second)
			if err != nil {
				t.Fatalf("dial the restored listener: %v", err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			_, err = io.WriteString(conn, "ping-after-restore\n")
			if err == nil {
				var byteReceived [1]byte
				if n, readErr := conn.Read(byteReceived[:]); n != 0 {
					t.Fatalf("older checkpoint permitted a policy-denied reply: %q", byteReceived[:n])
				} else {
					err = readErr
				}
			}
			var timeout net.Error
			if err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
				t.Fatalf("restored relay did not close a policy-denied connection: %v", err)
			}
		})
	}
}

type policyGuest struct {
	log   *outputLog
	done  chan struct{}
	stdin io.WriteCloser
	stop  func()
}

func startPolicyGuest(t *testing.T, ctx context.Context, bin string, env, args []string) policyGuest {
	t.Helper()
	guestCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(guestCtx, bin, args...)
	cmd.Env = env
	cmd.WaitDelay = 3 * time.Second
	log := newOutputLog()
	cmd.Stdout, cmd.Stderr = log, log
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start rungv %v: %v", args, err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := cmd.Wait(); err != nil && guestCtx.Err() == nil {
			_, _ = io.WriteString(log, "\nrungv: "+err.Error()+"\n")
		}
	}()
	stop := func() {
		cancel()
		<-done
	}
	t.Cleanup(stop)
	return policyGuest{log: log, done: done, stdin: stdin, stop: stop}
}

func policyGuestPort(t *testing.T, log *outputLog) int {
	t.Helper()
	const prefix = "rungv: publishing "
	for _, line := range strings.Split(log.String(), "\n") {
		if rest, ok := strings.CutPrefix(line, prefix); ok {
			address, _, _ := strings.Cut(rest, " -> ")
			if _, port, err := net.SplitHostPort(address); err == nil {
				if value, err := strconv.Atoi(port); err == nil && value > 0 {
					return value
				}
			}
		}
	}
	t.Fatalf("no bound TCP port in %s", log.String())
	return 0
}
