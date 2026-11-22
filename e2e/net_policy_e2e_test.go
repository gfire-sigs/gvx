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
	"bytes"
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

func TestE2ENATPolicyCheckpointUsesOperatorRulesOnRestore(t *testing.T) {
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			bin := toolPath(t, rungvPkg)
			guest := acceptprog.BuildCheckpointProbe(t, hostArch())
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()

			private := t.TempDir()
			const filter = "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\n"
			const permitTCP = "-A INPUT -p tcp -j ACCEPT\n-A OUTPUT -p tcp -j ACCEPT\n"
			const allow = filter + permitTCP + "COMMIT\n"
			const deny = filter + "COMMIT\n"
			writeRules := func(name, rules string) string {
				t.Helper()
				path := filepath.Join(private, name)
				if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			}
			initial4 := writeRules("initial.v4", allow)
			initial6 := writeRules("initial.v6", deny)

			control := "tcp://" + freeLoopbackControlSocketAddr(t)
			cache := filepath.Join(private, "cache")
			bundle := filepath.Join(private, "bundle")
			userCache := filepath.Join(private, "user-cache")
			env := append(os.Environ(), "XDG_CACHE_HOME="+userCache, "LOCALAPPDATA="+userCache, "HOME="+private)
			command := func(args ...string) *exec.Cmd {
				cmd := exec.CommandContext(ctx, bin, args...)
				cmd.Env = env
				return cmd
			}
			run := func(args ...string) []byte {
				t.Helper()
				out, err := command(args...).CombinedOutput()
				if err != nil {
					t.Fatalf("rungv %v: %v\n%s", args, err, out)
				}
				return out
			}
			get := func(socket, wantV4, wantV6 string, wantTX, wantRX policyLimitReadback) {
				t.Helper()
				out := run("net-policy", "get", "-control-socket", socket)
				var got struct {
					RulesV4 string          `json:"rules_v4"`
					RulesV6 string          `json:"rules_v6"`
					TX      json.RawMessage `json:"qos_tx"`
					RX      json.RawMessage `json:"qos_rx"`
				}
				decodePolicyReadback(t, out, &got)
				if got.RulesV4 != wantV4 || got.RulesV6 != wantV6 {
					t.Fatalf("get policy rules = (%q, %q), want (%q, %q)", got.RulesV4, got.RulesV6, wantV4, wantV6)
				}
				requirePolicyLimit(t, "TX", got.TX, wantTX)
				requirePolicyLimit(t, "RX", got.RX, wantRX)
			}
			common := []string{
				"-backend=" + b.name, "-net=nat", "-cache-dir=" + cache, "-checkpoint-dir=" + bundle,
				"-p", "127.0.0.1:0:8080",
			}
			args := append([]string{"run"}, common...)
			args = append(args, "-control-socket="+control, "--net-policy-live",
				"--nat-iptables-file="+initial4, "--nat-ip6tables-file="+initial6, "-bin="+guest, "--", "-mode=net-policy")
			child := startPolicyGuest(t, ctx, bin, env, args)
			child.log.waitFor(t, 0, "READY:net\n", 30*time.Second, child.done)
			port := policyGuestPort(t, child.log)
			var unlimited policyLimitReadback
			get(control, allow, deny, unlimited, unlimited)
			exchangeForwardedTCP(t, port, "ping-before-ckpt\n", "pong-before-ckpt\n")
			child.log.waitFor(t, 0, "PRE_CONN_DONE:net\n", 10*time.Second, child.done)

			// The guest service keeps port 8080 if restore binds a different host port.
			const liveRules = filter +
				"-A OUTPUT -d 10.0.2.15 -p tcp -m tcp --dport 8080 -j DROP\n" +
				"-A OUTPUT -d 127.0.0.1 -p tcp -m tcp --dport 8080 -j DROP\n" +
				permitTCP + "COMMIT\n"
			live4 := writeRules("live.v4", liveRules)
			live6 := writeRules("live.v6", allow)
			const rate = "rate-bps=10000000,burst-bytes=131072,queue-bytes=524288"
			limited := policyLimitReadback{RateBPS: 10000000, BurstBytes: 131072, QueueBytes: 524288}
			out := run("net-policy", "replace", "-control-socket", control, "--file", live4, "--file6", live6,
				"--qos-tx", "unlimited", "--qos-rx", rate)
			var replaced struct {
				OK bool `json:"ok"`
			}
			decodePolicyReadback(t, out, &replaced)
			if !replaced.OK {
				t.Fatalf("replace policy response = %s, want {\"ok\":true}", out)
			}
			get(control, liveRules, allow, unlimited, limited)
			for _, f := range []struct{ path, rules string }{
				{initial4, allow}, {initial6, deny}, {live4, liveRules}, {live6, allow},
			} {
				got, err := os.ReadFile(f.path)
				if err != nil || string(got) != f.rules {
					t.Errorf("rule file %s after live replace = (%q, %v), want %q", f.path, got, err, f.rules)
				}
			}

			run("checkpoint", "-control-socket", control, "-leave-running")
			resumePolicyGuest(t, child)
			requirePolicyTCPDenied(t, port)
			child.stop()

			args = append([]string{"restore"}, common...)
			out, err := command(args...).CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || !strings.Contains(string(out), "policy_required:") {
				t.Fatalf("restore without policy = (%v, %q), want policy_required", err, out)
			}

			restore4 := writeRules("restore.v4", deny)
			restore6 := writeRules("restore.v6", deny)
			restoreControl := "tcp://" + freeLoopbackControlSocketAddr(t)
			args = append(args, "-control-socket="+restoreControl, "--net-policy-live",
				"--nat-iptables-file="+restore4, "--nat-ip6tables-file="+restore6, "--qos-tx="+rate)
			restored := startPolicyGuest(t, ctx, bin, env, args)
			resumePolicyGuest(t, restored)
			get(restoreControl, deny, deny, limited, unlimited)
			restoredPort := policyGuestPort(t, restored.log)
			requirePolicyTCPDenied(t, restoredPort)
			run("net-policy", "replace", "-control-socket", restoreControl, "--file", initial4, "--file6", initial6,
				"--qos-tx", rate, "--qos-rx", "unlimited")
			exchangeForwardedTCP(t, restoredPort, "ping-after-restore\n", "pong-after-restore\n")
			restored.log.waitFor(t, 0, "VERIFIED:net\n", 10*time.Second, restored.done)
		})
	}
}

type policyLimitReadback struct {
	RateBPS    uint64 `json:"rate_bps"`
	BurstBytes int    `json:"burst_bytes"`
	QueueBytes int    `json:"queue_bytes"`
}

func decodePolicyReadback(t *testing.T, out []byte, dst any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(out))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		t.Fatalf("decode policy response %q: %v", out, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("unexpected data after policy response %q: %v", out, err)
	}
}

func requirePolicyLimit(t *testing.T, dir string, raw json.RawMessage, want policyLimitReadback) {
	t.Helper()
	if want == (policyLimitReadback{}) {
		if string(raw) != `"unlimited"` {
			t.Errorf("policy %s limit = %s, want unlimited", dir, raw)
		}
		return
	}
	var got policyLimitReadback
	if err := json.Unmarshal(raw, &got); err != nil || got != want {
		t.Errorf("policy %s limit = (%s, %v), want %+v", dir, raw, err, want)
	}
}

func resumePolicyGuest(t *testing.T, child policyGuest) {
	t.Helper()
	if _, err := io.WriteString(child.stdin, "RESUME\n"); err != nil {
		t.Fatalf("resume guest: %v\n%s", err, child.log.String())
	}
	child.log.waitFor(t, 0, "READY_POST_CONN:net\n", 30*time.Second, child.done)
}

func requirePolicyTCPDenied(t *testing.T, port int) {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp4", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forwarded port %s: %v", addr, err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(conn, "ping-after-restore\n"); err == nil {
		var reply [1]byte
		n, readErr := conn.Read(reply[:])
		if n != 0 {
			t.Fatalf("live policy allowed a reply on denied port %s: %q", addr, reply[:n])
		}
		err = readErr
	}
	var timeout net.Error
	if err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
		t.Fatalf("want live policy to close the connection on %s, got %v", addr, err)
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
