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

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/pkg/gvx"
)

const acceptPolicyRules = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
const dropPolicyRules = "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\nCOMMIT\n"

func startLivePolicySandbox(t *testing.T) (*controlEndpoint, string, string) {
	t.Helper()
	platform := requireCheckpointCLIPlatform(t)
	isolateControlTokenDir(t)
	guest, err := testelf.BuildGuestELF64(runtime.GOARCH, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(t.TempDir(), "guest.elf")
	if err := os.WriteFile(binaryPath, guest, 0o700); err != nil {
		t.Fatal(err)
	}
	rules := t.TempDir()
	path4, path6 := filepath.Join(rules, "rules.v4"), filepath.Join(rules, "rules.v6")
	writePolicyFixture(t, path4, acceptPolicyRules)
	writePolicyFixture(t, path6, dropPolicyRules)
	args := []string{
		"-bin=" + binaryPath, "-platform=" + platform, "-lockdown=false", "-cache-dir=" + t.TempDir(),
		"--net-policy-live", "-control-socket=tcp://127.0.0.1:0",
		"--nat-iptables-file=" + path4, "--nat-ip6tables-file=" + path6,
	}
	rc, code, done, stderr := parse(t, args...)
	if done || code != 0 {
		t.Fatalf("parse protected run: exit %d: %s", code, stderr)
	}
	var bindError bytes.Buffer
	ep, ok := bindControlSocket(&rc.cfg, rc.controlSocket, "rungv run", &bindError)
	if !ok {
		t.Fatalf("bind protected run: %s", &bindError)
	}
	t.Cleanup(ep.Cleanup)
	sb, err := gvx.New(t.Context(), rc.cfg)
	if err != nil {
		t.Fatalf("create protected sandbox: %v", err)
	}
	t.Cleanup(func() { _ = sb.Close() })
	t.Cleanup(startSandboxControl(t.Context(), sb, ep, rc.netPolicyLive, "", ""))
	return ep, path4, path6
}

func TestNetPolicyCLIReplacesLiveSandboxPolicy(t *testing.T) {
	ep, path4, path6 := startLivePolicySandbox(t)
	address := "-control-socket=tcp://" + ep.Listener.Addr().String()
	assertLivePolicy(t, address, acceptPolicyRules, dropPolicyRules, gvx.NetPolicyLimit{}, gvx.NetPolicyLimit{})

	// Check the live policy-only listener with the real legacy client.
	var out, diag bytes.Buffer
	if code := executeCLI(t.Context(), []string{"checkpoint", address}, nil, &out, &diag); code != 1 || !strings.Contains(diag.String(), "without -checkpoint-dir") {
		t.Fatalf("checkpoint on policy-only listener: exit %d, stderr %q", code, &diag)
	}

	limit := gvx.NetPolicyLimit{RateBPS: 10000000, BurstBytes: 131072, QueueBytes: 524288}
	const finite = "rate-bps=10000000,burst-bytes=131072,queue-bytes=524288"
	assertReplace := func(file4, file6, tx, rx string) {
		t.Helper()
		var committed map[string]json.RawMessage
		cliPolicyJSON(t, &committed, "replace", address, "--file="+file4, "--file6="+file6, "--qos-tx="+tx, "--qos-rx="+rx)
		if len(committed) != 1 || string(committed["ok"]) != "true" {
			t.Fatalf("replace reply = %v, want only ok: true", committed)
		}
	}

	assertReplace(path6, path4, finite, "unlimited")
	assertLivePolicy(t, address, dropPolicyRules, acceptPolicyRules, limit, gvx.NetPolicyLimit{})
	assertReplace(path4, path6, "unlimited", finite)
	assertLivePolicy(t, address, acceptPolicyRules, dropPolicyRules, gvx.NetPolicyLimit{}, limit)
}

func TestRunAndRestorePolicyFlags(t *testing.T) {
	rules := t.TempDir()
	path4, path6 := filepath.Join(rules, "rules.v4"), filepath.Join(rules, "rules.v6")
	writePolicyFixture(t, path4, acceptPolicyRules)
	writePolicyFixture(t, path6, dropPolicyRules)
	file4, file6 := "--nat-iptables-file="+path4, "--nat-ip6tables-file="+path6
	socket := "-control-socket=tcp://127.0.0.1:0"
	const finite = "rate-bps=10000000,burst-bytes=131072,queue-bytes=524288"
	limit := gvx.NetPolicyLimit{RateBPS: 10000000, BurstBytes: 131072, QueueBytes: 524288}
	for _, cmd := range []string{"run", "restore"} {
		t.Run(cmd, func(t *testing.T) {
			for _, tc := range []struct {
				name        string
				args        []string
				configured  bool
				wantTX      gvx.NetPolicyLimit
				wantRX      gvx.NetPolicyLimit
				wantFailure string
			}{
				{name: "ordinary NAT"},
				{name: "socket alone", args: []string{socket}},
				{name: "files with unlimited defaults", args: []string{file4, file6}, configured: true},
				{name: "only TX set", args: []string{file4, file6, "--qos-tx=" + finite}, configured: true, wantTX: limit},
				{name: "only RX set", args: []string{file4, file6, "--qos-rx=" + finite}, configured: true, wantRX: limit},
				{name: "live with files and socket", args: []string{file4, file6, "--net-policy-live", socket}, configured: true},
				{name: "missing IPv4 path", args: []string{file6}, wantFailure: "--nat-iptables-file"},
				{name: "empty IPv6 path", args: []string{file4, "--nat-ip6tables-file="}, wantFailure: "--nat-ip6tables-file"},
				{name: "limit without files", args: []string{"--qos-rx=unlimited"}, wantFailure: "--nat-iptables-file"},
				{name: "empty TX", args: []string{file4, file6, "--qos-tx="}, wantFailure: "--qos-tx"},
				{name: "empty RX", args: []string{file4, file6, "--qos-rx="}, wantFailure: "--qos-rx"},
				{name: "live without files", args: []string{"--net-policy-live", socket}, wantFailure: "--nat-iptables-file"},
				{name: "live without socket", args: []string{file4, file6, "--net-policy-live"}, wantFailure: "-control-socket"},
				{name: "non-NAT", args: []string{file4, file6, "--net=none"}, wantFailure: "unsupported_mode"},
				{name: "obsolete state flag", args: []string{"--net-policy-state=policy"}, wantFailure: "flag provided but not defined"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					var opts *gvx.NetPolicyOptions
					var code int
					var done bool
					var diag string
					if cmd == "run" {
						rc, status, ended, stderr := parse(t, append([]string{"-image=alpine"}, tc.args...)...)
						opts, code, done, diag = rc.cfg.NetPolicy, status, ended, stderr
					} else {
						var stderr bytes.Buffer
						rc, status, ended := parseRestoreArgs(append([]string{"-checkpoint-dir=bundle"}, tc.args...), nil, io.Discard, &stderr)
						opts, code, done, diag = rc.cfg.NetPolicy, status, ended, stderr.String()
					}
					if tc.wantFailure != "" {
						if !done || code != 2 || !strings.Contains(diag, tc.wantFailure) {
							t.Fatalf("exit = %d, done = %v, stderr = %q; want usage error containing %q", code, done, diag, tc.wantFailure)
						}
						return
					}
					if done || code != 0 || (opts != nil) != tc.configured {
						t.Fatalf("exit = %d, done = %v, policy configured = %v, stderr = %q; want success and policy configured = %v", code, done, opts != nil, diag, tc.configured)
					}
					if opts != nil && (opts.Policy.RulesV4 != acceptPolicyRules || opts.Policy.RulesV6 != dropPolicyRules || opts.Policy.TX != tc.wantTX || opts.Policy.RX != tc.wantRX) {
						t.Fatalf("policy = %+v; want both rule files, TX %+v, RX %+v", opts.Policy, tc.wantTX, tc.wantRX)
					}
				})
			}
		})
	}
}

func TestNetPolicyCLIReplaceRequiresCompleteConfiguration(t *testing.T) {
	rules := filepath.Join(t.TempDir(), "rules")
	writePolicyFixture(t, rules, acceptPolicyRules)
	settings := []string{"--file=" + rules, "--file6=" + rules, "--qos-tx=unlimited", "--qos-rx=unlimited"}
	for index, setting := range settings {
		name, _, _ := strings.Cut(setting, "=")
		t.Run(name, func(t *testing.T) {
			args := []string{"net-policy", "replace", "-control-socket=tcp://127.0.0.1:1"}
			args = append(args, settings[:index]...)
			args = append(args, settings[index+1:]...)
			var stdout, stderr bytes.Buffer
			if code := executeCLI(t.Context(), args, nil, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), name) {
				t.Fatalf("replace without %s: exit %d, stdout %q, stderr %q", name, code, &stdout, &stderr)
			}
		})
	}
	t.Run("obsolete revision flag", func(t *testing.T) {
		args := append([]string{"net-policy", "replace", "-control-socket=tcp://127.0.0.1:1", "--expected-revision=old"}, settings...)
		var stdout, stderr bytes.Buffer
		if code := executeCLI(t.Context(), args, nil, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "flag provided but not defined: -expected-revision") {
			t.Fatalf("replace with obsolete flag: exit %d, stdout %q, stderr %q", code, &stdout, &stderr)
		}
	})
}

func TestNetPolicyCLIRejectsInvalidReplies(t *testing.T) {
	isolateControlTokenDir(t)
	rules := filepath.Join(t.TempDir(), "rules")
	writePolicyFixture(t, rules, acceptPolicyRules)
	for _, tc := range []struct {
		name, op, reply string
	}{
		{"no acknowledgement", "replace", ""},
		{"obsolete revision reply", "replace", `{"revision":"old"}`},
		{"false acknowledgement", "replace", `{"ok":false}`},
		{"nonboolean acknowledgement", "replace", `{"ok":"true"}`},
		{"extra acknowledgement member", "replace", `{"ok":true,"revision":"old"}`},
		{"duplicate acknowledgement", "replace", `{"ok":true,"ok":true}`},
		{"failure mixed with success", "replace", `{"ok":true,"code":"invalid_policy"}`},
		{"success without policy", "get", `{"ok":true}`},
		{"policy with obsolete revision", "get", `{"rules_v4":"","rules_v6":"","qos_tx":"unlimited","qos_rx":"unlimited","revision":"old"}`},
		{"policy with missing limit", "get", `{"rules_v4":"","rules_v6":"","qos_tx":"unlimited"}`},
		{"policy with null limit", "get", `{"rules_v4":"","rules_v6":"","qos_tx":null,"qos_rx":"unlimited"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address := startPolicyReplyPeer(t, tc.reply)
			args := []string{"net-policy", tc.op, "-control-socket=tcp://" + address}
			if tc.op == "replace" {
				args = append(args, "--file="+rules, "--file6="+rules, "--qos-tx=unlimited", "--qos-rx=unlimited")
			}
			var stdout, stderr bytes.Buffer
			if code := executeCLI(t.Context(), args, nil, &stdout, &stderr); code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "incompatible_protocol") {
				t.Fatalf("CLI with invalid reply: exit %d, stdout %q, stderr %q", code, &stdout, &stderr)
			}
			const advice = "run net-policy get before retrying replace"
			if strings.Contains(stderr.String(), advice) != (tc.op == "replace") {
				t.Fatalf("CLI %s diagnostics = %q; want retry advice only for replace", tc.op, &stderr)
			}
		})
	}
}

func startPolicyReplyPeer(t *testing.T, reply string) string {
	t.Helper()
	ep, err := listenCheckpointSocket("tcp://127.0.0.1:0", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ep.Cleanup)
	done := make(chan error, 1)
	go func() {
		done <- func() error {
			conn, err := ep.Listener.Accept()
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return err
			}
			if _, err := readNetPolicyFrame(conn); err != nil || reply == "" {
				return err
			}
			frame := binary.BigEndian.AppendUint32([]byte("GVXNP/2\n"), uint32(len(reply)))
			_, err = conn.Write(append(frame, reply...))
			return err
		}()
	}()
	t.Cleanup(func() {
		_ = ep.Listener.Close()
		if err := <-done; err != nil {
			t.Errorf("reply peer exchange: %v", err)
		}
	})
	return ep.Listener.Addr().String()
}

func TestNetPolicyCLIRejectsInvalidUTF8RuleFile(t *testing.T) {
	rules := t.TempDir()
	path4, path6 := filepath.Join(rules, "rules.v4"), filepath.Join(rules, "rules.v6")
	writePolicyFixture(t, path4, acceptPolicyRules+"\xff")
	writePolicyFixture(t, path6, acceptPolicyRules)
	var stdout, stderr bytes.Buffer
	args := []string{
		"net-policy", "replace", "-control-socket=tcp://127.0.0.1:1",
		"--file=" + path4, "--file6=" + path6, "--qos-tx=unlimited", "--qos-rx=unlimited",
	}
	if code := executeCLI(t.Context(), args, nil, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "rule file is not UTF-8") {
		t.Fatalf("replace with non-UTF-8 rule file: exit %d, stdout %q, stderr %q", code, &stdout, &stderr)
	}
}

func TestProtectedControlRejectsGuestMountsOfEndpointFiles(t *testing.T) {
	isolateControlTokenDir(t)
	tokenDir, err := controlTokenDir()
	if err != nil {
		t.Fatal(err)
	}
	socketDir := shortSocketDir(t)
	rules := filepath.Join(t.TempDir(), "rules")
	writePolicyFixture(t, rules, acceptPolicyRules)
	cache := t.TempDir()
	for _, tc := range []struct {
		name, socket, workspace, private string
	}{
		{"TCP token sidecar", "tcp://127.0.0.1:0", tokenDir, "tcp-"},
		{"Unix path", filepath.Join(socketDir, "ctrl.sock"), socketDir, "ctrl.sock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{
				"run", "-image=unused.invalid/image", "--pull=never", "-lockdown=false", "-cache-dir=" + cache,
				"--nat-iptables-file=" + rules, "--nat-ip6tables-file=" + rules,
				"-control-socket=" + tc.socket, "-workspace=" + tc.workspace,
			}
			var stderr bytes.Buffer
			code := executeCLI(t.Context(), args, nil, io.Discard, &stderr)
			if code != 2 || !strings.Contains(stderr.String(), "private path") || !strings.Contains(stderr.String(), tc.private) || !strings.Contains(stderr.String(), "overlaps") {
				t.Fatalf("run with a mount containing the control endpoint: exit %d, stderr %q", code, &stderr)
			}
		})
	}
}

func TestProtectedControlPreservesExistingFilesAtTokenPath(t *testing.T) {
	isolateControlTokenDir(t)
	addr := freeLoopbackAddr(t)
	tokenPath, err := controlTokenPath("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatal(err)
	}
	const content = "existing host file"
	writePolicyFixture(t, tokenPath, content)
	ep, err := listenCheckpointSocket("tcp://"+addr, true)
	if ep != nil {
		_ = ep.Listener.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "verify stale control token") {
		t.Errorf("bind protected endpoint = %v, want stale token verification error", err)
	}
	if got, err := os.ReadFile(tokenPath); err != nil || string(got) != content {
		t.Fatalf("pre-existing host file = %q (%v), want %q", got, err, content)
	}
}

func writePolicyFixture(t *testing.T, path, rules string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
}

func cliPolicyJSON(t *testing.T, result any, args ...string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := executeCLI(t.Context(), append([]string{"net-policy"}, args...), nil, &stdout, &stderr); code != 0 {
		t.Fatalf("net-policy %s: exit %d, stderr %q", args[0], code, &stderr)
	}
	if err := json.Unmarshal(stdout.Bytes(), result); err != nil {
		t.Fatalf("decode CLI JSON: %v", err)
	}
}

func assertLivePolicy(t *testing.T, address, rules4, rules6 string, tx, rx gvx.NetPolicyLimit) {
	t.Helper()
	var got gvx.NetPolicyConfig
	cliPolicyJSON(t, &got, "get", address)
	if got.RulesV4 != rules4 || got.RulesV6 != rules6 || got.TX != tx || got.RX != rx {
		t.Fatalf("live policy = %+v, want IPv4 %q, IPv6 %q, TX %+v, RX %+v", got, rules4, rules6, tx, rx)
	}
}

func TestNetPolicyControlRejectsInvalidFramesAndCredentials(t *testing.T) {
	ep, _, _ := startLivePolicySandbox(t)
	addr := ep.Listener.Addr().String()
	valid := fmt.Sprintf(`{"op":"net-policy.get","token":%q}`, ep.Token)
	replace := fmt.Sprintf(`{"op":"net-policy.replace","token":%q,"rules_v4":%q,"rules_v6":%q,"qos_rx":"unlimited"`, ep.Token, dropPolicyRules, acceptPolicyRules)
	sensitiveRules := strings.TrimSuffix(acceptPolicyRules, "COMMIT\n") + "-A OUTPUT --" + ep.Token + " -j ACCEPT\nCOMMIT\n"
	rejectedRule := fmt.Sprintf(`{"op":"net-policy.replace","token":%q,"rules_v4":%q,"rules_v6":%q,"qos_tx":"unlimited","qos_rx":"unlimited"}`, ep.Token, sensitiveRules, dropPolicyRules)
	for _, tc := range []struct {
		name, tag, body, code, option string
		declared                      uint32
	}{
		{name: "old version", tag: "GVXNP/1\n", code: "incompatible_protocol"},
		{name: "frame limit", declared: 1048577, code: "too_large"},
		{name: "zero length", code: "invalid_policy"},
		{name: "missing token", body: `{"op":"net-policy.get"}`, code: "unauthorized"},
		{name: "wrong token", body: `{"op":"net-policy.get","token":"incorrect"}`, code: "unauthorized"},
		{name: "malformed token", body: `{"op":"net-policy.get","token":true}`, code: "unauthorized"},
		{name: "duplicate key", body: valid[:len(valid)-1] + `,"op":"net-policy.get"}`, code: "invalid_policy"},
		{name: "invalid UTF-8", body: `{"op":"net-policy.get","token":"` + "\xff" + `"}`, code: "invalid_policy"},
		{name: "truncated frame", body: valid, declared: uint32(len(valid) + 1), code: "invalid_policy"},
		{name: "unknown operation", body: fmt.Sprintf(`{"op":"checkpoint","token":%q}`, ep.Token), code: "invalid_policy"},
		{name: "unknown key", body: valid[:len(valid)-1] + `,"dir":"checkpoint"}`, code: "invalid_policy"},
		{name: "replace field on get", body: valid[:len(valid)-1] + `,"qos_tx":null}`, code: "invalid_policy"},
		{name: "trailing JSON", body: valid + `{}`, code: "invalid_policy"},
		{name: "missing limit", body: replace + `}`, code: "invalid_policy"},
		{name: "null limit", body: replace + `,"qos_tx":null}`, code: "invalid_policy"},
		{name: "duplicate limit key", body: replace + `,"qos_tx":{"rate_bps":100,"rate_bps":100,"burst_bytes":65537,"queue_bytes":65537}}`, code: "invalid_policy"},
		{name: "obsolete replacement field", body: replace + `,"qos_tx":"unlimited","expected_revision":"a"}`, code: "invalid_policy"},
		{name: "redact token in invalid rule", body: rejectedRule, code: "unsupported_rule", option: "--[redacted]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := dialRaw(t, "tcp", addr)
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			length := tc.declared
			if length == 0 {
				length = uint32(len(tc.body))
			}
			tag := tc.tag
			if tag == "" {
				tag = "GVXNP/2\n"
			}
			frame := binary.BigEndian.AppendUint32([]byte(tag), length)
			if _, err := conn.Write(append(frame, tc.body...)); err != nil {
				t.Fatalf("write request: %v", err)
			}
			if length > uint32(len(tc.body)) && tc.code == "invalid_policy" {
				if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
					t.Fatalf("finish sending partial request: %v", err)
				}
			}
			payload, err := readNetPolicyFrame(conn)
			if err != nil {
				t.Fatalf("read framed rejection: %v", err)
			}
			if bytes.Contains(payload, []byte(ep.Token)) {
				t.Fatal("rejected request disclosed a token")
			}
			var response map[string]json.RawMessage
			if err := json.Unmarshal(payload, &response); err != nil || string(response["code"]) != fmt.Sprintf(`%q`, tc.code) {
				t.Fatalf("response = %s (%v), want code %q", payload, err, tc.code)
			}
			if response["revision"] != nil || response["rules_v4"] != nil || response["ok"] != nil {
				t.Fatal("rejected request disclosed a policy or reported success")
			}
			if tc.option != "" && string(response["option"]) != fmt.Sprintf(`%q`, tc.option) {
				t.Fatalf("option = %s, want %q", response["option"], tc.option)
			}
		})
	}
	assertLivePolicy(t, "-control-socket=tcp://"+addr, acceptPolicyRules, dropPolicyRules, gvx.NetPolicyLimit{}, gvx.NetPolicyLimit{})
}

func TestNetPolicyCLIRejectsCheckpointOnlyListener(t *testing.T) {
	isolateControlTokenDir(t)
	addr := freeLoopbackAddr(t)
	cp := &fakeCheckpointer{}
	startFakeControl(t, "tcp://"+addr, cp)
	var stdout, stderr bytes.Buffer
	address := "-control-socket=tcp://" + addr
	if code := executeCLI(t.Context(), []string{"net-policy", "get", address}, nil, &stdout, &stderr); code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "policy_disabled") {
		t.Fatalf("policy get on checkpoint-only listener: exit %d, stdout %q, stderr %q", code, &stdout, &stderr)
	}
	if got := cp.calls.Load(); got != 0 {
		t.Fatalf("policy request invoked checkpoint %d times", got)
	}
	if code := executeCLI(t.Context(), []string{"checkpoint", address}, nil, &stdout, &stderr); code != 0 || cp.calls.Load() != 1 {
		t.Fatalf("legacy request: exit %d, checkpoint calls %d, stderr %q", code, cp.calls.Load(), &stderr)
	}
}

func TestNetPolicyCLIIncompatibleWithLegacyControlDecoder(t *testing.T) {
	isolateControlTokenDir(t)
	ep, err := listenCheckpointSocket("tcp://127.0.0.1:0", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ep.Cleanup)
	legacyResult := make(chan error, 1)
	var legacy sync.WaitGroup
	legacy.Add(1)
	go func() {
		defer legacy.Done()
		conn, err := ep.Listener.Accept()
		if err != nil {
			legacyResult <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		var req checkpointControlRequest
		err = json.NewDecoder(io.LimitReader(conn, 64<<10)).Decode(&req)
		if err != nil {
			_ = json.NewEncoder(conn).Encode(checkpointControlResponse{Error: "decode checkpoint request"})
		}
		legacyResult <- err
	}()
	t.Cleanup(func() {
		_ = ep.Listener.Close()
		legacy.Wait()
	})

	var stdout, stderr bytes.Buffer
	address := "-control-socket=tcp://" + ep.Listener.Addr().String()
	if code := executeCLI(t.Context(), []string{"net-policy", "get", address}, nil, &stdout, &stderr); code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "incompatible_protocol") {
		t.Fatalf("policy get on old server: exit %d, stdout %q, stderr %q", code, &stdout, &stderr)
	}
	select {
	case err := <-legacyResult:
		if _, ok := err.(*json.SyntaxError); !ok {
			t.Fatalf("legacy checkpoint decoder = %v, want a syntax error before dispatch", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("legacy server did not receive the policy request")
	}
}
