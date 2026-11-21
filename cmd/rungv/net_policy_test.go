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

func TestNetPolicyCLIReplacesLiveSandboxPolicy(t *testing.T) {
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
	storeDir, err := filepath.EvalSymlinks(shortSocketDir(t))
	if err != nil {
		t.Fatal(err)
	}
	rules := t.TempDir()
	seed4, seed6 := filepath.Join(rules, "seed.v4"), filepath.Join(rules, "seed.v6")
	writePolicyFixture(t, seed4, acceptPolicyRules)
	writePolicyFixture(t, seed6, dropPolicyRules)
	args := []string{
		"-bin=" + binaryPath, "-platform=" + platform, "-lockdown=false", "-cache-dir=" + t.TempDir(),
		"--net-policy-state=" + filepath.Join(storeDir, "policy"), "--net-policy-live", "-control-socket=tcp://127.0.0.1:0",
		"--nat-iptables-file=" + seed4, "--nat-ip6tables-file=" + seed6, "--qos-tx=unlimited", "--qos-rx=unlimited",
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
	addr := ep.Listener.Addr().(*net.TCPAddr).AddrPort()
	if got := rc.cfg.NetPolicy.ControlAddress; got != addr || got.Port() == 0 {
		t.Fatalf("control address supplied to SDK = %s, want actual listener address %s", got, addr)
	}
	sb, err := gvx.New(t.Context(), rc.cfg)
	if err != nil {
		t.Fatalf("create protected sandbox: %v", err)
	}
	t.Cleanup(func() { _ = sb.Close() })
	t.Cleanup(startSandboxControl(t.Context(), sb, ep, rc.netPolicyLive, "", ""))
	address := "-control-socket=tcp://" + addr.String()

	var initial gvx.NetPolicySnapshot
	cliPolicyJSON(t, &initial, "get", address)
	if initial.Revision == "" || initial.RulesV4 != acceptPolicyRules || initial.RulesV6 != dropPolicyRules || initial.TX.RateBPS != 0 || initial.RX.RateBPS != 0 {
		t.Fatalf("initial snapshot = %+v, want seeded policy and a revision", initial)
	}

	// Check the live policy-only listener with the real legacy client.
	var out, diag bytes.Buffer
	if code := executeCLI(t.Context(), []string{"checkpoint", address}, nil, &out, &diag); code != 1 || !strings.Contains(diag.String(), "without -checkpoint-dir") {
		t.Fatalf("checkpoint on policy-only listener: exit %d, stderr %q", code, &diag)
	}

	replace := []string{
		"replace", address, "--expected-revision=" + initial.Revision, "--file=" + seed6, "--file6=" + seed4,
		"--qos-tx=rate-bps=10000000,burst-bytes=131072,queue-bytes=524288", "--qos-rx=unlimited",
	}
	var committed netPolicyRevision
	cliPolicyJSON(t, &committed, replace...)
	if committed.Revision == "" || committed.Revision == initial.Revision {
		t.Fatalf("replacement revision = %q, want new revision (old %q)", committed.Revision, initial.Revision)
	}
	out.Reset()
	diag.Reset()
	if code := executeCLI(t.Context(), append([]string{"net-policy"}, replace...), nil, &out, &diag); code != 1 || out.Len() != 0 || !strings.Contains(diag.String(), "revision_conflict") {
		t.Fatalf("stale replacement: exit %d, stdout %q, stderr %q", code, &out, &diag)
	}
	var after gvx.NetPolicySnapshot
	cliPolicyJSON(t, &after, "get", address)
	if after.Revision != committed.Revision || after.RulesV4 != dropPolicyRules || after.RulesV6 != acceptPolicyRules || after.TX.RateBPS != 10000000 || after.TX.QueueBytes != 524288 || after.RX.RateBPS != 0 {
		t.Fatalf("final snapshot = %+v, want replacement revision %q and rules/limits", after, committed.Revision)
	}
}

func TestNetPolicyCLIRejectsInvalidUTF8RuleFile(t *testing.T) {
	rules := t.TempDir()
	path4, path6 := filepath.Join(rules, "rules.v4"), filepath.Join(rules, "rules.v6")
	writePolicyFixture(t, path4, acceptPolicyRules+"\xff")
	writePolicyFixture(t, path6, acceptPolicyRules)
	var stdout, stderr bytes.Buffer
	args := []string{
		"net-policy", "replace", "-control-socket=tcp://127.0.0.1:1", "--expected-revision=rev",
		"--file=" + path4, "--file6=" + path6, "--qos-tx=unlimited", "--qos-rx=unlimited",
	}
	if code := executeCLI(t.Context(), args, nil, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "rule file is not UTF-8") {
		t.Fatalf("replace with non-UTF-8 rule file: exit %d, stdout %q, stderr %q", code, &stdout, &stderr)
	}
}

func TestProtectedControlPreservesExistingFilesAtTokenPath(t *testing.T) {
	isolateControlTokenDir(t)
	for _, scenario := range []string{"state path", "state hard link", "not a credential"} {
		t.Run(scenario, func(t *testing.T) {
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
			t.Cleanup(func() { _ = os.Remove(tokenPath) })
			statePath := filepath.Join(t.TempDir(), "state")
			want := "state_mismatch"
			switch scenario {
			case "state path":
				statePath = tokenPath
			case "state hard link":
				if err := os.Link(tokenPath, statePath); err != nil {
					t.Fatal(err)
				}
			case "not a credential":
				want = "verify stale control token"
			}
			ep, err := listenCheckpointSocket("tcp://"+addr, statePath)
			if ep != nil {
				_ = ep.Listener.Close()
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("bind protected endpoint = %v, want %s", err, want)
			}
			if got, err := os.ReadFile(tokenPath); err != nil || string(got) != content {
				t.Fatalf("pre-existing host file = %q (%v), want %q", got, err, content)
			}
		})
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

func TestNetPolicyControlRejectsInvalidFramesAndCredentials(t *testing.T) {
	isolateControlTokenDir(t)
	ep, err := listenCheckpointSocket("tcp://127.0.0.1:0", filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ep.Cleanup)
	policy := &unexpectedPolicyAccess{t: t}
	t.Cleanup(serveControl(t.Context(), &controlServer{policy: policy, token: ep.Token}, ep.Listener.Accept, ep.Listener))
	addr := ep.Listener.Addr().String()
	valid := fmt.Sprintf(`{"op":"net-policy.get","token":%q}`, ep.Token)
	replace := fmt.Sprintf(`{"op":"net-policy.replace","token":%q,"expected_revision":"a","rules_v4":"","rules_v6":"","qos_rx":"unlimited"`, ep.Token)
	for _, tc := range []struct {
		name, tag, body, code string
		declared              uint32
	}{
		{name: "bad version", tag: "GVXNP/2\n", code: "incompatible_protocol"},
		{name: "frame limit", tag: "GVXNP/1\n", declared: 1048577, code: "too_large"},
		{name: "zero length", tag: "GVXNP/1\n", code: "invalid_policy"},
		{name: "missing token", tag: "GVXNP/1\n", body: `{"op":"net-policy.get"}`, code: "unauthorized"},
		{name: "invalid token", tag: "GVXNP/1\n", body: `{"op":"net-policy.get","token":"incorrect"}`, code: "unauthorized"},
		{name: "duplicate key", tag: "GVXNP/1\n", body: valid[:len(valid)-1] + `,"op":"net-policy.get"}`, code: "invalid_policy"},
		{name: "invalid UTF-8", tag: "GVXNP/1\n", body: valid[:len(valid)-1] + ",\"rules_v4\":\"\xff\"}", code: "invalid_policy"},
		{name: "truncated frame", tag: "GVXNP/1\n", body: valid, declared: uint32(len(valid) + 1), code: "invalid_policy"},
		{name: "unknown key", tag: "GVXNP/1\n", body: valid[:len(valid)-1] + `,"dir":"checkpoint"}`, code: "invalid_policy"},
		{name: "replace field on get", tag: "GVXNP/1\n", body: valid[:len(valid)-1] + `,"qos_tx":null}`, code: "invalid_policy"},
		{name: "trailing JSON", tag: "GVXNP/1\n", body: valid + `{}`, code: "invalid_policy"},
		{name: "missing limit", tag: "GVXNP/1\n", body: replace + `}`, code: "invalid_policy"},
		{name: "null limit", tag: "GVXNP/1\n", body: replace + `,"qos_tx":null}`, code: "invalid_policy"},
		{name: "duplicate limit key", tag: "GVXNP/1\n", body: replace + `,"qos_tx":{"rate_bps":100,"rate_bps":100,"burst_bytes":65537,"queue_bytes":65537}}`, code: "invalid_policy"},
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
			frame := binary.BigEndian.AppendUint32([]byte(tc.tag), length)
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
			var response map[string]json.RawMessage
			if err := json.Unmarshal(payload, &response); err != nil || string(response["code"]) != fmt.Sprintf(`%q`, tc.code) {
				t.Fatalf("response = %s (%v), want code %q", payload, err, tc.code)
			}
			if response["revision"] != nil || response["rules_v4"] != nil || bytes.Contains(payload, []byte(ep.Token)) {
				t.Fatal("rejected request disclosed a token or policy state")
			}
		})
	}
}

type unexpectedPolicyAccess struct{ t *testing.T }

func (p *unexpectedPolicyAccess) NetPolicy() (gvx.NetPolicySnapshot, error) {
	p.t.Error("rejected request read the policy")
	return gvx.NetPolicySnapshot{}, fmt.Errorf("unexpected read")
}

func (p *unexpectedPolicyAccess) ReplaceNetPolicy(string, gvx.NetPolicyConfig) (gvx.NetPolicySnapshot, error) {
	p.t.Error("rejected request replaced the policy")
	return gvx.NetPolicySnapshot{}, fmt.Errorf("unexpected replacement")
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
	ep, err := listenCheckpointSocket("tcp://127.0.0.1:0", filepath.Join(t.TempDir(), "state"))
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
