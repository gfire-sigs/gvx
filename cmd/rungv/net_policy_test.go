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
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/gvx/control"
)

const testNATPolicy = `{"egress":{"default":"deny","rules":[{"action":"allow","cidr":"203.0.113.0/24","protocol":"tcp","ports":"443"}]},"ingress":{"default":"allow"}}`

func writeNATPolicyFile(t *testing.T, contents string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "policy file.json")
	if err := os.WriteFile(file, []byte(contents), 0o600); err != nil {
		t.Fatalf("write NAT policy: %v", err)
	}
	return file
}

func TestRunAndRestoreLoadNATPolicyFile(t *testing.T) {
	file := writeNATPolicyFile(t, testNATPolicy)
	run, code, done, stderr := parse(t, "-nat-policy-file", file, "--network=bridge", "-image=x")
	if done || code != 0 {
		t.Fatalf("parse run policy: code=%d, done=%t, stderr=%q", code, done, stderr)
	}
	assertConfiguredNATPolicy(t, run.cfg)

	var restoreErr bytes.Buffer
	restore, code, done := parseRestoreArgs([]string{"-checkpoint-dir", t.TempDir(), "--nat-policy-file", file}, nil, io.Discard, &restoreErr)
	if done || code != 0 {
		t.Fatalf("parse restore policy without network mode: code=%d, done=%t, stderr=%q", code, done, restoreErr.String())
	}
	assertConfiguredNATPolicy(t, restore.cfg)
}

func assertConfiguredNATPolicy(t *testing.T, cfg gvx.Config) {
	t.Helper()
	if cfg.NetworkMode != gvx.NetModeNAT || cfg.NetworkPolicy == nil {
		t.Fatalf("network mode = %q, policy = %+v; want NAT with a policy", cfg.NetworkMode, cfg.NetworkPolicy)
	}
	p := cfg.NetworkPolicy
	if p.Egress.Default != "deny" || p.Ingress.Default != "allow" || len(p.Egress.Rules) != 1 || p.Egress.Rules[0].Ports != "443" {
		t.Fatalf("policy = %+v, want egress deny with a port 443 exception and ingress allow", p)
	}
}

func TestNATPolicyFileRejectsNonNATNetworkMode(t *testing.T) {
	file := writeNATPolicyFile(t, testNATPolicy)
	for _, args := range [][]string{
		{"run", "--nat-policy-file", file, "-net=none", "-image=x"},
		{"restore", "--nat-policy-file", file, "--network=wg", "-checkpoint-dir", t.TempDir()},
		{"restore", "--nat-policy-file", file, "-net=", "-checkpoint-dir", t.TempDir()},
	} {
		res := runCLIArgs(t, nil, args...)
		if res.code != 2 || !strings.Contains(res.stderr, "requires -net=nat") {
			t.Errorf("%v exited %d with stderr %q; want a NAT mode usage error", args, res.code, res.stderr)
		}
	}
}

func TestNATPolicyFileRejectsInvalidDocuments(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
	}{
		{"null policy", "null"},
		{"unknown field", `{"egress":{"default":"allow","dflt":"deny"},"ingress":{"default":"allow"}}`},
		{"trailing JSON", testNATPolicy + " {}"},
		{"oversize whitespace", testNATPolicy + strings.Repeat(" ", 64<<10)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := writeNATPolicyFile(t, tc.json)
			_, code, done, stderr := parse(t, "--nat-policy-file", file, "-image=x")
			if !done || code != 2 || !strings.Contains(stderr, "--nat-policy-file:") {
				t.Errorf("parse %s policy: code=%d, done=%t, stderr=%q; want policy file usage error", tc.name, code, done, stderr)
			}
		})
	}
}

func TestNetPolicyReadOnlyAllowsGetButDeniesReplace(t *testing.T) {
	caps := control.FilterCapabilities([]string{control.CapNATPolicyRead, control.CapNATPolicyWrite}, control.PolicyReadOnly, nil)
	ep := startMockCLIServer(t, caps, func(_ context.Context, stream *control.Stream, req control.RequestEnvelope) error {
		if req.Method != control.MethodNATPolicyGet {
			t.Errorf("readonly server dispatched %q", req.Method)
		}
		return stream.Reply(control.NATPolicyState{Policy: json.RawMessage("null")})
	})
	res := runCLIArgs(t, nil, "net-policy", "get", "-S", ep.Address, "--token", ep.Token).mustSucceed(t, "net-policy get")
	if got := strings.TrimSpace(res.stdout); got != "null" {
		t.Errorf("net-policy get with no installed policy = %q, want JSON null", got)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := control.Dial(ctx, control.DialOptions{Endpoint: ep.Address, Token: ep.Token})
	if err != nil {
		t.Fatalf("dial readonly control server: %v", err)
	}
	defer client.Close()
	if err := client.Call(ctx, control.MethodNATPolicySet, control.NATPolicyState{Policy: json.RawMessage(testNATPolicy)}, nil); !control.IsCode(err, control.CodeForbiddenByPolicy) {
		t.Errorf("readonly net.policy_set = %v, want FORBIDDEN_BY_POLICY", err)
	}
}

func TestNetPolicyReplaceSendsPolicyDocument(t *testing.T) {
	file := writeNATPolicyFile(t, testNATPolicy)
	ep := startMockCLIServer(t, []string{control.CapNATPolicyWrite}, func(_ context.Context, stream *control.Stream, req control.RequestEnvelope) error {
		if req.Method != control.MethodNATPolicySet {
			t.Errorf("replace sent method %q, want net.policy_set", req.Method)
		}
		var state control.NATPolicyState
		if err := json.Unmarshal(req.Params, &state); err != nil {
			return err
		}
		return stream.Reply(state)
	})
	res := runCLIArgs(t, nil, "net-policy", "replace", "-S", ep.Address, "--token", ep.Token, "--file", file).mustSucceed(t, "net-policy replace")
	p, err := gvx.ParseNATPolicy(strings.NewReader(res.stdout))
	if err != nil || p.Egress.Default != "deny" || p.Ingress.Default != "allow" || len(p.Egress.Rules) != 1 || p.Egress.Rules[0].CIDR != "203.0.113.0/24" {
		t.Fatalf("replacement policy JSON = %q, err=%v; want both directions and the selected CIDR", res.stdout, err)
	}
}

func TestNetPolicyGetAtFileSizeLimitCanBeReused(t *testing.T) {
	const (
		limit = 64 << 10
		start = `{"egress":{"default":"deny","rules":[`
		rule  = `{"action":"allow","cidr":"203.0.113.0/24","protocol":"tcp","ports":"443"},`
		end   = `]},"ingress":{"default":"allow"}}`
	)
	ruleBytes := limit - len(start) - len(end) + 1
	rules := strings.Repeat(rule, ruleBytes/len(rule))
	policy := start + strings.TrimSuffix(strings.Replace(rules, `"443"`, `"8443"`, ruleBytes%len(rule)), ",") + end
	if _, err := gvx.ParseNATPolicy(strings.NewReader(policy)); err != nil || len(policy) != limit {
		t.Fatalf("fixture size = %d, parse error = %v; want valid %d-byte policy", len(policy), err, limit)
	}

	ep := startMockCLIServer(t, []string{control.CapNATPolicyRead}, func(_ context.Context, stream *control.Stream, _ control.RequestEnvelope) error {
		return stream.Reply(control.NATPolicyState{Policy: json.RawMessage(policy)})
	})
	res := runCLIArgs(t, nil, "net-policy", "get", "-S", ep.Address, "--token", ep.Token).mustSucceed(t, "net-policy get")
	if _, err := gvx.ParseNATPolicy(strings.NewReader(res.stdout)); err != nil {
		t.Errorf("get produced a %d-byte policy that cannot be reused: %v", len(res.stdout), err)
	}
}

func TestNetPolicyOldPeerDoesNotAdvertisePolicy(t *testing.T) {
	ep := startMockCLIServer(t, []string{control.CapPing}, func(_ context.Context, _ *control.Stream, req control.RequestEnvelope) error {
		t.Errorf("old peer dispatched unsupported method %q", req.Method)
		return control.NewError(control.CodeUnsupported, "old peer")
	})
	res := runCLIArgs(t, nil, "net-policy", "get", "-S", ep.Address, "--token", ep.Token)
	if res.code != 126 || res.stdout != "" || !strings.Contains(res.stderr, "did not advertise") || !strings.Contains(res.stderr, control.CapNATPolicyRead) {
		t.Errorf("net-policy get against old peer exited %d; stdout=%q, stderr=%q; want a missing read capability error", res.code, res.stdout, res.stderr)
	}
}

func TestDisableNetPolicyLeavesNetDialAvailable(t *testing.T) {
	group := []string{"net.policy"}
	if err := control.ValidateDisableList(group); err != nil {
		t.Fatalf("validate net.policy capability group: %v", err)
	}
	caps := control.FilterCapabilities([]string{control.CapNetDial, control.CapNATPolicyRead, control.CapNATPolicyWrite}, control.PolicyDefault, group)
	if !control.MethodAllowed(control.MethodNetDial, caps) || control.MethodAllowed(control.MethodNATPolicyGet, caps) || control.MethodAllowed(control.MethodNATPolicySet, caps) {
		t.Errorf("capabilities after disabling net.policy = %v, want only net.dial", caps)
	}
}
