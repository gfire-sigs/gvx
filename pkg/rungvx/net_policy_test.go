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

package rungvx

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
const testNATPolicyYAML = `egress:
  default: deny
  rules:
    - action: allow
      cidr: 203.0.113.0/24
      protocol: tcp
      ports: "443"
ingress:
  default: allow
`

func writeNATPolicyFile(t *testing.T, suffix, contents string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "policy file"+suffix)
	if err := os.WriteFile(file, []byte(contents), 0o600); err != nil {
		t.Fatalf("write NAT policy %q: %v", file, err)
	}
	return file
}

func TestRunAndRestoreLoadNATPolicyFile(t *testing.T) {
	for _, tc := range []struct {
		name     string
		suffix   string
		contents string
	}{
		{"JSON", ".json", testNATPolicy},
		{"YAML", ".yaml", testNATPolicyYAML},
		{"YML", ".yml", testNATPolicyYAML},
		{"YAML at size limit", ".yaml", testNATPolicyYAML + strings.Repeat(" ", (64<<10)-len(testNATPolicyYAML))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := writeNATPolicyFile(t, tc.suffix, tc.contents)
			t.Run("run", func(t *testing.T) {
				run, code, done, stderr := parse(t, "-nat-policy-file", file, "--network=bridge", "-image=x")
				if done || code != 0 {
					t.Fatalf("parse run policy: code=%d, done=%t, stderr=%q", code, done, stderr)
				}
				assertConfiguredNATPolicy(t, run.cfg)
			})
			t.Run("restore", func(t *testing.T) {
				var restoreErr bytes.Buffer
				restore, code, done := parseRestoreArgs([]string{"-checkpoint-dir", t.TempDir(), "--nat-policy-file", file}, nil, io.Discard, &restoreErr)
				if done || code != 0 {
					t.Fatalf("parse restore policy without network mode: code=%d, done=%t, stderr=%q", code, done, restoreErr.String())
				}
				assertConfiguredNATPolicy(t, restore.cfg)
			})
		})
	}
}

func assertConfiguredNATPolicy(t *testing.T, cfg gvx.Config) {
	t.Helper()
	if cfg.NetworkMode != gvx.NetModeNAT || cfg.NetworkPolicy == nil {
		t.Fatalf("network mode = %q, policy = %+v; want NAT with a policy", cfg.NetworkMode, cfg.NetworkPolicy)
	}
	assertTestNATPolicy(t, cfg.NetworkPolicy)
}

func assertTestNATPolicy(t *testing.T, p *gvx.NATPolicyConfig) {
	t.Helper()
	if p.Egress.Default != "deny" || p.Ingress.Default != "allow" || len(p.Egress.Rules) != 1 || len(p.Ingress.Rules) != 0 {
		t.Fatalf("policy = %+v, want egress deny with one exception and ingress allow without exceptions", p)
	}
	if rule := p.Egress.Rules[0]; rule.Action != "allow" || rule.CIDR != "203.0.113.0/24" || rule.Protocol != "tcp" || rule.Ports != "443" {
		t.Errorf("egress exception = %+v, want allow TCP port 443 to 203.0.113.0/24", rule)
	}
}

func TestNATPolicyFileRejectsNonNATNetworkMode(t *testing.T) {
	file := writeNATPolicyFile(t, ".json", testNATPolicy)
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
			file := writeNATPolicyFile(t, ".json", tc.json)
			_, code, done, stderr := parse(t, "--nat-policy-file", file, "-image=x")
			if !done || code != 2 || !strings.Contains(stderr, "--nat-policy-file:") {
				t.Errorf("parse %s policy: code=%d, done=%t, stderr=%q; want policy file usage error", tc.name, code, done, stderr)
			}
		})
	}
}

func TestNATPolicyFileRequiresSupportedSuffix(t *testing.T) {
	for _, tc := range []struct {
		name     string
		suffix   string
		contents string
		want     string
	}{
		{"missing suffix", "", testNATPolicy, "expected .json, .yaml, or .yml"},
		{"unsupported suffix", ".txt", testNATPolicyYAML, "expected .json, .yaml, or .yml"},
		{"YAML with JSON suffix", ".json", testNATPolicyYAML, "--nat-policy-file:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := writeNATPolicyFile(t, tc.suffix, tc.contents)
			_, code, done, stderr := parse(t, "--nat-policy-file", file, "-image=x")
			if !done || code != 2 || !strings.Contains(stderr, tc.want) {
				t.Errorf("parse policy: code=%d, done=%t, stderr=%q; want usage error containing %q", code, done, stderr, tc.want)
			}
		})
	}
}

func TestNATPolicyFileRejectsInvalidYAML(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
	}{
		{"unknown policy field", testNATPolicyYAML + "extra: deny\n"},
		{"unknown direction field", strings.Replace(testNATPolicyYAML, "ingress:\n", "ingress:\n  extra: deny\n", 1)},
		{"unknown rule field", strings.Replace(testNATPolicyYAML, `ports: "443"`, "extra: deny\n      ports: \"443\"", 1)},
		{"duplicate policy field", testNATPolicyYAML + "ingress:\n  default: allow\n"},
		{"duplicate direction field", strings.Replace(testNATPolicyYAML, "default: deny", "default: deny\n  default: deny", 1)},
		{"duplicate rule field", strings.Replace(testNATPolicyYAML, "protocol: tcp", "protocol: tcp\n      protocol: tcp", 1)},
		{"multiple documents", testNATPolicyYAML + "---\n" + testNATPolicyYAML},
		{"sequence root", "- " + testNATPolicy},
		{"null selector", strings.Replace(testNATPolicyYAML, `ports: "443"`, "ports: null", 1)},
		{"numeric selector", strings.Replace(testNATPolicyYAML, `ports: "443"`, "ports: 443", 1)},
		{"alias", "egress: &direction {default: deny}\ningress: *direction\n"},
		{"merge key", "egress: {<<: {default: deny}}\ningress: {default: allow}\n"},
		{"one byte over size limit", testNATPolicyYAML + strings.Repeat(" ", (64<<10)+1-len(testNATPolicyYAML))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := writeNATPolicyFile(t, ".yaml", tc.yaml)
			_, code, done, stderr := parse(t, "--nat-policy-file", file, "-image=x")
			if !done || code != 2 || !strings.Contains(stderr, "--nat-policy-file:") {
				t.Errorf("parse YAML policy: code=%d, done=%t, stderr=%q; want policy file usage error", code, done, stderr)
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
	for _, tc := range []struct {
		suffix   string
		contents string
	}{
		{".json", testNATPolicy},
		{".yaml", testNATPolicyYAML},
	} {
		t.Run(tc.suffix, func(t *testing.T) {
			file := writeNATPolicyFile(t, tc.suffix, tc.contents)
			ep := startMockCLIServer(t, []string{control.CapNATPolicyWrite}, func(_ context.Context, stream *control.Stream, req control.RequestEnvelope) error {
				if req.Method != control.MethodNATPolicySet {
					t.Errorf("replace sent method %q, want net.policy_set", req.Method)
				}
				var state control.NATPolicyState
				if err := json.Unmarshal(req.Params, &state); err != nil {
					return err
				}
				if _, err := gvx.ParseNATPolicy(bytes.NewReader(state.Policy)); err != nil {
					t.Errorf("RPC policy = %q; want a policy JSON object: %v", state.Policy, err)
					return err
				}
				return stream.Reply(state)
			})
			res := runCLIArgs(t, nil, "net-policy", "replace", "-S", ep.Address, "--token", ep.Token, "--file", file).mustSucceed(t, "net-policy replace")
			p, err := gvx.ParseNATPolicy(strings.NewReader(res.stdout))
			if err != nil {
				t.Fatalf("replacement output = %q; want a policy JSON object: %v", res.stdout, err)
			}
			assertTestNATPolicy(t, &p)
		})
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
