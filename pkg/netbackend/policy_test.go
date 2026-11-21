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

package netbackend

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

const (
	schedulerAcceptRules = "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\n"
	schedulerDropRules   = "*filter\n:INPUT DROP [0:0]\n:OUTPUT DROP [0:0]\n:FORWARD DROP [0:0]\nCOMMIT\n"
)

func schedulerCompile(t *testing.T, v4, v6 string, tx, rx PolicyLimit) *CompiledPolicy {
	t.Helper()
	compiled, err := CompilePolicy(PolicyConfig{RulesV4: v4, RulesV6: v6, TX: tx, RX: rx})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return compiled
}

func TestPolicyLimitWireFormat(t *testing.T) {
	for _, tc := range []struct {
		name, cli, wire string
		want            PolicyLimit
	}{
		{"unlimited", "unlimited", `"unlimited"`, PolicyLimit{}},
		{"finite", "rate-bps=10000000,burst-bytes=131072,queue-bytes=524288", `{"rate_bps":10000000,"burst_bytes":131072,"queue_bytes":524288}`, PolicyLimit{RateBPS: 10000000, BurstBytes: 131072, QueueBytes: 524288}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limit, err := ParsePolicyLimit(tc.cli)
			if err != nil || limit != tc.want {
				t.Fatalf("ParsePolicyLimit(%q) = (%+v, %v), want %+v", tc.cli, limit, err, tc.want)
			}
			var decoded PolicyLimit
			if err := json.Unmarshal([]byte(tc.wire), &decoded); err != nil || decoded != tc.want {
				t.Fatalf("decode %s = (%+v, %v), want %+v", tc.wire, decoded, err, tc.want)
			}
			encoded, err := json.Marshal(limit)
			if err != nil || string(encoded) != tc.wire {
				t.Fatalf("encode %+v = (%s, %v), want %s", limit, encoded, err, tc.wire)
			}
		})
	}
}

func TestPolicyLimitRejectsInvalidWireValues(t *testing.T) {
	for _, data := range []string{
		`null`, `0`, `"Unlimited"`, `[]`, `{}`,
		`{"rate_bps":1,"burst_bytes":65537}`,
		`{"rate_bps":1,"burst_bytes":65537,"queue_bytes":65537,"other":0}`,
		`{"rate_bps":1,"rate_bps":2,"burst_bytes":65537,"queue_bytes":65537}`,
		`{"Rate_BPS":1,"burst_bytes":65537,"queue_bytes":65537}`,
		`{"rate_bps":null,"burst_bytes":65537,"queue_bytes":65537}`,
		`{"rate_bps":1e1,"burst_bytes":65537,"queue_bytes":65537}`,
		`{"rate_bps":-1,"burst_bytes":65537,"queue_bytes":65537}`,
		`{"rate_bps":"1","burst_bytes":65537,"queue_bytes":65537}`,
		`{"rate_bps":0,"burst_bytes":0,"queue_bytes":0}`,
	} {
		t.Run(data, func(t *testing.T) {
			limit := PolicyLimit{RateBPS: 8, BurstBytes: 65537, QueueBytes: 65537}
			old := limit
			var policyErr *PolicyError
			if err := json.Unmarshal([]byte(data), &limit); !errors.As(err, &policyErr) || policyErr.Code != "invalid_policy" {
				t.Fatalf("decode %s = %v, want invalid_policy", data, err)
			}
			if limit != old {
				t.Errorf("decode %s changed limit to %+v, want %+v", data, limit, old)
			}
		})
	}
}

func TestPolicyLimitRejectsUnsafeCLIValues(t *testing.T) {
	for _, value := range []string{
		"rate-bps=8,burst-bytes=65536,queue-bytes=65537",
		"rate-bps=8,burst-bytes=65538,queue-bytes=65537",
		"rate-bps=8,burst-bytes=65537,queue-bytes=67108865",
		"rate-bps=1000000000001,burst-bytes=65537,queue-bytes=65537",
		"rate-bps=8,burst-bytes=65537,queue-bytes=18446744073709551616",
		"rate-bps=8,rate-bps=9,burst-bytes=65537,queue-bytes=65537",
		"rate-bps=8,burst-bytes=65537,queue-bytes=65537,",
	} {
		var policyErr *PolicyError
		if _, err := ParsePolicyLimit(value); !errors.As(err, &policyErr) || policyErr.Code != "invalid_policy" {
			t.Errorf("ParsePolicyLimit(%q) = %v, want invalid_policy", value, err)
		}
	}
}

func TestCompilePolicyRejectsInvalidDirection(t *testing.T) {
	_, err := CompilePolicy(PolicyConfig{RulesV4: schedulerAcceptRules, RulesV6: schedulerAcceptRules, RX: PolicyLimit{RateBPS: 1}})
	var policyErr *PolicyError
	if !errors.As(err, &policyErr) || policyErr.Code != "invalid_policy" || policyErr.Option != "qos_rx" {
		t.Fatalf("CompilePolicy(invalid RX) = %v, want invalid_policy on qos_rx", err)
	}
}

func TestCompilePolicyRejectsOversizeRules(t *testing.T) {
	_, err := CompilePolicy(PolicyConfig{RulesV4: schedulerAcceptRules, RulesV6: strings.Repeat("\n", MaxPolicyRules+1)})
	var policyErr *PolicyError
	if !errors.As(err, &policyErr) || policyErr.Code != "too_large" || policyErr.Family != "ipv6" {
		t.Fatalf("CompilePolicy(oversize IPv6) = %v, want too_large for ipv6", err)
	}
}

func TestNATPolicyRejectsControlAddressAliases(t *testing.T) {
	compiled := schedulerCompile(t, schedulerAcceptRules, schedulerAcceptRules, PolicyLimit{}, PolicyLimit{})
	p := NewNATPolicy(compiled, netip.MustParseAddrPort("127.0.0.1:7401"))
	defer p.Close()
	for _, target := range []string{"[::ffff:127.0.0.1]:7401", "0.0.0.0:7401", "[::]:7401"} {
		if p.HostDialAllowed(netip.MustParseAddrPort(target)) {
			t.Errorf("allowed %s as a target for the control endpoint", target)
		}
	}
	if !p.HostDialAllowed(netip.MustParseAddrPort("127.0.0.1:7402")) {
		t.Error("denied an unrelated port at the control address")
	}
}
