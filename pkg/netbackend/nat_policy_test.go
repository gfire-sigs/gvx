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
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/tcpip/header"
)

func compileNATPolicyForTest(t *testing.T, cfg NATPolicyConfig) *CompiledNATPolicy {
	t.Helper()
	compiled, err := CompileNATPolicy(&cfg)
	if err != nil {
		t.Fatalf("compile NAT policy: %v", err)
	}
	return compiled
}

func TestNATPolicyMatchesDirectionAndOrderedRules(t *testing.T) {
	p := NewNATPolicy(compileNATPolicyForTest(t, NATPolicyConfig{
		Egress: NATPolicyDirectionConfig{Default: "deny", Rules: []NATPolicyRule{
			{Action: "deny", CIDR: "192.0.2.7", Protocol: "tcp", Ports: "443"},
			{Action: "allow", CIDR: "192.0.2.0/24", Protocol: "6", Ports: "440-443", GuestCIDR: "10.0.2.0/24"},
			{Action: "allow", CIDR: "2001:db8::/32", Protocol: "icmpv6"},
		}},
		Ingress: NATPolicyDirectionConfig{Default: "deny", Rules: []NATPolicyRule{
			{Action: "allow", CIDR: "::ffff:192.0.2.0/120", Ports: "443", GuestCIDR: "::1"},
		}},
	}), netip.AddrPort{})
	t.Cleanup(p.Close)

	for _, tc := range []struct {
		name          string
		dir           NATPolicyDirection
		guest, remote string
		proto         uint8
		port          uint16
		want          bool
	}{
		{"first rule denies", NATPolicyEgress, "10.0.2.15", "192.0.2.7", uint8(header.TCPProtocolNumber), 443, false},
		{"range lower endpoint", NATPolicyEgress, "10.0.2.15", "192.0.2.8", uint8(header.TCPProtocolNumber), 440, true},
		{"range upper endpoint", NATPolicyEgress, "10.0.2.15", "192.0.2.8", uint8(header.TCPProtocolNumber), 443, true},
		{"range outside", NATPolicyEgress, "10.0.2.15", "192.0.2.8", uint8(header.TCPProtocolNumber), 444, false},
		{"guest source constrains egress", NATPolicyEgress, "10.1.2.15", "192.0.2.8", uint8(header.TCPProtocolNumber), 443, false},
		{"mapped address uses IPv4 rule", NATPolicyEgress, "10.0.2.15", "::ffff:192.0.2.8", uint8(header.TCPProtocolNumber), 443, true},
		{"IPv4 does not match IPv6 prefix", NATPolicyEgress, "10.0.2.15", "192.0.2.8", uint8(header.ICMPv6ProtocolNumber), 0, false},
		{"IPv6 and portless protocol", NATPolicyEgress, "2001:db8::15", "2001:db8::8", uint8(header.ICMPv6ProtocolNumber), 0, true},
		{"guest service constrains ingress", NATPolicyIngress, "2001:db8::15", "192.0.2.8", uint8(header.UDPProtocolNumber), 443, false},
		{"mapped prefix and mixed families", NATPolicyIngress, "::1", "192.0.2.8", uint8(header.UDPProtocolNumber), 443, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flow := NATPolicyFlow{
				Direction: tc.dir,
				Protocol:  tc.proto,
				Guest:     netip.MustParseAddr(tc.guest),
				Remote:    netip.MustParseAddr(tc.remote),
				Port:      tc.port,
				PortKnown: tc.port != 0,
			}
			if got := p.Allows(flow); got != tc.want {
				t.Errorf("Allows(%+v) = %t, want %t", flow, got, tc.want)
			}
		})
	}
}

func TestNATPolicyRequiresBothEgressAddresses(t *testing.T) {
	p := NewNATPolicy(compileNATPolicyForTest(t, NATPolicyConfig{
		Egress: NATPolicyDirectionConfig{Default: "deny", Rules: []NATPolicyRule{
			{Action: "allow", CIDR: "10.0.2.2"},
			{Action: "allow", CIDR: "127.0.0.1"},
		}},
		Ingress: NATPolicyDirectionConfig{Default: "deny"},
	}), netip.AddrPort{})
	t.Cleanup(p.Close)
	flow := NATPolicyFlow{Direction: NATPolicyEgress, Remote: netip.MustParseAddr("10.0.2.2"), RemoteAlias: netip.MustParseAddr("127.0.0.1")}
	if !p.Allows(flow) {
		t.Fatal("both egress addresses match allow rules")
	}
	flow.RemoteAlias = netip.MustParseAddr("127.0.0.2")
	if p.Allows(flow) {
		t.Error("allowed original address authorized a denied dial target")
	}
	flow.Remote, flow.RemoteAlias = flow.RemoteAlias, flow.Remote
	if p.Allows(flow) {
		t.Error("allowed dial target authorized a denied original address")
	}
}

func TestNATPolicyUnknownFieldsOnlyDenyPotentialMatches(t *testing.T) {
	p := NewNATPolicy(compileNATPolicyForTest(t, NATPolicyConfig{
		Egress: NATPolicyDirectionConfig{Default: "allow", Rules: []NATPolicyRule{
			{Action: "allow", CIDR: "192.0.2.0/24", GuestCIDR: "10.0.2.0/24", Protocol: "tcp", Ports: "443"},
		}},
		Ingress: NATPolicyDirectionConfig{Default: "allow"},
	}), netip.AddrPort{})
	t.Cleanup(p.Close)

	guest := netip.MustParseAddr("10.0.2.15")
	remote := netip.MustParseAddr("192.0.2.8")
	otherRemote := netip.MustParseAddr("2001:db8::8")
	for _, tc := range []struct {
		name          string
		guest, remote netip.Addr
		protocol      uint8
		port          uint16
		want          bool
	}{
		{"unknown guest address", netip.Addr{}, remote, uint8(header.TCPProtocolNumber), 443, false},
		{"unknown remote address", guest, netip.Addr{}, uint8(header.TCPProtocolNumber), 443, false},
		{"unknown protocol", guest, remote, 0, 443, false},
		{"unknown port", guest, remote, uint8(header.TCPProtocolNumber), 0, false},
		{"known remote mismatch", netip.Addr{}, otherRemote, 0, 0, true},
		{"known protocol mismatch", netip.Addr{}, remote, uint8(header.UDPProtocolNumber), 0, true},
		{"known port mismatch", guest, netip.Addr{}, 0, 444, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flow := NATPolicyFlow{Direction: NATPolicyEgress, Guest: tc.guest, Remote: tc.remote, Protocol: tc.protocol, Port: tc.port, PortKnown: tc.port != 0}
			if got := p.Allows(flow); got != tc.want {
				t.Errorf("Allows(%+v) = %t, want %t", flow, got, tc.want)
			}
		})
	}
}

func TestParseNATPolicyStrictAndBounded(t *testing.T) {
	const valid = `{"egress":{"default":"deny","rules":[{"action":"allow","cidr":"::1","protocol":"tcp","ports":"65535","guest_cidr":"::/0"}]},"ingress":{"default":"allow"}}`
	atLimit := valid + strings.Repeat(" ", maxNATPolicyBytes-len(valid))
	cfg, err := ParseNATPolicy(strings.NewReader(atLimit))
	if err != nil {
		t.Fatalf("parse policy at size limit: %v", err)
	}
	p := NewNATPolicy(compileNATPolicyForTest(t, cfg), netip.AddrPort{})
	t.Cleanup(p.Close)
	if !p.Allows(NATPolicyFlow{
		Direction: NATPolicyEgress, Protocol: uint8(header.TCPProtocolNumber),
		Guest: netip.IPv6Loopback(), Remote: netip.IPv6Loopback(), Port: 65535, PortKnown: true,
	}) {
		t.Error("decoded policy did not permit the configured flow")
	}

	for _, tc := range []struct{ name, data string }{
		{"oversize whitespace", atLimit + " "},
		{"null policy", "null"},
		{"null direction", `{"egress":null,"ingress":{"default":"allow"}}`},
		{"null rule list", `{"egress":{"default":"allow","rules":null}}`},
		{"null rule", `{"egress":{"default":"allow","rules":[null]}}`},
		{"null selector", `{"egress":{"default":"deny","rules":[{"action":"allow","cidr":null}]}}`},
		{"empty CIDR", `{"egress":{"default":"deny","rules":[{"action":"allow","cidr":""}]}}`},
		{"empty guest CIDR", `{"egress":{"default":"deny","rules":[{"action":"allow","guest_cidr":""}]}}`},
		{"empty protocol", `{"egress":{"default":"deny","rules":[{"action":"allow","protocol":""}]}}`},
		{"empty ports", `{"egress":{"default":"deny","rules":[{"action":"allow","ports":""}]}}`},
		{"unknown direction", `{"input":{"default":"allow"}}`},
		{"unknown selector", `{"egress":{"default":"deny","rules":[{"action":"allow","sport":"123"}]}}`},
		{"duplicate direction", `{"egress":{"default":"deny"},"egress":{"default":"allow"}}`},
		{"duplicate selector", `{"egress":{"default":"deny","rules":[{"action":"allow","cidr":"::1","cidr":"::/0"}]}}`},
		{"wrong case", `{"Egress":{"default":"allow"}}`},
		{"numeric instead of string", `{"egress":{"default":"deny","rules":[{"action":"allow","ports":443}]}}`},
		{"trailing JSON", valid + " {}"},
		{"trailing non-JSON", valid + " !"},
		{"invalid UTF-8", valid + "\xff"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseNATPolicy(strings.NewReader(tc.data)); err == nil {
				t.Error("ParseNATPolicy accepted invalid input")
			}
		})
	}
}

func TestCompileNATPolicyRejectsInvalidRules(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule NATPolicyRule
	}{
		{"unknown action", NATPolicyRule{Action: "accept"}},
		{"hostname", NATPolicyRule{Action: "allow", CIDR: "host.example.test"}},
		{"invalid guest prefix", NATPolicyRule{Action: "allow", GuestCIDR: "192.0.2.0/33"}},
		{"address zone", NATPolicyRule{Action: "allow", CIDR: "fe80::1%eth0"}},
		{"broad mapped prefix", NATPolicyRule{Action: "allow", CIDR: "::ffff:192.0.2.0/95"}},
		{"unknown protocol", NATPolicyRule{Action: "allow", Protocol: "sctp-ish"}},
		{"unknown protocol number", NATPolicyRule{Action: "allow", Protocol: "0"}},
		{"out of bounds protocol number", NATPolicyRule{Action: "allow", Protocol: "256"}},
		{"portless protocol", NATPolicyRule{Action: "allow", Protocol: "icmp", Ports: "53"}},
		{"named port", NATPolicyRule{Action: "allow", Ports: "https"}},
		{"port zero", NATPolicyRule{Action: "allow", Ports: "0"}},
		{"out of bounds port", NATPolicyRule{Action: "allow", Ports: "65536"}},
		{"descending port range", NATPolicyRule{Action: "allow", Ports: "443-440"}},
		{"open port range", NATPolicyRule{Action: "allow", Ports: "443-"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := NATPolicyConfig{
				Egress:  NATPolicyDirectionConfig{Default: "allow"},
				Ingress: NATPolicyDirectionConfig{Default: "deny", Rules: []NATPolicyRule{tc.rule}},
			}
			if compiled, err := CompileNATPolicy(&cfg); err == nil || compiled != nil {
				t.Errorf("compiled invalid rule %+v with error %v", tc.rule, err)
			}
		})
	}
	for _, cfg := range []NATPolicyConfig{
		{Egress: NATPolicyDirectionConfig{Default: "allow"}},
		{Ingress: NATPolicyDirectionConfig{Default: "deny"}},
	} {
		if compiled, err := CompileNATPolicy(&cfg); err == nil || compiled != nil {
			t.Errorf("compiled policy with missing directional default: %+v (error %v)", cfg, err)
		}
	}
}

func TestNATPolicyBoundsRuleCount(t *testing.T) {
	const rule = `{"action":"allow"}`
	jsonPrefix := `{"ingress":{"default":"allow"},"egress":{"default":"deny","rules":[`
	rules := strings.Repeat(rule+",", maxNATPolicyRules-1) + rule
	if _, err := ParseNATPolicy(strings.NewReader(jsonPrefix + rules + `]}}`)); err != nil {
		t.Fatalf("parse policy at rule limit: %v", err)
	}
	if _, err := ParseNATPolicy(strings.NewReader(jsonPrefix + rules + "," + rule + `]}}`)); err == nil {
		t.Error("ParseNATPolicy accepted too many rules")
	}

	cfg := NATPolicyConfig{
		Egress:  NATPolicyDirectionConfig{Default: "deny", Rules: make([]NATPolicyRule, maxNATPolicyRules)},
		Ingress: NATPolicyDirectionConfig{Default: "allow"},
	}
	for i := range cfg.Egress.Rules {
		cfg.Egress.Rules[i].Action = "allow"
	}
	compileNATPolicyForTest(t, cfg)
	cfg.Egress.Rules = append(cfg.Egress.Rules, NATPolicyRule{Action: "allow"})
	if compiled, err := CompileNATPolicy(&cfg); err == nil || compiled != nil {
		t.Errorf("compiled too many rules: %v, %v", compiled, err)
	}
}

func TestCompileNATPolicyBoundsTypedConfigSize(t *testing.T) {
	oversizedValue := strings.Repeat("0", maxNATPolicyBytes/2) + "53"
	for _, tc := range []struct {
		name    string
		egress  []NATPolicyRule
		ingress []NATPolicyRule
	}{
		{
			name:    "values exceed the aggregate limit across directions",
			egress:  []NATPolicyRule{{Action: "allow", Ports: oversizedValue}},
			ingress: []NATPolicyRule{{Action: "deny", Ports: oversizedValue}},
		},
		{
			name: "serialized keys exceed the limit even if values fit",
			egress: []NATPolicyRule{
				{Action: "allow", Ports: strings.Repeat("0", maxNATPolicyBytes-40) + "53"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := NATPolicyConfig{
				Egress:  NATPolicyDirectionConfig{Default: "deny", Rules: tc.egress},
				Ingress: NATPolicyDirectionConfig{Default: "deny", Rules: tc.ingress},
			}
			if compiled, err := CompileNATPolicy(&cfg); compiled != nil || !errors.Is(err, errNATPolicyTooLarge) {
				t.Errorf("CompileNATPolicy oversized policy = %v, %v; want size error", compiled, err)
			}
		})
	}
}

func TestNATPolicyReplacementRejectsPartialConfigAndCopiesBothDirections(t *testing.T) {
	cfg := NATPolicyConfig{
		Egress:  NATPolicyDirectionConfig{Default: "deny", Rules: []NATPolicyRule{{Action: "allow", CIDR: "192.0.2.8"}}},
		Ingress: NATPolicyDirectionConfig{Default: "deny", Rules: []NATPolicyRule{{Action: "allow", CIDR: "2001:db8::8"}}},
	}
	flow := NATPolicyFlow{Direction: NATPolicyEgress, Remote: netip.MustParseAddr("192.0.2.8")}
	p := NewNATPolicy(compileNATPolicyForTest(t, cfg), netip.AddrPort{})
	t.Cleanup(p.Close)
	view := p.Config()
	if view == nil || len(view.Egress.Rules) != 1 || len(view.Ingress.Rules) != 1 {
		t.Fatalf("unexpected published config: %+v", view)
	}
	view.Egress.Rules[0].CIDR = "192.0.2.99"
	view.Ingress.Rules[0].CIDR = "2001:db8::99"
	ctx, release, ok := p.Track(t.Context(), flow)
	if !ok {
		t.Fatal("initial policy denied allowed flow")
	}
	t.Cleanup(release)
	cfg.Egress.Rules[0].Action = "deny"
	cfg.Ingress.Rules[0].CIDR = "bad-prefix"
	candidate, err := CompileNATPolicy(&cfg)
	if err == nil || candidate != nil {
		t.Fatalf("compile partial candidate = %v, %v; want no candidate and an error", candidate, err)
	}
	if err := p.Replace(candidate); err == nil {
		t.Error("Replace accepted a nil candidate")
	}
	if !p.Allows(flow) || ctx.Err() != nil {
		t.Errorf("invalid replacement revoked an admitted flow: allows=%t, ctx=%v", p.Allows(flow), ctx.Err())
	}
	current := p.Config()
	if current == nil || len(current.Egress.Rules) != 1 || len(current.Ingress.Rules) != 1 ||
		current.Egress.Rules[0] != (NATPolicyRule{Action: "allow", CIDR: "192.0.2.8"}) ||
		current.Ingress.Rules[0].CIDR != "2001:db8::8" {
		t.Errorf("mutation or invalid replacement changed published config: %+v", current)
	}
}

func TestNATPolicyActivationRevokesDeniedRelations(t *testing.T) {
	p := NewNATPolicy(nil, netip.AddrPort{})
	t.Cleanup(p.Close)
	allowed := NATPolicyFlow{Direction: NATPolicyEgress, Remote: netip.MustParseAddr("192.0.2.8")}
	denied := NATPolicyFlow{Direction: NATPolicyIngress, Remote: netip.MustParseAddr("192.0.2.9")}
	unix := NATPolicyFlow{Direction: NATPolicyIngress}
	if p.Active() || !p.Allows(unix) {
		t.Fatal("disabled policy did not permit Unix publication")
	}
	track := func(flows ...NATPolicyFlow) context.Context {
		t.Helper()
		ctx, release, ok := p.Track(t.Context(), flows...)
		if !ok {
			t.Fatalf("inactive policy denied %+v", flows)
		}
		t.Cleanup(release)
		return ctx
	}
	survivor := track(allowed)
	both := []NATPolicyFlow{allowed, denied}
	paired := track(both...)
	both[1] = allowed
	unixCtx := track(unix)

	candidate := compileNATPolicyForTest(t, NATPolicyConfig{
		Egress: NATPolicyDirectionConfig{Default: "allow"},
		Ingress: NATPolicyDirectionConfig{Default: "allow", Rules: []NATPolicyRule{
			{Action: "deny", CIDR: "192.0.2.9"},
		}},
	})
	if err := p.Replace(candidate); err != nil {
		t.Fatalf("activate policy: %v", err)
	}
	current := p.Config()
	if !p.Active() || current == nil || len(current.Ingress.Rules) != 1 || current.Ingress.Rules[0].CIDR != "192.0.2.9" {
		t.Fatal("replacement did not publish the new config")
	}
	if paired.Err() != context.Canceled || unixCtx.Err() != context.Canceled || survivor.Err() != nil {
		t.Errorf("after activation: paired=%v, Unix=%v, survivor=%v", paired.Err(), unixCtx.Err(), survivor.Err())
	}
	if _, _, ok := p.Track(t.Context(), allowed, denied); ok {
		t.Error("admitted a relation with a denied leg after activation")
	}
	if p.Allows(unix) {
		t.Error("active default-allow policy admitted a peer without an IP address")
	}

	p.Close()
	if survivor.Err() != context.Canceled || p.Allows(allowed) {
		t.Errorf("close did not end relay authority: survivor=%v, allows=%t", survivor.Err(), p.Allows(allowed))
	}
	if err := p.Replace(candidate); err == nil {
		t.Error("replacement reopened a closed controller")
	}
}

func TestNATPolicyReplaceRacingAdmissionCannotLeaveDeniedFlowLive(t *testing.T) {
	p := NewNATPolicy(compileNATPolicyForTest(t, NATPolicyConfig{
		Egress:  NATPolicyDirectionConfig{Default: "allow"},
		Ingress: NATPolicyDirectionConfig{Default: "deny"},
	}), netip.AddrPort{})
	t.Cleanup(p.Close)
	deny := compileNATPolicyForTest(t, NATPolicyConfig{
		Egress:  NATPolicyDirectionConfig{Default: "deny"},
		Ingress: NATPolicyDirectionConfig{Default: "allow"},
	})
	flow := NATPolicyFlow{Direction: NATPolicyEgress, Remote: netip.MustParseAddr("192.0.2.8")}
	established, release, ok := p.Track(t.Context(), flow)
	if !ok {
		t.Fatal("initial policy denied allowed flow")
	}
	t.Cleanup(release)

	start := make(chan struct{})
	type admission struct {
		ctx     context.Context
		release func()
	}
	result := make(chan admission, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-start
		ctx, release, ok := p.Track(t.Context(), flow)
		if !ok {
			result <- admission{}
			return
		}
		result <- admission{ctx: ctx, release: release}
	}()
	close(start)
	err := p.Replace(deny)
	raced := <-result
	<-done
	if raced.release != nil {
		t.Cleanup(raced.release)
	}
	if err != nil {
		t.Fatalf("replace policy: %v", err)
	}
	if established.Err() != context.Canceled {
		t.Errorf("replacement did not cancel established denied flow: %v", established.Err())
	}
	if raced.ctx != nil && raced.ctx.Err() != context.Canceled {
		t.Errorf("admission that overlapped replacement left a denied flow live: %v", raced.ctx.Err())
	}
	if !p.Allows(NATPolicyFlow{Direction: NATPolicyIngress, Remote: flow.Remote}) {
		t.Error("replacement did not replace the ingress default")
	}
}

func TestNATPolicyRestoreRequirementSurvivesClose(t *testing.T) {
	var absent *NATPolicy
	if absent.RequiredOnRestore() {
		t.Error("nil controller required a restore policy")
	}
	p := NewNATPolicy(nil, netip.AddrPort{})
	t.Cleanup(p.Close)
	if p.RequiredOnRestore() {
		t.Fatal("disabled controller required a restore policy")
	}
	if err := p.Replace(nil); err == nil || p.RequiredOnRestore() {
		t.Fatalf("invalid activation affected restore requirement: err=%v, required=%t", err, p.RequiredOnRestore())
	}
	compiled := compileNATPolicyForTest(t, NATPolicyConfig{
		Egress:  NATPolicyDirectionConfig{Default: "deny"},
		Ingress: NATPolicyDirectionConfig{Default: "deny"},
	})
	startup := NewNATPolicy(compiled, netip.AddrPort{})
	if !startup.RequiredOnRestore() {
		t.Error("startup policy did not require a restore policy")
	}
	startup.Close()
	if err := p.Replace(compiled); err != nil {
		t.Fatalf("activate policy: %v", err)
	}
	if !p.RequiredOnRestore() {
		t.Error("activation did not require a restore policy")
	}
	p.Close()
	if p.Active() || !p.RequiredOnRestore() {
		t.Errorf("after close: active=%t, required=%t; want false, true", p.Active(), p.RequiredOnRestore())
	}
}

func TestNATPolicyDeniesManagementEndpointIndependently(t *testing.T) {
	candidate := compileNATPolicyForTest(t, NATPolicyConfig{
		Egress:  NATPolicyDirectionConfig{Default: "allow"},
		Ingress: NATPolicyDirectionConfig{Default: "allow"},
	})
	for _, tc := range []struct {
		name, listener, denied, allowed string
	}{
		{"mapped dial", "127.0.0.1:7401", "[::ffff:127.0.0.1]:7401", "127.0.0.1:7402"},
		{"mapped listener", "[::ffff:127.0.0.1]:7401", "127.0.0.1:7401", "127.0.0.2:7401"},
		{"IPv6 loopback", "[::1]:7401", "[::1]:7401", "127.0.0.1:7401"},
		{"unspecified dial", "127.0.0.1:7401", "0.0.0.0:7401", "192.0.2.8:7401"},
		{"IPv4 wildcard listener", "0.0.0.0:7401", "192.0.2.8:7401", "[::1]:7401"},
		{"cross-family unspecified dial to concrete IPv4", "127.0.0.1:7401", "[::]:7401", "[::1]:7401"},
		{"cross-family unspecified dial to wildcard IPv4", "0.0.0.0:7401", "[::]:7401", "[::1]:7401"},
		{"cross-family mapped unspecified dial to IPv6", "[::1]:7401", "[::ffff:0.0.0.0]:7401", "127.0.0.1:7401"},
		{"dual-stack wildcard listener", "[::]:7401", "127.0.0.1:7401", "127.0.0.1:7402"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := NewNATPolicy(nil, netip.MustParseAddrPort(tc.listener))
			t.Cleanup(p.Close)
			denied, allowed := netip.MustParseAddrPort(tc.denied), netip.MustParseAddrPort(tc.allowed)
			if p.AllowsHostDial(header.TCPProtocolNumber, denied) || !p.AllowsHostDial(header.TCPProtocolNumber, allowed) {
				t.Errorf("inactive guard: %s must deny and %s must allow", denied, allowed)
			}
			if err := p.Replace(candidate); err != nil {
				t.Fatalf("activate allow-all policy: %v", err)
			}
			if p.AllowsHostDial(header.TCPProtocolNumber, denied) || !p.AllowsHostDial(header.TCPProtocolNumber, allowed) {
				t.Errorf("active guard: %s must deny and %s must allow", denied, allowed)
			}
			if !p.AllowsHostDial(header.UDPProtocolNumber, denied) {
				t.Errorf("TCP management listener must not block UDP to %s", denied)
			}
		})
	}
}
