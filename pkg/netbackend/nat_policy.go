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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
)

const (
	maxNATPolicyBytes = 64 << 10
	maxNATPolicyRules = 1024 // Per direction, including for policies supplied through the SDK.
)

// ErrNATPolicyRevoked cancels an admitted flow when a replacement denies it.
var ErrNATPolicyRevoked = errors.New("NAT policy revoked the flow")

// NATPolicyConfig specifies both directions of the host-owned firewall.
type NATPolicyConfig struct {
	Egress  NATPolicyDirectionConfig `json:"egress"`
	Ingress NATPolicyDirectionConfig `json:"ingress"`
}

// NATPolicyDirectionConfig applies the first matching rule, then the default.
type NATPolicyDirectionConfig struct {
	Default string          `json:"default"`
	Rules   []NATPolicyRule `json:"rules,omitempty"`
}

// NATPolicyRule matches the remote address, guest address, protocol, and service
// port. Omitted selectors do not restrict the match.
type NATPolicyRule struct {
	Action    string `json:"action"`
	CIDR      string `json:"cidr,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Ports     string `json:"ports,omitempty"`
	GuestCIDR string `json:"guest_cidr,omitempty"`
}

// NATPolicyDirection identifies the side that initiated the flow.
type NATPolicyDirection uint8

const (
	NATPolicyEgress NATPolicyDirection = iota + 1
	NATPolicyIngress
)

// NATPolicyFlow describes an admission. Port is the dial target's service port.
// An invalid address, a zero Protocol, or a false PortKnown marks an unknown field.
// RemoteAlias optionally records the alternate egress address after NAT translation.
type NATPolicyFlow struct {
	Direction   NATPolicyDirection
	Protocol    uint8
	Guest       netip.Addr
	Remote      netip.Addr
	RemoteAlias netip.Addr
	Port        uint16
	PortKnown   bool
}

// ParseNATPolicy decodes a single policy object of at most 64 KiB. CompileNATPolicy
// validates the values before publication.
func ParseNATPolicy(r io.Reader) (NATPolicyConfig, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxNATPolicyBytes+1))
	if err != nil {
		return NATPolicyConfig{}, fmt.Errorf("read NAT policy: %w", err)
	}
	if len(data) > maxNATPolicyBytes {
		return NATPolicyConfig{}, errNATPolicyTooLarge
	}
	if !utf8.Valid(data) {
		return NATPolicyConfig{}, errNATPolicyUTF8
	}

	d := json.NewDecoder(bytes.NewReader(data))
	var cfg NATPolicyConfig
	err = parseNATPolicyObject(d, []string{"egress", "ingress"}, func(field int) error {
		if field == 0 {
			return parseNATPolicyDirection(d, &cfg.Egress)
		}
		return parseNATPolicyDirection(d, &cfg.Ingress)
	})
	if err != nil {
		return NATPolicyConfig{}, fmt.Errorf("parse NAT policy: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return NATPolicyConfig{}, errNATPolicyTrailingData
	}
	return cfg, nil
}

var (
	errNATPolicyTooLarge       = errors.New("NAT policy exceeds 64 KiB")
	errNATPolicyUTF8           = errors.New("NAT policy is not valid UTF-8")
	errNATPolicyTrailingData   = errors.New("unexpected data after NAT policy object")
	errNATPolicyExpectedString = errors.New("expected JSON string")
	errNATPolicyEmptyField     = errors.New("field must not be an empty string")
	errNATPolicyClosed         = errors.New("NAT policy controller is closed")
	errNATPolicyUncompiled     = errors.New("replacement requires a compiled NAT policy")
)

func parseNATPolicyObject(d *json.Decoder, names []string, parse func(int) error) error {
	if err := expectNATPolicyDelim(d, '{'); err != nil {
		return err
	}
	var seen uint8
	for d.More() {
		name, err := parseNATPolicyString(d)
		if err != nil {
			return err
		}
		field := slices.Index(names, name)
		if field < 0 {
			return fmt.Errorf("unknown field %q", name)
		}
		bit := uint8(1) << field
		if seen&bit != 0 {
			return fmt.Errorf("duplicate field %q", name)
		}
		seen |= bit
		if err := parse(field); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return expectNATPolicyDelim(d, '}')
}

func parseNATPolicyDirection(d *json.Decoder, cfg *NATPolicyDirectionConfig) error {
	return parseNATPolicyObject(d, []string{"default", "rules"}, func(field int) error {
		if field == 0 {
			var err error
			cfg.Default, err = parseNATPolicyString(d)
			return err
		}
		if err := expectNATPolicyDelim(d, '['); err != nil {
			return err
		}
		for d.More() {
			if len(cfg.Rules) == maxNATPolicyRules {
				return fmt.Errorf("too many rules: maximum %d", maxNATPolicyRules)
			}
			var rule NATPolicyRule
			fields := [...]*string{&rule.Action, &rule.CIDR, &rule.Protocol, &rule.Ports, &rule.GuestCIDR}
			err := parseNATPolicyObject(d, []string{"action", "cidr", "protocol", "ports", "guest_cidr"}, func(field int) error {
				value, err := parseNATPolicyString(d)
				if err == nil && value == "" {
					return errNATPolicyEmptyField
				}
				*fields[field] = value
				return err
			})
			if err != nil {
				return fmt.Errorf("rule %d: %w", len(cfg.Rules)+1, err)
			}
			cfg.Rules = append(cfg.Rules, rule)
		}
		return expectNATPolicyDelim(d, ']')
	})
}

func expectNATPolicyDelim(d *json.Decoder, expected json.Delim) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	if token != expected {
		return fmt.Errorf("expected %q", expected)
	}
	return nil
}

func parseNATPolicyString(d *json.Decoder) (string, error) {
	token, err := d.Token()
	if err != nil {
		return "", err
	}
	value, ok := token.(string)
	if !ok {
		return "", errNATPolicyExpectedString
	}
	return value, nil
}

// CompiledNATPolicy is an immutable snapshot. CompileNATPolicy constructs valid snapshots.
type CompiledNATPolicy struct {
	config  *NATPolicyConfig
	egress  natPolicyDirection
	ingress natPolicyDirection
}

type natPolicyDirection struct {
	defaultAllow bool
	rules        []natPolicyRule
}

type natPolicyRule struct {
	remote   netip.Prefix
	guest    netip.Prefix
	minPort  uint16
	maxPort  uint16
	protocol uint8
	allow    bool
}

// CompileNATPolicy validates both directions and takes a private copy of the config.
// A nil config represents a firewall that has not yet been enabled.
func CompileNATPolicy(config *NATPolicyConfig) (*CompiledNATPolicy, error) {
	if config == nil {
		return nil, nil
	}
	if err := boundNATPolicyConfig(config); err != nil {
		return nil, err
	}
	egress, err := compileNATPolicyDirection(config.Egress)
	if err != nil {
		return nil, fmt.Errorf("egress: %w", err)
	}
	ingress, err := compileNATPolicyDirection(config.Ingress)
	if err != nil {
		return nil, fmt.Errorf("ingress: %w", err)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxNATPolicyBytes {
		return nil, errNATPolicyTooLarge
	}
	return &CompiledNATPolicy{
		config:  cloneNATPolicyConfig(config),
		egress:  egress,
		ingress: ingress,
	}, nil
}

func boundNATPolicyConfig(config *NATPolicyConfig) error {
	remaining := maxNATPolicyBytes
	for i, dir := range [...]NATPolicyDirectionConfig{config.Egress, config.Ingress} {
		if len(dir.Rules) > maxNATPolicyRules {
			name := [...]string{"egress", "ingress"}[i]
			return fmt.Errorf("%s: too many rules: maximum %d", name, maxNATPolicyRules)
		}
		remaining -= len(dir.Default)
		if remaining < 0 {
			return errNATPolicyTooLarge
		}
		for i := range dir.Rules {
			r := &dir.Rules[i]
			for _, value := range [...]string{r.Action, r.CIDR, r.Protocol, r.Ports, r.GuestCIDR} {
				remaining -= len(value)
				if remaining < 0 {
					return errNATPolicyTooLarge
				}
			}
		}
	}
	return nil
}

func compileNATPolicyDirection(cfg NATPolicyDirectionConfig) (natPolicyDirection, error) {
	allow, err := parseNATPolicyAction(cfg.Default)
	if err != nil {
		return natPolicyDirection{}, fmt.Errorf("default: %w", err)
	}
	dir := natPolicyDirection{defaultAllow: allow, rules: make([]natPolicyRule, len(cfg.Rules))}
	for i, rule := range cfg.Rules {
		dir.rules[i], err = compileNATPolicyRule(rule)
		if err != nil {
			return natPolicyDirection{}, fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	return dir, nil
}

func compileNATPolicyRule(rule NATPolicyRule) (natPolicyRule, error) {
	var compiled natPolicyRule
	var err error
	compiled.allow, err = parseNATPolicyAction(rule.Action)
	if err != nil {
		return natPolicyRule{}, fmt.Errorf("action: %w", err)
	}
	compiled.remote, err = parseNATPolicyPrefix(rule.CIDR)
	if err != nil {
		return natPolicyRule{}, fmt.Errorf("cidr: %w", err)
	}
	compiled.guest, err = parseNATPolicyPrefix(rule.GuestCIDR)
	if err != nil {
		return natPolicyRule{}, fmt.Errorf("guest_cidr: %w", err)
	}
	switch rule.Protocol {
	case "":
	case "tcp":
		compiled.protocol = uint8(header.TCPProtocolNumber)
	case "udp":
		compiled.protocol = uint8(header.UDPProtocolNumber)
	case "icmp":
		compiled.protocol = uint8(header.ICMPv4ProtocolNumber)
	case "icmpv6":
		compiled.protocol = uint8(header.ICMPv6ProtocolNumber)
	default:
		number, err := strconv.ParseUint(rule.Protocol, 10, 8)
		if err != nil || number == 0 {
			return natPolicyRule{}, fmt.Errorf("unsupported protocol %q", rule.Protocol)
		}
		compiled.protocol = uint8(number)
	}
	if rule.Ports != "" {
		if compiled.protocol != 0 && !natPolicyPortProtocol(compiled.protocol) {
			return natPolicyRule{}, fmt.Errorf("protocol %q does not have service ports", rule.Protocol)
		}
		compiled.minPort, compiled.maxPort, err = parseNATPolicyPorts(rule.Ports)
		if err != nil {
			return natPolicyRule{}, err
		}
	}
	return compiled, nil
}

func parseNATPolicyAction(action string) (bool, error) {
	switch action {
	case "allow":
		return true, nil
	case "deny":
		return false, nil
	default:
		return false, fmt.Errorf("expected allow or deny, got %q", action)
	}
}

func parseNATPolicyPrefix(text string) (netip.Prefix, error) {
	if text == "" {
		return netip.Prefix{}, nil
	}
	if !strings.Contains(text, "/") {
		addr, err := netip.ParseAddr(text)
		if err != nil {
			return netip.Prefix{}, err
		}
		if addr.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("address %q must not contain a zone", text)
		}
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	prefix, err := netip.ParsePrefix(text)
	if err != nil {
		return netip.Prefix{}, err
	}
	if addr := prefix.Addr(); addr.Is4In6() {
		if prefix.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("IPv4-mapped prefix %q is shorter than /96", text)
		}
		prefix = netip.PrefixFrom(addr.Unmap(), prefix.Bits()-96)
	}
	return prefix.Masked(), nil
}

func parseNATPolicyPorts(text string) (uint16, uint16, error) {
	first, last, ranged := strings.Cut(text, "-")
	lo, loErr := strconv.ParseUint(first, 10, 16)
	hi, hiErr := lo, loErr
	if ranged {
		hi, hiErr = strconv.ParseUint(last, 10, 16)
	}
	if loErr != nil || hiErr != nil || lo == 0 || lo > hi {
		return 0, 0, fmt.Errorf("invalid ports %q: expected a port or ascending range from 1 to 65535", text)
	}
	return uint16(lo), uint16(hi), nil
}

func cloneNATPolicyConfig(cfg *NATPolicyConfig) *NATPolicyConfig {
	copy := *cfg
	copy.Egress.Rules = slices.Clone(cfg.Egress.Rules)
	copy.Ingress.Rules = slices.Clone(cfg.Ingress.Rules)
	return &copy
}

func natPolicyPortProtocol(protocol uint8) bool {
	return protocol == uint8(header.TCPProtocolNumber) || protocol == uint8(header.UDPProtocolNumber)
}

func natPolicyAddr(addr netip.Addr) netip.Addr {
	return addr.Unmap().WithZone("")
}

func (c *CompiledNATPolicy) allows(flow *NATPolicyFlow) bool {
	if c == nil {
		return true
	}
	if c.config == nil {
		return false
	}
	guest, remote := natPolicyAddr(flow.Guest), natPolicyAddr(flow.Remote)
	switch flow.Direction {
	case NATPolicyEgress:
		if !c.egress.allows(flow, guest, remote) {
			return false
		}
		alias := natPolicyAddr(flow.RemoteAlias)
		return !alias.IsValid() || alias == remote || c.egress.allows(flow, guest, alias)
	case NATPolicyIngress:
		// A Unix or otherwise unidentified peer does not have an IP policy relation.
		return remote.IsValid() && c.ingress.allows(flow, guest, remote)
	default:
		return false
	}
}

func (d *natPolicyDirection) allows(flow *NATPolicyFlow, guest, remote netip.Addr) bool {
	remoteKnown, guestKnown := remote.IsValid(), guest.IsValid()
	protocolKnown := flow.Protocol != 0
	noServicePort := protocolKnown && !natPolicyPortProtocol(flow.Protocol)
	for i := range d.rules {
		r := &d.rules[i]
		remoteRequired, guestRequired := r.remote.IsValid(), r.guest.IsValid()
		protocolRequired, portRequired := r.protocol != 0, r.minPort != 0
		if (remoteRequired && remoteKnown && !r.remote.Contains(remote)) ||
			(guestRequired && guestKnown && !r.guest.Contains(guest)) ||
			(protocolRequired && protocolKnown && r.protocol != flow.Protocol) ||
			(portRequired && noServicePort) ||
			(portRequired && flow.PortKnown && (flow.Port < r.minPort || flow.Port > r.maxPort)) {
			continue
		}
		// An unknown selector can change the decision only after all known selectors match.
		if (remoteRequired && !remoteKnown) || (guestRequired && !guestKnown) ||
			(protocolRequired && !protocolKnown) || (portRequired && (!protocolKnown || !flow.PortKnown)) {
			return false
		}
		return r.allow
	}
	return d.defaultAllow
}

// NATPolicy owns one live firewall. A nil controller admits all flows.
type NATPolicy struct {
	current         atomic.Pointer[CompiledNATPolicy]
	restoreRequired atomic.Bool
	controlAddr     netip.AddrPort
	mu              sync.Mutex
	tracked         map[*natPolicyRelation]struct{}
}

type natPolicyRelation struct {
	first      NATPolicyFlow
	additional []NATPolicyFlow
	cancel     context.CancelCauseFunc
}

var closedNATPolicy CompiledNATPolicy

// NewNATPolicy starts with a compiled policy or with nil for disabled. The control
// address is the bound TCP endpoint; use an invalid address for no TCP listener.
func NewNATPolicy(compiled *CompiledNATPolicy, controlAddr netip.AddrPort) *NATPolicy {
	p := &NATPolicy{controlAddr: netip.AddrPortFrom(natPolicyAddr(controlAddr.Addr()), controlAddr.Port())}
	p.restoreRequired.Store(compiled != nil && compiled.config != nil)
	p.current.Store(compiled)
	return p
}

// Active reports whether the controller has an enabled policy.
func (p *NATPolicy) Active() bool {
	if p == nil {
		return false
	}
	c := p.current.Load()
	return c != nil && c.config != nil
}

// RequiredOnRestore reports whether policy was ever active, even after Close.
func (p *NATPolicy) RequiredOnRestore() bool {
	return p != nil && p.restoreRequired.Load()
}

// Config returns an independent copy of the active policy, or nil if inactive.
func (p *NATPolicy) Config() *NATPolicyConfig {
	if p == nil {
		return nil
	}
	c := p.current.Load()
	if c == nil || c.config == nil {
		return nil
	}
	return cloneNATPolicyConfig(c.config)
}

// Allows evaluates the flow against one snapshot without locking or allocating.
func (p *NATPolicy) Allows(flow NATPolicyFlow) bool {
	return p == nil || p.current.Load().allows(&flow)
}

// AllowsHostDial denies TCP self-dials even when the firewall is inactive.
func (p *NATPolicy) AllowsHostDial(proto tcpip.TransportProtocolNumber, target netip.AddrPort) bool {
	return p == nil || proto != header.TCPProtocolNumber || allowsNATControlTCPDial(p.controlAddr, target)
}

func allowsNATControlTCPDial(listener, target netip.AddrPort) bool {
	if !listener.IsValid() || target.Port() != listener.Port() {
		return true
	}
	addr, control := natPolicyAddr(target.Addr()), natPolicyAddr(listener.Addr())
	if !addr.IsValid() || addr.IsUnspecified() {
		return false
	}
	if control.IsUnspecified() {
		// An IPv6 wildcard can also accept IPv4 connections on a dual-stack socket.
		return control.Is4() && !addr.Is4()
	}
	return addr != control
}

// Track authorizes every relation under one snapshot and returns a revocable context.
// Call release when the flow ends. Track registers flows even before policy activation.
func (p *NATPolicy) Track(ctx context.Context, flows ...NATPolicyFlow) (_ context.Context, release func(), ok bool) {
	if p == nil {
		return ctx, func() {}, true
	}
	if len(flows) == 0 {
		return ctx, nil, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.current.Load()
	if ctx.Err() != nil || !c.allowsAll(flows) {
		return ctx, nil, false
	}
	ctx, cancel := context.WithCancelCause(ctx)
	relation := &natPolicyRelation{first: flows[0], additional: slices.Clone(flows[1:]), cancel: cancel}
	if p.tracked == nil {
		p.tracked = make(map[*natPolicyRelation]struct{})
	}
	p.tracked[relation] = struct{}{}
	return ctx, func() {
		p.mu.Lock()
		delete(p.tracked, relation)
		p.mu.Unlock()
		cancel(nil)
	}, true
}

func (c *CompiledNATPolicy) allowsAll(flows []NATPolicyFlow) bool {
	for i := range flows {
		if !c.allows(&flows[i]) {
			return false
		}
	}
	return true
}

// Replace publishes both directions together and cancels relations the new policy denies.
func (p *NATPolicy) Replace(compiled *CompiledNATPolicy) error {
	if compiled == nil || compiled.config == nil {
		return errNATPolicyUncompiled
	}
	if p == nil {
		return errNATPolicyClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.current.Load() == &closedNATPolicy {
		return errNATPolicyClosed
	}
	for relation := range p.tracked {
		if !compiled.allows(&relation.first) || !compiled.allowsAll(relation.additional) {
			delete(p.tracked, relation)
			relation.cancel(ErrNATPolicyRevoked)
		}
	}
	p.restoreRequired.Store(true)
	p.current.Store(compiled)
	return nil
}

// Close cancels every relation and prevents further admissions or replacements.
func (p *NATPolicy) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for relation := range p.tracked {
		relation.cancel(nil)
	}
	p.tracked = nil
	p.current.Store(&closedNATPolicy)
}
