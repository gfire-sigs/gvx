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
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"z.gfire.dev/gvx/pkg/tcpip/header"
)

// PolicyChain selects a hook on the private NAT peer.
type PolicyChain uint8

const (
	PolicyInput PolicyChain = iota
	PolicyOutput
	PolicyForward
	policyChainCount
)

// PolicyTuple holds the fields known for one leg of a transfer. An invalid
// address means unknown; the Known fields distinguish unknown from zero.
type PolicyTuple struct {
	IPv6                                  bool
	Protocol                              uint8
	ProtocolKnown                         bool
	Source, Destination                   netip.Addr
	SourcePort, DestinationPort           uint16
	SourcePortKnown, DestinationPortKnown bool
}

// Reverse returns the tuple for the opposite direction of the same leg.
func (t PolicyTuple) Reverse() PolicyTuple {
	t.Source, t.Destination = t.Destination, t.Source
	t.SourcePort, t.DestinationPort = t.DestinationPort, t.SourcePort
	t.SourcePortKnown, t.DestinationPortKnown = t.DestinationPortKnown, t.SourcePortKnown
	return t
}

const (
	maxPolicyVisits = 4096
	maxPolicyJumps  = 32
	maxPolicyPorts  = 15
)

var policyEntryNames = [policyChainCount]string{"INPUT", "OUTPUT", "FORWARD"}

type policyPrograms struct {
	v4, v6 []policyChainProgram
}

type policyChainProgram struct {
	rules  []policyRule
	accept bool
}

type policyTarget int

const (
	policyAccept policyTarget = -1 - iota
	policyDrop
	policyReturn
)

// Nonnegative targets index a user chain.
type policyRule struct {
	source, destination netip.Prefix
	target              policyTarget
	ports               []policyPortSelector
	protocol            uint8 // Zero matches all protocols, including unknown ones.
	negateSource        bool
	negateDestination   bool
	negateProtocol      bool
}

type policyPortDirection uint8

const (
	policySourcePort policyPortDirection = iota
	policyDestinationPort
	policyEitherPort
)

type policyPortSelector struct {
	ranges    []policyPortRange
	direction policyPortDirection
	negate    bool
}

type policyPortRange struct {
	low, high uint16
}

type policyMatch uint8

const (
	policyMatchNo policyMatch = iota
	policyMatchYes
	policyMatchUnknown
)

func (p *policyPrograms) allows(entry PolicyChain, t PolicyTuple) bool {
	if entry >= policyChainCount {
		return false
	}
	chains := p.v4
	if t.IPv6 {
		chains = p.v6
	}
	// Prefix.Contains does not match scoped addresses. Scope is not a selector.
	if t.Source.Zone() != "" {
		t.Source = t.Source.WithZone("")
	}
	if t.Destination.Zone() != "" {
		t.Destination = t.Destination.WithZone("")
	}
	type continuation struct{ chain, next int }
	var returns [maxPolicyJumps]continuation
	chain, next, depth := int(entry), 0, 0
	for {
		rules := chains[chain].rules
		if next == len(rules) {
			if depth == 0 {
				return chains[entry].accept
			}
			depth--
			chain, next = returns[depth].chain, returns[depth].next
			continue
		}
		rule := &rules[next]
		next++
		switch rule.match(&t) {
		case policyMatchNo:
			continue
		case policyMatchUnknown:
			return false
		}
		switch rule.target {
		case policyAccept:
			return true
		case policyDrop:
			return false
		case policyReturn:
			next = len(rules)
		default:
			returns[depth] = continuation{chain, next}
			depth++
			chain, next = int(rule.target), 0
		}
	}
}

func (r *policyRule) match(t *PolicyTuple) policyMatch {
	unknown := false
	if r.protocol != 0 {
		if !t.ProtocolKnown {
			unknown = true
		} else if (t.Protocol == r.protocol) == r.negateProtocol {
			return policyMatchNo
		}
	}
	if r.source.IsValid() {
		if !t.Source.IsValid() {
			unknown = true
		} else if r.source.Contains(t.Source) == r.negateSource {
			return policyMatchNo
		}
	}
	if r.destination.IsValid() {
		if !t.Destination.IsValid() {
			unknown = true
		} else if r.destination.Contains(t.Destination) == r.negateDestination {
			return policyMatchNo
		}
	}
	for i := range r.ports {
		switch r.ports[i].match(t) {
		case policyMatchNo:
			return policyMatchNo
		case policyMatchUnknown:
			unknown = true
		}
	}
	if unknown {
		return policyMatchUnknown
	}
	return policyMatchYes
}

func (s *policyPortSelector) match(t *PolicyTuple) policyMatch {
	unknown := false
	if s.direction != policyDestinationPort {
		if !t.SourcePortKnown {
			unknown = true
		} else if s.contains(t.SourcePort) {
			if s.negate {
				return policyMatchNo
			}
			return policyMatchYes
		}
	}
	if s.direction != policySourcePort {
		if !t.DestinationPortKnown {
			unknown = true
		} else if s.contains(t.DestinationPort) {
			if s.negate {
				return policyMatchNo
			}
			return policyMatchYes
		}
	}
	if unknown {
		return policyMatchUnknown
	}
	if s.negate {
		return policyMatchYes
	}
	return policyMatchNo
}

func (s *policyPortSelector) contains(port uint16) bool {
	for _, span := range s.ranges {
		if span.low <= port && port <= span.high {
			return true
		}
	}
	return false
}

func compilePolicyRules(v4, v6 string) (*policyPrograms, error) {
	ipv4, err := compilePolicyFamily(v4, "ipv4", false)
	if err != nil {
		return nil, err
	}
	ipv6, err := compilePolicyFamily(v6, "ipv6", true)
	if err != nil {
		return nil, err
	}
	return &policyPrograms{v4: ipv4, v6: ipv6}, nil
}

type policyRuleSource struct {
	family string
	line   int
}

func (s policyRuleSource) error(code, option, detail string) *PolicyError {
	return &PolicyError{Code: code, Family: s.family, Line: s.line, Option: option, Detail: detail}
}

func (s policyRuleSource) invalid(option, detail string) *PolicyError {
	return s.error("invalid_policy", option, detail)
}

func (s policyRuleSource) unsupported(option, detail string) *PolicyError {
	return s.error("unsupported_rule", option, detail)
}

type policyFamilyCompiler struct {
	ipv6   bool
	state  policyParseState
	chains []policyChainProgram
	names  map[string]int
	lines  [][]int
}

type policyParseState uint8

const (
	policyBeforeTable policyParseState = iota
	policyDeclarations
	policyRules
	policyAfterCommit
)

func compilePolicyFamily(text, family string, ipv6 bool) ([]policyChainProgram, error) {
	source := policyRuleSource{family: family}
	if len(text) > MaxPolicyRules {
		return nil, source.error("too_large", "", "rule file exceeds 64 KiB")
	}
	c := policyFamilyCompiler{
		ipv6:   ipv6,
		chains: make([]policyChainProgram, policyChainCount),
		names:  make(map[string]int),
		lines:  make([][]int, policyChainCount),
	}
	for raw := range strings.Lines(text) {
		source.line++
		line := strings.TrimSuffix(strings.TrimSuffix(raw, "\r\n"), "\n")
		if !utf8.ValidString(line) || strings.IndexFunc(line, func(r rune) bool {
			return (r < ' ' && r != '\t') || r == 0x7f
		}) >= 0 {
			return nil, source.invalid("", "expected UTF-8 text without control characters")
		}
		line = strings.Trim(line, " \t")
		if line == "" || line[0] == '#' {
			continue
		}
		if err := c.addLine(source, line); err != nil {
			return nil, err
		}
	}
	source.line = max(source.line, 1)
	if c.state != policyAfterCommit {
		if c.state == policyBeforeTable {
			return nil, source.invalid("*filter", "missing filter table")
		}
		return nil, source.invalid("COMMIT", "missing COMMIT")
	}
	for _, name := range policyEntryNames {
		if _, declared := c.names[name]; !declared {
			return nil, source.invalid(name, "missing built-in chain")
		}
	}
	if err := c.validateGraph(family); err != nil {
		return nil, err
	}
	return c.chains, nil
}

func (c *policyFamilyCompiler) addLine(s policyRuleSource, line string) error {
	switch {
	case c.state == policyAfterCommit:
		return s.invalid("COMMIT", "unexpected content after COMMIT")
	case line[0] == '*':
		if c.state != policyBeforeTable || line != "*filter" {
			table, _, _ := strings.Cut(line, " ")
			table, _, _ = strings.Cut(table, "\t")
			return s.unsupported(table, "expected exactly one filter table")
		}
		c.state = policyDeclarations
		return nil
	case c.state == policyBeforeTable:
		return s.invalid("*filter", "expected filter table")
	case line == "COMMIT":
		c.state = policyAfterCommit
		return nil
	case line[0] == ':':
		if c.state != policyDeclarations {
			return s.invalid(":", "chain declarations must precede rules")
		}
		return c.addChain(s, line)
	default:
		c.state = policyRules
		return c.addRule(s, line)
	}
}

func (c *policyFamilyCompiler) addChain(s policyRuleSource, line string) error {
	words := strings.Fields(line)
	if len(words) < 2 || len(words) > 3 {
		return s.invalid(":", "expected chain name, policy, and optional counters")
	}
	name := words[0][1:]
	if !validPolicyChainName(name) || name == "ACCEPT" || name == "DROP" || name == "RETURN" {
		return s.invalid(":", "invalid chain name")
	}
	if _, exists := c.names[name]; exists {
		return s.invalid(name, "duplicate chain")
	}
	if len(words) == 3 && !validPolicyCounters(words[2]) {
		return s.invalid("[packets:bytes]", "invalid chain counters")
	}
	for i, builtin := range policyEntryNames {
		if name != builtin {
			continue
		}
		switch words[1] {
		case "ACCEPT":
			c.chains[i].accept = true
		case "DROP":
		default:
			return s.invalid(name, "built-in policy must be ACCEPT or DROP")
		}
		c.names[name] = i
		return nil
	}
	if words[1] != "-" {
		return s.invalid(name, "user chain policy must be -")
	}
	c.names[name] = len(c.chains)
	c.chains = append(c.chains, policyChainProgram{})
	c.lines = append(c.lines, nil)
	return nil
}

func validPolicyChainName(name string) bool {
	if name == "" || strings.ContainsAny(name[:1], "-!:") {
		return false
	}
	return !strings.ContainsAny(name, " \t\"\\")
}

func validPolicyCounters(word string) bool {
	if len(word) < 5 || word[0] != '[' || word[len(word)-1] != ']' {
		return false
	}
	packets, octets, ok := strings.Cut(word[1:len(word)-1], ":")
	if !ok {
		return false
	}
	_, packetsOK := policyDecimal(packets, 64)
	_, octetsOK := policyDecimal(octets, 64)
	return packetsOK && octetsOK
}

func policyDecimal(word string, bits int) (uint64, bool) {
	if word == "" {
		return 0, false
	}
	for i := range len(word) {
		if word[i] < '0' || word[i] > '9' {
			return 0, false
		}
	}
	value, err := strconv.ParseUint(word, 10, bits)
	return value, err == nil
}

func (c *policyFamilyCompiler) addRule(s policyRuleSource, line string) error {
	words, err := policyRuleWords(s, line)
	if err != nil {
		return err
	}
	if strings.HasPrefix(words[0], "[") {
		if !validPolicyCounters(words[0]) {
			return s.invalid("[packets:bytes]", "invalid rule counters")
		}
		words = words[1:]
	}
	if len(words) < 2 || words[0] != "-A" {
		return s.unsupported("-A", "expected an append rule")
	}
	chain, ok := c.names[words[1]]
	if !ok {
		return s.invalid("-A", "undefined source chain")
	}
	rule, err := c.parseRule(s, words[2:])
	if err != nil {
		return err
	}
	c.chains[chain].rules = append(c.chains[chain].rules, rule)
	c.lines[chain] = append(c.lines[chain], s.line)
	return nil
}

func policyRuleWords(s policyRuleSource, line string) ([]string, error) {
	var words []string
	for line != "" {
		end := 0
		if line[0] == '"' {
			end = policyQuotedEnd(line)
			if end == 0 || (end < len(line) && line[end] != ' ' && line[end] != '\t') {
				return nil, s.invalid("--comment", "invalid quoted text")
			}
		} else {
			end = strings.IndexAny(line, " \t")
			if end < 0 {
				end = len(line)
			}
			if strings.ContainsAny(line[:end], "\"\\") {
				return nil, s.invalid("", "unexpected quote or escape")
			}
		}
		words = append(words, line[:end])
		line = strings.TrimLeft(line[end:], " \t")
	}
	return words, nil
}

func policyQuotedEnd(word string) int {
	for i := 1; i < len(word); i++ {
		switch word[i] {
		case '"':
			return i + 1
		case '\\':
			i++
			if i == len(word) || (word[i] != '\\' && word[i] != '"') {
				return 0
			}
		}
	}
	return 0
}

type policyModule uint8

const (
	policyTCPModule policyModule = 1 << iota
	policyUDPModule
	policyMultiportModule
	policyCommentModule
)

func (c *policyFamilyCompiler) parseRule(s policyRuleSource, words []string) (policyRule, error) {
	var rule policyRule
	var modules, module policyModule
	var protocolSet, targetSet, sourcePortSet, destPortSet, multiportSet, commentSet bool
	for len(words) != 0 {
		negate := words[0] == "!"
		if negate {
			words = words[1:]
		}
		if len(words) == 0 {
			return policyRule{}, s.invalid("!", "missing selector")
		}
		option := words[0]
		switch option {
		case "-m", "-j", "--comment":
			if negate {
				return policyRule{}, s.invalid(option, "option does not accept negation")
			}
		case "-s", "-d", "-p", "--sport", "--dport", "--sports", "--dports", "--ports":
		default:
			if !strings.HasPrefix(option, "-") {
				return policyRule{}, s.invalid("-A", "expected a rule option")
			}
			return policyRule{}, s.unsupported(option, "option is outside the filter profile")
		}
		if len(words) < 2 || (option != "--comment" && (words[1] == "!" || strings.HasPrefix(words[1], `"`))) {
			return policyRule{}, s.invalid(option, "expected an argument")
		}
		value := words[1]
		words = words[2:]
		switch option {
		case "-s", "-d":
			prefix, ok := parsePolicyPrefix(value, c.ipv6)
			if !ok {
				return policyRule{}, s.invalid(option, "expected a numeric address or CIDR of this family")
			}
			if option == "-s" && !rule.source.IsValid() {
				rule.source, rule.negateSource = prefix, negate
			} else if option == "-d" && !rule.destination.IsValid() {
				rule.destination, rule.negateDestination = prefix, negate
			} else {
				return policyRule{}, s.invalid(option, "duplicate address selector")
			}
		case "-p":
			protocol, ok := parsePolicyProtocol(value, c.ipv6)
			if !ok || (protocol == 0 && negate) || protocolSet {
				return policyRule{}, s.invalid(option, "invalid or duplicate protocol selector")
			}
			rule.protocol, rule.negateProtocol, protocolSet = protocol, negate, true
		case "-m":
			switch value {
			case "tcp":
				module = policyTCPModule
			case "udp":
				module = policyUDPModule
			case "multiport":
				module = policyMultiportModule
			case "comment":
				module = policyCommentModule
			default:
				return policyRule{}, s.unsupported(option, "match module is outside the filter profile")
			}
			if modules&module != 0 {
				return policyRule{}, s.invalid(option, "duplicate match module")
			}
			modules |= module
		case "--sport", "--dport":
			if module != policyTCPModule && module != policyUDPModule {
				return policyRule{}, s.invalid(option, "port selector requires its TCP or UDP match module")
			}
			span, ok := parsePolicyPortRange(value, true)
			if !ok {
				return policyRule{}, s.invalid(option, "expected a numeric port or inclusive range")
			}
			direction := policySourcePort
			if option == "--sport" && !sourcePortSet {
				sourcePortSet = true
			} else if option == "--dport" && !destPortSet {
				destPortSet, direction = true, policyDestinationPort
			} else {
				return policyRule{}, s.invalid(option, "duplicate port selector")
			}
			rule.ports = append(rule.ports, policyPortSelector{[]policyPortRange{span}, direction, negate})
		case "--sports", "--dports", "--ports":
			if module != policyMultiportModule || multiportSet {
				return policyRule{}, s.invalid(option, "expected one list per multiport match module")
			}
			multiportSet = true
			spans, ok := parsePolicyPortList(value)
			if !ok {
				return policyRule{}, s.invalid(option, "expected numeric ports or ranges in at most 15 port slots")
			}
			direction := policyEitherPort
			if option == "--sports" {
				direction = policySourcePort
			} else if option == "--dports" {
				direction = policyDestinationPort
			}
			rule.ports = append(rule.ports, policyPortSelector{spans, direction, negate})
		case "--comment":
			if module != policyCommentModule || commentSet {
				return policyRule{}, s.invalid(option, "expected one comment per comment match module")
			}
			commentSet = true
		case "-j":
			if targetSet {
				return policyRule{}, s.invalid(option, "duplicate target")
			}
			targetSet = true
			switch value {
			case "ACCEPT":
				rule.target = policyAccept
			case "DROP":
				rule.target = policyDrop
			case "RETURN":
				rule.target = policyReturn
			default:
				target, ok := c.names[value]
				if !ok || target < int(policyChainCount) {
					return policyRule{}, s.unsupported(option, "expected ACCEPT, DROP, RETURN, or a declared user chain")
				}
				rule.target = policyTarget(target)
			}
		}
	}
	if !targetSet {
		return policyRule{}, s.invalid("-j", "missing target")
	}
	if modules&policyCommentModule != 0 && !commentSet {
		return policyRule{}, s.invalid("--comment", "missing comment")
	}
	if modules&policyMultiportModule != 0 && !multiportSet {
		return policyRule{}, s.invalid("-m", "multiport requires a port list")
	}
	tcp := rule.protocol == uint8(header.TCPProtocolNumber) && !rule.negateProtocol
	udp := rule.protocol == uint8(header.UDPProtocolNumber) && !rule.negateProtocol
	if (modules&policyTCPModule != 0 && !tcp) || (modules&policyUDPModule != 0 && !udp) ||
		(modules&policyMultiportModule != 0 && !tcp && !udp) {
		return policyRule{}, s.invalid("-p", "port match module requires a matching TCP or UDP protocol")
	}
	return rule, nil
}

func parsePolicyPrefix(value string, ipv6 bool) (netip.Prefix, bool) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		return prefix.Masked(), err == nil && prefix.Addr().Is6() == ipv6
	}
	addr, err := netip.ParseAddr(value)
	return netip.PrefixFrom(addr, addr.BitLen()), err == nil && addr.Zone() == "" && addr.Is6() == ipv6
}

func parsePolicyProtocol(value string, ipv6 bool) (uint8, bool) {
	const icmp4 = uint8(header.ICMPv4ProtocolNumber)
	const icmp6 = uint8(header.ICMPv6ProtocolNumber)
	switch value {
	case "all":
		return 0, true
	case "tcp":
		return uint8(header.TCPProtocolNumber), true
	case "udp":
		return uint8(header.UDPProtocolNumber), true
	case "icmp":
		return icmp4, !ipv6
	case "ipv6-icmp":
		return icmp6, ipv6
	}
	proto, ok := policyDecimal(value, 8)
	return uint8(proto), ok && !(ipv6 && uint8(proto) == icmp4) && !(!ipv6 && uint8(proto) == icmp6)
}

func parsePolicyPortRange(value string, open bool) (policyPortRange, bool) {
	low, high, rangeSyntax := strings.Cut(value, ":")
	lo, lowOK := policyDecimal(low, 16)
	if !rangeSyntax {
		return policyPortRange{uint16(lo), uint16(lo)}, lowOK
	}
	hi, highOK := policyDecimal(high, 16)
	if open && low == "" {
		lowOK = true
	}
	if open && high == "" {
		hi, highOK = 65535, true
	}
	return policyPortRange{uint16(lo), uint16(hi)}, lowOK && highOK && lo <= hi
}

func parsePolicyPortList(list string) ([]policyPortRange, bool) {
	var spans []policyPortRange
	slots := 0
	for item := range strings.SplitSeq(list, ",") {
		slots++
		if strings.Contains(item, ":") {
			slots++
		}
		if slots > maxPolicyPorts {
			return nil, false
		}
		span, ok := parsePolicyPortRange(item, false)
		if !ok {
			return nil, false
		}
		spans = append(spans, span)
	}
	return spans, true
}

type policyChainBound struct {
	active, done  bool
	jumps, visits int
}

func (c *policyFamilyCompiler) validateGraph(family string) error {
	bounds := make([]policyChainBound, len(c.chains))
	for i := range c.chains {
		bound, err := c.boundChain(i, 0, bounds, policyRuleSource{family: family})
		if err != nil {
			return err
		}
		if i < int(policyChainCount) && bound.visits > maxPolicyVisits {
			return &PolicyError{Code: "too_large", Family: family, Option: policyEntryNames[i], Detail: "entry chain exceeds 4096 rule visits"}
		}
	}
	return nil
}

func (c *policyFamilyCompiler) boundChain(index, depth int, bounds []policyChainBound, source policyRuleSource) (policyChainBound, error) {
	bound := &bounds[index]
	if bound.active {
		return policyChainBound{}, source.invalid("-j", "cyclic chain jump")
	}
	if depth+bound.jumps > maxPolicyJumps {
		return policyChainBound{}, source.invalid("-j", "chain jump depth exceeds 32")
	}
	if bound.done {
		return *bound, nil
	}
	bound.active = true
	rules := c.chains[index].rules
	bound.visits = min(len(rules), maxPolicyVisits+1)
	for i := range rules {
		if rules[i].target < 0 {
			continue
		}
		source.line = c.lines[index][i]
		child, err := c.boundChain(int(rules[i].target), depth+1, bounds, source)
		if err != nil {
			return policyChainBound{}, err
		}
		bound.jumps = max(bound.jumps, 1+child.jumps)
		if bound.visits <= maxPolicyVisits {
			// The callee can return at every call site, even after a previous call.
			bound.visits = min(bound.visits+child.visits, maxPolicyVisits+1)
		}
	}
	bound.active, bound.done = false, true
	return *bound, nil
}
