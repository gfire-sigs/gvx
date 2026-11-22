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
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MaxPolicyRules is the byte limit for each family rule file.
const MaxPolicyRules = 64 * 1024

const (
	// TCP DNS adds a two-byte length prefix to the largest DNS message.
	minPolicyBurst = max(maxUDPDatagram, maxDNSMessage+2)
	maxPolicyQueue = 64 << 20
	maxPolicyRate  = 1_000_000_000_000
)

// PolicyConfig replaces the rules and both directional limits together.
type PolicyConfig struct {
	RulesV4 string      `json:"rules_v4"`
	RulesV6 string      `json:"rules_v6"`
	TX      PolicyLimit `json:"qos_tx"`
	RX      PolicyLimit `json:"qos_rx"`
}

// PolicyLimit sets a directional rate in bits per second and byte capacities.
// The zero value means unlimited in Go; JSON requires the string "unlimited".
type PolicyLimit struct {
	RateBPS    uint64 `json:"rate_bps"`
	BurstBytes int    `json:"burst_bytes"`
	QueueBytes int    `json:"queue_bytes"`
}

// PolicyError describes a rejected configuration or unavailable policy.
type PolicyError struct {
	Code   string
	Family string
	Line   int
	Option string
	Detail string
}

func (e *PolicyError) Error() string {
	var b strings.Builder
	b.WriteString(e.Code)
	if e.Family != "" {
		fmt.Fprintf(&b, ": %s", e.Family)
		if e.Line > 0 {
			fmt.Fprintf(&b, ":%d", e.Line)
		}
	}
	if e.Option != "" {
		fmt.Fprintf(&b, ": %s", e.Option)
	}
	if e.Detail != "" {
		fmt.Fprintf(&b, ": %s", e.Detail)
	}
	return b.String()
}

func invalidPolicyLimit(detail string) *PolicyError {
	return &PolicyError{Code: "invalid_policy", Detail: detail}
}

func (l PolicyLimit) validate() *PolicyError {
	if l == (PolicyLimit{}) {
		return nil
	}
	if l.RateBPS == 0 || l.RateBPS > maxPolicyRate {
		return invalidPolicyLimit(fmt.Sprintf("rate must be between 1 and %d bits per second", maxPolicyRate))
	}
	if l.BurstBytes < minPolicyBurst || l.BurstBytes > maxPolicyQueue {
		return invalidPolicyLimit(fmt.Sprintf("burst must be between %d and %d bytes", minPolicyBurst, maxPolicyQueue))
	}
	if l.QueueBytes < l.BurstBytes || l.QueueBytes > maxPolicyQueue {
		return invalidPolicyLimit(fmt.Sprintf("queue must be at least the burst and at most %d bytes", maxPolicyQueue))
	}
	return nil
}

type policyLimitFields struct {
	values [3]uint64
	seen   uint8
}

func (f *policyLimitFields) set(field int, value string) *PolicyError {
	bit := uint8(1 << field)
	if f.seen&bit != 0 {
		return invalidPolicyLimit("duplicate limit field")
	}
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || n == 0 {
		return invalidPolicyLimit("limit fields must be positive integers")
	}
	f.seen |= bit
	f.values[field] = n
	return nil
}

func (f policyLimitFields) limit() (PolicyLimit, error) {
	if f.seen != 0b111 {
		return PolicyLimit{}, invalidPolicyLimit("limit requires rate, burst, and queue fields")
	}
	if f.values[1] > maxPolicyQueue || f.values[2] > maxPolicyQueue {
		return PolicyLimit{}, invalidPolicyLimit(fmt.Sprintf("burst and queue must not exceed %d bytes", maxPolicyQueue))
	}
	l := PolicyLimit{RateBPS: f.values[0], BurstBytes: int(f.values[1]), QueueBytes: int(f.values[2])}
	if err := l.validate(); err != nil {
		return PolicyLimit{}, err
	}
	return l, nil
}

// ParsePolicyLimit parses unlimited or the three named integer CLI fields.
func ParsePolicyLimit(s string) (PolicyLimit, error) {
	if s == "unlimited" {
		return PolicyLimit{}, nil
	}
	var fields policyLimitFields
	for part := range strings.SplitSeq(s, ",") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return PolicyLimit{}, invalidPolicyLimit("limit fields require name=value")
		}
		var field int
		switch key {
		case "rate-bps":
			field = 0
		case "burst-bytes":
			field = 1
		case "queue-bytes":
			field = 2
		default:
			return PolicyLimit{}, invalidPolicyLimit("unknown limit field")
		}
		if err := fields.set(field, value); err != nil {
			return PolicyLimit{}, err
		}
	}
	return fields.limit()
}

// MarshalJSON encodes an unlimited or finite limit in the policy wire format.
func (l PolicyLimit) MarshalJSON() ([]byte, error) {
	if l == (PolicyLimit{}) {
		return []byte(`"unlimited"`), nil
	}
	if err := l.validate(); err != nil {
		return nil, err
	}
	type wireLimit PolicyLimit
	return json.Marshal(wireLimit(l))
}

// UnmarshalJSON rejects missing, duplicate, unknown, and noninteger fields.
func (l *PolicyLimit) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	first, err := dec.Token()
	if err != nil {
		return invalidPolicyLimit("expected unlimited or an object")
	}
	var limit PolicyLimit
	switch first {
	case "unlimited":
	case json.Delim('{'):
		limit, err = decodeFinitePolicyLimit(dec)
		if err != nil {
			return err
		}
	default:
		return invalidPolicyLimit("expected unlimited or an object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return invalidPolicyLimit("unexpected data after limit")
	}
	*l = limit
	return nil
}

func decodeFinitePolicyLimit(dec *json.Decoder) (PolicyLimit, error) {
	var fields policyLimitFields
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return PolicyLimit{}, invalidPolicyLimit("invalid limit field")
		}
		var field int
		switch key {
		case "rate_bps":
			field = 0
		case "burst_bytes":
			field = 1
		case "queue_bytes":
			field = 2
		default:
			return PolicyLimit{}, invalidPolicyLimit("unknown limit field")
		}
		value, err := dec.Token()
		n, ok := value.(json.Number)
		if err != nil || !ok {
			return PolicyLimit{}, invalidPolicyLimit("limit fields must be positive integers")
		}
		if err := fields.set(field, string(n)); err != nil {
			return PolicyLimit{}, err
		}
	}
	if end, err := dec.Token(); err != nil || end != json.Delim('}') {
		return PolicyLimit{}, invalidPolicyLimit("invalid limit object")
	}
	return fields.limit()
}

// CompiledPolicy is an immutable, validated policy shared by all NAT paths.
type CompiledPolicy struct {
	config PolicyConfig
	rules  *policyPrograms
}

// CompilePolicy validates a complete replacement without changing live state.
func CompilePolicy(config PolicyConfig) (*CompiledPolicy, error) {
	if err := config.TX.validate(); err != nil {
		err.Option = "qos_tx"
		return nil, err
	}
	if err := config.RX.validate(); err != nil {
		err.Option = "qos_rx"
		return nil, err
	}
	rules, err := compilePolicyRules(config.RulesV4, config.RulesV6)
	if err != nil {
		return nil, err
	}
	return &CompiledPolicy{config: config, rules: rules}, nil
}

func (c *CompiledPolicy) allows(chain PolicyChain, tuples []PolicyTuple) bool {
	if c == nil || c.rules == nil || len(tuples) == 0 || chain > PolicyForward {
		return false
	}
	for _, tuple := range tuples {
		if !c.rules.allows(chain, tuple) {
			return false
		}
	}
	return true
}

var (
	// ErrPolicyDenied indicates that a handoff cannot proceed under live policy.
	ErrPolicyDenied = errors.New("netbackend: NAT policy denied transfer")
	// ErrPolicyQueueFull indicates that a transfer exceeds a live capacity.
	ErrPolicyQueueFull = errors.New("netbackend: NAT policy queue full")
)

// NATPolicy owns one sandbox's active policy, admitted work, and QoS state.
// A nil *NATPolicy leaves the legacy NAT path unrestricted.
type NATPolicy struct {
	update     sync.Mutex                       // serializes Commit and Close
	transition atomic.Pointer[policyTransition] // stays set after Close
	gate       sync.RWMutex
	active     *CompiledPolicy
	release    func()
	control    netip.AddrPort
	dialCtx    context.Context
	cancelDial context.CancelFunc
	done       chan struct{}

	streamsMu    sync.Mutex
	streams      map[*policyStream]struct{}
	streamCounts [2]int
	tx, rx       policyScheduler
	workers      sync.WaitGroup
}

type policyTransition struct {
	published chan struct{}
}

// NewNATPolicy activates a compiled policy without initial token credit.
func NewNATPolicy(compiled *CompiledPolicy, control netip.AddrPort) *NATPolicy {
	p := &NATPolicy{active: compiled, control: policyControlAddr(control), done: make(chan struct{})}
	p.release = p.gate.RUnlock
	p.dialCtx, p.cancelDial = context.WithCancel(context.Background())
	var tx, rx PolicyLimit
	if compiled != nil {
		tx, rx = compiled.config.TX, compiled.config.RX
	}
	now := time.Now()
	p.tx.init(tx, now)
	p.rx.init(rx, now)
	p.workers.Go(func() { p.tx.run(p) })
	p.workers.Go(func() { p.rx.run(p) })
	return p
}

func policyControlAddr(addr netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(addr.Addr().Unmap().WithZone(""), addr.Port())
}

func (p *NATPolicy) tryRead() func() {
	release := p.release
	if release == nil || p.transition.Load() != nil || !p.gate.TryRLock() {
		return nil
	}
	if p.transition.Load() != nil {
		p.gate.RUnlock() // +checklocksforce: TryRLock succeeded before cutover.
		return nil
	}
	return release
}

// Allow evaluates all legs against one rule snapshot without waiting at cutover.
func (p *NATPolicy) Allow(chain PolicyChain, tuples ...PolicyTuple) bool {
	if p == nil {
		return true
	}
	release := p.tryRead()
	if release == nil {
		return false
	}
	allowed := p.active.allows(chain, tuples)
	release()
	return allowed
}

func noopPolicyRelease() {}

// Begin pins the active rule snapshot for a nonblocking final handoff.
// Call release exactly once after a permitted handoff.
func (p *NATPolicy) Begin(chain PolicyChain, tuples ...PolicyTuple) (release func(), allowed bool) {
	if p != nil && len(tuples) == 0 {
		return noopPolicyRelease, false
	}
	return p.beginUnshaped(chain, false, tuples...)
}

func (p *NATPolicy) beginUnshaped(chain PolicyChain, requireUnlimited bool, tuples ...PolicyTuple) (func(), bool) {
	if p == nil {
		return noopPolicyRelease, true
	}
	release := p.tryRead()
	if release == nil {
		return noopPolicyRelease, false
	}
	// Inside the synchronous TX pipe, the peer INPUT hook owns the tuple.
	active := p.active
	peerInput := len(tuples) == 0 && chain == PolicyInput && active != nil && active.rules != nil
	if !peerInput && !active.allows(chain, tuples) {
		release()
		return noopPolicyRelease, false
	}
	if requireUnlimited {
		limit := active.config.TX
		if chain == PolicyOutput {
			limit = active.config.RX
		}
		if limit.RateBPS != 0 {
			release()
			return noopPolicyRelease, false
		}
	}
	return release, true
}

// HostDialAllowed rejects protected guest paths to the management listener.
func (p *NATPolicy) HostDialAllowed(target netip.AddrPort) bool {
	if p == nil {
		return true
	}
	target = policyControlAddr(target)
	// Socket dialers can replace an unspecified destination with loopback.
	if !target.IsValid() || target.Addr().IsUnspecified() || target.Port() == 0 {
		return false
	}
	if !p.control.IsValid() || p.control.Port() != target.Port() {
		return true
	}
	return !p.control.Addr().IsUnspecified() && p.control != target
}

// Dial authorizes a context-aware dial before it can submit a connection.
// Commit cancels and settles pending dials before it replaces the rules.
func (p *NATPolicy) Dial(ctx context.Context, chain PolicyChain, dial func(context.Context) (net.Conn, error), tuples ...PolicyTuple) (net.Conn, error) {
	if p == nil {
		return dial(ctx)
	}
	release, allowed := p.Begin(chain, tuples...)
	if !allowed {
		return nil, ErrPolicyDenied
	}
	defer release()
	if p.dialCtx.Err() != nil {
		return nil, ErrPolicyDenied
	}
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(p.dialCtx, cancel)
	defer stop()
	conn, err := dial(dialCtx)
	if p.transition.Load() != nil {
		if conn != nil {
			return nil, errors.Join(ErrPolicyDenied, conn.Close())
		}
		return nil, ErrPolicyDenied
	}
	return conn, err
}

// Commit replaces the rules and QoS limits after pending handoffs settle.
func (p *NATPolicy) Commit(compiled *CompiledPolicy) error {
	if p == nil || p.done == nil || compiled == nil || compiled.rules == nil {
		return &PolicyError{Code: "invalid_policy", Detail: "invalid live policy commit"}
	}
	p.update.Lock()
	defer p.update.Unlock()
	if p.active == nil {
		return ErrPolicyDenied
	}
	transition := &policyTransition{published: make(chan struct{})}
	// Stop earning credit when admission closes, before waiting for pinned work.
	freeze := time.Now()
	p.transition.Store(transition)
	p.cancelDial()
	p.gate.Lock()
	txDropped := p.tx.replace(compiled, compiled.config.TX, freeze)
	rxDropped := p.rx.replace(compiled, compiled.config.RX, freeze)
	p.streamsMu.Lock()
	for stream := range p.streams {
		if !compiled.allows(stream.chain, stream.tuples) {
			stream.cancel(ErrPolicyDenied)
		}
	}
	p.streamsMu.Unlock()
	p.active = compiled
	p.dialCtx, p.cancelDial = context.WithCancel(context.Background())
	now := time.Now()
	p.tx.bucket.last, p.rx.bucket.last = now, now
	p.gate.Unlock()
	p.transition.Store(nil)
	close(transition.published)
	p.tx.signal()
	p.rx.signal()
	finishPolicyWork(txDropped, ErrPolicyDenied)
	finishPolicyWork(rxDropped, ErrPolicyDenied)
	return nil
}

// Close cancels pending traffic and waits for pinned handoffs to finish.
func (p *NATPolicy) Close() {
	if p == nil || p.done == nil {
		return
	}
	p.update.Lock()
	defer p.update.Unlock()
	if p.transition.Load() != nil {
		return
	}
	p.transition.Store(&policyTransition{})
	p.cancelDial()
	p.gate.Lock()
	p.active = nil
	p.streamsMu.Lock()
	for stream := range p.streams {
		stream.cancel(ErrPolicyDenied)
	}
	p.streamsMu.Unlock()
	close(p.done)
	p.gate.Unlock()
	p.workers.Wait()
}
