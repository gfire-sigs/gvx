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

package netfilter

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// This file implements the iptables "limit" match (net/netfilter/xt_limit.c).
// A rule such as "-m limit --limit 10/minute --limit-burst 10" matches until
// the token bucket of the rule is empty. The bucket gains credit with time and
// each matching packet costs credit. kube-router and Calico use the match to
// rate-limit logging rules.

const (
	matcherNameLimit = "limit"

	// limitInfoSize is sizeof(struct xt_rateinfo) on a 64-bit kernel: avg,
	// burst, the 8-byte prev, credit, credit_cap, cost, 4 bytes of padding, and
	// the 8-byte master pointer.
	limitInfoSize = 40

	// limitScale is XT_LIMIT_SCALE. The avg field counts time in units of
	// 1/limitScale second.
	limitScale = 10000

	// limitHZ is the tick rate of the credit clock. The clock of the stack
	// counts nanoseconds, and the bucket converts them to ticks.
	limitHZ = 1000

	// limitMaxCPJ is MAX_CPJ: the credits for each tick that still allow the
	// slowest rate of userspace, one packet for each day, in 32 bits.
	limitMaxCPJ = 0xFFFFFFFF / (limitHZ * 60 * 60 * 24)

	// limitCreditsPerTick is CREDITS_PER_JIFFY: the largest power of 2 that is
	// not above limitMaxCPJ. The two assertions below fail to compile when
	// the value does not fit limitMaxCPJ.
	limitCreditsPerTick = 32
)

const (
	_ = uint(limitMaxCPJ - limitCreditsPerTick)
	_ = uint(2*limitCreditsPerTick - limitMaxCPJ - 1)
)

// Byte offsets of the fields of struct xt_rateinfo.
const (
	limitOffAvg       = 0
	limitOffBurst     = 4
	limitOffCredit    = 16
	limitOffCreditCap = 20
	limitOffCost      = 24
)

func init() {
	registerMatchMaker(limitMarshaler{})
}

// limitMarshaler implements matchMaker for the limit match.
type limitMarshaler struct{}

// name implements matchMaker.name.
func (limitMarshaler) name() string { return matcherNameLimit }

// revision implements matchMaker.revision.
func (limitMarshaler) revision() uint8 { return 0 }

// marshal implements matchMaker.marshal. Linux copies the user part of the
// struct back, and iptables-save reads avg and burst. The rule returns the
// bytes that userspace sent, so the credit of the bucket stays private.
func (limitMarshaler) marshal(mr matcher) []byte {
	return marshalEntryMatch(matcherNameLimit, mr.(*LimitMatcher).raw)
}

// unmarshal implements matchMaker.unmarshal. It applies the checks of
// limit_mt_check.
func (limitMarshaler) unmarshal(_ IDMapper, _ *stack.Stack, buf []byte, _ stack.IPHeaderFilter) (stack.Matcher, error) {
	// WHY: Linux requires the exact aligned size.
	if len(buf) != limitInfoSize {
		return nil, fmt.Errorf("limit: buf has size %d, want %d", len(buf), limitInfoSize)
	}
	order := hostarch.ByteOrder
	avg := order.Uint32(buf[limitOffAvg:])
	burst := order.Uint32(buf[limitOffBurst:])
	// Both products wrap at 32 bits, as the u32 arithmetic of Linux does.
	if burst == 0 || limitUserToCredits(avg*burst) < limitUserToCredits(avg) {
		return nil, fmt.Errorf("limit: overflow, try lower: %d/%d", avg, burst)
	}
	m := &LimitMatcher{
		raw:       slices.Clone(buf),
		credit:    limitUserToCredits(avg * burst),
		creditCap: order.Uint32(buf[limitOffCreditCap:]),
		cost:      order.Uint32(buf[limitOffCost:]),
	}
	if m.cost == 0 {
		// Userspace leaves cost at 0. The bucket starts full and holds at
		// most that credit.
		m.creditCap = m.credit
		m.cost = limitUserToCredits(avg)
	}
	nflog("parsed limit: avg %d burst %d credit %d cap %d cost %d", avg, burst, m.credit, m.creditCap, m.cost)
	return m, nil
}

// limitUserToCredits is user2credits. It converts a time in units of
// 1/limitScale second to credits.
func limitUserToCredits(user uint32) uint32 {
	// If the multiplication would overflow, divide first.
	if user > 0xFFFFFFFF/(limitHZ*limitCreditsPerTick) {
		return (user / limitScale) * limitHZ * limitCreditsPerTick
	}
	return (user * limitHZ * limitCreditsPerTick) / limitScale
}

// LimitMatcher is a token bucket. Each rule has its own bucket, which a
// replacement of the table resets, as in Linux.
//
// +stateify savable
type LimitMatcher struct {
	// raw is the struct xt_rateinfo as parsed. Marshal returns it unchanged.
	raw []byte

	// creditCap and cost are the private values that limit_mt_check sets
	// from avg and burst when userspace sends cost 0.
	creditCap uint32
	cost      uint32

	stk      *stack.Stack
	savedNow time.Duration

	// clock returns the time since the bucket started. bindStack sets it
	// before the rule is published, so Match reads it without a lock.
	clock func() time.Duration `state:"nosave"`

	mu sync.Mutex `state:"nosave"`
	// prev is the tick of the last packet. credit is the current credit.
	prev   int64
	credit uint32
}

func (m *LimitMatcher) beforeSave() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.clock != nil {
		m.savedNow = m.clock()
	}
}

func (m *LimitMatcher) afterLoad(context.Context) {
	baseOffset := m.savedNow
	if m.stk != nil {
		clock := m.stk.Clock()
		epoch := clock.NowMonotonic()
		m.clock = func() time.Duration { return clock.NowMonotonic().Sub(epoch) + baseOffset }
		return
	}
	start := time.Now()
	m.clock = func() time.Duration { return time.Since(start) + baseOffset }
}

// name implements matcher.name.
func (*LimitMatcher) name() string { return matcherNameLimit }

// revision implements matcher.revision.
func (*LimitMatcher) revision() uint8 { return 0 }

// bindStack implements stackBinder.bindStack. The bucket counts time with the
// monotonic clock of the stack, from the moment of the bind. It is the
// initialization of prev in limit_mt_check.
func (m *LimitMatcher) bindStack(stk *stack.Stack) *syserr.Error {
	m.stk = stk
	clock := stk.Clock()
	epoch := clock.NowMonotonic()
	m.clock = func() time.Duration { return clock.NowMonotonic().Sub(epoch) }
	return nil
}

// Match implements stack.Matcher.Match. It follows limit_mt. The match needs
// no packet data.
func (m *LimitMatcher) Match(stack.Hook, *stack.PacketBuffer, string, string) (bool, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// The clock read is under the lock, so a later packet never sees an
	// earlier tick than the packet before it.
	now := int64(m.clock() / (time.Second / limitHZ))
	elapsed := max(now-m.prev, 0)
	m.prev = now
	// The sum fits in 64 bits, so a long idle time cannot wrap the credit.
	credit := min(uint64(m.credit)+uint64(elapsed)*limitCreditsPerTick, uint64(m.creditCap))
	if credit < uint64(m.cost) {
		m.credit = uint32(credit)
		return false, false
	}
	m.credit = uint32(credit - uint64(m.cost))
	return true, false
}
