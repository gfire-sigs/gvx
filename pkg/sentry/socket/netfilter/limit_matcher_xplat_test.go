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
	"bytes"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// limitInfo is the user space view of struct xt_rateinfo.
type limitInfo struct {
	avg, burst uint32
	// prev, credit, creditCap, cost, and master are the fields that the
	// kernel owns. Userspace leaves them zero, except for old versions that
	// set cost and credit_cap.
	prev                    uint64
	credit, creditCap, cost uint32
	master                  uint64
}

// bytes lays out the struct as the iptables binary writes it on a 64-bit
// little-endian host.
func (i limitInfo) bytes() []byte {
	data := make([]byte, limitInfoSize)
	binary.LittleEndian.PutUint32(data[0:], i.avg)
	binary.LittleEndian.PutUint32(data[4:], i.burst)
	binary.LittleEndian.PutUint64(data[8:], i.prev)
	binary.LittleEndian.PutUint32(data[16:], i.credit)
	binary.LittleEndian.PutUint32(data[20:], i.creditCap)
	binary.LittleEndian.PutUint32(data[24:], i.cost)
	binary.LittleEndian.PutUint64(data[32:], i.master)
	return data
}

func limitEntry(info limitInfo) []byte {
	return marshalEntryMatch(matcherNameLimit, info.bytes())
}

// parseLimit runs the production parse path and binds the matcher to a stack
// with a manual clock.
func parseLimit(t *testing.T, info limitInfo) (*LimitMatcher, *matchStack) {
	t.Helper()
	ms := newMatchStack(t)
	m, ok := parseOneMatcher(t, stack.EmptyFilter4(), limitEntry(info)).(*LimitMatcher)
	if !ok {
		t.Fatalf("parseMatchers did not return a *LimitMatcher")
	}
	if err := m.bindStack(ms.stack); err != nil {
		t.Fatalf("bindStack: %v", err)
	}
	return m, ms
}

// perSecond is the info of "--limit N/second --limit-burst burst", with the avg
// that userspace computes: XT_LIMIT_SCALE divided by the rate.
func perSecond(rate, burst uint32) limitInfo {
	return limitInfo{avg: limitScale / rate, burst: burst}
}

// perMinute is the info of "--limit N/minute --limit-burst burst".
func perMinute(rate, burst uint32) limitInfo {
	return limitInfo{avg: limitScale * 60 / rate, burst: burst}
}

// hits matches n packets and returns how many matched.
func hits(t *testing.T, m *LimitMatcher, n int) int {
	t.Helper()
	count := 0
	for range n {
		matched, hotdrop := m.Match(stack.Input, nil, "", "")
		if hotdrop {
			t.Errorf("Match returned hotdrop")
		}
		if matched {
			count++
		}
	}
	return count
}

func TestLimitBurstThenRefill(t *testing.T) {
	m, ms := parseLimit(t, perSecond(1, 5))
	if got := hits(t, m, 20); got != 5 {
		t.Errorf("first burst matched %d packets, want 5", got)
	}
	// One packet costs one second of credit. The failed packet at 999 ms
	// keeps its credit, so one more millisecond pays for a packet.
	ms.clock.Advance(999 * time.Millisecond)
	if got := hits(t, m, 1); got != 0 {
		t.Errorf("packet after 999 ms matched, want a miss")
	}
	ms.clock.Advance(time.Millisecond)
	if got := hits(t, m, 3); got != 1 {
		t.Errorf("packets after 1 s matched %d times, want 1", got)
	}
	ms.clock.Advance(3 * time.Second)
	if got := hits(t, m, 10); got != 3 {
		t.Errorf("packets after 3 s matched %d times, want 3", got)
	}
}

func TestLimitCreditIsCappedAtTheBurst(t *testing.T) {
	m, ms := parseLimit(t, perSecond(1, 5))
	hits(t, m, 5)
	ms.clock.Advance(24 * time.Hour)
	if got := hits(t, m, 20); got != 5 {
		t.Errorf("packets after a day matched %d times, want the burst of 5", got)
	}
}

func TestLimitKubeRouterRule(t *testing.T) {
	// "-m limit --limit 10/minute --limit-burst 10" as in the kube-router rules.
	m, ms := parseLimit(t, perMinute(10, 10))
	if got := hits(t, m, 50); got != 10 {
		t.Errorf("burst matched %d packets, want 10", got)
	}
	ms.clock.Advance(5900 * time.Millisecond)
	if got := hits(t, m, 1); got != 0 {
		t.Errorf("packet after 5.9 s matched, want a miss")
	}
	ms.clock.Advance(100 * time.Millisecond)
	if got := hits(t, m, 5); got != 1 {
		t.Errorf("packets after 6 s matched %d times, want 1", got)
	}
}

func TestLimitSlowestRateOfUserspace(t *testing.T) {
	// "--limit 1/day": the credit for a day must not overflow 32 bits.
	m, ms := parseLimit(t, limitInfo{avg: limitScale * 86400, burst: 1})
	if got := hits(t, m, 3); got != 1 {
		t.Errorf("burst matched %d packets, want 1", got)
	}
	ms.clock.Advance(23 * time.Hour)
	if got := hits(t, m, 1); got != 0 {
		t.Errorf("packet after 23 hours matched, want a miss")
	}
	ms.clock.Advance(time.Hour)
	if got := hits(t, m, 3); got != 1 {
		t.Errorf("packets after a day matched %d times, want 1", got)
	}
}

func TestLimitUsesCostAndCapFromUserspace(t *testing.T) {
	// Old userspace sends credit_cap and cost. Linux then keeps them.
	// Initial credit 32000 gets capped at 200 by the first packet.
	m, _ := parseLimit(t, limitInfo{avg: 10000, burst: 1, creditCap: 200, cost: 100})
	if got := hits(t, m, 5); got != 2 {
		t.Errorf("matched %d packets, want 2 (cap 200 over cost 100)", got)
	}
}

func TestLimitMatchesAtMostTheBurstUnderContention(t *testing.T) {
	m, _ := parseLimit(t, perSecond(1, 50))
	var matched atomic.Int64
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			matched.Add(int64(hits(t, m, 100)))
		})
	}
	wg.Wait()
	if got := matched.Load(); got != 50 {
		t.Errorf("matched %d packets at a frozen clock, want 50", got)
	}
}

func TestLimitMarshalReturnsTheUserBytes(t *testing.T) {
	info := perMinute(10, 10)
	// Kernel owned fields keep the bytes that came in.
	info.prev, info.master = 0x1122334455667788, 0x99aabbccddeeff00
	entry := limitEntry(info)
	m, _ := parseLimit(t, info)
	hits(t, m, 3)
	got := marshalMatcher(m)
	if !bytes.Equal(got, entry) {
		t.Errorf("marshalMatcher = %x, want %x", got, entry)
	}
	var hdr linux.XTEntryMatch
	hdr.UnmarshalBytes(got)
	if hdr.Name.String() != matcherNameLimit || int(hdr.MatchSize) != len(got) || len(got)%8 != 0 {
		t.Errorf("header = name %q size %d for %d bytes, want an 8-byte aligned size", hdr.Name.String(), hdr.MatchSize, len(got))
	}
	// iptables-save reads avg and burst.
	data := got[linux.SizeOfXTEntryMatch:]
	if avg, burst := binary.LittleEndian.Uint32(data), binary.LittleEndian.Uint32(data[4:]); avg != info.avg || burst != info.burst {
		t.Errorf("avg/burst = %d/%d, want %d/%d", avg, burst, info.avg, info.burst)
	}
}

func TestLimitUnmarshalRejects(t *testing.T) {
	tests := []struct {
		name  string
		entry []byte
	}{
		{"burst 0", limitEntry(limitInfo{avg: 10000, burst: 0})},
		// avg * burst wraps to 0 in 32 bits, which is less than the credit of avg.
		{"overflow of avg times burst", limitEntry(limitInfo{avg: 0x80000000, burst: 2})},
		{"too short", marshalEntryMatch(matcherNameLimit, make([]byte, 24))},
		{"too long", marshalEntryMatch(matcherNameLimit, make([]byte, 48))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseMatchers(nil, nil, stack.EmptyFilter4(), tc.entry); err == nil {
				t.Errorf("parseMatchers accepted the match")
			}
		})
	}
}

func TestLimitMatchRevisionIsReported(t *testing.T) {
	if rev, ok := matchMakerRevision(matcherNameLimit, 0); !ok || rev != 0 {
		t.Errorf("matchMakerRevision(limit) = (%d, %v), want (0, true)", rev, ok)
	}
}

// TestLimitRuleDropsRepliesWithinTheBudget sends echo requests through the
// INPUT chain of a stack. A rule that drops the requests within a limit of one
// request each second, with a burst of 2, removes the replies of the burst.
// Later requests get their replies until a second passes.
func TestLimitRuleDropsRepliesWithinTheBudget(t *testing.T) {
	ms := newMatchStack(t)
	filter := icmpFilter(false)
	m := parseOneMatcher(t, filter, limitEntry(perSecond(1, 2)))
	ms.installRules(t, false, stack.Input, dropRule(filter, m))

	var got []bool
	for range 4 {
		got = append(got, ms.injectEchoRequest(t, false))
	}
	want := []bool{false, false, true, true}
	if !equalBools(got, want) {
		t.Errorf("replies = %v, want %v", got, want)
	}
	ms.clock.Advance(time.Second)
	got = got[:0]
	for range 2 {
		got = append(got, ms.injectEchoRequest(t, false))
	}
	if want := []bool{false, true}; !equalBools(got, want) {
		t.Errorf("replies after one second = %v, want %v", got, want)
	}
}

func equalBools(a, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
