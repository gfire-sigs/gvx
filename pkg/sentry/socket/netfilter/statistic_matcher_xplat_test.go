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
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// statisticInfo is the user space view of struct xt_statistic_info.
type statisticInfo struct {
	mode, flags uint16
	words       [3]uint32
	master      uint64
}

// bytes lays out the struct as the iptables binary writes it on a 64-bit
// little-endian host.
func (i statisticInfo) bytes() []byte {
	data := make([]byte, 24)
	binary.LittleEndian.PutUint16(data[0:], i.mode)
	binary.LittleEndian.PutUint16(data[2:], i.flags)
	for n, w := range i.words {
		binary.LittleEndian.PutUint32(data[4+4*n:], w)
	}
	binary.LittleEndian.PutUint64(data[16:], i.master)
	return data
}

// statisticEntry returns the bytes of one xt_entry_match for the statistic
// match, as userspace builds them.
func statisticEntry(info statisticInfo) []byte {
	buf := marshalEntryMatch("statistic", info.bytes())
	buf[revisionOffset] = 0
	return buf
}

func randomInfo(probability uint32, flags uint16) statisticInfo {
	return statisticInfo{mode: 0, flags: flags, words: [3]uint32{probability, 0, 0}}
}

// nthInfo mirrors "--every every --packet packet": userspace sends every - 1
// as every and every - 1 - packet as count.
func nthInfo(every, packet uint32, flags uint16) statisticInfo {
	return statisticInfo{mode: 1, flags: flags, words: [3]uint32{every - 1, packet, every - 1 - packet}}
}

// parseStatistic runs the production parse path over info.
func parseStatistic(t *testing.T, info statisticInfo) stack.Matcher {
	t.Helper()
	parsed, err := parseMatchers(nil, nil, stack.EmptyFilter4(), statisticEntry(info))
	if err != nil {
		t.Fatalf("parseMatchers: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("parseMatchers returned %d matchers, want 1", len(parsed))
	}
	if _, ok := parsed[0].(*StatisticMatcher); !ok {
		t.Fatalf("parseMatchers returned %T, want *StatisticMatcher", parsed[0])
	}
	return parsed[0]
}

// matchSequence feeds n packets to m and returns the 1-based packet numbers
// that matched.
func matchSequence(t *testing.T, m stack.Matcher, n int) []int {
	t.Helper()
	var hits []int
	for i := 1; i <= n; i++ {
		matched, hotdrop := m.Match(stack.Input, nil, "", "")
		if hotdrop {
			t.Fatalf("packet %d: hotdrop = true, want false", i)
		}
		if matched {
			hits = append(hits, i)
		}
	}
	return hits
}

func TestStatisticRandomExtremes(t *testing.T) {
	tests := []struct {
		name        string
		probability uint32
		flags       uint16
		want        int
	}{
		{"probability 0 never matches", 0, 0, 0},
		{"probability 2^31 always matches", 1 << 31, 0, 2000},
		{"inverted probability 0 always matches", 0, 1, 2000},
		{"inverted probability 2^31 never matches", 1 << 31, 1, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := parseStatistic(t, randomInfo(tc.probability, tc.flags))
			if got := len(matchSequence(t, m, 2000)); got != tc.want {
				t.Errorf("matched %d of 2000 packets, want %d", got, tc.want)
			}
		})
	}
}

func TestStatisticRandomHalfMatchesAboutHalf(t *testing.T) {
	const packets = 100000
	m := parseStatistic(t, randomInfo(1<<30, 0))
	got := len(matchSequence(t, m, packets))
	// The standard deviation is about 158 packets, so 2000 packets of
	// tolerance is 12 deviations.
	if got < packets*48/100 || got > packets*52/100 {
		t.Errorf("probability 0.5 matched %d of %d packets, want 48%% to 52%%", got, packets)
	}
}

func TestStatisticNthPositions(t *testing.T) {
	tests := []struct {
		name string
		info statisticInfo
		want []int
	}{
		{"every 3 packet 0", nthInfo(3, 0, 0), []int{1, 4, 7, 10}},
		{"every 3 packet 1", nthInfo(3, 1, 0), []int{2, 5, 8}},
		{"every 3 packet 2", nthInfo(3, 2, 0), []int{3, 6, 9}},
		{"every 1 packet 0", nthInfo(1, 0, 0), []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
		{"every 4 packet 3", nthInfo(4, 3, 0), []int{4, 8}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := parseStatistic(t, tc.info)
			if got := matchSequence(t, m, 10); !slices.Equal(got, tc.want) {
				t.Errorf("matched packets %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStatisticNthInversionMatchesTheOtherPackets(t *testing.T) {
	m := parseStatistic(t, nthInfo(3, 0, 1))
	want := []int{2, 3, 5, 6, 8, 9}
	if got := matchSequence(t, m, 9); !slices.Equal(got, want) {
		t.Errorf("inverted every 3 packet 0 matched packets %v, want %v", got, want)
	}
}

func TestStatisticMatchersKeepIndependentCounters(t *testing.T) {
	a := parseStatistic(t, nthInfo(3, 0, 0))
	b := parseStatistic(t, nthInfo(3, 0, 0))
	if got := matchSequence(t, a, 2); !slices.Equal(got, []int{1}) {
		t.Fatalf("first matcher matched packets %v, want [1]", got)
	}
	// The second matcher starts from its own counter, so its packet 1 matches
	// although the first matcher already saw two packets.
	if got := matchSequence(t, b, 3); !slices.Equal(got, []int{1}) {
		t.Errorf("second matcher matched packets %v, want [1]", got)
	}
}

func TestStatisticReparseStartsANewCounter(t *testing.T) {
	info := nthInfo(3, 0, 0)
	m := parseStatistic(t, info)
	matchSequence(t, m, 2)
	// iptables-restore replaces the table, so each parse restarts the counter.
	m = parseStatistic(t, info)
	if got := matchSequence(t, m, 3); !slices.Equal(got, []int{1}) {
		t.Errorf("matcher after reparse matched packets %v, want [1]", got)
	}
}

func TestStatisticNthCountsEveryPacketUnderConcurrency(t *testing.T) {
	const (
		workers = 8
		packets = 3000
	)
	m := parseStatistic(t, nthInfo(3, 0, 0))
	var matched atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range packets / workers {
				if ok, _ := m.Match(stack.Input, nil, "", ""); ok {
					matched.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if got, want := matched.Load(), int64(packets/3); got != want {
		t.Errorf("%d goroutines matched %d of %d packets, want exactly %d", workers, got, packets, want)
	}
}

func TestStatisticMarshalRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		info statisticInfo
	}{
		{"random probability 0.5", randomInfo(1<<30, 0)},
		{"inverted random", randomInfo(12345, 1)},
		{"nth every 3 packet 0", nthInfo(3, 0, 0)},
		{"inverted nth every 3 packet 1", nthInfo(3, 1, 1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Userspace leaves garbage in the private master pointer.
			in := tc.info
			in.master = 0xdeadbeefcafe
			m := parseStatistic(t, in)
			// Live counter state must not leak into the saved rule.
			matchSequence(t, m, 5)

			got := marshalMatcher(m)
			want := statisticEntry(tc.info)
			if !bytes.Equal(got, want) {
				t.Errorf("marshalled match = %x, want %x", got, want)
			}
			var hdr linux.XTEntryMatch
			hdr.UnmarshalBytes(got)
			if hdr.Name.String() != "statistic" || hdr.Revision != 0 || int(hdr.MatchSize) != len(got) {
				t.Errorf("header = name %q revision %d size %d, want statistic, 0, %d", hdr.Name.String(), hdr.Revision, hdr.MatchSize, len(got))
			}
		})
	}
}

func TestStatisticUnmarshalKernelLayout(t *testing.T) {
	// 64-bit host (include/uapi/linux/netfilter/xt_statistic.h): every 2,
	// packet 1, count 1, then the 8-byte master pointer.
	data := []byte{
		0x01, 0x00, // mode NTH
		0x00, 0x00, // flags
		0x02, 0x00, 0x00, 0x00, // every
		0x01, 0x00, 0x00, 0x00, // packet
		0x01, 0x00, 0x00, 0x00, // count
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // master
	}
	m, err := statisticMarshaler{}.unmarshal(nil, nil, data, stack.EmptyFilter4())
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got, want := matchSequence(t, m, 6), []int{2, 5}; !slices.Equal(got, want) {
		t.Errorf("matched packets %v, want %v", got, want)
	}
}

func TestStatisticAppliesToIPv6Rules(t *testing.T) {
	parsed, err := parseMatchers(nil, nil, stack.EmptyFilter6(), statisticEntry(nthInfo(2, 0, 0)))
	if err != nil {
		t.Fatalf("parseMatchers for IPv6: %v", err)
	}
	if got, want := matchSequence(t, parsed[0], 4), []int{1, 3}; !slices.Equal(got, want) {
		t.Errorf("IPv6 matcher matched packets %v, want %v", got, want)
	}
}

func TestStatisticUnmarshalRejects(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
	}{
		{"mode above NTH", statisticInfo{mode: 2}.bytes()},
		{"flags with an unknown bit", statisticInfo{mode: 0, flags: 2}.bytes()},
		{"flags with invert and an unknown bit", statisticInfo{mode: 1, flags: 3}.bytes()},
		{"short buffer", statisticInfo{}.bytes()[:16]},
		{"long buffer", append(statisticInfo{}.bytes(), make([]byte, 8)...)},
		{"empty buffer", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := (statisticMarshaler{}).unmarshal(nil, nil, tc.buf, stack.EmptyFilter4()); err == nil {
				t.Errorf("unmarshal succeeded, want an error")
			}
		})
	}
}

func TestStatisticRevisionNegotiation(t *testing.T) {
	rev, found := matchMakerRevision("statistic", 0)
	if !found || rev != 0 {
		t.Errorf("matchMakerRevision(statistic) = (%d, %v), want (0, true)", rev, found)
	}
}
