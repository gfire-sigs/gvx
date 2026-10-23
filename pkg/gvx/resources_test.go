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

package gvx

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestParseMemory(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{"512m", 512 << 20},
		{"512M", 512 << 20},
		{"512MB", 512 << 20},
		{"1g", 1 << 30},
		{"1.5g", 3 << 29},
		{"8192k", 8 << 20},
		{"6291456", 6 << 20},
		{"6291456b", 6 << 20},
		{"1t", 1 << 40},
		{"0", 0},
		{"0m", 0},
		{" 64m ", 64 << 20},
	} {
		got, err := ParseMemory(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("ParseMemory(%q) = (%d, %v), want %d", tc.in, got, err, tc.want)
		}
	}
}

func TestParseMemoryRejectsBadSizes(t *testing.T) {
	for _, in := range []string{"", "m", "abc", "-1m", "1x", "1.2.3m", "5m", "6291455", "9999999999t", "nan", "inf"} {
		if got, err := ParseMemory(in); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("ParseMemory(%q) = (%d, %v), want an ErrInvalidConfig error", in, got, err)
		}
	}
}

func TestParseCPUs(t *testing.T) {
	for _, tc := range []struct {
		in   string
		host int
		want int64
	}{
		{"1", 4, 1000},
		{"1.5", 4, 1500},
		{"0.25", 4, 250},
		{"0.001", 4, 1},
		{"4", 4, 4000},
		{"0", 4, 0},
	} {
		got, err := ParseCPUs(tc.in, tc.host)
		if err != nil || got != tc.want {
			t.Errorf("ParseCPUs(%q, %d) = (%d, %v), want %d", tc.in, tc.host, got, err, tc.want)
		}
	}
	for _, tc := range []struct {
		in   string
		host int
	}{{"", 4}, {"x", 4}, {"-1", 4}, {"4.001", 4}, {"0.0004", 4}, {"nan", 4}} {
		if got, err := ParseCPUs(tc.in, tc.host); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("ParseCPUs(%q, %d) = (%d, %v), want an ErrInvalidConfig error", tc.in, tc.host, got, err)
		}
	}
}

func TestGuestCPUs(t *testing.T) {
	for _, tc := range []struct {
		quota int64
		host  int
		want  int
	}{
		{0, 8, 8},
		{1, 8, 1},
		{1000, 8, 1},
		{1001, 8, 2},
		{2500, 8, 3},
		{8000, 8, 8},
		{9000, 8, 8},
		{500, 0, 1},
	} {
		if got := guestCPUs(tc.quota, tc.host); got != tc.want {
			t.Errorf("guestCPUs(%d, %d) = %d, want %d", tc.quota, tc.host, got, tc.want)
		}
	}
}

func TestMemoryGuardKillsWhenUseCrossesLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var use atomic.Uint64
		var kills atomic.Int32
		g := memoryGuard{
			limit:    100,
			used:     use.Load,
			interval: 10 * time.Millisecond,
			kill:     func() { kills.Add(1) },
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		result := make(chan bool, 1)
		go func() { result <- g.run(ctx) }()

		use.Store(100) // The limit itself is allowed.
		time.Sleep(50 * time.Millisecond)
		synctest.Wait()
		if got := kills.Load(); got != 0 {
			t.Fatalf("kill called %d times while the use equals the limit, want 0", got)
		}
		use.Store(101)
		if exceeded := <-result; !exceeded {
			t.Fatalf("run returned false, want true after the use passed the limit")
		}
		if got := kills.Load(); got != 1 {
			t.Errorf("kill called %d times, want exactly 1", got)
		}
	})
}

func TestMemoryGuardStopsWhenContextEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := memoryGuard{limit: 100, used: func() uint64 { return 1 }, interval: time.Millisecond, kill: func() { t.Error("kill called") }}
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan bool, 1)
		go func() { result <- g.run(ctx) }()
		time.Sleep(10 * time.Millisecond)
		cancel()
		if exceeded := <-result; exceeded {
			t.Fatalf("run returned true for a guest below the limit")
		}
	})
}
