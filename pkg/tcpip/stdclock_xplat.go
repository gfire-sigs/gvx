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

package tcpip

import (
	"context"
	"fmt"
	"time"
)

// hostClock implements Clock with a monotonic source that keeps sub-millisecond
// resolution on hosts where time.Since reads a coarse interrupt clock.
//
// Keeping hostClock in a Tier 2 xplat file leaves stdclock.go and
// stdclock_state.go pristine while preserving cross-OS checkpoint/restore
// compatibility because every OS registers pkg/tcpip.hostClock.
//
// +stateify savable
type hostClock struct {
	baseTime        time.Time     `state:"nosave"`
	baseTicks       int64         `state:"nosave"`
	monotonicOffset MonotonicTime `state:".(MonotonicTime)"`
}

// NewHostClock returns a Clock backed by the finest monotonic host counter.
func NewHostClock() Clock {
	return &hostClock{
		baseTime:  time.Now(),
		baseTicks: hostTicks(),
	}
}

var _ Clock = (*hostClock)(nil)

// Now implements Clock.Now.
func (*hostClock) Now() time.Time {
	return time.Now()
}

// NowMonotonic implements Clock.NowMonotonic.
func (s *hostClock) NowMonotonic() MonotonicTime {
	sinceBase := hostSince(s.baseTime, s.baseTicks)
	if sinceBase < 0 {
		panic(fmt.Sprintf("got negative duration = %s since base time = %s", sinceBase, s.baseTime))
	}
	return s.monotonicOffset.Add(sinceBase)
}

// AfterFunc implements Clock.AfterFunc.
func (*hostClock) AfterFunc(d time.Duration, f func()) Timer {
	return &stdTimer{
		t: time.AfterFunc(d, f),
	}
}

func (s *hostClock) saveMonotonicOffset() MonotonicTime {
	return s.NowMonotonic()
}

func (s *hostClock) loadMonotonicOffset(_ context.Context, offset MonotonicTime) {
	s.monotonicOffset = offset
}

func (s *hostClock) afterLoad(context.Context) {
	s.baseTime = time.Now()
	s.baseTicks = hostTicks()
}
