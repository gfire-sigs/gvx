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

package kernel

import (
	"strings"
	"time"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sync"
)

// Per-descriptor /dev/kmsg rate limits matching Linux DEFAULT_RATELIMIT_INTERVAL
// and DEFAULT_RATELIMIT_BURST.
const (
	logRateInterval = 5 * time.Second
	logRateBurst    = 10
)

// DevkmsgMode represents /proc/sys/kernel/printk_devkmsg.
//
// +stateify savable
type DevkmsgMode int32

// Supported modes for kernel.printk_devkmsg.
const (
	// DevkmsgRatelimit caps each /dev/kmsg descriptor at 10 writes per 5 seconds.
	DevkmsgRatelimit DevkmsgMode = iota
	// DevkmsgOn accepts every /dev/kmsg write.
	DevkmsgOn
	// DevkmsgOff drops every /dev/kmsg write and reports success.
	DevkmsgOff
)

// String formats m for /proc/sys/kernel/printk_devkmsg reads.
func (m DevkmsgMode) String() string {
	switch m {
	case DevkmsgOn:
		return "on"
	case DevkmsgOff:
		return "off"
	default:
		return "ratelimit"
	}
}

// ParseDevkmsgMode parses "on", "off", or "ratelimit" with an optional trailing
// newline.
func ParseDevkmsgMode(text string) (DevkmsgMode, bool) {
	switch strings.TrimSuffix(text, "\n") {
	case "on":
		return DevkmsgOn, true
	case "off":
		return DevkmsgOff, true
	case "ratelimit":
		return DevkmsgRatelimit, true
	}
	return 0, false
}

// LogRateLimit enforces a burst of 10 writes per 5-second window for one
// /dev/kmsg file description, matching Linux ___ratelimit.
//
// +stateify savable
type LogRateLimit struct {
	mu sync.Mutex `state:"nosave"`
	// +checklocks:mu
	begin time.Duration
	// +checklocks:mu
	started bool
	// +checklocks:mu
	printed int
	// +checklocks:mu
	missed int
}

// Allow reports whether a write at elapsed time now passes the rate limit. It
// accumulates dropped writes across windows until descriptor release, matching
// Linux RATELIMIT_MSG_ON_RELEASE.
func (r *LogRateLimit) Allow(now time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started {
		r.started = true
		r.begin = now
	}
	if now-r.begin > logRateInterval {
		r.begin = now
		r.printed = 0
	}
	if r.printed < logRateBurst {
		r.printed++
		return true
	}
	r.missed++
	return false
}

// Missed returns the cumulative count of rate-limited writes.
func (r *LogRateLimit) Missed() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.missed
}

// WriteDevkmsg parses a /dev/kmsg write payload and appends records to l,
// matching Linux devkmsg_write. Payloads exceeding KernelLogRecordMax bytes
// fail with EINVAL. An optional "<N>" prefix sets priority (facility << 3 | level);
// facility 0 or an omitted prefix selects LogFacilityUser.
func (l *KernelLog) WriteDevkmsg(rl *LogRateLimit, data []byte) error {
	if len(data) > KernelLogRecordMax {
		return linuxerr.EINVAL
	}
	switch l.DevkmsgMode() {
	case DevkmsgOff:
		return nil
	case DevkmsgRatelimit:
		var now time.Duration
		if l.now != nil {
			now = l.now()
		}
		if !rl.Allow(now) {
			return nil
		}
	}
	facility, level, text := LogFacilityUser, LogDefaultLevel, string(data)
	if rest, ok := strings.CutPrefix(text, "<"); ok {
		end := 0
		var prefix uint64
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			prefix = prefix*10 + uint64(rest[end]-'0')
			end++
		}
		if end < len(rest) && rest[end] == '>' {
			prefix = uint64(uint32(prefix))
			level = int(prefix & 7)
			if f := int(prefix >> 3 & 0xff); f != 0 {
				facility = f
			}
			text = rest[end+1:]
		}
	}
	l.Emit(facility, level, text)
	return nil
}

// ReleaseDevkmsg emits a kernel warning summarizing suppressed writes when a
// /dev/kmsg descriptor closes, matching Linux ratelimit_state_exit.
func (l *KernelLog) ReleaseDevkmsg(rl *LogRateLimit, comm string) {
	if n := rl.Missed(); n > 0 {
		l.Printkf(LogWarning, "%s: %d output lines suppressed due to ratelimiting", comm, n)
	}
}
